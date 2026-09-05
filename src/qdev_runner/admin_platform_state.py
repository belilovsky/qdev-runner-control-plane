"""Atomic, receipt-bound state transitions for the Admin Platform program."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import secrets
import stat
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

import yaml

from .admin_platform import (
    ACTIVE_STATUSES_V3,
    ORDER_V3,
    RESULT_LANES_V3,
    AdminPlatformCandidate,
    AdminPlatformLedger,
    AdminPlatformLedgerError,
)
from .admin_platform_ledger import AdminPlatformLedger as LegacyAdminPlatformLedger
from .admin_platform_ledger import (
    AdminPlatformLedgerError as LegacyAdminPlatformLedgerError,
)
from .operations import format_utc, parse_utc, payload_digest, sign_payload
from .operator import verify_controller_receipt

_MAX_LEDGER_BYTES = 4 * 1024 * 1024
_MAX_RECEIPT_BYTES = 1024 * 1024


class AdminPlatformStateError(ValueError):
    """Raised when a requested durable ledger transition is not admissible."""


@dataclass(frozen=True)
class AdminPlatformStateUpdate:
    """Identity of one successfully committed durable ledger revision."""

    previous_sha256: str
    ledger_sha256: str
    active_stage: str | None
    active_status: str | None
    receipt_uris: tuple[str, ...]
    migration_archive_uri: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class AdminPlatformStateStore:
    """Serialize v3 state changes using CAS, immutable receipts, and atomic replace."""

    def __init__(
        self,
        path: Path,
        *,
        receipt_key: str,
        receipt_root: Path | None = None,
        file_uid: int | None = None,
        file_gid: int | None = None,
    ) -> None:
        if not receipt_key:
            raise ValueError("admin platform receipt key is required")
        if (file_uid is None) != (file_gid is None):
            raise ValueError("admin platform file owner requires both uid and gid")
        if file_uid is not None and (file_uid < 0 or cast(int, file_gid) < 0):
            raise ValueError("admin platform file owner must be non-negative")
        self.path = path
        self.receipt_key = receipt_key
        self.receipt_root = receipt_root or path.parent / "receipts"
        self.lock_path = path.with_name(f".{path.name}.lock")
        self.file_uid = file_uid
        self.file_gid = file_gid

    def initialize_from_template(
        self,
        *,
        template_path: Path,
        candidate: AdminPlatformCandidate,
        source_receipt: Mapping[str, Any],
        allow_legacy_migration: bool = False,
        migration_archive_root: Path | None = None,
    ) -> AdminPlatformStateUpdate:
        """Bind a pristine v3 template to one exact, receipt-proven controller.

        This is the single bounded bootstrap path for breaking the initial
        controller/admission cycle.  It refuses to replace an initialized v3
        program.  Legacy v1/v2 input is accepted only with an explicit flag and
        is archived byte-for-byte before the new state is committed.
        """

        with self._lock():
            template = self._load_pristine_template(template_path)
            receipt_document, source = self._evidence(
                source_receipt, evidence_type="lane_result"
            )
            if candidate.repository != template["entries"]["controller"]["repository"]:
                raise AdminPlatformStateError(
                    "candidate repository does not match controller template"
                )
            self._require_candidate_source(
                template,
                candidate,
                source,
                stage="controller",
            )
            if source["lane"] != "source" or source["outcome"] != "passed":
                raise AdminPlatformStateError(
                    "initialization requires passing source evidence"
                )

            previous_raw: bytes
            document: dict[str, Any]
            migration_archive_uri: str | None = None
            try:
                previous_raw = self._read_regular_file(self.path, _MAX_LEDGER_BYTES)
            except FileNotFoundError:
                previous_raw = b""
                document = template
            except OSError as error:
                raise AdminPlatformStateError(
                    "durable admin platform ledger is unsafe"
                ) from error
            else:
                schema = self._schema_from_raw(previous_raw)
                if schema == "qdev-admin-platform-ledger-v3":
                    try:
                        current = AdminPlatformLedger(
                            self.path,
                            receipt_key=self.receipt_key,
                            receipt_root=self.receipt_root,
                        )
                    except (AdminPlatformLedgerError, OSError) as error:
                        raise AdminPlatformStateError(
                            "durable admin platform ledger is invalid"
                        ) from error
                    if (
                        current.active_stage != "controller"
                        or current.active_candidate != candidate
                    ):
                        raise AdminPlatformStateError(
                            "initialized admin platform candidate does not match"
                        )
                    if self._source_is_passed(current.document(), candidate.release_id):
                        return self._unchanged_update(previous_raw, current)
                    document = current.document()
                    self._require_pristine_controller(document)
                elif schema in {
                    "qdev-admin-platform-ledger-v1",
                    "qdev-admin-platform-ledger-v2",
                }:
                    if not allow_legacy_migration:
                        raise AdminPlatformStateError(
                            "legacy admin platform ledger migration was not authorized"
                        )
                    self._validate_legacy_raw(previous_raw)
                    migration_archive_uri = self._archive_legacy_state(
                        previous_raw,
                        migration_archive_root
                        or self.path.parent / "ledger-migrations",
                    )
                    document = template
                else:
                    raise AdminPlatformStateError(
                        "durable admin platform ledger schema is not migratable"
                    )

            self._bind_pristine_controller(document, candidate, source)
            uri, checksum = self._persist_receipt(receipt_document)
            controller = cast(dict[str, Any], document["entries"]["controller"])
            result = cast(list[dict[str, Any]], controller["results"])[0]
            result["receipt_uri"] = uri
            result["receipt_sha256"] = checksum
            return self._commit_locked(
                previous_raw,
                document,
                (uri,),
                migration_archive_uri=migration_archive_uri,
            )

    def current(self) -> tuple[str, dict[str, Any]]:
        """Return the verified current state and its compare-and-swap digest."""

        with self._lock():
            raw, ledger = self._load_locked()
            return hashlib.sha256(raw).hexdigest(), ledger.snapshot()

    @staticmethod
    def _schema_from_raw(raw: bytes) -> str | None:
        try:
            document = yaml.safe_load(raw.decode("utf-8"))
        except (UnicodeDecodeError, yaml.YAMLError) as error:
            raise AdminPlatformStateError(
                "durable admin platform ledger cannot be decoded"
            ) from error
        if not isinstance(document, dict):
            return None
        schema = document.get("schema_version")
        return schema if isinstance(schema, str) else None

    def _load_pristine_template(self, template_path: Path) -> dict[str, Any]:
        try:
            template = AdminPlatformLedger(template_path).document()
        except (AdminPlatformLedgerError, OSError) as error:
            raise AdminPlatformStateError(
                "admin platform v3 bootstrap template is invalid"
            ) from error
        self._require_pristine_controller(template)
        return template

    @staticmethod
    def _require_pristine_controller(document: dict[str, Any]) -> None:
        if (
            document["program"]["status"] != "active"
            or document["active_stage"] != "controller"
            or not isinstance(document["active_candidate"], dict)
        ):
            raise AdminPlatformStateError(
                "admin platform bootstrap state is not a pristine controller template"
            )
        controller = cast(dict[str, Any], document["entries"]["controller"])
        attempts = cast(list[dict[str, Any]], controller["attempts"])
        results = cast(list[dict[str, Any]], controller["results"])
        candidate = cast(dict[str, Any], document["active_candidate"])
        if (
            controller["status"] != "candidate"
            or len(attempts) != 1
            or len(results) != 1
            or attempts[0]["release_id"] != candidate["release_id"]
            or results[0]
            != {
                "release_id": candidate["release_id"],
                "lane": "source",
                "outcome": "pending",
                "recorded_at": results[0]["recorded_at"],
                "receipt_uri": None,
                "receipt_sha256": None,
            }
        ):
            raise AdminPlatformStateError(
                "admin platform bootstrap controller already contains evidence"
            )
        for stage in ORDER_V3[1:]:
            entry = cast(dict[str, Any], document["entries"][stage])
            if (
                entry["status"] != "blocked"
                or entry["source_sha"] is not None
                or entry["reference"] is not None
                or entry["attempts"]
                or entry["results"]
            ):
                raise AdminPlatformStateError(
                    "admin platform bootstrap successor is not pristine"
                )

    @staticmethod
    def _bind_pristine_controller(
        document: dict[str, Any],
        candidate: AdminPlatformCandidate,
        source: Mapping[str, Any],
    ) -> None:
        controller = cast(dict[str, Any], document["entries"]["controller"])
        observed_at = cast(str, source["observed_at"])
        controller.update(
            {
                "source_sha": candidate.source_sha,
                "reference": candidate.reference,
                "status": "candidate",
                "attempts": [
                    {
                        "release_id": candidate.release_id,
                        "source_sha": candidate.source_sha,
                        "reference": candidate.reference,
                        "started_at": observed_at,
                        "finished_at": None,
                        "terminal_state": None,
                        "receipt_uri": None,
                        "receipt_sha256": None,
                    }
                ],
                "results": [
                    {
                        "release_id": candidate.release_id,
                        "lane": "source",
                        "outcome": "passed",
                        "recorded_at": observed_at,
                        "receipt_uri": None,
                        "receipt_sha256": None,
                    }
                ],
            }
        )
        document["active_candidate"] = asdict(candidate)
        document["program"]["updated_at"] = observed_at

    @staticmethod
    def _source_is_passed(document: dict[str, Any], release_id: str) -> bool:
        results = cast(
            list[dict[str, Any]], document["entries"]["controller"]["results"]
        )
        return any(
            result["release_id"] == release_id
            and result["lane"] == "source"
            and result["outcome"] == "passed"
            for result in results
        )

    def _unchanged_update(
        self, raw: bytes, ledger: AdminPlatformLedger
    ) -> AdminPlatformStateUpdate:
        digest = hashlib.sha256(raw).hexdigest()
        active_stage = ledger.active_stage
        active_status = None
        if active_stage is not None:
            active_status = next(
                entry.status for entry in ledger.entries if entry.entry_id == active_stage
            )
        return AdminPlatformStateUpdate(
            previous_sha256=digest,
            ledger_sha256=digest,
            active_stage=active_stage,
            active_status=active_status,
            receipt_uris=(),
        )

    def _validate_legacy_raw(self, raw: bytes) -> None:
        directory = os.open(
            self.path.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        temporary_name = f".{self.path.name}.legacy-validate.{secrets.token_hex(8)}"
        temporary_path = self.path.parent / temporary_name
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory,
            )
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            LegacyAdminPlatformLedger(temporary_path)
        except (LegacyAdminPlatformLedgerError, OSError) as error:
            raise AdminPlatformStateError(
                "legacy admin platform ledger is invalid"
            ) from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=directory)
            os.close(directory)

    def _archive_legacy_state(self, raw: bytes, root: Path) -> str:
        checksum = hashlib.sha256(raw).hexdigest()
        root.mkdir(parents=True, exist_ok=True)
        try:
            directory = os.open(
                root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
        except OSError as error:
            raise AdminPlatformStateError(
                "legacy admin platform archive root is unavailable"
            ) from error
        try:
            metadata = os.fstat(directory)
            if not stat.S_ISDIR(metadata.st_mode):
                raise AdminPlatformStateError(
                    "legacy admin platform archive root is unsafe"
                )
            os.fchmod(directory, 0o700)
            filename = f"{self.path.name}.{checksum}.legacy.yml"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(filename, flags, 0o600, dir_fd=directory)
            except FileExistsError as error:
                existing = self._read_regular_file_at(
                    directory, filename, _MAX_LEDGER_BYTES
                )
                if existing != raw:
                    raise AdminPlatformStateError(
                        "immutable legacy ledger archive collision"
                    ) from error
            else:
                try:
                    view = memoryview(raw)
                    while view:
                        written = os.write(descriptor, view)
                        view = view[written:]
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.fsync(directory)
        finally:
            os.close(directory)
        return str(root / filename)

    def record_result(
        self,
        *,
        expected_sha256: str,
        receipt: Mapping[str, Any],
    ) -> AdminPlatformStateUpdate:
        """Append one non-terminal lane transition for the active attempt."""

        with self._lock():
            raw, ledger = self._load_locked()
            self._require_digest(raw, expected_sha256)
            document = ledger.document()
            verified, payload = self._evidence(receipt, evidence_type="lane_result")
            entry, attempt = self._active_attempt(document)
            self._require_active_tuple(document, payload)
            outcome = cast(str, payload["outcome"])
            lane = cast(str, payload["lane"])
            if outcome in {"failed", "blocked"}:
                raise AdminPlatformStateError(
                    "terminal lane failures must be committed with finish_attempt"
                )
            uri, checksum = self._persist_receipt(verified)
            self._append_result(entry, payload, uri, checksum)

            if lane == "ci" and outcome == "queued":
                entry["status"] = "ci_queued"
            elif lane == "ci" and outcome == "passed":
                entry["status"] = "ci_passed"
            elif lane == "deploy" and outcome in {"queued", "passed"}:
                entry["status"] = "deploying"
            elif entry["status"] not in ACTIVE_STATUSES_V3:
                raise AdminPlatformStateError("active attempt is not advancing")

            if attempt["terminal_state"] is not None:
                raise AdminPlatformStateError("active attempt is already terminal")
            self._touch(document, cast(str, payload["observed_at"]))
            return self._commit_locked(raw, document, (uri,))

    def finish_attempt(
        self,
        *,
        expected_sha256: str,
        terminal_receipt: Mapping[str, Any],
        result_receipt: Mapping[str, Any] | None = None,
    ) -> AdminPlatformStateUpdate:
        """Atomically finish a failed or rolled-back attempt.

        A final failing lane receipt can be supplied with the terminal receipt so
        the durable ledger never exposes an ambiguous half-finished state.
        """

        with self._lock():
            raw, ledger = self._load_locked()
            self._require_digest(raw, expected_sha256)
            document = ledger.document()
            terminal_document, terminal = self._evidence(
                terminal_receipt, evidence_type="attempt_terminal"
            )
            self._require_active_tuple(document, terminal)
            terminal_state = cast(str, terminal["outcome"])
            if terminal_state not in {"blocked", "rolled_back"}:
                raise AdminPlatformStateError(
                    "finish_attempt accepts only blocked or rolled_back outcomes"
                )
            entry, attempt = self._active_attempt(document)
            uris: list[str] = []
            if result_receipt is not None:
                result_document, result = self._evidence(
                    result_receipt, evidence_type="lane_result"
                )
                self._require_active_tuple(document, result)
                if parse_utc(cast(str, result["observed_at"])) > parse_utc(
                    cast(str, terminal["observed_at"])
                ):
                    raise AdminPlatformStateError("lane result follows its terminal receipt")
                result_uri, result_checksum = self._persist_receipt(result_document)
                self._append_result(entry, result, result_uri, result_checksum)
                uris.append(result_uri)

            terminal_uri, terminal_checksum = self._persist_receipt(terminal_document)
            attempt.update(
                {
                    "finished_at": terminal["observed_at"],
                    "terminal_state": terminal_state,
                    "receipt_uri": terminal_uri,
                    "receipt_sha256": terminal_checksum,
                }
            )
            entry["status"] = terminal_state
            document["program"]["status"] = "blocked"
            self._touch(document, cast(str, terminal["observed_at"]))
            uris.append(terminal_uri)
            return self._commit_locked(raw, document, tuple(uris))

    def supersede_attempt(
        self,
        *,
        expected_sha256: str,
        result_receipt: Mapping[str, Any],
        terminal_receipt: Mapping[str, Any],
        candidate: AdminPlatformCandidate,
        source_receipt: Mapping[str, Any],
    ) -> AdminPlatformStateUpdate:
        """Atomically block the active attempt and admit its replacement."""

        with self._lock():
            raw, ledger = self._load_locked()
            self._require_digest(raw, expected_sha256)
            document = ledger.document()
            if document["program"]["status"] != "active":
                raise AdminPlatformStateError("program is not active for supersession")
            entry, previous_attempt = self._active_attempt(document)
            if entry["status"] not in {"candidate", "ci_queued", "ci_passed"}:
                raise AdminPlatformStateError("active attempt cannot be superseded")
            if previous_attempt["terminal_state"] is not None:
                raise AdminPlatformStateError("active attempt is already terminal")

            result_document, result = self._evidence(
                result_receipt, evidence_type="lane_result"
            )
            terminal_document, terminal = self._evidence(
                terminal_receipt, evidence_type="attempt_terminal"
            )
            source_document, source = self._evidence(
                source_receipt, evidence_type="lane_result"
            )
            self._require_active_tuple(document, result)
            self._require_active_tuple(document, terminal)
            self._require_candidate_source(document, candidate, source)
            if result["outcome"] != "blocked" or terminal["outcome"] != "blocked":
                raise AdminPlatformStateError("supersession requires blocked terminal evidence")
            if source["lane"] != "source" or source["outcome"] != "passed":
                raise AdminPlatformStateError("supersession requires passing source evidence")
            result_at = parse_utc(cast(str, result["observed_at"]))
            terminal_at = parse_utc(cast(str, terminal["observed_at"]))
            source_at = parse_utc(cast(str, source["observed_at"]))
            if result_at > terminal_at:
                raise AdminPlatformStateError("lane result follows its terminal receipt")
            if source_at <= terminal_at:
                raise AdminPlatformStateError(
                    "replacement candidate does not follow terminal receipt"
                )
            if candidate.repository != entry["repository"]:
                raise AdminPlatformStateError("candidate repository does not match active stage")
            if any(
                attempt["release_id"] == candidate.release_id for attempt in entry["attempts"]
            ):
                raise AdminPlatformStateError("candidate release id was already used")

            transaction_id, transaction_receipts = self._transaction_receipts(
                (result_document, terminal_document, source_document),
                previous_raw=raw,
            )
            (
                (result_uri, result_checksum, _),
                (terminal_uri, terminal_checksum, _),
                (source_uri, source_checksum, _),
            ) = transaction_receipts
            self._append_result(entry, result, result_uri, result_checksum)
            previous_attempt.update(
                {
                    "finished_at": terminal["observed_at"],
                    "terminal_state": "blocked",
                    "receipt_uri": terminal_uri,
                    "receipt_sha256": terminal_checksum,
                }
            )
            entry.update(
                {
                    "source_sha": candidate.source_sha,
                    "reference": candidate.reference,
                    "status": "candidate",
                }
            )
            entry["attempts"].append(
                {
                    "release_id": candidate.release_id,
                    "source_sha": candidate.source_sha,
                    "reference": candidate.reference,
                    "started_at": source["observed_at"],
                    "finished_at": None,
                    "terminal_state": None,
                    "receipt_uri": None,
                    "receipt_sha256": None,
                }
            )
            self._append_result(entry, source, source_uri, source_checksum)
            document["active_candidate"] = asdict(candidate)
            document["program"]["status"] = "active"
            self._touch(document, cast(str, source["observed_at"]))
            self._persist_receipt_transaction(
                transaction_id=transaction_id,
                receipts=transaction_receipts,
                previous_raw=raw,
                document=document,
                observed_at=cast(str, source["observed_at"]),
            )
            return self._commit_locked(
                raw,
                document,
                (result_uri, terminal_uri, source_uri),
            )

    def restart_attempt(
        self,
        *,
        expected_sha256: str,
        candidate: AdminPlatformCandidate,
        source_receipt: Mapping[str, Any],
    ) -> AdminPlatformStateUpdate:
        """Start a new exact candidate only after a terminal blocked attempt."""

        with self._lock():
            raw, ledger = self._load_locked()
            self._require_digest(raw, expected_sha256)
            document = ledger.document()
            if document["program"]["status"] != "blocked":
                raise AdminPlatformStateError("program is not blocked for restart")
            entry, previous_attempt = self._active_attempt(document)
            if entry["status"] not in {"blocked", "rolled_back"}:
                raise AdminPlatformStateError("active stage has no terminal attempt to replace")
            if previous_attempt["terminal_state"] not in {"blocked", "rolled_back"}:
                raise AdminPlatformStateError("latest attempt is not terminal")
            if candidate.repository != entry["repository"]:
                raise AdminPlatformStateError("candidate repository does not match active stage")

            receipt_document, source = self._evidence(
                source_receipt, evidence_type="lane_result"
            )
            self._require_candidate_source(document, candidate, source)
            if source["lane"] != "source" or source["outcome"] != "passed":
                raise AdminPlatformStateError("restart requires passing source evidence")
            if any(
                attempt["release_id"] == candidate.release_id for attempt in entry["attempts"]
            ):
                raise AdminPlatformStateError("candidate release id was already used")

            transaction_id, transaction_receipts = self._transaction_receipts(
                (receipt_document,),
                previous_raw=raw,
            )
            ((uri, checksum, _),) = transaction_receipts
            entry.update(
                {
                    "source_sha": candidate.source_sha,
                    "reference": candidate.reference,
                    "status": "candidate",
                }
            )
            entry["attempts"].append(
                {
                    "release_id": candidate.release_id,
                    "source_sha": candidate.source_sha,
                    "reference": candidate.reference,
                    "started_at": source["observed_at"],
                    "finished_at": None,
                    "terminal_state": None,
                    "receipt_uri": None,
                    "receipt_sha256": None,
                }
            )
            self._append_result(entry, source, uri, checksum)
            document["active_candidate"] = asdict(candidate)
            document["program"]["status"] = "active"
            self._touch(document, cast(str, source["observed_at"]))
            self._persist_receipt_transaction(
                transaction_id=transaction_id,
                receipts=transaction_receipts,
                previous_raw=raw,
                document=document,
                observed_at=cast(str, source["observed_at"]),
            )
            return self._commit_locked(raw, document, (uri,))

    def accept_and_advance(
        self,
        *,
        expected_sha256: str,
        terminal_receipt: Mapping[str, Any],
        next_candidate: AdminPlatformCandidate | None = None,
        next_source_receipt: Mapping[str, Any] | None = None,
    ) -> AdminPlatformStateUpdate:
        """Accept the current stage and atomically admit its immediate successor."""

        with self._lock():
            raw, ledger = self._load_locked()
            self._require_digest(raw, expected_sha256)
            document = ledger.document()
            terminal_document, terminal = self._evidence(
                terminal_receipt, evidence_type="attempt_terminal"
            )
            self._require_active_tuple(document, terminal)
            if terminal["outcome"] != "live_accepted":
                raise AdminPlatformStateError("advance requires live_accepted evidence")
            entry, attempt = self._active_attempt(document)
            latest = self._latest_results(entry, cast(str, attempt["release_id"]))
            if set(latest) != set(RESULT_LANES_V3) or any(
                outcome not in {"passed", "not_applicable"} for outcome in latest.values()
            ):
                raise AdminPlatformStateError("current stage does not have complete lane evidence")

            terminal_uri, terminal_checksum = self._persist_receipt(terminal_document)
            attempt.update(
                {
                    "finished_at": terminal["observed_at"],
                    "terminal_state": "live_accepted",
                    "receipt_uri": terminal_uri,
                    "receipt_sha256": terminal_checksum,
                }
            )
            entry["status"] = "live_accepted"
            uris = [terminal_uri]
            current_index = ORDER_V3.index(cast(str, document["active_stage"]))
            if current_index == len(ORDER_V3) - 1:
                if next_candidate is not None or next_source_receipt is not None:
                    raise AdminPlatformStateError("complete program cannot admit another candidate")
                document["program"]["status"] = "complete"
                document["active_stage"] = None
                document["active_candidate"] = None
                self._touch(document, cast(str, terminal["observed_at"]))
                return self._commit_locked(raw, document, tuple(uris))

            if next_candidate is None or next_source_receipt is None:
                raise AdminPlatformStateError("next candidate and source evidence are required")
            next_stage = ORDER_V3[current_index + 1]
            next_entry = cast(dict[str, Any], document["entries"][next_stage])
            if (
                next_entry["status"] != "blocked"
                or next_entry["source_sha"] is not None
                or next_entry["reference"] is not None
                or next_entry["attempts"]
                or next_entry["results"]
            ):
                raise AdminPlatformStateError(
                    "next stage contains history and cannot be destructively replaced"
                )
            if next_candidate.repository != next_entry["repository"]:
                raise AdminPlatformStateError("next candidate repository does not match stage")
            source_document, source = self._evidence(
                next_source_receipt, evidence_type="lane_result"
            )
            if source["stage"] != next_stage:
                raise AdminPlatformStateError("source evidence is not for the next stage")
            self._require_candidate_source(document, next_candidate, source, stage=next_stage)
            if source["lane"] != "source" or source["outcome"] != "passed":
                raise AdminPlatformStateError("next candidate requires passing source evidence")
            if parse_utc(cast(str, source["observed_at"])) < parse_utc(
                cast(str, terminal["observed_at"])
            ):
                raise AdminPlatformStateError("next candidate predates accepted prerequisite")

            source_uri, source_checksum = self._persist_receipt(source_document)
            next_entry.update(
                {
                    "source_sha": next_candidate.source_sha,
                    "reference": next_candidate.reference,
                    "status": "candidate",
                    "attempts": [
                        {
                            "release_id": next_candidate.release_id,
                            "source_sha": next_candidate.source_sha,
                            "reference": next_candidate.reference,
                            "started_at": source["observed_at"],
                            "finished_at": None,
                            "terminal_state": None,
                            "receipt_uri": None,
                            "receipt_sha256": None,
                        }
                    ],
                    "results": [],
                }
            )
            self._append_result(next_entry, source, source_uri, source_checksum)
            document["active_stage"] = next_stage
            document["active_candidate"] = asdict(next_candidate)
            document["program"]["status"] = "active"
            self._touch(document, cast(str, source["observed_at"]))
            uris.append(source_uri)
            return self._commit_locked(raw, document, tuple(uris))

    @contextmanager
    def _lock(self) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.lock_path, flags, 0o600)
        except OSError as error:
            raise AdminPlatformStateError("admin platform ledger lock is unavailable") from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise AdminPlatformStateError("admin platform ledger lock is unsafe")
            self._set_runtime_owner(descriptor)
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _load_locked(self) -> tuple[bytes, AdminPlatformLedger]:
        try:
            raw = self._read_regular_file(self.path, _MAX_LEDGER_BYTES)
            ledger = AdminPlatformLedger(
                self.path,
                receipt_key=self.receipt_key,
                receipt_root=self.receipt_root,
            )
        except (AdminPlatformLedgerError, OSError) as error:
            raise AdminPlatformStateError("durable admin platform ledger is invalid") from error
        return raw, ledger

    @staticmethod
    def _read_regular_file(path: Path, limit: int) -> bytes:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        return AdminPlatformStateStore._read_regular_descriptor(descriptor, limit)

    @staticmethod
    def _read_regular_file_at(directory: int, filename: str, limit: int) -> bytes:
        descriptor = os.open(
            filename,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory,
        )
        return AdminPlatformStateStore._read_regular_descriptor(descriptor, limit)

    @staticmethod
    def _read_regular_descriptor(descriptor: int, limit: int) -> bytes:
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
                raise AdminPlatformStateError("state file is unsafe")
            chunks: list[bytes] = []
            remaining = limit + 1
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > limit:
                raise AdminPlatformStateError("state file is too large")
            return raw
        finally:
            os.close(descriptor)

    @staticmethod
    def _require_digest(raw: bytes, expected: str) -> None:
        actual = hashlib.sha256(raw).hexdigest()
        if expected != actual:
            raise AdminPlatformStateError("admin platform ledger compare-and-swap conflict")

    def _evidence(
        self,
        receipt: Mapping[str, Any],
        *,
        evidence_type: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        try:
            verified = verify_controller_receipt(receipt, receipt_key=self.receipt_key)
        except ValueError as error:
            raise AdminPlatformStateError("admin platform evidence receipt is invalid") from error
        payload = verified["payload"]
        if payload.get("kind") != "admin-platform-evidence":
            raise AdminPlatformStateError("receipt is not admin platform evidence")
        if payload.get("evidence_type") != evidence_type:
            raise AdminPlatformStateError("receipt evidence type is invalid for transition")
        observed_at = payload.get("observed_at")
        try:
            canonical_observed_at = (
                isinstance(observed_at, str)
                and format_utc(parse_utc(observed_at)) == observed_at
            )
        except (TypeError, ValueError):
            canonical_observed_at = False
        if not canonical_observed_at:
            raise AdminPlatformStateError("receipt timestamp must use canonical UTC")
        return verified, cast(dict[str, Any], payload)

    @staticmethod
    def _active_attempt(
        document: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        stage = document["active_stage"]
        if not isinstance(stage, str):
            raise AdminPlatformStateError("program has no active stage")
        entry = cast(dict[str, Any], document["entries"][stage])
        attempts = cast(list[dict[str, Any]], entry["attempts"])
        if not attempts:
            raise AdminPlatformStateError("active stage has no attempt")
        return entry, attempts[-1]

    @staticmethod
    def _require_active_tuple(document: dict[str, Any], payload: Mapping[str, Any]) -> None:
        candidate = document["active_candidate"]
        if not isinstance(candidate, dict):
            raise AdminPlatformStateError("program has no active candidate")
        if (
            payload.get("program_id") != document["program"]["id"]
            or payload.get("stage") != document["active_stage"]
            or payload.get("release_id") != candidate["release_id"]
            or payload.get("source_sha") != candidate["source_sha"]
        ):
            raise AdminPlatformStateError("receipt does not match active candidate tuple")

    @staticmethod
    def _require_candidate_source(
        document: dict[str, Any],
        candidate: AdminPlatformCandidate,
        payload: Mapping[str, Any],
        *,
        stage: str | None = None,
    ) -> None:
        expected_stage = stage or cast(str, document["active_stage"])
        if (
            payload.get("program_id") != document["program"]["id"]
            or payload.get("stage") != expected_stage
            or payload.get("release_id") != candidate.release_id
            or payload.get("source_sha") != candidate.source_sha
        ):
            raise AdminPlatformStateError("source receipt does not match candidate tuple")

    @staticmethod
    def _append_result(
        entry: dict[str, Any],
        payload: Mapping[str, Any],
        receipt_uri: str,
        receipt_sha256: str,
    ) -> None:
        cast(list[dict[str, Any]], entry["results"]).append(
            {
                "release_id": payload["release_id"],
                "lane": payload["lane"],
                "outcome": payload["outcome"],
                "recorded_at": payload["observed_at"],
                "receipt_uri": receipt_uri,
                "receipt_sha256": receipt_sha256,
            }
        )

    @staticmethod
    def _latest_results(entry: dict[str, Any], release_id: str) -> dict[str, str]:
        latest: dict[str, str] = {}
        for result in cast(list[dict[str, Any]], entry["results"]):
            if result["release_id"] == release_id:
                latest[cast(str, result["lane"])] = cast(str, result["outcome"])
        return latest

    def _persist_receipt(self, receipt: dict[str, Any]) -> tuple[str, str]:
        raw = self._receipt_raw(receipt)
        if len(raw) > _MAX_RECEIPT_BYTES:
            raise AdminPlatformStateError("admin platform receipt is too large")
        receipt_id = receipt.get("receipt_id")
        if not isinstance(receipt_id, str) or not all(
            character in "0123456789abcdef" for character in receipt_id
        ) or len(receipt_id) != 64:
            raise AdminPlatformStateError("admin platform receipt id is invalid")
        self.receipt_root.mkdir(parents=True, exist_ok=True)
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        try:
            directory = os.open(
                self.receipt_root,
                directory_flags | getattr(os, "O_NOFOLLOW", 0),
            )
        except OSError as error:
            raise AdminPlatformStateError(
                "admin platform receipt root is unavailable"
            ) from error
        metadata = os.fstat(directory)
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(directory)
            raise AdminPlatformStateError("admin platform receipt root is unsafe")
        self._set_runtime_owner(directory)
        os.fchmod(directory, 0o700)
        filename = f"{receipt_id}.json"
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(filename, flags, 0o600, dir_fd=directory)
            except FileExistsError as error:
                existing = self._read_regular_file_at(
                    directory, filename, _MAX_RECEIPT_BYTES
                )
                if existing != raw:
                    raise AdminPlatformStateError("immutable receipt id collision") from error
            else:
                try:
                    self._set_runtime_owner(descriptor)
                    os.fchmod(descriptor, 0o600)
                    view = memoryview(raw)
                    while view:
                        written = os.write(descriptor, view)
                        view = view[written:]
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.fsync(directory)
        finally:
            os.close(directory)
        return f"receipts/{filename}", hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _receipt_raw(receipt: Mapping[str, Any]) -> bytes:
        raw = (
            json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n"
        ).encode("utf-8")
        if len(raw) > _MAX_RECEIPT_BYTES:
            raise AdminPlatformStateError("admin platform receipt is too large")
        return raw

    def _transaction_receipts(
        self,
        receipts: tuple[dict[str, Any], ...],
        *,
        previous_raw: bytes,
    ) -> tuple[str, tuple[tuple[str, str, bytes], ...]]:
        encoded: list[tuple[str, str, bytes]] = []
        identities: list[dict[str, str]] = []
        for receipt in receipts:
            try:
                verified = verify_controller_receipt(receipt, receipt_key=self.receipt_key)
            except ValueError as error:
                raise AdminPlatformStateError(
                    "admin platform transaction receipt is invalid"
                ) from error
            ledger_bound = self._signed_receipt(
                cast(dict[str, Any], verified["payload"]),
                ledger_bound=True,
            )
            raw = self._receipt_raw(ledger_bound)
            receipt_id = ledger_bound.get("receipt_id")
            if (
                not isinstance(receipt_id, str)
                or len(receipt_id) != 64
                or any(character not in "0123456789abcdef" for character in receipt_id)
            ):
                raise AdminPlatformStateError("admin platform receipt id is invalid")
            checksum = hashlib.sha256(raw).hexdigest()
            identities.append({"receipt_id": receipt_id, "receipt_sha256": checksum})
            encoded.append((receipt_id, checksum, raw))
        transaction_id = payload_digest(
            {
                "previous_ledger_sha256": hashlib.sha256(previous_raw).hexdigest(),
                "receipts": identities,
            }
        )
        bound = tuple(
            (
                f"receipts/transactions/{transaction_id}/{receipt_id}.json",
                checksum,
                raw,
            )
            for receipt_id, checksum, raw in encoded
        )
        return transaction_id, bound

    def _persist_receipt_transaction(
        self,
        *,
        transaction_id: str,
        receipts: tuple[tuple[str, str, bytes], ...],
        previous_raw: bytes,
        document: dict[str, Any],
        observed_at: str,
    ) -> None:
        target_ledger_sha256 = hashlib.sha256(self._encode_ledger(document)).hexdigest()
        payload = {
            "kind": "admin-platform-state-transaction",
            "observed_at": observed_at,
            "transaction_id": transaction_id,
            "previous_ledger_sha256": hashlib.sha256(previous_raw).hexdigest(),
            "target_ledger_sha256": target_ledger_sha256,
            "receipts": [
                {"receipt_uri": uri, "receipt_sha256": checksum}
                for uri, checksum, _ in receipts
            ],
        }
        binding = self._signed_receipt(payload, ledger_bound=True)
        binding_raw = self._receipt_raw(binding)

        receipt_root_fd, root_fd = self._open_durable_child_directory(
            "transactions",
            unavailable="admin platform receipt transaction root is unavailable",
            unsafe="admin platform receipt transaction root is unsafe",
        )
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        transaction_filenames = tuple(uri.rsplit("/", 1)[1] for uri, _, _ in receipts) + (
            "ledger-binding.json",
        )
        self._remove_stale_transaction_directories(
            root_fd,
            transaction_id,
            transaction_filenames,
        )
        temporary_name = f".{transaction_id}.{secrets.token_hex(8)}.tmp"
        transaction_fd: int | None = None
        try:
            os.mkdir(temporary_name, mode=0o700, dir_fd=root_fd)
            transaction_fd = os.open(
                temporary_name,
                directory_flags | nofollow,
                dir_fd=root_fd,
            )
            self._set_runtime_owner(transaction_fd)
            os.fchmod(transaction_fd, 0o700)
            for uri, _, raw in receipts:
                self._write_transaction_file(
                    transaction_fd,
                    uri.rsplit("/", 1)[1],
                    raw,
                )
            self._write_transaction_file(
                transaction_fd,
                "ledger-binding.json",
                binding_raw,
            )
            os.fsync(transaction_fd)
            os.close(transaction_fd)
            transaction_fd = None
            try:
                os.rename(
                    temporary_name,
                    transaction_id,
                    src_dir_fd=root_fd,
                    dst_dir_fd=root_fd,
                )
                os.fsync(root_fd)
            except OSError as error:
                if error.errno not in {errno.EEXIST, errno.ENOTEMPTY}:
                    raise
                existing_fd = os.open(
                    transaction_id,
                    directory_flags | nofollow,
                    dir_fd=root_fd,
                )
                try:
                    for uri, _, raw in receipts:
                        if self._read_regular_file_at(
                            existing_fd,
                            uri.rsplit("/", 1)[1],
                            _MAX_RECEIPT_BYTES,
                        ) != raw:
                            raise AdminPlatformStateError(
                                "immutable receipt transaction collision"
                            )
                    if self._read_regular_file_at(
                        existing_fd,
                        "ledger-binding.json",
                        _MAX_RECEIPT_BYTES,
                    ) != binding_raw:
                        raise AdminPlatformStateError(
                            "immutable receipt transaction binding collision"
                        )
                finally:
                    os.close(existing_fd)
                self._remove_temporary_transaction(
                    root_fd,
                    temporary_name,
                    transaction_filenames,
                )
        finally:
            if transaction_fd is not None:
                os.close(transaction_fd)
            with suppress(FileNotFoundError, AdminPlatformStateError):
                self._remove_temporary_transaction(
                    root_fd,
                    temporary_name,
                    transaction_filenames,
                )
            os.close(root_fd)
            os.close(receipt_root_fd)

    def _open_durable_child_directory(
        self,
        child_name: str,
        *,
        unavailable: str,
        unsafe: str,
    ) -> tuple[int, int]:
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        try:
            receipt_root_fd = self._open_durable_directory_path(
                self.receipt_root,
                unavailable=unavailable,
                unsafe=unsafe,
            )
        except OSError as error:
            raise AdminPlatformStateError(unavailable) from error
        child_fd: int | None = None
        try:
            root_metadata = os.fstat(receipt_root_fd)
            if not stat.S_ISDIR(root_metadata.st_mode):
                raise AdminPlatformStateError(unsafe)
            self._set_runtime_owner(receipt_root_fd)
            os.fchmod(receipt_root_fd, 0o700)
            created = False
            try:
                os.mkdir(child_name, mode=0o700, dir_fd=receipt_root_fd)
                created = True
            except FileExistsError:
                pass
            if created:
                os.fsync(receipt_root_fd)
            child_fd = os.open(
                child_name,
                directory_flags | nofollow,
                dir_fd=receipt_root_fd,
            )
            child_metadata = os.fstat(child_fd)
            if not stat.S_ISDIR(child_metadata.st_mode):
                raise AdminPlatformStateError(unsafe)
            self._set_runtime_owner(child_fd)
            os.fchmod(child_fd, 0o700)
            return receipt_root_fd, child_fd
        except BaseException:
            if child_fd is not None:
                os.close(child_fd)
            os.close(receipt_root_fd)
            raise

    def _open_durable_directory_path(
        self,
        path: Path,
        *,
        unavailable: str,
        unsafe: str,
    ) -> int:
        """Open a directory without symlink traversal and persist every new edge."""

        absolute = path if path.is_absolute() else Path.cwd() / path
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(absolute.anchor, directory_flags | nofollow)
        try:
            for component in absolute.parts[1:]:
                created = False
                try:
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
                    created = True
                except FileExistsError:
                    pass
                child = os.open(
                    component,
                    directory_flags | nofollow,
                    dir_fd=descriptor,
                )
                metadata = os.fstat(child)
                if not stat.S_ISDIR(metadata.st_mode):
                    os.close(child)
                    raise AdminPlatformStateError(unsafe)
                if created:
                    self._set_runtime_owner(child)
                    os.fchmod(child, 0o700)
                    os.fsync(descriptor)
                os.close(descriptor)
                descriptor = child
            return descriptor
        except AdminPlatformStateError:
            os.close(descriptor)
            raise
        except OSError as error:
            os.close(descriptor)
            raise AdminPlatformStateError(unavailable) from error

    @classmethod
    def _remove_stale_transaction_directories(
        cls,
        root_fd: int,
        transaction_id: str,
        allowed_filenames: tuple[str, ...],
    ) -> None:
        prefix = f".{transaction_id}."
        suffix = ".tmp"
        for entry in sorted(os.listdir(root_fd)):
            if not entry.startswith(prefix) or not entry.endswith(suffix):
                continue
            nonce = entry[len(prefix) : -len(suffix)]
            if len(nonce) != 16 or any(
                character not in "0123456789abcdef" for character in nonce
            ):
                continue
            cls._remove_temporary_transaction(root_fd, entry, allowed_filenames)

    @staticmethod
    def _remove_temporary_transaction(
        root_fd: int,
        temporary_name: str,
        allowed_filenames: tuple[str, ...],
    ) -> None:
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        try:
            temporary_fd = os.open(
                temporary_name,
                directory_flags | nofollow,
                dir_fd=root_fd,
            )
        except FileNotFoundError:
            return
        try:
            entries = os.listdir(temporary_fd)
            if not set(entries).issubset(set(allowed_filenames)):
                raise AdminPlatformStateError(
                    "temporary receipt transaction contains unexpected files"
                )
            for filename in entries:
                metadata = os.stat(filename, dir_fd=temporary_fd, follow_symlinks=False)
                if not stat.S_ISREG(metadata.st_mode):
                    raise AdminPlatformStateError(
                        "temporary receipt transaction contains an unsafe file"
                    )
                os.unlink(filename, dir_fd=temporary_fd)
            os.fsync(temporary_fd)
        finally:
            os.close(temporary_fd)
        os.rmdir(temporary_name, dir_fd=root_fd)
        os.fsync(root_fd)

    def _write_transaction_file(self, directory_fd: int, filename: str, raw: bytes) -> None:
        descriptor = os.open(
            filename,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        try:
            self._set_runtime_owner(descriptor)
            os.fchmod(descriptor, 0o600)
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written == 0:
                    raise OSError(errno.ENOSPC, "receipt write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _signed_receipt(
        self,
        payload: Mapping[str, Any],
        *,
        ledger_bound: bool = False,
    ) -> dict[str, Any]:
        digest = payload_digest(payload)
        unsigned: dict[str, Any] = {
            "schema": (
                "qdev-controller-receipt-v3"
                if ledger_bound
                else "qdev-controller-receipt-v2"
            ),
            "receipt_id": digest,
            "payload": dict(payload),
            "digest": digest,
            "enforcement": "ledger-bound" if ledger_bound else "enforced",
        }
        receipt = unsigned | {"signature": sign_payload(unsigned, self.receipt_key)}
        return verify_controller_receipt(
            receipt,
            receipt_key=self.receipt_key,
            allow_ledger_bound=ledger_bound,
        )

    def _persist_ledger_link(
        self,
        *,
        previous_ledger_sha256: str,
        target_ledger_sha256: str,
        observed_at: str,
    ) -> None:
        receipt = self._signed_receipt(
            {
                "kind": "admin-platform-ledger-link",
                "observed_at": observed_at,
                "previous_ledger_sha256": previous_ledger_sha256,
                "target_ledger_sha256": target_ledger_sha256,
            },
            ledger_bound=True,
        )
        raw = self._receipt_raw(receipt)
        receipt_root_fd, directory = self._open_durable_child_directory(
            "ledger-links",
            unavailable="admin platform ledger lineage root is unavailable",
            unsafe="admin platform ledger lineage root is unsafe",
        )
        filename = f"{target_ledger_sha256}.json"
        temporary_name = f".{filename}.{secrets.token_hex(8)}.tmp"
        try:
            self._write_transaction_file(directory, temporary_name, raw)
            try:
                os.link(
                    temporary_name,
                    filename,
                    src_dir_fd=directory,
                    dst_dir_fd=directory,
                    follow_symlinks=False,
                )
            except FileExistsError as error:
                existing = self._read_regular_file_at(
                    directory,
                    filename,
                    _MAX_RECEIPT_BYTES,
                )
                if existing != raw:
                    raise AdminPlatformStateError(
                        "immutable admin platform ledger lineage collision"
                    ) from error
            os.unlink(temporary_name, dir_fd=directory)
            os.fsync(directory)
        finally:
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=directory)
                os.fsync(directory)
            os.close(directory)
            os.close(receipt_root_fd)

    @staticmethod
    def _touch(document: dict[str, Any], observed_at: str) -> None:
        document["program"]["updated_at"] = observed_at

    def _commit_locked(
        self,
        previous_raw: bytes,
        document: dict[str, Any],
        receipt_uris: tuple[str, ...],
        *,
        migration_archive_uri: str | None = None,
    ) -> AdminPlatformStateUpdate:
        encoded = self._encode_ledger(document)
        if len(encoded) > _MAX_LEDGER_BYTES:
            raise AdminPlatformStateError("admin platform ledger is too large")
        directory = os.open(
            self.path.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        temporary_name = f".{self.path.name}.{secrets.token_hex(8)}.tmp"
        temporary_path = self.path.parent / temporary_name
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory,
            )
            self._set_runtime_owner(descriptor)
            os.fchmod(descriptor, 0o600)
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            self._persist_ledger_link(
                previous_ledger_sha256=hashlib.sha256(previous_raw).hexdigest(),
                target_ledger_sha256=hashlib.sha256(encoded).hexdigest(),
                observed_at=cast(str, document["program"]["updated_at"]),
            )
            AdminPlatformLedger(
                temporary_path,
                receipt_key=self.receipt_key,
                receipt_root=self.receipt_root,
            )
            os.replace(
                temporary_name,
                self.path.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
            os.fsync(directory)
        except (AdminPlatformLedgerError, OSError, yaml.YAMLError) as error:
            raise AdminPlatformStateError("admin platform state transition is invalid") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=directory)
            os.close(directory)

        committed = AdminPlatformLedger(
            self.path,
            receipt_key=self.receipt_key,
            receipt_root=self.receipt_root,
        )
        active_stage = committed.active_stage
        active_status = None
        if active_stage is not None:
            active_status = next(
                entry.status for entry in committed.entries if entry.entry_id == active_stage
            )
        return AdminPlatformStateUpdate(
            previous_sha256=hashlib.sha256(previous_raw).hexdigest(),
            ledger_sha256=hashlib.sha256(encoded).hexdigest(),
            active_stage=active_stage,
            active_status=active_status,
            receipt_uris=receipt_uris,
            migration_archive_uri=migration_archive_uri,
        )

    @staticmethod
    def _encode_ledger(document: Mapping[str, Any]) -> bytes:
        encoded = yaml.safe_dump(dict(document), sort_keys=False).encode("utf-8")
        if len(encoded) > _MAX_LEDGER_BYTES:
            raise AdminPlatformStateError("admin platform ledger is too large")
        return encoded

    def _set_runtime_owner(self, descriptor: int) -> None:
        """Assign files created by a root bootstrap to the rootless broker."""

        if self.file_uid is None or self.file_gid is None:
            return
        metadata = os.fstat(descriptor)
        if metadata.st_uid != self.file_uid or metadata.st_gid != self.file_gid:
            os.fchown(descriptor, self.file_uid, self.file_gid)
