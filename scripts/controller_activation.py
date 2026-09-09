#!/usr/bin/env python3
"""Root-only CLI for the controller activation identity transaction."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

# The wrapper fingerprints the release tree after this CLI runs. Keep its
# imports from creating host-specific bytecode in that tree.
sys.dont_write_bytecode = True

from qdev_runner.controller_activation import (  # noqa: E402
    ActivationEnvelope,
    ActivationStateStore,
    ControllerActivationError,
    ControllerReleaseStatus,
    LegacyMeasuredControllerReleaseStatus,
    MeasuredControllerReleaseStatus,
    fingerprint_config_files,
    fingerprint_release_tree,
    load_activation_public_key,
    load_and_verify_envelope,
    verify_controller_artifact_manifest,
)
from qdev_runner.controller_release import (  # noqa: E402
    ControllerReleaseIdentityError,
    controller_release_digest,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=(
            "reserve",
            "bootstrap-measured",
            "assert-current",
            "authorize-rollback",
            "abort",
            "commit",
            "finalize",
            "finalize-measured",
            "finalize-historical",
            "complete-rollback",
            "verify-rollback-terminal",
            "fingerprint-config",
            "fingerprint-release",
            "fingerprint-source",
            "show",
            "verify-artifact",
            "verify-envelope",
            "verify-recovery-envelope",
            "verify-public",
            "verify-legacy-public",
        ),
    )
    parser.add_argument("--status", type=Path)
    parser.add_argument("--legacy-status", type=Path)
    parser.add_argument("--measured-status", type=Path)
    parser.add_argument("--envelope", type=Path)
    parser.add_argument("--key", type=Path)
    parser.add_argument("--candidate-source")
    parser.add_argument("--candidate-image")
    parser.add_argument("--candidate-public-image")
    parser.add_argument("--candidate-internal-image")
    parser.add_argument("--candidate-policy")
    parser.add_argument("--candidate-release-digest")
    parser.add_argument("--candidate-config-digest")
    parser.add_argument("--artifact-manifest-digest")
    parser.add_argument("--entrypoint-reconciliation-digest")
    parser.add_argument("--allow-legacy-import", action="store_true")
    parser.add_argument("--observed-current-image")
    parser.add_argument("--observed-current-public-image")
    parser.add_argument("--observed-current-internal-image")
    parser.add_argument("--observed-current-config")
    parser.add_argument("--rollback-config")
    parser.add_argument("--candidate-config-active", action="store_true")
    parser.add_argument("--allow-config-transition", action="store_true")
    parser.add_argument("--public-status", type=Path)
    parser.add_argument("--artifact-manifest", type=Path)
    parser.add_argument("--config-file", action="append", default=[])
    parser.add_argument("--release-root", type=Path)
    return parser


def _require_safe_regular(path: Path, *, description: str, mode_mask: int = 0o022) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ControllerActivationError(f"{description} is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise ControllerActivationError(f"{description} path is unsafe")
    if metadata.st_uid != 0 or metadata.st_mode & mode_mask:
        raise ControllerActivationError(f"{description} ownership is unsafe")


def _require_root_owned_state(
    path: Path,
    *,
    mutation: bool,
    allow_missing: bool = False,
) -> None:
    if mutation and os.geteuid() != 0:
        raise ControllerActivationError("controller activation mutation requires root")
    try:
        metadata = path.parent.lstat()
    except OSError as error:
        raise ControllerActivationError("controller status directory is unavailable") from error
    if not stat.S_ISDIR(metadata.st_mode) or path.parent.is_symlink():
        raise ControllerActivationError("controller status directory is unsafe")
    if metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise ControllerActivationError("controller status directory ownership is unsafe")
    if path.exists() or path.is_symlink():
        _require_safe_regular(path, description="controller status")
    elif not allow_missing:
        raise ControllerActivationError("controller status is unavailable")
    for auxiliary in (
        path.with_suffix(f"{path.suffix}.lock"),
        path.with_suffix(f"{path.suffix}.transaction"),
    ):
        if auxiliary.exists() or auxiliary.is_symlink():
            _require_safe_regular(auxiliary, description=f"controller {auxiliary.name}")


def _load_envelope(args: argparse.Namespace) -> ActivationEnvelope:
    if args.envelope is None or args.key is None:
        raise ControllerActivationError("activation envelope and key are required")
    _require_safe_regular(args.envelope, description="activation envelope")
    public_key = load_activation_public_key(args.key)
    envelope = load_and_verify_envelope(
        args.envelope,
        public_key=public_key,
        allow_expired_for_rollback=args.command
        in {
            "authorize-rollback",
            "abort",
            "complete-rollback",
            "finalize-measured",
            "finalize-historical",
            "verify-legacy-public",
            "verify-recovery-envelope",
            "verify-rollback-terminal",
        },
    )
    candidate_public_image = args.candidate_public_image or args.candidate_image
    candidate_internal_image = args.candidate_internal_image or args.candidate_image
    observed_candidate = (
        args.candidate_source,
        candidate_public_image,
        candidate_internal_image,
        args.candidate_policy,
    )
    if any(value is None for value in observed_candidate) or observed_candidate != (
        envelope.candidate.source_sha,
        envelope.candidate.public_image_digest,
        envelope.candidate.effective_internal_image_digest,
        envelope.candidate.policy_bundle_digest,
    ):
        raise ControllerActivationError("observed candidate tuple does not match envelope")
    if args.artifact_manifest_digest != envelope.artifact_manifest_digest:
        raise ControllerActivationError("observed artifact manifest digest does not match envelope")
    if args.candidate_config_digest != envelope.candidate_config_digest:
        raise ControllerActivationError("observed candidate config digest does not match envelope")
    if args.candidate_release_digest != envelope.candidate_release_digest:
        raise ControllerActivationError("observed candidate release digest does not match envelope")
    if args.entrypoint_reconciliation_digest != envelope.entrypoint_reconciliation_digest:
        raise ControllerActivationError(
            "observed entrypoint reconciliation digest does not match envelope"
        )
    return envelope


def _required_observation(args: argparse.Namespace) -> tuple[str, str, str]:
    observed_public = args.observed_current_public_image or args.observed_current_image
    observed_internal = args.observed_current_internal_image or args.observed_current_image
    if observed_public is None or observed_internal is None or args.observed_current_config is None:
        raise ControllerActivationError("observed public/internal images and config are required")
    return observed_public, observed_internal, args.observed_current_config


def _load_public_status(path: Path) -> ControllerReleaseStatus:
    _require_safe_regular(path, description="public controller status", mode_mask=0o077)
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077:
            raise ControllerActivationError("public controller status ownership is unsafe")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = json.loads(handle.read().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControllerActivationError("public controller status is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if isinstance(raw, dict) and "controller_release" in raw:
        raw = raw["controller_release"]
    return ControllerReleaseStatus.parse(raw)


def _load_measured_status(
    path: Path,
    *,
    description: str,
    private: bool,
) -> MeasuredControllerReleaseStatus:
    mode_mask = 0o077 if private else 0o022
    _require_safe_regular(path, description=description, mode_mask=mode_mask)
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & mode_mask
        ):
            raise ControllerActivationError(f"{description} ownership is unsafe")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = json.loads(handle.read().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControllerActivationError(f"{description} is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if isinstance(raw, dict) and "controller_release" in raw:
        raw = raw["controller_release"]
    return MeasuredControllerReleaseStatus.parse(raw)


def _load_legacy_measured_status(
    path: Path,
    *,
    description: str,
    private: bool,
) -> LegacyMeasuredControllerReleaseStatus:
    mode_mask = 0o077 if private else 0o022
    _require_safe_regular(path, description=description, mode_mask=mode_mask)
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & mode_mask
        ):
            raise ControllerActivationError(f"{description} ownership is unsafe")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = json.loads(handle.read().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControllerActivationError(f"{description} is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if isinstance(raw, dict) and "controller_release" in raw:
        raw = raw["controller_release"]
    return LegacyMeasuredControllerReleaseStatus.parse(raw)


def _verify_public_status(path: Path, envelope: ActivationEnvelope) -> None:
    status = _load_public_status(path)
    if not (
        status.generation == envelope.expected_generation + 1
        and status.current == envelope.candidate
        and status.previous == (envelope.expected_generation, envelope.expected_current)
        and status.transaction_id == envelope.transaction_id
    ):
        raise ControllerActivationError("public controller status does not prove candidate tuple")


def _verify_legacy_public_status(path: Path, envelope: ActivationEnvelope) -> None:
    _require_safe_regular(path, description="public controller status", mode_mask=0o077)
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077:
            raise ControllerActivationError("public controller status ownership is unsafe")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = json.loads(handle.read().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControllerActivationError("public controller status is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if isinstance(raw, dict) and "controller_release" in raw:
        raw = raw["controller_release"]
    expected = envelope.expected_current
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema", "state", "revision", "release_digest", "activated_at"}
        or raw.get("schema") != "qdev-controller-release-status-v1"
        or raw.get("state") != "active"
        or raw.get("revision") != expected.source_sha
        or raw.get("release_digest") != expected.policy_bundle_digest
        or not isinstance(raw.get("activated_at"), str)
    ):
        raise ControllerActivationError(
            "public legacy controller status does not prove rollback tuple"
        )


def main() -> int:
    args = _parser().parse_args()
    result: dict[str, object]
    try:
        if args.command == "verify-artifact":
            if args.artifact_manifest is None:
                raise ControllerActivationError("controller artifact manifest is required")
            artifact = verify_controller_artifact_manifest(
                args.artifact_manifest,
                expected_manifest_digest=args.artifact_manifest_digest,
            )
            print(
                json.dumps(
                    {
                        "schema": "qdev-controller-verified-artifact-v1",
                        "manifest_digest": artifact.manifest_digest,
                        "source_sha": artifact.source_sha,
                        "image_digest": artifact.image_digest,
                        "policy_bundle_digest": artifact.policy_bundle_digest,
                        "entrypoint_reconciliation_digest": (
                            artifact.entrypoint_reconciliation_digest
                        ),
                        "image_archive": str(artifact.image_archive),
                        "image_archive_digest": artifact.image_archive_digest,
                        "image_unpacked_size": artifact.image_unpacked_size,
                        "sbom_digest": artifact.sbom_digest,
                        "provenance_digest": artifact.provenance_digest,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 0
        if args.command == "fingerprint-release":
            if args.release_root is None:
                raise ControllerActivationError("controller release root is required")
            digest = fingerprint_release_tree(args.release_root)
            print(
                json.dumps(
                    {
                        "schema": "qdev-controller-entrypoint-reconciliation-v1",
                        "digest": digest,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 0
        if args.command == "fingerprint-source":
            if args.release_root is None:
                raise ControllerActivationError("controller release root is required")
            try:
                digest = controller_release_digest(args.release_root)
            except ControllerReleaseIdentityError as error:
                raise ControllerActivationError(str(error)) from error
            print(
                json.dumps(
                    {
                        "schema": "qdev-controller-source-fingerprint-v1",
                        "digest": digest.removeprefix("sha256:"),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 0
        if args.command == "fingerprint-config":
            files: dict[str, Path] = {}
            for item in args.config_file:
                if not isinstance(item, str) or "=" not in item:
                    raise ControllerActivationError(
                        "controller config input must be logical-name=path"
                    )
                logical_name, raw_path = item.split("=", 1)
                if logical_name in files:
                    raise ControllerActivationError("controller config logical name is duplicated")
                files[logical_name] = Path(raw_path)
            digest = fingerprint_config_files(files)
            print(
                json.dumps(
                    {"schema": "qdev-controller-config-fingerprint-v1", "digest": digest},
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 0
        if args.command in {"verify-envelope", "verify-legacy-public"}:
            envelope = _load_envelope(args)
            if args.command == "verify-legacy-public":
                if args.public_status is None:
                    raise ControllerActivationError("public controller status is required")
                _verify_legacy_public_status(args.public_status, envelope)
                result = {
                    "status": "legacy-rollback-proved",
                    "transaction_id": envelope.transaction_id,
                }
            else:
                result = {
                    "schema": "qdev-controller-verified-envelope-v1",
                    "transaction_id": envelope.transaction_id,
                    "issued_at": envelope.issued_at.isoformat().replace("+00:00", "Z"),
                    "expires_at": envelope.expires_at.isoformat().replace("+00:00", "Z"),
                    "expected_generation": envelope.expected_generation,
                    "expected_current": envelope.expected_current.mapping(),
                    "expected_current_status_digest": (envelope.expected_current_status_digest),
                    "expected_current_config_digest": (envelope.expected_current_config_digest),
                    "candidate": envelope.candidate.mapping(),
                    "candidate_release_digest": envelope.candidate_release_digest,
                    "candidate_config_digest": envelope.candidate_config_digest,
                    "artifact_manifest_digest": envelope.artifact_manifest_digest,
                    "entrypoint_reconciliation_digest": (envelope.entrypoint_reconciliation_digest),
                    "envelope_digest": envelope.digest,
                }
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 0
        if args.status is None:
            raise ControllerActivationError("controller status path is required")
        store = ActivationStateStore(args.status)
        if args.command == "show":
            _require_root_owned_state(args.status, mutation=False)
            print(json.dumps(store.read_status().mapping(), sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "verify-public":
            _require_root_owned_state(args.status, mutation=False)
            if args.public_status is None:
                raise ControllerActivationError("public controller status is required")
            local = store.read_status()
            public = _load_public_status(args.public_status)
            if public != local:
                raise ControllerActivationError(
                    "public controller status does not match durable status"
                )
            print(json.dumps(public.mapping(), sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "verify-rollback-terminal":
            _require_root_owned_state(args.status, mutation=False)
            envelope = _load_envelope(args)
            observed_public, observed_internal, observed_config = _required_observation(args)
            terminal = store.verify_rollback_terminal(
                envelope,
                observed_image_digest=observed_public,
                observed_internal_image_digest=observed_internal,
                observed_config_digest=observed_config,
            )
            print(json.dumps(terminal.mapping(), sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "verify-recovery-envelope":
            _require_root_owned_state(args.status, mutation=False)
            envelope = _load_envelope(args)
            observed_image, observed_internal_image, observed_config = _required_observation(args)
            recovery_state = store.recovery_state(
                envelope,
                observed_image_digest=observed_image,
                observed_internal_image_digest=observed_internal_image,
                observed_config_digest=observed_config,
                allow_config_transition=args.allow_config_transition,
            )
            result = {
                "schema": "qdev-controller-verified-recovery-envelope-v1",
                "transaction_id": envelope.transaction_id,
                "expires_at": envelope.expires_at.isoformat().replace("+00:00", "Z"),
                "expected_generation": envelope.expected_generation,
                "expected_current": envelope.expected_current.mapping(),
                "expected_current_config_digest": envelope.expected_current_config_digest,
                "candidate": envelope.candidate.mapping(),
                "candidate_config_digest": envelope.candidate_config_digest,
                "envelope_digest": envelope.digest,
                "recovery_state": recovery_state,
            }
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 0
        allow_missing_status = args.command == "bootstrap-measured" or (
            args.command == "reserve"
            and args.allow_legacy_import
            and args.legacy_status is not None
        )
        _require_root_owned_state(
            args.status,
            mutation=True,
            allow_missing=allow_missing_status,
        )
        if args.legacy_status is not None:
            if args.command != "reserve" or not args.allow_legacy_import:
                raise ControllerActivationError(
                    "legacy status is allowed only for an explicit reserve import"
                )
            _require_safe_regular(
                args.legacy_status,
                description="legacy controller status",
            )
        envelope = _load_envelope(args)
        if args.command == "bootstrap-measured":
            if args.measured_status is None:
                raise ControllerActivationError("measured controller status is required")
            _require_safe_regular(
                args.measured_status,
                description="measured controller status",
            )
            observed_image, observed_internal_image, observed_config = _required_observation(args)
            activation_status = store.bootstrap_from_measured(
                envelope,
                measured_status_path=args.measured_status,
                observed_image_digest=observed_image,
                observed_internal_image_digest=observed_internal_image,
                observed_config_digest=observed_config,
            )
            result = {
                "status": "measured-bootstrap-complete",
                "transaction_id": envelope.transaction_id,
                "activation_status": activation_status.mapping(),
            }
        elif args.command == "reserve":
            observed_image, observed_internal_image, observed_config = _required_observation(args)
            reservation_state = store.reserve(
                envelope,
                allow_legacy_import=args.allow_legacy_import,
                legacy_status_path=args.legacy_status,
                observed_image_digest=observed_image,
                observed_internal_image_digest=observed_internal_image,
                observed_config_digest=observed_config,
                allow_config_transition=args.allow_config_transition,
            )
            result = {
                "status": "reserved",
                "transaction_id": envelope.transaction_id,
                "idempotent": reservation_state != "new",
                "reservation_state": reservation_state,
            }
        elif args.command == "assert-current":
            observed_image, observed_internal_image, observed_config = _required_observation(args)
            store.assert_current(
                envelope,
                observed_image_digest=observed_image,
                observed_internal_image_digest=observed_internal_image,
                observed_config_digest=observed_config,
                candidate_config=args.candidate_config_active,
            )
            result = {"status": "current", "transaction_id": envelope.transaction_id}
        elif args.command == "authorize-rollback":
            if (
                (args.observed_current_public_image or args.observed_current_image) is None
                or (args.observed_current_internal_image or args.observed_current_image) is None
                or args.observed_current_config is None
                or args.rollback_config is None
            ):
                raise ControllerActivationError(
                    "observed image/config and rollback config snapshot are required"
                )
            store.authorize_rollback(
                envelope,
                observed_image_digest=(
                    args.observed_current_public_image or args.observed_current_image
                ),
                observed_internal_image_digest=(
                    args.observed_current_internal_image or args.observed_current_image
                ),
                observed_config_digest=args.observed_current_config,
                rollback_config_digest=args.rollback_config,
                allow_config_transition=args.allow_config_transition,
            )
            result = {"status": "rollback-authorized", "transaction_id": envelope.transaction_id}
        elif args.command == "abort":
            observed_image, observed_internal_image, observed_config = _required_observation(args)
            store.abort(
                envelope,
                observed_image_digest=observed_image,
                observed_internal_image_digest=observed_internal_image,
                observed_config_digest=observed_config,
            )
            result = {"status": "aborted", "transaction_id": envelope.transaction_id}
        elif args.command == "commit":
            observed_image, observed_internal_image, observed_config = _required_observation(args)
            committed_status = store.commit(
                envelope,
                observed_image_digest=observed_image,
                observed_internal_image_digest=observed_internal_image,
                observed_config_digest=observed_config,
            )
            result = committed_status.mapping()
        elif args.command == "finalize-measured":
            if args.measured_status is None or args.public_status is None:
                raise ControllerActivationError(
                    "local and public measured controller statuses are required"
                )
            observed_image, observed_internal_image, observed_config = _required_observation(args)
            measured_status = _load_measured_status(
                args.measured_status,
                description="measured controller status",
                private=False,
            )
            public_measured_status = _load_measured_status(
                args.public_status,
                description="public measured controller status",
                private=True,
            )
            finalized_status = store.finalize_measured(
                envelope,
                measured_status=measured_status,
                public_status=public_measured_status,
                observed_image_digest=observed_image,
                observed_internal_image_digest=observed_internal_image,
                observed_config_digest=observed_config,
            )
            result = {
                "status": "finalized",
                "transaction_id": envelope.transaction_id,
                "activation_status": finalized_status.mapping(),
            }
        elif args.command == "finalize-historical":
            if args.measured_status is None or args.public_status is None:
                raise ControllerActivationError(
                    "local and public historical controller statuses are required"
                )
            observed_image, observed_internal_image, observed_config = _required_observation(args)
            historical_status = _load_legacy_measured_status(
                args.measured_status,
                description="historical controller status",
                private=False,
            )
            public_historical_status = _load_legacy_measured_status(
                args.public_status,
                description="public historical controller status",
                private=True,
            )
            finalized_status = store.finalize_historical(
                envelope,
                measured_status=historical_status,
                public_status=public_historical_status,
                observed_image_digest=observed_image,
                observed_internal_image_digest=observed_internal_image,
                observed_config_digest=observed_config,
            )
            result = {
                "status": "historical-finalized",
                "transaction_id": envelope.transaction_id,
                "activation_status": finalized_status.mapping(),
            }
        elif args.command == "finalize":
            if args.public_status is None:
                raise ControllerActivationError("public controller status is required")
            _verify_public_status(args.public_status, envelope)
            result = store.finalize(envelope).mapping()
        else:
            observed_image, observed_internal_image, observed_config = _required_observation(args)
            result = store.complete_rollback(
                envelope,
                observed_image_digest=observed_image,
                observed_internal_image_digest=observed_internal_image,
                observed_config_digest=observed_config,
            ).mapping()
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except ControllerActivationError as error:
        print(str(error), file=sys.stderr)
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
