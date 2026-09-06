"""Translate trusted native IdP observations, never caller assertions or admission.

Only the installed, bundle-verified in-process collector is an observation source.
These structural checks do not authenticate an arbitrary JSON document. The host
journal/transport supplies provenance; the retained observation makes its claims
auditable without inventing AVDS evidence or retroactive CI for previous files.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any

PROJECT = "id-qdev-run"
REPOSITORY = "belilovsky/id-qdev-run"
ADAPTER = "idp-file-v1"
ARTIFACT_PREFIX = "qdev/idp-release"
PROVENANCE_SCHEMA = "qdev-idp-file-runtime-provenance-v1"
ASSOCIATED_PROVENANCE_SCHEMA = "qdev-idp-file-runtime-provenance-v2"
INSTALLED_MANIFEST = ".qdev-release-manifest.json"
PREVIOUS_PROVENANCE = "observed_files_only_not_retroactive_ci"
READINESS = {"identity": "ok", "native": "ok", "public": "ok"}
PREFIX = [
    "preflight_started",
    "preflight",
    "backup_started",
    "database_restore_intent",
    "database_restore_verified",
    "rollback_verified",
]
CHECKS = {
    key: "pass"
    for key in (
        "installed_component_digests",
        "runtime_images_unchanged",
        "configuration_unchanged",
        "public_identity_health_discovery_jwks",
        "retained_file_restore",
        "retained_database_backup",
    )
}


class IdPObservationError(ValueError):
    """No runtime receipt can be emitted for this observation."""


def canonical(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def require(condition: bool) -> None:
    if not condition:
        # Never interpolate observations, provider errors or private paths.
        raise IdPObservationError("IdP native observation binding or evidence is invalid")


def timestamp(value: Any) -> float:
    require(
        isinstance(value, str)
        and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)", value)
        is not None
    )
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def hex_value(value: Any, length: int = 64) -> bool:
    return isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{length}}}", value) is not None


def _capacity(value: Any, observed: float, *, database: bool = False) -> None:
    expected = {"observed_at", "filesystems"}
    allowed = {"release-files", "bundle-backup-drill"}
    if database:
        expected |= {"database_bytes", "estimate_policy"}
        allowed = {"database-dump", "postgres-data-and-temp", "postgres-wal"}
    require(isinstance(value, dict) and set(value) == expected)
    if database:
        require(type(value["database_bytes"]) is int and value["database_bytes"] > 0)
        require(value["estimate_policy"] == "dump-2x_data-temp-3x_wal-2x_v1")
    require(observed - 300 <= timestamp(value["observed_at"]) <= observed)
    filesystems = value["filesystems"]
    require(isinstance(filesystems, list) and bool(filesystems))
    seen: set[str] = set()
    lanes: set[str] = set()
    for item in filesystems:
        require(
            isinstance(item, dict)
            and set(item)
            == {
                "filesystem",
                "free_bytes",
                "free_inodes",
                "lanes",
                "peak_additional_bytes",
                "peak_inodes",
                "reserve_bytes",
            }
        )
        fs = item["filesystem"]
        require(
            isinstance(fs, str)
            and re.fullmatch(r"[A-Za-z0-9:_-]{1,128}", fs) is not None
            and fs not in seen
        )
        seen.add(fs)
        require(isinstance(item["lanes"], list) and bool(item["lanes"]))
        for lane in item["lanes"]:
            require(lane in allowed and lane not in lanes)
            lanes.add(lane)
        for name in (
            "free_bytes",
            "free_inodes",
            "peak_additional_bytes",
            "peak_inodes",
            "reserve_bytes",
        ):
            require(type(item[name]) is int and item[name] >= 0)
        require(item["reserve_bytes"] >= 512 * 1024 * 1024)
        require(item["free_bytes"] >= item["peak_additional_bytes"] + item["reserve_bytes"])
        require(item["free_inodes"] >= item["peak_inodes"] + 1024)
    require(lanes == allowed)


def validate_component_manifest(value: Any, binding: dict[str, Any]) -> int:
    """Shared strict manifest contract for native observations and bundle loading."""
    require(
        isinstance(value, dict)
        and set(value)
        == {
            "schema_version",
            "repository",
            "source_sha",
            "tree_sha",
            "generated_components",
            "components",
        }
    )
    require(value["schema_version"] == "qdev-idp-release-bundle-v1")
    require(value["repository"] == REPOSITORY and value["source_sha"] == binding["source_sha"])
    require(hex_value(value["tree_sha"], 40) and digest(value) == binding["manifest_sha256"])
    marker = "public/.well-known/qdev-release.json"
    require(value["generated_components"] == {marker: "commit-time-release-identity-v1"})
    components = value["components"]
    require(isinstance(components, dict) and marker in components)
    for name, component in components.items():
        require(isinstance(name, str) and bool(name))
        path = PurePosixPath(name)
        require(not path.is_absolute() and str(path) == name and bool(path.parts))
        require(
            not any(
                part in {".", "..", ".git", "backups", ".ssh", "__pycache__", ".env"}
                or part.endswith((".pat", ".pem", ".key", ".p12"))
                for part in path.parts
            )
        )
        require("\\" not in name and not any(ord(char) < 32 for char in name))
        require(isinstance(component, dict) and set(component) == {"sha256", "mode", "size"})
        require(hex_value(component["sha256"]))
        require(type(component["mode"]) is int and component["mode"] in {0o644, 0o755})
        require(type(component["size"]) is int and 0 <= component["size"] <= 64 * 1024 * 1024)
    return len(components)


def _images(value: Any) -> dict[str, str]:
    require(isinstance(value, list) and len(value) == 5)
    dependencies = {}
    for item in value:
        require(isinstance(item, dict) and set(item) == {"container_id", "image_digest"})
        container, image = item["container_id"], item["image_digest"]
        require(
            isinstance(container, str) and re.fullmatch(r"[0-9a-f]{12,64}", container) is not None
        )
        require(isinstance(image, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", image) is not None)
        require(container not in dependencies)
        dependencies[container] = image
    return dependencies


def _snapshot(value: Any, binding: dict[str, Any], manifest: dict[str, Any]) -> None:
    require(
        isinstance(value, dict)
        and set(value)
        == {
            "schema_version",
            "snapshot_sha256",
            "index",
            "previous_component_manifest",
        }
    )
    require(value["schema_version"] == "qdev-idp-file-snapshot-v1")
    index, previous = value["index"], value["previous_component_manifest"]
    require(isinstance(index, dict) and INSTALLED_MANIFEST in index)
    require(value["snapshot_sha256"] == binding["snapshot_sha256"] == digest(index))
    expected_names = set(manifest["components"]) | {INSTALLED_MANIFEST}
    if previous is None:
        require(index[INSTALLED_MANIFEST] is None)
    else:
        validate_component_manifest(
            previous,
            {
                "source_sha": binding["expected_previous_sha"],
                "manifest_sha256": digest(previous),
            },
        )
        expected_names |= set(previous["components"])
        require(index[INSTALLED_MANIFEST] == {"mode": 0o600, "sha256": digest(previous)})
        for name, component in previous["components"].items():
            require(index.get(name) == {key: component[key] for key in ("mode", "sha256")})
        require(
            all(
                index.get(name) is None
                for name in expected_names - set(previous["components"]) - {INSTALLED_MANIFEST}
            )
        )
    require(set(index) == expected_names)
    for name, item in index.items():
        if item is not None:
            require(isinstance(item, dict) and set(item) == {"mode", "sha256"})
            require(hex_value(item["sha256"]) and type(item["mode"]) is int)
            require(item["mode"] in ({0o600} if name == INSTALLED_MANIFEST else {0o644, 0o755}))


def _events(observation: dict[str, Any], binding: dict[str, Any], installed: bool) -> list[Any]:
    events = observation["events"]
    require(isinstance(events, list))
    phases = [event.get("phase") if isinstance(event, dict) else None for event in events]
    if installed:
        require(
            phases
            in (
                PREFIX + ["apply_started", "files_installed", "verified"],
                PREFIX + ["apply_started", "verified"],
            )
        )
        require(phases[-2] == "files_installed" or events[-1].get("outcome_reconciled") is True)
    else:
        require(phases == PREFIX)
    common = {
        "schema_version": "qdev-idp-release-transaction-v1",
        "transaction": binding["transaction"],
        "source_sha": binding["source_sha"],
        "previous_runtime_sha": binding["expected_previous_sha"],
        "bundle_sha256": binding["bundle_sha256"],
        "component_manifest_sha256": binding["manifest_sha256"],
        "release_scope": "files_only_no_database_image_or_mfa_change",
        "acceptance": "not_run",
    }
    previous = None
    previous_time = float("-inf")
    extra_fields = {
        "preflight_started": set(),
        "preflight": {"runtime_images", "ci_observation", "previous_provenance", "capacity"},
        "backup_started": {"ci_observation"},
        "database_restore_intent": {"disposable_database", "backup_sha256", "capacity"},
        "database_restore_verified": {
            "backup_sha256",
            "restored_tables",
            "disposable_database_removed",
        },
        "rollback_verified": {"file_restore", "database_restore", "snapshot_sha256"},
        "apply_started": {"ci_observation", "capacity", "controller_apply_binding_sha256"},
        "files_installed": set(),
        "verified": {
            "runtime_images",
            "installed_components",
            "rollback",
            "public_checks",
            "protected_acceptance",
        },
    }
    for event in events:
        expected_fields = set(common) | {"phase", "observed_at", "previous_event_digest"}
        expected_fields |= extra_fields[event["phase"]]
        if event["phase"] == "verified" and "outcome_reconciled" in event:
            require(event["outcome_reconciled"] is True)
            expected_fields.add("outcome_reconciled")
        require(set(event) == expected_fields)
        require(all(event.get(key) == value for key, value in common.items()))
        require(event.get("previous_event_digest") == previous)
        event_time = timestamp(event.get("observed_at"))
        require(previous_time <= event_time <= timestamp(observation["observed_at"]))
        if "capacity" in event:
            _capacity(
                event["capacity"], event_time, database=event["phase"] == "database_restore_intent"
            )
        if "ci_observation" in event:
            _validate_gate_reference(event["ci_observation"], binding, event_time)
        previous, previous_time = digest(event), event_time
    end_key = "terminal_event_sha256" if installed else "prepared_event_sha256"
    require(observation[end_key] == previous)
    require(events[1].get("runtime_images") == observation["runtime_images"])
    require(events[1].get("previous_provenance") == PREVIOUS_PROVENANCE)
    for event in (events[1], events[2]):
        gate = event.get("ci_observation")
        require(
            isinstance(gate, dict)
            and all(
                gate.get(key) == binding["ci_observation"][key]
                for key in ("quality", "runner_contract", "artifact")
            )
        )
    require(events[5].get("snapshot_sha256") == binding["snapshot_sha256"])
    require(events[5].get("file_restore") == "exact_files_and_configuration")
    require(events[5].get("database_restore") == "disposable_database_read_verified")
    require(hex_value(events[4].get("backup_sha256")))
    require(events[4]["backup_sha256"] == events[3].get("backup_sha256"))
    require(
        re.fullmatch(r"qdev_restore_[0-9a-f]{24}", events[3]["disposable_database"]) is not None
    )
    require(type(events[4].get("restored_tables")) is int and events[4]["restored_tables"] > 0)
    require(events[4].get("disposable_database_removed") is True)
    require(
        timestamp(binding["ci_observation"]["observed_at"]) >= timestamp(events[5]["observed_at"])
    )
    require(
        all(
            binding["ci_observation"]["path"] != event["ci_observation"]["path"]
            for event in (events[1], events[2])
        )
    )
    return list(events)


def _validate_gate_reference(gate: Any, binding: dict[str, Any], at: float) -> None:
    from qdev_runner.file_apply_authorization import parse_binding
    from qdev_runner.release_lane import ReleaseLaneError

    try:
        parse_binding(canonical({**binding, "ci_observation": gate}), now=at)
    except ReleaseLaneError:
        raise IdPObservationError("invalid retained IdP CI reference") from None


def _binding(observation: dict[str, Any], installed: bool) -> dict[str, Any]:
    # Lazy import avoids a release_lane -> validator -> authorization -> lane cycle.
    from qdev_runner.file_apply_authorization import parse_binding
    from qdev_runner.release_lane import ReleaseLaneError

    if installed:
        events = observation["events"]
        require(isinstance(events, list) and len(events) in {8, 9})
        binding = {
            "schema_version": "qdev-idp-controller-apply-binding-v1",
            "repository": REPOSITORY,
            "source_sha": observation["source_sha"],
            "transaction": observation["transaction"],
            "expected_previous_sha": observation["previous_runtime_sha"],
            "bundle_sha256": observation["bundle_sha256"],
            "manifest_sha256": observation["component_manifest_sha256"],
            "snapshot_sha256": events[5]["snapshot_sha256"],
            "ci_observation": events[6]["ci_observation"],
        }
        at = timestamp(events[6]["observed_at"])
    else:
        binding = observation["binding"]
        at = timestamp(observation["observed_at"])
    try:
        return parse_binding(canonical(binding), now=at).model_dump()
    except ReleaseLaneError:
        raise IdPObservationError("invalid IdP cutover binding") from None


def _translate(observation: dict[str, Any], installed: bool) -> dict[str, Any]:
    require(isinstance(observation, dict) and len(canonical(observation)) <= 1024 * 1024)
    common = {
        "schema_version",
        "repository",
        "source_sha",
        "transaction",
        "observed_at",
        "status",
        "events",
        "component_manifest",
        "runtime_images",
        "controller_admission",
        "acceptance",
        "redacted",
    }
    specific = (
        {
            "previous_runtime_sha",
            "bundle_sha256",
            "component_manifest_sha256",
            "terminal_event_sha256",
            "ci_observation",
            "installed_components",
            "current_checks",
        }
        if installed
        else {
            "binding",
            "binding_sha256",
            "prepared_event_sha256",
            "rollback_material",
            "capacity",
            "previous_provenance",
            "deployment",
        }
    )
    v2 = observation.get("schema_version") in {
        "qdev-idp-release-observation-v2",
        "qdev-idp-prepared-observation-v2",
    }
    if v2:
        specific.add("rollback_snapshot")
    require(set(observation) == common | specific)
    expected = (
        (
            "qdev-idp-release-observation-v2" if v2 else "qdev-idp-release-observation-v1",
            "installed_release_reobserved",
            "historical_binding_only_not_current_authorization",
        )
        if installed
        else (
            "qdev-idp-prepared-observation-v2" if v2 else "qdev-idp-prepared-observation-v1",
            "prepared_runtime_reobserved",
            "not_authorized",
        )
    )
    require(
        tuple(observation[key] for key in ("schema_version", "status", "controller_admission"))
        == expected
    )
    require(observation["repository"] == REPOSITORY and observation["redacted"] is True)
    require(observation["acceptance"] == "not_run")
    binding = _binding(observation, installed)
    require(binding["source_sha"] == observation["source_sha"])
    require(binding["transaction"] == observation["transaction"])
    count = validate_component_manifest(observation["component_manifest"], binding)
    if v2:
        _snapshot(observation["rollback_snapshot"], binding, observation["component_manifest"])
    dependencies = _images(observation["runtime_images"])
    events = _events(observation, binding, installed)
    if installed:
        applied, terminal = events[6], events[-1]
        require(applied.get("controller_apply_binding_sha256") == digest(binding))
        ci = observation["ci_observation"]
        require(
            isinstance(ci, dict)
            and set(ci)
            == {
                "schema_version",
                "repository",
                "source_sha",
                "status",
                "observed_at",
                "component_manifest_sha256",
                "artifact",
                "download",
                "quality",
                "runner_contract",
            }
        )
        require(ci["schema_version"] == "qdev-idp-ci-release-observation-v1")
        require(ci["repository"] == REPOSITORY and ci["source_sha"] == binding["source_sha"])
        require(ci["status"] == "source_ci_bundle_verified")
        require(ci["component_manifest_sha256"] == binding["manifest_sha256"])
        require(digest(ci) == binding["ci_observation"]["sha256"])
        require(
            all(
                ci[key] == binding["ci_observation"][key]
                for key in ("observed_at", "quality", "runner_contract", "artifact")
            )
        )
        require(
            ci["download"]
            == {
                "transport": "operator_ssh_existing_store",
                "status": "retrieved_verified",
                "storage_key": ci["artifact"]["storage_key"],
                "artifact_sha256": ci["artifact"]["artifact_sha256"],
            }
        )
        require(terminal.get("runtime_images") == observation["runtime_images"])
        require(
            type(observation["installed_components"]) is int
            and observation["installed_components"] == count == terminal.get("installed_components")
        )
        require(
            terminal.get("rollback") == "verified" and terminal.get("public_checks") == "passed"
        )
        require(terminal.get("protected_acceptance") == "not_run")
        require(observation["current_checks"] == CHECKS)
        source = binding["source_sha"]
        artifact = binding["ci_observation"]["artifact"]["artifact_sha256"]
    else:
        require(observation["binding_sha256"] == digest(binding))
        require(observation["previous_provenance"] == PREVIOUS_PROVENANCE)
        require(observation["deployment"] == "not_applied")
        require(
            observation["rollback_material"]
            == {
                "snapshot_sha256": binding["snapshot_sha256"],
                "database_backup_sha256": events[4]["backup_sha256"],
                "restored_tables": events[4]["restored_tables"],
                "disposable_database_removed": True,
            }
        )
        _capacity(observation["capacity"], timestamp(observation["observed_at"]))
        source, artifact = binding["expected_previous_sha"], binding["snapshot_sha256"]
    release = {
        "source_sha": source,
        "artifact_digest": f"sha256:{artifact}",
        "artifact_ref": f"{ARTIFACT_PREFIX}@sha256:{artifact}",
    }
    return {
        "schema": "qdev-admin-platform-native-receipt-v1",
        "project_id": PROJECT,
        "native_host_adapter": ADAPTER,
        **release,
        "readiness": dict(READINESS),
        "runtime_identity": {**release, "measured": True},
        "dependency_identity": dependencies,
        "artifact_provenance": {
            "schema": PROVENANCE_SCHEMA,
            "stage": "installed" if installed else "prepared",
            "observation_sha256": digest(observation),
            "observation": observation,
        },
    }


def native_receipt(
    observation: dict[str, Any],
    *,
    installed: bool,
    expected_binding: bytes | None = None,
    now: float | None = None,
    previous_observation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate retained content; caller must separately verify collector origin/freshness."""
    try:
        # Snapshot inputs so later caller mutation cannot alter the accepted receipt.
        observation = json.loads(canonical(observation))
        result = _translate(observation, installed)
        if previous_observation is not None:
            previous = json.loads(canonical(previous_observation))
            prior = _translate(previous, True)
            binding = _binding(observation, installed)
            require(
                observation.get("rollback_snapshot", {}).get("previous_component_manifest")
                == previous["component_manifest"]
            )
            require(prior["source_sha"] == binding["expected_previous_sha"])
            require(previous["transaction"] != observation["transaction"])
            require(timestamp(previous["observed_at"]) <= timestamp(observation["observed_at"]))
            require(previous["runtime_images"] == observation["runtime_images"])
            previous_release = {
                key: prior[key] for key in ("source_sha", "artifact_digest", "artifact_ref")
            }
            if not installed:
                result.update(previous_release)
                result["runtime_identity"] = {**previous_release, "measured": True}
            result["artifact_provenance"].update(
                {
                    "schema": ASSOCIATED_PROVENANCE_SCHEMA,
                    "rollback_association": {
                        "schema": "qdev-idp-rollback-association-v1",
                        "snapshot_sha256": binding["snapshot_sha256"],
                        "previous_release": previous_release,
                        "previous_observation_sha256": digest(previous),
                        "previous_observation": previous,
                    },
                }
            )
        if expected_binding is not None:
            require(canonical(_binding(observation, installed)) == expected_binding)
        if now is not None:
            require(now - 300 <= timestamp(observation["observed_at"]) <= now + 30)
        return result
    except (ValueError, TypeError, KeyError, IndexError, AttributeError):
        raise IdPObservationError("invalid IdP native observation") from None


def installed_binding(observation: dict[str, Any]) -> bytes:
    """Validated historical cutover bytes; not current admission authority."""
    native_receipt(observation, installed=True)
    return canonical(_binding(observation, True))


def same_installed_release(retained: dict[str, Any], fresh: dict[str, Any]) -> bool:
    """Compare complete validated receipts, allowing ONLY a later reobservation.

    Both original observations/digests are checked before normalization. Journal,
    CI, rollback, component and scope contents stay exact; no receipt is modified.
    Collector origin and current freshness are enforced by the locked caller.
    """
    for receipt in (retained, fresh):
        validate_runtime_evidence(receipt, installed_only=True)
    old, new = (json.loads(canonical(value)) for value in (retained, fresh))
    old_proof, new_proof = (value["artifact_provenance"] for value in (old, new))
    if timestamp(new_proof["observation"]["observed_at"]) < timestamp(
        old_proof["observation"]["observed_at"]
    ):
        return False
    for proof in (old_proof, new_proof):
        del proof["observation_sha256"]
        del proof["observation"]["observed_at"]
    return bool(old == new)


def validate_runtime_evidence(receipt: dict[str, Any], *, installed_only: bool = False) -> None:
    """Same validator on host and controller; hashes without content cannot pass."""
    try:
        provenance = receipt["artifact_provenance"]
        associated = provenance.get("schema") == ASSOCIATED_PROVENANCE_SCHEMA
        require(
            isinstance(provenance, dict)
            and set(provenance)
            == {
                "schema",
                "stage",
                "observation_sha256",
                "observation",
            }
            | ({"rollback_association"} if associated else set())
        )
        require(provenance["schema"] in {PROVENANCE_SCHEMA, ASSOCIATED_PROVENANCE_SCHEMA})
        require(provenance["stage"] in {"prepared", "installed"})
        require(not installed_only or provenance["stage"] == "installed")
        expected = native_receipt(
            provenance["observation"],
            installed=provenance["stage"] == "installed",
            previous_observation=(
                provenance["rollback_association"]["previous_observation"] if associated else None
            ),
        )
        require(
            all(
                receipt.get(key) == expected[key]
                for key in (
                    "source_sha",
                    "artifact_digest",
                    "artifact_ref",
                    "runtime_identity",
                    "dependency_identity",
                    "artifact_provenance",
                    "readiness",
                )
            )
        )
        if installed_only:
            binding = _binding(provenance["observation"], True)
            artifact = f"sha256:{binding['snapshot_sha256']}"
            rollback = (
                expected["artifact_provenance"]["rollback_association"]["previous_release"]
                if associated
                else {
                    "source_sha": binding["expected_previous_sha"],
                    "artifact_digest": artifact,
                    "artifact_ref": f"{ARTIFACT_PREFIX}@{artifact}",
                }
            )
            require(
                receipt.get("rollback")
                == {
                    "verified": True,
                    **rollback,
                }
            )
    except (ValueError, TypeError, KeyError, IndexError, AttributeError):
        raise IdPObservationError("invalid IdP runtime evidence") from None
