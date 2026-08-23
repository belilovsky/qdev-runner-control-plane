from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def load_script() -> ModuleType:
    path = ROOT / "scripts/configure_required_check.py"
    spec = importlib.util.spec_from_file_location("configure_required_check", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_required_contexts_supports_legacy_and_app_bound_checks() -> None:
    module = load_script()
    protection = {
        "required_status_checks": {
            "contexts": ["tests"],
            "checks": [
                {"context": "lint", "app_id": 12},
                {"context": "tests", "app_id": None},
            ],
        }
    }
    assert module.required_contexts(protection) == {"tests", "lint"}


def test_required_contexts_handles_disabled_status_checks() -> None:
    module = load_script()
    assert module.required_contexts({"required_status_checks": None}) == set()


def test_protection_payload_preserves_existing_settings() -> None:
    module = load_script()
    protection = {
        "enforce_admins": {"enabled": True},
        "required_linear_history": {"enabled": True},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
        "block_creations": {"enabled": False},
        "required_conversation_resolution": {"enabled": True},
        "lock_branch": {"enabled": False},
        "allow_fork_syncing": {"enabled": False},
        "required_pull_request_reviews": {
            "dismissal_restrictions": {
                "users": [{"login": "maintainer"}],
                "teams": [{"slug": "reviewers"}],
                "apps": [],
            },
            "dismiss_stale_reviews": True,
            "require_code_owner_reviews": True,
            "required_approving_review_count": 2,
            "require_last_push_approval": True,
            "bypass_pull_request_allowances": {"users": [], "teams": [], "apps": []},
        },
        "restrictions": {
            "users": [{"login": "maintainer"}],
            "teams": [],
            "apps": [],
        },
    }
    payload = module.protection_update_payload(protection)
    assert payload["required_status_checks"] == {
        "strict": False,
        "contexts": ["qdev-runner-contract"],
    }
    assert payload["enforce_admins"] is True
    assert payload["required_linear_history"] is True
    assert payload["required_conversation_resolution"] is True
    assert payload["required_pull_request_reviews"]["required_approving_review_count"] == 2
    assert payload["required_pull_request_reviews"]["dismissal_restrictions"] == {
        "users": ["maintainer"],
        "teams": ["reviewers"],
        "apps": [],
    }
    assert payload["restrictions"] == {"users": ["maintainer"], "teams": [], "apps": []}
