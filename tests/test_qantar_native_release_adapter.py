from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tarfile
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA = "a" * 40


def _load() -> ModuleType:
    path = ROOT / "scripts" / "qantar_native_release_adapter.py"
    spec = importlib.util.spec_from_file_location("qantar_native_release_adapter", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ADAPTER = _load()


class _Response:
    def __init__(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.status_code = status
        self.headers = {"content-type": content_type}
        self._body = body

    def iter_bytes(self):
        yield self._body


def _patch_stream(monkeypatch: pytest.MonkeyPatch, response: _Response) -> dict[str, Any]:
    observed: dict[str, Any] = {}

    def stream(
        method: str, url: str, **kwargs: Any
    ) -> contextlib.AbstractContextManager[_Response]:
        observed.update(method=method, url=url, **kwargs)
        return contextlib.nullcontext(response)

    monkeypatch.setattr(ADAPTER.httpx, "stream", stream)
    return observed


def test_http_json_uses_bounded_https_json_request_without_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _Response(200, b'{"source_sha":"' + SOURCE_SHA.encode() + b'"}')
    observed = _patch_stream(monkeypatch, response)

    status, payload = ADAPTER._http_json("/release.json")

    assert status == 200
    assert payload == {"source_sha": SOURCE_SHA}
    assert observed["method"] == "GET"
    assert observed["url"] == "https://q22.qdev.run/release.json"
    assert observed["timeout"] == 20
    assert observed["follow_redirects"] is False
    assert observed["headers"]["Accept"] == "application/json"


def test_http_json_accepts_503_only_for_explicit_prelaunch_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _Response(503, b'{"status":"not_ready"}')
    _patch_stream(monkeypatch, response)

    assert ADAPTER._http_json("/ready", allow_not_ready=True) == (
        503,
        {"status": "not_ready"},
    )
    with pytest.raises(ADAPTER.AdapterError, match="public_runtime_http_status_invalid"):
        ADAPTER._http_json("/ready")


@pytest.mark.parametrize(
    ("body", "content_type", "error"),
    [
        (b"<html>not JSON</html>", "text/html", "public_runtime_content_type_invalid"),
        (b"not-json", "application/json", "public_runtime_identity_invalid"),
        (
            b"x" * (2 * 1024 * 1024 + 1),
            "application/json",
            "public_runtime_payload_too_large",
        ),
    ],
)
def test_http_json_rejects_wrong_type_invalid_json_and_oversized_body(
    monkeypatch: pytest.MonkeyPatch, body: bytes, content_type: str, error: str
) -> None:
    _patch_stream(monkeypatch, _Response(200, body, content_type))

    with pytest.raises(ADAPTER.AdapterError, match=error):
        ADAPTER._http_json("/release.json")


def test_http_json_maps_transport_errors_to_closed_failure_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = httpx.Request("GET", "https://q22.qdev.run/health")

    def fail_stream(*_args: Any, **_kwargs: Any) -> Any:
        raise httpx.ConnectError("offline", request=request)

    monkeypatch.setattr(ADAPTER.httpx, "stream", fail_stream)
    with pytest.raises(ADAPTER.AdapterError, match="public_runtime_unreachable"):
        ADAPTER._http_json("/health")


def _write_source_archive(
    path: Path,
    members: list[tuple[str, bytes, int]],
    *,
    symlink: tuple[str, str] | None = None,
) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, contents, mode in members:
            member = tarfile.TarInfo(name)
            member.mode = mode
            member.size = len(contents)
            archive.addfile(member, io.BytesIO(contents))
        if symlink is not None:
            name, target = symlink
            member = tarfile.TarInfo(name)
            member.type = tarfile.SYMTYPE
            member.linkname = target
            archive.addfile(member)


def _valid_source_members() -> list[tuple[str, bytes, int]]:
    return [
        ("RELEASE_COMMIT", f"{SOURCE_SHA}\n".encode(), 0o644),
        ("RELEASE_ANCESTORS", f"{SOURCE_SHA}\n".encode(), 0o644),
        ("scripts/deploy.sh", b"deploy\n", 0o755),
        ("scripts/rollback.sh", b"rollback\n", 0o755),
        ("app.py", b"application\n", 0o644),
    ]


def test_extract_source_checks_sha_ancestry_and_normalizes_file_modes(tmp_path: Path) -> None:
    archive = tmp_path / "source.tar.gz"
    destination = tmp_path / "source"
    destination.mkdir()
    _write_source_archive(archive, _valid_source_members())

    size = ADAPTER._extract_source(archive, destination, SOURCE_SHA)

    assert size == sum(len(contents) for _, contents, _ in _valid_source_members())
    assert (destination / "RELEASE_COMMIT").read_text(encoding="ascii").strip() == SOURCE_SHA
    assert (destination / "scripts/deploy.sh").stat().st_mode & 0o777 == 0o755
    assert (destination / "app.py").stat().st_mode & 0o777 == 0o644


@pytest.mark.parametrize(
    ("members", "symlink", "error"),
    [
        (
            _valid_source_members() + [("../outside.txt", b"escape", 0o644)],
            None,
            "source_archive_path_invalid",
        ),
        (
            _valid_source_members(),
            ("scripts/untrusted.sh", "../../outside.sh"),
            "source_archive_member_invalid",
        ),
    ],
)
def test_extract_source_rejects_traversal_and_links(
    tmp_path: Path,
    members: list[tuple[str, bytes, int]],
    symlink: tuple[str, str] | None,
    error: str,
) -> None:
    archive = tmp_path / "source.tar.gz"
    destination = tmp_path / "source"
    destination.mkdir()
    _write_source_archive(archive, members, symlink=symlink)

    with pytest.raises(ADAPTER.AdapterError, match=error):
        ADAPTER._extract_source(archive, destination, SOURCE_SHA)
    assert not (tmp_path / "outside.txt").exists()
    assert not (tmp_path / "outside.sh").exists()
