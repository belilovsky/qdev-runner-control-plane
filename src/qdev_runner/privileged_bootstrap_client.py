"""Unprivileged client for the root-owned fleet bootstrap executor.

The client performs no policy decision. It forwards one bounded JSON envelope
over the controller-local Unix socket and returns one bounded JSON response.
It deliberately has no hostname, TCP, executable, or shell configuration.
"""

from __future__ import annotations

import json
import os
import socket
import sys
from pathlib import Path
from typing import Any, cast

MAX_MESSAGE_BYTES = 256 * 1024
DEFAULT_SOCKET = Path("/run/qdev-runner-bootstrap/executor.sock")


class ClientError(RuntimeError):
    """The local privileged boundary was unavailable or malformed."""


def _read_bounded(stream: Any) -> bytes:
    data = stream.buffer.read(MAX_MESSAGE_BYTES + 1)
    if not data or len(data) > MAX_MESSAGE_BYTES:
        raise ClientError("bootstrap adapter request is empty or too large")
    return cast(bytes, data)


def _json_object(data: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ClientError(f"bootstrap adapter {label} is not JSON") from error
    if not isinstance(value, dict):
        raise ClientError(f"bootstrap adapter {label} is not an object")
    return value


def exchange(envelope: dict[str, Any], *, socket_path: Path = DEFAULT_SOCKET) -> dict[str, Any]:
    encoded = json.dumps(
        envelope, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode()
    if len(encoded) > MAX_MESSAGE_BYTES:
        raise ClientError("bootstrap adapter request is too large")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(125)
            client.connect(str(socket_path))
            client.sendall(encoded)
            client.shutdown(socket.SHUT_WR)
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = client.recv(min(65536, MAX_MESSAGE_BYTES + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_MESSAGE_BYTES:
                    raise ClientError("bootstrap adapter response is too large")
    except (OSError, TimeoutError) as error:
        raise ClientError("bootstrap privileged executor is unavailable") from error
    return _json_object(b"".join(chunks), label="response")


def main() -> int:
    try:
        envelope = _json_object(_read_bounded(sys.stdin), label="request")
        socket_path = Path(os.environ.get("QDEV_BOOTSTRAP_EXECUTOR_SOCKET", DEFAULT_SOCKET))
        response = exchange(envelope, socket_path=socket_path)
    except ClientError as error:
        print(f"bootstrap_adapter_failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(response, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
