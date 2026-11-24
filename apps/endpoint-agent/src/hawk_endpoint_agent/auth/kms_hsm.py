from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import platform
import socket
import stat
import struct
import subprocess
from typing import Callable
from uuid import uuid4

from .device_key import (
    DeviceKeyError,
    DeviceKeyStatus,
    DevicePublicIdentity,
    public_key_thumbprint,
)


Runner = Callable[[str, str, bytes], dict]
HelperVerifier = Callable[[str], bool]
PipeAuthProvider = Callable[[], bytearray]


MAX_HELPER_MESSAGE_BYTES = 1_048_576
HELPER_PROTOCOL = "hawk-kms-helper/1.0"


class KmsHsmHelperProvider:
    """Opaque key-reference transport to a bank-managed KMS/HSM signing helper."""

    provider_name = "kms_hsm_helper"

    def __init__(
        self,
        *,
        helper_path: str,
        key_reference: str,
        runner: Runner | None = None,
        helper_verifier: HelperVerifier | None = None,
        pipe_auth_provider: PipeAuthProvider | None = None,
    ) -> None:
        reference = str(key_reference or "").strip()
        if not reference or len(reference) > 512 or not reference.startswith(("kms://", "hsm://", "pkcs11://")):
            raise ValueError("invalid KMS/HSM key reference")
        endpoint = str(helper_path or "").strip()
        if endpoint.startswith("unix://"):
            self._transport = "unix"
            self._helper_path = str(Path(endpoint.removeprefix("unix://")).expanduser())
        elif endpoint.startswith("pipe://"):
            self._transport = "pipe"
            self._helper_path = endpoint.removeprefix("pipe://")
        else:
            self._transport = "process"
            self._helper_path = str(Path(endpoint).expanduser())
        self._key_reference = reference
        self._runner = runner or self._run_helper
        self._pipe_auth_provider = pipe_auth_provider
        self._verify = helper_verifier or (
            self._verify_unix_endpoint
            if self._transport == "unix"
            else self._verify_pipe_endpoint
            if self._transport == "pipe"
            else self._default_verify
        )
        if not self._verify(self._helper_path):
            raise DeviceKeyError("KMS/HSM helper identity verification failed")

    @staticmethod
    def _default_verify(path: str) -> bool:
        helper = Path(path)
        if not helper.is_file() or helper.is_symlink() or helper.stat().st_mode & 0o022:
            return False
        if Path("/usr/bin/codesign").is_file():
            result = subprocess.run(
                ["/usr/bin/codesign", "-dv", "--verbose=4", str(helper)],
                capture_output=True,
                timeout=5,
                check=False,
            )
            output = result.stdout + result.stderr
            return result.returncode == 0 and b"TeamIdentifier=" in output and b"TeamIdentifier=not set" not in output
        return helper.stat().st_uid == 0

    @staticmethod
    def _verify_unix_endpoint(path: str) -> bool:
        helper = Path(path)
        try:
            metadata = helper.lstat()
            parent = helper.parent.stat()
        except OSError:
            return False
        allowed_owner = metadata.st_uid in {0, os.getuid()}
        return bool(
            stat.S_ISSOCK(metadata.st_mode)
            and not helper.is_symlink()
            and allowed_owner
            and metadata.st_mode & 0o022 == 0
            and parent.st_uid in {0, os.getuid()}
            and parent.st_mode & 0o022 == 0
        )

    def _verify_pipe_endpoint(self, path: str) -> bool:
        return bool(
            platform.system() == "Windows"
            and path.startswith(r"\\.\pipe\Hawk")
            and self._pipe_auth_provider is not None
        )

    @staticmethod
    def _recv_exact(connection: socket.socket, length: int) -> bytes:
        if length < 0 or length > MAX_HELPER_MESSAGE_BYTES:
            raise DeviceKeyError("KMS/HSM helper message length is invalid")
        chunks: list[bytes] = []
        remaining = length
        while remaining:
            chunk = connection.recv(remaining)
            if not chunk:
                raise DeviceKeyError("KMS/HSM helper transport closed early")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    @staticmethod
    def _peer_identity_allowed(connection: socket.socket) -> bool:
        allowed = {0, os.getuid()}
        getpeereid = getattr(connection, "getpeereid", None)
        if callable(getpeereid):
            uid, _gid = getpeereid()
            return int(uid) in allowed
        peercred = getattr(socket, "SO_PEERCRED", None)
        if peercred is not None:
            raw = connection.getsockopt(socket.SOL_SOCKET, peercred, struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", raw)
            return int(uid) in allowed
        # CPython on macOS exposes LOCAL_PEERCRED but not getpeereid or
        # SO_PEERCRED. Darwin's xucred layout binds the peer UID without
        # trusting filesystem ownership alone.
        local_peercred = getattr(socket, "LOCAL_PEERCRED", None)
        if local_peercred is not None:
            layout = "=IIh2x16I"
            try:
                raw = connection.getsockopt(
                    getattr(socket, "SOL_LOCAL", 0),
                    local_peercred,
                    struct.calcsize(layout),
                )
                version, uid, _group_count, *_groups = struct.unpack(layout, raw)
            except (OSError, ValueError, struct.error):
                return False
            return version == 0 and int(uid) in allowed
        return False

    @staticmethod
    def _request(verb: str, key_ref: str, payload: bytes) -> tuple[str, bytes]:
        request_id = str(uuid4())
        body = json.dumps(
            {
                "protocol": HELPER_PROTOCOL,
                "request_id": request_id,
                "verb": verb,
                "key_reference": key_ref,
                "payload_base64": base64.b64encode(payload).decode("ascii"),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(body) > MAX_HELPER_MESSAGE_BYTES:
            raise DeviceKeyError("KMS/HSM helper request is too large")
        return request_id, body

    @staticmethod
    def _decode_response(raw: bytes, request_id: str) -> dict:
        try:
            response = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DeviceKeyError("KMS/HSM helper returned invalid output") from exc
        if not isinstance(response, dict) or response.get("protocol") != HELPER_PROTOCOL:
            raise DeviceKeyError("KMS/HSM helper protocol mismatch")
        if response.get("request_id") != request_id:
            raise DeviceKeyError("KMS/HSM helper response is not bound to the request")
        response = dict(response)
        response.pop("protocol", None)
        response.pop("request_id", None)
        return response

    def _run_unix_helper(self, verb: str, key_ref: str, payload: bytes) -> dict:
        before = Path(self._helper_path).lstat()
        request_id, body = self._request(verb, key_ref, payload)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(10)
                connection.connect(self._helper_path)
                after = Path(self._helper_path).lstat()
                if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                    raise DeviceKeyError("KMS/HSM helper endpoint changed during connection")
                if not self._peer_identity_allowed(connection):
                    raise DeviceKeyError("KMS/HSM helper peer identity is not trusted")
                connection.sendall(struct.pack("!I", len(body)) + body)
                response_length = struct.unpack("!I", self._recv_exact(connection, 4))[0]
                raw = self._recv_exact(connection, response_length)
        except DeviceKeyError:
            raise
        except (OSError, ValueError, struct.error) as exc:
            raise DeviceKeyError("KMS/HSM helper transport failed") from exc
        return self._decode_response(raw, request_id)

    def _run_pipe_helper(self, verb: str, key_ref: str, payload: bytes) -> dict:
        if self._pipe_auth_provider is None:
            raise DeviceKeyError("KMS/HSM named-pipe authentication is unavailable")
        from multiprocessing.connection import Client

        auth = self._pipe_auth_provider()
        if not isinstance(auth, bytearray) or len(auth) < 32:
            raise DeviceKeyError("KMS/HSM named-pipe authentication material is invalid")
        request_id, body = self._request(verb, key_ref, payload)
        try:
            connection = Client(self._helper_path, family="AF_PIPE", authkey=bytes(auth))
            try:
                connection.send_bytes(body)
                raw = connection.recv_bytes(MAX_HELPER_MESSAGE_BYTES)
            finally:
                connection.close()
        except (OSError, EOFError, ValueError) as exc:
            raise DeviceKeyError("KMS/HSM helper transport failed") from exc
        finally:
            for index in range(len(auth)):
                auth[index] = 0
        return self._decode_response(raw, request_id)

    def _run_helper(self, verb: str, key_ref: str, payload: bytes) -> dict:
        if verb not in {"public", "sign", "status"}:
            raise DeviceKeyError("unsupported KMS/HSM helper operation")
        if self._transport == "unix":
            return self._run_unix_helper(verb, key_ref, payload)
        if self._transport == "pipe":
            return self._run_pipe_helper(verb, key_ref, payload)
        try:
            result = subprocess.run(
                [self._helper_path, verb, key_ref],
                input=payload,
                capture_output=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise DeviceKeyError("KMS/HSM helper transport failed") from exc
        if result.returncode != 0:
            raise DeviceKeyError("KMS/HSM helper operation failed")
        try:
            response = json.loads(result.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DeviceKeyError("KMS/HSM helper returned invalid output") from exc
        if not isinstance(response, dict):
            raise DeviceKeyError("KMS/HSM helper returned invalid output")
        return response

    def _checked(self, response: dict) -> dict:
        if any("private" in str(key).lower() or "secret" in str(key).lower() for key in response):
            raise DeviceKeyError("KMS/HSM helper returned private key material")
        if response.get("ok") is not True:
            raise DeviceKeyError("KMS/HSM helper operation was not successful")
        if response.get("key_id") != self._key_reference or response.get("algorithm") != "ES256":
            raise DeviceKeyError("KMS/HSM helper response binding mismatch")
        return response

    def ensure_key(self, endpoint_id: str) -> DevicePublicIdentity:
        del endpoint_id
        response = self._checked(self._runner("public", self._key_reference, b""))
        public_key_pem = str(response.get("public_key_pem") or "")
        return DevicePublicIdentity(
            provider=self.provider_name,
            public_key_pem=public_key_pem,
            key_thumbprint=public_key_thumbprint(public_key_pem),
            hardware_backed=response.get("hardware_backed") is True,
        )

    def sign(self, payload: bytes) -> bytes:
        response = self._checked(self._runner("sign", self._key_reference, payload))
        encoded = str(response.get("signature") or "")
        try:
            return base64.urlsafe_b64decode(encoded + ("=" * (-len(encoded) % 4)))
        except ValueError as exc:
            raise DeviceKeyError("KMS/HSM helper returned invalid signature") from exc

    def status(self) -> DeviceKeyStatus:
        try:
            response = self._checked(self._runner("status", self._key_reference, b""))
        except DeviceKeyError as exc:
            return DeviceKeyStatus(
                provider=self.provider_name,
                available=False,
                hardware_backed=False,
                signed_helper=True,
                detail=str(exc),
            )
        return DeviceKeyStatus(
            provider=self.provider_name,
            available=response.get("available") is True,
            hardware_backed=response.get("hardware_backed") is True,
            signed_helper=True,
            detail="opaque key-reference helper",
        )

    def destroy(self) -> None:
        raise DeviceKeyError("KMS/HSM key destruction is not permitted through the endpoint helper")
