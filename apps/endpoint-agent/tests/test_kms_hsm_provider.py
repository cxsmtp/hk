from __future__ import annotations

import base64
import json
import os
import struct

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from hawk_endpoint_agent.auth.device_key import DeviceKeyError
from hawk_endpoint_agent.auth.kms_hsm import KmsHsmHelperProvider
from hawk_endpoint_agent.auth.kms_hsm import HELPER_PROTOCOL


PUBLIC_KEY = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("ascii")


def test_kms_hsm_helper_uses_opaque_key_reference_and_never_accepts_private_material() -> None:
    calls: list[tuple[str, bytes]] = []

    def run(verb: str, key_ref: str, payload: bytes) -> dict:
        calls.append((f"{verb}:{key_ref}", payload))
        if verb == "public":
            return {"ok": True, "key_id": key_ref, "algorithm": "ES256", "public_key_pem": PUBLIC_KEY, "hardware_backed": True}
        return {"ok": True, "key_id": key_ref, "algorithm": "ES256", "signature": base64.urlsafe_b64encode(b"signature").decode("ascii")}

    provider = KmsHsmHelperProvider(
        helper_path="/opt/hawk/bin/hawk-kms-signer",
        key_reference="kms://bank-prod/hawk-native-control",
        runner=run,
        helper_verifier=lambda _path: True,
    )
    identity = provider.ensure_key("endpoint-1")
    signature = provider.sign(b"canonical-envelope")

    assert identity.hardware_backed is True
    assert signature == b"signature"
    assert calls == [
        ("public:kms://bank-prod/hawk-native-control", b""),
        ("sign:kms://bank-prod/hawk-native-control", b"canonical-envelope"),
    ]

    bad = KmsHsmHelperProvider(
        helper_path="/opt/hawk/bin/hawk-kms-signer",
        key_reference="kms://bank-prod/hawk-native-control",
        runner=lambda *_args: {"ok": True, "key_id": "other", "algorithm": "ES256", "private_key": "forbidden"},
        helper_verifier=lambda _path: True,
    )
    with pytest.raises(DeviceKeyError, match="private key material"):
        bad.sign(b"payload")


def test_unix_socket_transport_binds_peer_request_and_opaque_key(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    endpoint = tmp_path / "hawk-kms.sock"
    endpoint.touch(mode=0o600)

    class FakeSocket:
        def __init__(self, *_args):
            self.response = b""

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def settimeout(self, _timeout):
            return None

        def connect(self, path):
            assert path == str(endpoint)

        def getpeereid(self):
            return os.getuid(), os.getgid()

        def sendall(self, framed):
            length = struct.unpack("!I", framed[:4])[0]
            request = json.loads(framed[4:4 + length])
            assert request["protocol"] == HELPER_PROTOCOL
            assert request["verb"] == "sign"
            assert request["key_reference"] == "hsm://bank/hawk"
            assert base64.b64decode(request["payload_base64"]) == b"canonical"
            body = json.dumps(
                {
                    "protocol": HELPER_PROTOCOL,
                    "request_id": request["request_id"],
                    "ok": True,
                    "key_id": "hsm://bank/hawk",
                    "algorithm": "ES256",
                    "signature": base64.urlsafe_b64encode(b"signed").decode("ascii"),
                }
            ).encode("utf-8")
            self.response = struct.pack("!I", len(body)) + body

        def recv(self, length):
            result, self.response = self.response[:length], self.response[length:]
            return result

    monkeypatch.setattr("hawk_endpoint_agent.auth.kms_hsm.socket.socket", FakeSocket)
    provider = KmsHsmHelperProvider(
        helper_path=f"unix://{endpoint}",
        key_reference="hsm://bank/hawk",
        helper_verifier=lambda _path: True,
    )

    assert provider.sign(b"canonical") == b"signed"


def test_macos_local_peer_credentials_are_accepted_only_for_the_current_or_root_uid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class MacPeerSocket:
        def getsockopt(self, level, option, length):
            assert level == 0  # SOL_LOCAL on Darwin
            assert option == 1  # LOCAL_PEERCRED
            assert length == struct.calcsize("=IIh2x16I")
            return struct.pack("=IIh2x16I", 0, os.getuid(), 1, os.getgid(), *([0] * 15))

    monkeypatch.delattr("hawk_endpoint_agent.auth.kms_hsm.socket.SO_PEERCRED", raising=False)
    monkeypatch.setattr("hawk_endpoint_agent.auth.kms_hsm.socket.LOCAL_PEERCRED", 1, raising=False)

    assert KmsHsmHelperProvider._peer_identity_allowed(MacPeerSocket()) is True


def test_named_pipe_transport_zeroizes_ephemeral_auth_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    auth = bytearray(b"a" * 32)

    class FakePipe:
        def send_bytes(self, body):
            request = json.loads(body)
            response = {
                "protocol": HELPER_PROTOCOL,
                "request_id": request["request_id"],
                "ok": True,
                "key_id": "kms://bank/hawk",
                "algorithm": "ES256",
                "signature": base64.urlsafe_b64encode(b"pipe-signed").decode("ascii"),
            }
            self.response = json.dumps(response).encode("utf-8")

        def recv_bytes(self, _maximum):
            return self.response

        def close(self):
            return None

    def fake_client(address, *, family, authkey):
        assert address == r"\\.\pipe\HawkKmsSigner"
        assert family == "AF_PIPE"
        assert authkey == b"a" * 32
        return FakePipe()

    monkeypatch.setattr("multiprocessing.connection.Client", fake_client)
    provider = KmsHsmHelperProvider(
        helper_path=r"pipe://\\.\pipe\HawkKmsSigner",
        key_reference="kms://bank/hawk",
        helper_verifier=lambda _path: True,
        pipe_auth_provider=lambda: auth,
    )

    assert provider.sign(b"canonical") == b"pipe-signed"
    assert auth == bytearray(b"\x00" * 32)
