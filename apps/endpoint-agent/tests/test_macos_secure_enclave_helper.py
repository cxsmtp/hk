from __future__ import annotations

import platform
import subprocess
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from hawk_endpoint_agent.auth.device_key import MacSecureEnclaveProvider


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "build" / "hawk-device-identity"
BUILD_SCRIPT = ROOT / "scripts" / "build_macos_identity_helper.sh"


@pytest.mark.skipif(platform.system() != "Darwin", reason="macOS Secure Enclave only")
def test_macos_helper_creates_non_exportable_key_and_signs() -> None:
    subprocess.run([str(BUILD_SCRIPT)], check=True, cwd=ROOT)
    tag = f"com.hawk.endpoint-agent.test.{uuid.uuid4()}"
    provider = MacSecureEnclaveProvider(
        helper_path=str(HELPER), key_tag=tag, require_signed=False
    )
    try:
        identity = provider.ensure_key("mac-test-endpoint")
        public_key = serialization.load_pem_public_key(
            identity.public_key_pem.encode("ascii")
        )
        status = provider.status()
        assert status.available is True
        assert status.hardware_backed is True
        for index in range(3):
            payload = f"hawk secure enclave proof {index}".encode("ascii")
            signature = provider.sign(payload)
            public_key.verify(
                signature,
                payload,
                ec.ECDSA(hashes.SHA256()),
            )
        assert "PRIVATE" not in identity.public_key_pem
    finally:
        provider.destroy()
