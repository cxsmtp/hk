from __future__ import annotations

from pathlib import Path

import pytest

from hawk_endpoint_agent.chatgpt_desktop import inspect_chatgpt_installation


CHATGPT_APP = Path("/Applications/ChatGPT.app")
ACCEPTED_VERSION = "26.715.31925"
ACCEPTED_BUILD = "5551"
ACCEPTED_BUNDLE_ID = "com.openai.codex"
ACCEPTED_TEAM_ID = "2DC432GLL2"


@pytest.mark.skipif(not CHATGPT_APP.is_dir(), reason="ChatGPT desktop is not installed")
def test_installed_chatgpt_identity_matches_manifest_and_fails_closed_on_invalid_signature() -> None:
    observation = inspect_chatgpt_installation(CHATGPT_APP)

    assert observation.installed is True
    assert observation.bundle_id == ACCEPTED_BUNDLE_ID
    assert observation.version == ACCEPTED_VERSION
    assert observation.build == ACCEPTED_BUILD
    assert observation.team_id == ACCEPTED_TEAM_ID
    assert observation.code_directory_hash
    # On 2026-08-12 macOS strict verification reported that this installed
    # bundle had been modified. Hawk must keep it unverified even though an
    # embedded Team ID and a stapled ticket are still visible.
    assert observation.signature_verified is False
    assert observation.hardened_runtime is True
    assert observation.notarization_verified is False
    # Installation identity is not evidence of a product-wide enforcement hook.
    assert observation.native_hook_available is False
