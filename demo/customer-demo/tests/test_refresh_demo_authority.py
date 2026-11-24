import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "tools" / "refresh_demo_authority.py"
SPEC = importlib.util.spec_from_file_location("refresh_demo_authority", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class RefreshDemoAuthorityTests(unittest.TestCase):
    def test_claude_launcher_is_repository_launcher(self):
        expected = str(
            SCRIPT.parents[3]
            / "packages/hawk-mcp-proxy/bin/hawk-github-pr-endpoint.mjs"
        )
        self.assertEqual(MODULE.CLAUDE_LAUNCHER, expected)

    def test_authority_fits_owner_attestation_margin(self):
        self.assertLessEqual(MODULE.OWNER_ATTESTATION_MINUTES, 60)
        self.assertLessEqual(
            MODULE.AUTHORITY_MINUTES,
            MODULE.OWNER_ATTESTATION_MINUTES - 5,
        )

    def test_claude_update_changes_only_session(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "claude.json"
            original = {
                "theme": "dark",
                "mcpServers": {
                    "unrelated": {"command": "/bin/true"},
                    MODULE.CLAUDE_PROFILE: {
                        "command": MODULE.NODE_COMMAND,
                        "args": [
                            MODULE.CLAUDE_LAUNCHER,
                            "claude",
                            "--repository-scope",
                            MODULE.REPOSITORY,
                            "--keychain-service",
                            MODULE.KEYCHAIN_SERVICE,
                            "--keychain-account",
                            MODULE.KEYCHAIN_ACCOUNT,
                            "--session-id",
                            "mcp_sess_old",
                        ],
                        "env": {},
                    },
                },
            }
            path.write_text(json.dumps(original), encoding="utf-8")
            MODULE.update_claude_config(path, "mcp_sess_new")
            updated = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(updated["theme"], "dark")
            self.assertEqual(updated["mcpServers"]["unrelated"], {"command": "/bin/true"})
            args = updated["mcpServers"][MODULE.CLAUDE_PROFILE]["args"]
            self.assertEqual(args[args.index("--session-id") + 1], "mcp_sess_new")

    def test_claude_update_rejects_repository_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "claude.json"
            value = {
                "mcpServers": {
                    MODULE.CLAUDE_PROFILE: {
                        "command": MODULE.NODE_COMMAND,
                        "args": [
                            MODULE.CLAUDE_LAUNCHER,
                            "claude",
                            "--repository-scope",
                            "github.com/personal/repo",
                            "--keychain-service",
                            MODULE.KEYCHAIN_SERVICE,
                            "--keychain-account",
                            MODULE.KEYCHAIN_ACCOUNT,
                            "--session-id",
                            "mcp_sess_old",
                        ],
                    }
                }
            }
            original = json.dumps(value)
            path.write_text(original, encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "repository scope"):
                MODULE.update_claude_config(path, "mcp_sess_new")
            self.assertEqual(path.read_text(encoding="utf-8"), original)

    def test_keychain_write_keeps_capability_out_of_process_arguments(self):
        capability = "A" * 48
        with mock.patch.object(MODULE.subprocess, "run") as run:
            run.return_value.returncode = 0
            MODULE.write_keychain(capability)
        argv = run.call_args.args[0]
        self.assertNotIn(capability, argv)
        self.assertEqual(argv[-1], "-w")
        self.assertEqual(run.call_args.kwargs["input"], capability + "\n")
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_claude_rotation_restores_matched_pair_on_verification_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "claude.json"
            original = {
                "mcpServers": {
                    MODULE.CLAUDE_PROFILE: {
                        "command": MODULE.NODE_COMMAND,
                        "args": [
                            MODULE.CLAUDE_LAUNCHER,
                            "claude",
                            "--repository-scope",
                            MODULE.REPOSITORY,
                            "--keychain-service",
                            MODULE.KEYCHAIN_SERVICE,
                            "--keychain-account",
                            MODULE.KEYCHAIN_ACCOUNT,
                            "--session-id",
                            "mcp_sess_old",
                        ],
                    }
                }
            }
            original_text = json.dumps(original)
            path.write_text(original_text, encoding="utf-8")
            with (
                mock.patch.object(MODULE, "read_keychain", side_effect=["old-capability", "wrong-capability"]),
                mock.patch.object(MODULE, "write_keychain"),
                mock.patch.object(MODULE, "restore_keychain") as restore,
            ):
                with self.assertRaisesRegex(RuntimeError, "verification failed"):
                    MODULE.rotate_claude_authority(path, "mcp_sess_new", "B" * 48)
            self.assertEqual(path.read_text(encoding="utf-8"), original_text)
            restore.assert_called_once_with("old-capability")


if __name__ == "__main__":
    unittest.main()
