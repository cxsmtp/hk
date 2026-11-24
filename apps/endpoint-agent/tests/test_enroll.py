import json
import os
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from hawk_endpoint_agent.auth.session import EnrollmentBundle
from hawk_endpoint_agent.__main__ import main
from hawk_endpoint_agent.bridge.manifest import HOST_NAME
from hawk_endpoint_agent.enroll import EnrollmentReport, enroll, enroll_existing_config
from hawk_endpoint_agent.enroll import _render_launch_agent
from hawk_endpoint_agent.tls.certs import cryptography_available


class EnrollTests(unittest.TestCase):
    def test_launch_agent_uses_installed_python_and_bounded_logs(self):
        plist = _render_launch_agent(
            "/opt/hawk/venv/bin/python",
            Path("/tmp/hawk/config.json"),
            Path("/tmp/hawk/logs"),
            "/opt/hawk/app",
        )
        self.assertIn("/opt/hawk/venv/bin/python", plist)
        self.assertIn("StandardOutPath", plist)
        self.assertIn("StandardErrorPath", plist)
        self.assertIn("ProcessType", plist)
        self.assertIn("PYTHONPATH", plist)
        self.assertIn("/opt/hawk/app", plist)

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self._old_home = os.environ.get("HOME")
        # Redirect ~ so manifest/service writes land in the sandbox, not the real HOME.
        os.environ["HOME"] = str(self.root)

    def tearDown(self) -> None:
        if self._old_home is not None:
            os.environ["HOME"] = self._old_home
        self.tmp.cleanup()

    def _steps(self, report) -> dict:
        return {s["step"]: s for s in report.as_dict()["steps"]}

    def test_config_written_secure_without_any_static_secret(self) -> None:
        cfg = self.root / "cfg.json"
        report = enroll(
            api_url="https://hawk.example",
            tenant_id="t1",
            config_path=str(cfg),
        )
        self.assertTrue(cfg.exists())
        self.assertEqual(oct(cfg.stat().st_mode)[-3:], "600")  # 0600
        data = json.loads(cfg.read_text())
        self.assertEqual(data["api_base_url"], "https://hawk.example")
        self.assertEqual(data["tenant_id"], "t1")
        self.assertNotIn("agent_token", data)
        self.assertNotIn("operator_token", data)
        self.assertNotIn("refresh_token", data)
        self.assertTrue(report.as_dict()["ok"])

    def test_config_report_never_mentions_legacy_token_delivery(self) -> None:
        cfg = self.root / "cfg.json"
        report = enroll(api_url="https://hawk.example", tenant_id="t1", config_path=str(cfg))
        step = self._steps(report)["config"]
        self.assertEqual(step["status"], "ok")
        rendered = json.dumps(report.as_dict())
        self.assertNotIn("HAWK_AGENT_TOKEN", rendered)
        self.assertNotIn("operator_token", rendered)

    def test_live_enrollment_bundle_is_used_but_never_persisted_or_reported(self) -> None:
        cfg = self.root / "cfg.json"
        secret_code = "one-time-super-secret-enrollment-code"
        secret_nonce = "one-time-super-secret-enrollment-nonce"

        class FakeSession:
            def __init__(self):
                self.received = None

            def enroll(self, bundle):
                self.received = bundle
                return {
                    "identity_id": "identity-1",
                    "key_provider": "macos_secure_enclave",
                    "key_thumbprint": "a" * 64,
                }

        session = FakeSession()
        report = enroll(
            api_url="https://hawk.example",
            tenant_id="t1",
            endpoint_id="endpoint-1",
            default_ai_system_id="ai-system-1",
            config_path=str(cfg),
            enrollment_bundle=EnrollmentBundle(
                authorization_id="authorization-1",
                enrollment_code=secret_code,
                enrollment_nonce=secret_nonce,
            ),
            auth_session=session,
        )
        self.assertEqual(session.received.enrollment_code, secret_code)
        persisted = cfg.read_text()
        rendered = json.dumps(report.as_dict())
        self.assertNotIn(secret_code, persisted + rendered)
        self.assertNotIn(secret_nonce, persisted + rendered)
        self.assertEqual(self._steps(report)["device_identity"]["status"], "ok")

    def test_existing_windows_config_enrollment_preserves_native_policy_trust(self) -> None:
        cfg = self.root / "cfg.json"
        verification_key = "MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE="
        cfg.write_text(json.dumps({
            "api_base_url": "https://hawk.example",
            "tenant_id": "t1",
            "endpoint_id": "endpoint-1",
            "default_ai_system_id": "ai-system-1",
            "os_type": "windows",
            "deployment_mode": "managed_machine",
            "security_profile": "bank",
            "key_provider": "windows_tpm_cng",
            "identity_helper_sha256": "a" * 64,
            "windows_native_enforcement_enabled": True,
            "endpoint_floor_policy_public_keys": {"floor-1": verification_key},
        }))

        class FakeSession:
            def enroll(self, _bundle):
                return {
                    "identity_id": "identity-1",
                    "key_provider": "windows_tpm_cng",
                    "key_thumbprint": "b" * 64,
                }

        report = enroll_existing_config(
            config_path=cfg,
            enrollment_bundle=EnrollmentBundle(
                authorization_id="authorization-1",
                enrollment_code="one-time-secret",
                enrollment_nonce="one-time-nonce",
            ),
            auth_session=FakeSession(),
        )

        persisted = json.loads(cfg.read_text())
        self.assertTrue(report.as_dict()["ok"])
        self.assertTrue(persisted["windows_native_enforcement_enabled"])
        self.assertEqual(
            persisted["endpoint_floor_policy_public_keys"],
            {"floor-1": verification_key},
        )
        self.assertEqual(persisted["ipc_trusted_device_thumbprint"], "b" * 64)
        self.assertNotIn("one-time-secret", cfg.read_text())

    def test_full_macos_enrollment(self) -> None:
        cfg = self.root / "cfg.json"
        report = enroll(
            api_url="https://hawk.example", tenant_id="t1", config_path=str(cfg),
            ca_dir=str(self.root / "ca"), enable_tls=True, install_service=True, install_bridge=True,
            extension_ids=["extabc"], os_type="darwin", security_profile="development",
        )
        steps = self._steps(report)
        self.assertEqual(steps["config"]["status"], "ok")
        self.assertEqual(steps["service"]["status"], "ok")
        self.assertEqual(steps["bridge_launcher"]["status"], "ok")
        for browser in ("chrome", "edge", "firefox"):
            self.assertEqual(steps[f"bridge_manifest_{browser}"]["status"], "ok")

        # Launch agent + bridge launcher exist and are shaped correctly.
        plist = self.root / "Library/LaunchAgents/com.hawk.endpoint-agent.plist"
        self.assertTrue(plist.exists())
        self.assertIn("RunAtLoad", plist.read_text())
        launcher = self.root / ".config/hawk/hawk-bridge"
        # bridge launcher is written next to the config file
        self.assertTrue((self.root / "hawk-bridge").exists() or launcher.exists())

        # Chrome native-messaging manifest points at the launcher and allows the extension.
        chrome_manifest = self.root / f"Library/Application Support/Google/Chrome/NativeMessagingHosts/{HOST_NAME}.json"
        self.assertTrue(chrome_manifest.exists())
        manifest = json.loads(chrome_manifest.read_text())
        self.assertEqual(manifest["name"], HOST_NAME)
        self.assertEqual(manifest["allowed_origins"], ["chrome-extension://extabc/"])

        # CA behavior depends on whether cryptography is installed; both are honest.
        if cryptography_available():
            self.assertEqual(steps["ca"]["status"], "ok")
            self.assertTrue((self.root / "ca/hawk-endpoint-ca.crt").exists())
            self.assertIn("trust_command", steps["ca"])
        else:
            self.assertEqual(steps["ca"]["status"], "skipped")

    def test_linux_systemd_unit(self) -> None:
        cfg = self.root / "cfg.json"
        report = enroll(
            api_url="https://hawk.example", tenant_id="t1", config_path=str(cfg),
            install_service=True, os_type="linux",
        )
        steps = self._steps(report)
        self.assertEqual(steps["service"]["status"], "ok")
        unit = self.root / ".config/systemd/user/hawk-endpoint-agent.service"
        self.assertTrue(unit.exists())
        body = unit.read_text()
        self.assertIn("ExecStart", body)
        self.assertIn("hawk_endpoint_agent", body)

    def test_cli_enroll_returns_zero(self) -> None:
        cfg = self.root / "cfg.json"
        fake_report = EnrollmentReport()
        fake_report.add("device_identity", "ok")
        fake_report.add("config", "ok")
        stdin = SimpleNamespace(
            buffer=BytesIO(
                json.dumps(
                    {
                        "authorization_id": "authorization-1",
                        "enrollment_code": "c" * 32,
                        "enrollment_nonce": "n" * 32,
                    }
                ).encode()
            )
        )
        with patch("hawk_endpoint_agent.__main__.sys.stdin", stdin), patch(
            "hawk_endpoint_agent.__main__.enroll", return_value=fake_report
        ) as enroll_mock:
            rc = main([
                "--enroll", "--api-url", "https://hawk.example", "--tenant-id", "t1",
                "--ai-system-id", "ai-system-1",
                "--enrollment-bundle-stdin", "--config", str(cfg), "--install-bridge",
                "--extension-id", "e1",
            ])
        self.assertEqual(rc, 0)
        self.assertIsInstance(enroll_mock.call_args.kwargs["enrollment_bundle"], EnrollmentBundle)
        self.assertEqual(enroll_mock.call_args.kwargs["default_ai_system_id"], "ai-system-1")

    def test_cli_live_enroll_requires_registered_ai_system(self) -> None:
        with self.assertRaisesRegex(SystemExit, "--ai-system-id"):
            main([
                "--enroll", "--api-url", "https://hawk.example", "--tenant-id", "t1",
                "--enrollment-bundle-stdin",
            ])

    def test_live_enrollment_requires_registered_ai_system(self) -> None:
        with self.assertRaisesRegex(ValueError, "registered default AI system"):
            enroll(
                api_url="https://hawk.example",
                tenant_id="t1",
                endpoint_id="endpoint-1",
                enrollment_bundle=EnrollmentBundle(
                    authorization_id="authorization-1",
                    enrollment_code="c" * 32,
                    enrollment_nonce="n" * 32,
                ),
                auth_session=object(),
            )

    def test_cli_rejects_legacy_token_argument(self) -> None:
        with self.assertRaises(SystemExit):
            main([
                "--enroll", "--api-url", "https://hawk.example", "--tenant-id", "t1",
                "--agent-token", "legacy-secret",
            ])

    def test_cli_enroll_requires_api_and_tenant(self) -> None:
        with self.assertRaises(SystemExit):
            main(["--enroll"])

    def test_bank_profile_rejects_http_and_file_backed_tls(self) -> None:
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            enroll(api_url="http://hawk.example", tenant_id="t1")
        with self.assertRaisesRegex(ValueError, "file-backed TLS"):
            enroll(
                api_url="https://hawk.example",
                tenant_id="t1",
                enable_tls=True,
            )


if __name__ == "__main__":
    unittest.main()
