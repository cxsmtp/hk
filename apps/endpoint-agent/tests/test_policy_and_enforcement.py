import json
import tempfile
import unittest
from pathlib import Path

from hawk_endpoint_agent.config import AgentConfig
from hawk_endpoint_agent.decision import Action, ControlMode
from hawk_endpoint_agent.enforcement import EnforcementOrchestrator, decision_from_response
from hawk_endpoint_agent.hawk_client import HawkUnavailable
from hawk_endpoint_agent.policy import PolicyStore


class _RaisingClient:
    def sync_policy(self):
        raise HawkUnavailable("down")


class FailSecureTests(unittest.TestCase):
    def _store(self, mode):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = AgentConfig(fail_secure_mode=mode, policy_cache_path=str(Path(tmp) / "cache.json"))
            return PolicyStore(cfg, _RaisingClient())

    def test_fail_secure_block(self):
        d = self._store("block").fail_secure_decision(surface="llm_prompt", reason="unreachable")
        self.assertEqual(d.action, Action.BLOCK)
        self.assertEqual(d.control_mode, ControlMode.INLINE_PREVENTED)

    def test_fail_secure_warn(self):
        d = self._store("warn").fail_secure_decision(surface="llm_prompt", reason="unreachable")
        self.assertEqual(d.action, Action.WARN)

    def test_fail_secure_allow(self):
        d = self._store("allow").fail_secure_decision(surface="llm_prompt", reason="unreachable")
        self.assertEqual(d.action, Action.ALLOW)

    def test_refresh_failure_marks_stale(self):
        store = self._store("warn")
        self.assertFalse(store.refresh())
        self.assertTrue(store.stale)


class CacheIntegrityTests(unittest.TestCase):
    def test_tampered_cache_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "cache.json"
            # Valid payload but wrong hash => must be rejected (fail-secure, no drift).
            cache.write_text(json.dumps({"fetched_at": 1.0, "hash": "deadbeef", "payload": {"platform_mode": "allow"}}))
            cfg = AgentConfig(policy_cache_path=str(cache))
            store = PolicyStore(cfg, _RaisingClient())
            self.assertIsNone(store.policy)


class DecisionMappingTests(unittest.TestCase):
    def test_review_and_approval_decisions_map_to_hold(self):
        for backend_decision in (
            "review",
            "require_approval",
            "require_second_approval",
            "step_up",
        ):
            with self.subTest(backend_decision=backend_decision):
                decision = decision_from_response(
                    {"decision": backend_decision},
                    surface="agent_action",
                )
                self.assertEqual(decision.action, Action.HOLD)
                self.assertNotEqual(decision.action, Action.ALLOW)

    def test_missing_or_unknown_backend_decisions_fail_closed(self):
        for response in (
            {},
            {"decision": None},
            {"decision": ""},
            {"decision": "future_unrecognized_action"},
        ):
            with self.subTest(response=response):
                decision = decision_from_response(response, surface="agent_action")
                self.assertEqual(decision.action, Action.BLOCK)
                self.assertNotEqual(decision.action, Action.ALLOW)

    def test_block_on_preventable_surface_is_inline_prevented(self):
        response = {"final_decision": "block", "guardian_results": [{"threat_types": ["prompt_injection"]}]}
        d = decision_from_response(response, surface="llm_prompt")
        self.assertEqual(d.action, Action.BLOCK)
        self.assertEqual(d.control_mode, ControlMode.INLINE_PREVENTED)
        self.assertIn("prompt_injection", d.threat_types)

    def test_block_on_non_preventable_surface_degrades_to_detect_only(self):
        d = decision_from_response({"final_decision": "block"}, surface="notetaker")
        self.assertEqual(d.action, Action.BLOCK)
        self.assertEqual(d.control_mode, ControlMode.DETECT_ONLY)

    def test_allow_maps_to_inline_allowed(self):
        d = decision_from_response({"final_decision": "allow"}, surface="llm_prompt")
        self.assertEqual(d.action, Action.ALLOW)
        self.assertEqual(d.control_mode, ControlMode.INLINE_ALLOWED)

    def test_decision_maps_canonical_governance_evidence_and_policy(self):
        d = decision_from_response(
            {
                "final_decision": "allow",
                "pre_action_governance_check": {
                    "policy": {"policy_version_id": "policy-version-1"},
                    "evidence": {"evidence_refs": ["evidence-node-1"]},
                },
            },
            surface="agent_action",
        )

        self.assertEqual(d.action, Action.ALLOW)
        self.assertEqual(d.evidence_ref, "evidence-node-1")
        self.assertEqual(d.detail["policy_version_id"], "policy-version-1")

    def test_orchestrator_fail_secure_on_unreachable_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = AgentConfig(fail_secure_mode="block", policy_cache_path=str(Path(tmp) / "c.json"))
            orch = EnforcementOrchestrator(cfg, PolicyStore(cfg, _RaisingClient()))

            def endpoint(_payload):
                raise HawkUnavailable("down")

            d = orch.evaluate(endpoint=endpoint, payload={}, surface="llm_prompt")
            self.assertEqual(d.action, Action.BLOCK)
            self.assertTrue(str(d.source).startswith("fail_secure"))


if __name__ == "__main__":
    unittest.main()
