import unittest

from hawk_endpoint_agent.catalog import match_notetaker
from hawk_endpoint_agent.collectors.audio import AudioCandidate
from hawk_endpoint_agent.collectors.base import Connection, ProcessInfo
from hawk_endpoint_agent.collectors.meetings import MeetingContext
from hawk_endpoint_agent.config import AgentConfig
from hawk_endpoint_agent.decision import Action, ControlMode, Decision
from hawk_endpoint_agent.enforcers.banner import BannerResult
from hawk_endpoint_agent.hawk_client import HawkUnavailable
from hawk_endpoint_agent.modules.notetaker import NotetakerController


class _StubPolicy:
    def __init__(self, notetaker=None):
        self._nt = notetaker or {"action": "warn", "allow_eviction": True, "banner": True}

    def fail_secure_decision(self, *, surface, reason):
        return Decision(action=Action.WARN, control_mode=ControlMode.WARNED, reason=f"fail_secure:warn:{reason}", source="fail_secure_default")

    def notetaker_policy(self):
        return self._nt


class _StubClient:
    def __init__(self, response=None, raise_exc=None):
        self._response = response
        self._raise = raise_exc

    def evaluate_notetaker(self, payload):
        if self._raise:
            raise self._raise
        return self._response


def _banner(choice):
    return lambda **kw: BannerResult(shown=True, choice=choice)


class NotetakerDetectionTests(unittest.TestCase):
    def setUp(self):
        # eviction disabled so tests never terminate a real process
        self.config = AgentConfig(allow_process_termination=False)
        self.controller = NotetakerController(self.config, banner_fn=_banner(None))

    def test_detects_local_recorder_by_process(self):
        procs = [ProcessInfo(pid=4242, name="otter", cmdline="/Applications/Otter.app otter")]
        detected = self.controller.detect(
            processes=procs, connections=[], audio_candidates=[],
            meeting=MeetingContext(active=False, signals=[]),
        )
        self.assertEqual(len(detected), 1)
        self.assertEqual(detected[0].signature.id, "otter")
        # Local recorder listening to the laptop, not "in the room".
        self.assertTrue(detected[0].local_audio)

    def test_detects_by_domain_egress(self):
        conns = [Connection(pid=10, process_name="Google Chrome", remote_host="app.fireflies.ai", remote_port=443)]
        detected = self.controller.detect(
            processes=[], connections=conns, audio_candidates=[],
            meeting=MeetingContext(active=True, signals=["zoom"]),
        )
        self.assertTrue(any(d.signature.id == "fireflies" for d in detected))

    def test_benign_processes_do_not_match(self):
        procs = [ProcessInfo(pid=1, name="Finder"), ProcessInfo(pid=2, name="Safari")]
        detected = self.controller.detect(
            processes=procs, connections=[], audio_candidates=[],
            meeting=MeetingContext(active=False, signals=[]),
        )
        self.assertEqual(detected, [])

    def test_renderer_feature_flags_do_not_match_notetaker_names(self):
        procs = [
            ProcessInfo(
                pid=101,
                name="Claude Helper (Renderer)",
                cmdline='Claude Helper --capabilities={"chorusIn3p":{"status":"unavailable"}}',
            ),
            ProcessInfo(
                pid=102,
                name="Google Chrome Helper (Renderer)",
                cmdline="Google Chrome Helper --origin-trial-disabled-features=WebAssemblyCustomDescriptors",
            ),
        ]

        detected = self.controller.detect(
            processes=procs,
            connections=[],
            audio_candidates=[],
            meeting=MeetingContext(active=False, signals=[]),
        )

        self.assertEqual(detected, [])

    def test_notetaker_domain_must_be_the_host_or_a_subdomain(self):
        detected = self.controller.detect(
            processes=[],
            connections=[
                Connection(
                    pid=10,
                    process_name="Google Chrome",
                    remote_host="chorus.ai.attacker.example",
                    remote_port=443,
                )
            ],
            audio_candidates=[],
            meeting=MeetingContext(active=False, signals=[]),
        )

        self.assertEqual(detected, [])


class NotetakerDecisionTests(unittest.TestCase):
    def setUp(self):
        self.config = AgentConfig(allow_process_termination=False)
        self.controller = NotetakerController(self.config, banner_fn=_banner("Dismiss"))
        self.detected = self.controller.detect(
            processes=[ProcessInfo(pid=4242, name="fathom", cmdline="fathom")],
            connections=[], audio_candidates=[], meeting=MeetingContext(active=False, signals=[]),
        )[0]

    def test_server_decision_is_used(self):
        client = _StubClient(response={"decision": "block", "reason": "policy", "eviction_allowed": True, "banner": True, "auto_evict": True})
        decision = self.controller.evaluate(self.detected, client=client, policy=_StubPolicy())
        self.assertEqual(decision.action, Action.BLOCK)
        self.assertEqual(decision.source, "backend")

    def test_fail_secure_when_backend_unreachable(self):
        client = _StubClient(raise_exc=HawkUnavailable("down"))
        decision = self.controller.evaluate(self.detected, client=client, policy=_StubPolicy())
        # Even offline, a notetaker always warns with a banner.
        self.assertIn(decision.action, {Action.WARN, Action.BLOCK})
        self.assertTrue(decision.detail.get("banner"))
        self.assertTrue(str(decision.source).startswith("fail_secure"))


class NotetakerEnforcementTests(unittest.TestCase):
    def setUp(self):
        self.config = AgentConfig(
            agent_mode="enforce",
            notetaker_allow_eviction=True,
            allow_process_termination=False,
        )  # safe: no real kill
        self.detected = NotetakerController(self.config).detect(
            processes=[ProcessInfo(pid=4242, name="otter", cmdline="otter")],
            connections=[], audio_candidates=[], meeting=MeetingContext(active=False, signals=[]),
        )[0]

    def test_banner_shown_and_evict_flow_invoked(self):
        controller = NotetakerController(self.config, banner_fn=_banner("Evict notetaker"))
        decision = Decision(action=Action.WARN, control_mode=ControlMode.WARNED, reason="x",
                            detail={"eviction_allowed": True, "banner": True})
        outcome = controller.enforce(self.detected, decision)
        self.assertTrue(outcome.banner_shown)
        # eviction path attempted (termination disabled -> recorded, not performed)
        self.assertTrue(any(a["type"] == "terminate_process" for a in outcome.actions))

    def test_dismiss_does_not_evict(self):
        controller = NotetakerController(self.config, banner_fn=_banner("Dismiss"))
        decision = Decision(action=Action.WARN, control_mode=ControlMode.WARNED, reason="x",
                            detail={"eviction_allowed": True, "banner": True})
        outcome = controller.enforce(self.detected, decision)
        self.assertFalse(outcome.evicted)
        self.assertEqual([a for a in outcome.actions if a["type"] == "terminate_process"], [])

    def test_monitor_mode_never_banners_or_attempts_eviction(self):
        banners = []
        config = AgentConfig(
            agent_mode="monitor",
            notetaker_allow_eviction=True,
            allow_process_termination=False,
        )
        controller = NotetakerController(
            config,
            banner_fn=lambda **kwargs: banners.append(kwargs) or BannerResult(shown=True, choice="Evict notetaker"),
        )
        detected = controller.detect(
            processes=[ProcessInfo(pid=4242, name="Otter", cmdline="/Applications/Otter.app")],
            connections=[],
            audio_candidates=[],
            meeting=MeetingContext(active=False, signals=[]),
        )[0]
        decision = Decision(
            action=Action.BLOCK,
            control_mode=ControlMode.INLINE_PREVENTED,
            reason="policy",
            detail={"eviction_allowed": True, "banner": True, "auto_evict": True},
        )

        outcome = controller.enforce(detected, decision)

        self.assertEqual(banners, [])
        self.assertFalse(outcome.banner_shown)
        self.assertFalse(outcome.evicted)
        self.assertEqual(outcome.actions, [])

    def test_repeated_detection_is_bannered_once_within_cooldown(self):
        banners = []
        controller = NotetakerController(
            self.config,
            banner_fn=lambda **kwargs: banners.append(kwargs) or BannerResult(shown=True, choice="Dismiss"),
        )
        decision = Decision(
            action=Action.WARN,
            control_mode=ControlMode.WARNED,
            reason="policy",
            detail={"eviction_allowed": True, "banner": True},
        )

        controller.enforce(self.detected, decision)
        controller.enforce(self.detected, decision)

        self.assertEqual(len(banners), 1)

    def test_banner_false_suppresses_presentation_but_still_auto_evicts(self):
        banners = []
        controller = NotetakerController(
            self.config,
            banner_fn=lambda **kwargs: banners.append(kwargs) or BannerResult(shown=True, choice="Dismiss"),
        )
        decision = Decision(
            action=Action.WARN,
            control_mode=ControlMode.WARNED,
            reason="policy",
            detail={"eviction_allowed": True, "banner": False, "auto_evict": True},
        )

        outcome = controller.enforce(self.detected, decision)

        self.assertEqual(banners, [])
        self.assertFalse(outcome.banner_shown)
        self.assertTrue(any(action["type"] == "terminate_process" for action in outcome.actions))

    def test_banner_false_does_not_consume_banner_cooldown(self):
        banners = []
        controller = NotetakerController(
            self.config,
            banner_fn=lambda **kwargs: banners.append(kwargs) or BannerResult(shown=True, choice="Dismiss"),
        )

        controller.enforce(
            self.detected,
            Decision(
                action=Action.WARN,
                control_mode=ControlMode.WARNED,
                reason="silent_policy",
                detail={"eviction_allowed": True, "banner": False},
            ),
        )
        outcome = controller.enforce(
            self.detected,
            Decision(
                action=Action.WARN,
                control_mode=ControlMode.WARNED,
                reason="visible_policy",
                detail={"eviction_allowed": True, "banner": True},
            ),
        )

        self.assertEqual(len(banners), 1)
        self.assertTrue(outcome.banner_shown)

    def test_banner_false_still_plans_blocking_platform_action(self):
        banners = []
        controller = NotetakerController(
            self.config,
            banner_fn=lambda **kwargs: banners.append(kwargs) or BannerResult(shown=True, choice="Dismiss"),
        )
        detected = controller.detect(
            processes=[ProcessInfo(pid=0, name="Read.ai", cmdline="Read.ai meeting bot")],
            connections=[],
            audio_candidates=[],
            meeting=MeetingContext(active=True, signals=["teams"]),
        )[0]
        decision = Decision(
            action=Action.BLOCK,
            control_mode=ControlMode.INLINE_PREVENTED,
            reason="policy",
            detail={"eviction_allowed": True, "banner": False},
        )

        outcome = controller.enforce(detected, decision)

        self.assertEqual(banners, [])
        self.assertFalse(outcome.banner_shown)
        self.assertTrue(any(action["type"] == "remove_meeting_participant" for action in outcome.actions))

    def test_allow_without_banner_instruction_stays_silent(self):
        banners = []
        controller = NotetakerController(
            self.config,
            banner_fn=lambda **kwargs: banners.append(kwargs) or BannerResult(shown=True, choice="Dismiss"),
        )

        outcome = controller.enforce(
            self.detected,
            Decision(action=Action.ALLOW, control_mode=ControlMode.MONITOR_WOULD_ALLOW, reason="policy"),
        )

        self.assertEqual(banners, [])
        self.assertFalse(outcome.banner_shown)


class AgentConfigSafetyDefaultsTests(unittest.TestCase):
    def test_process_eviction_is_opt_in(self):
        config = AgentConfig()

        self.assertFalse(config.notetaker_allow_eviction)
        self.assertFalse(config.allow_process_termination)


if __name__ == "__main__":
    unittest.main()
