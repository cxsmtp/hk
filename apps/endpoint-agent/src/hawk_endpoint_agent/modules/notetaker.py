"""AI notetaker control.

Detects AI notetakers on the endpoint — whether they join a call as a participant
bot *or* run locally and listen to the laptop's audio without being "in the room" —
raises a warning banner, and offers to evict them. Eviction of a local recorder is
process termination (which stops its capture); for participant bots and SaaS
recorders it is complemented by capability-gated mic/egress controls.

The verdict (warn / block / allow, and whether eviction is offered) is decided by
the backend so posture never drifts from central policy. If the backend is
unreachable, the fail-secure policy default applies (warn, with a banner).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Any, Callable

from ..catalog import NotetakerCategory, NotetakerSignature, match_notetaker
from ..collectors.audio import AudioCandidate
from ..collectors.base import Connection, ProcessInfo
from ..collectors.meetings import MeetingContext
from ..config import AgentConfig
from ..decision import Action, ControlMode, Decision
from ..enforcers.audio_control import AudioControl
from ..enforcers.banner import BannerResult, show_banner
from ..enforcers.meeting_platform_control import normalize_meeting_platforms, plan_notetaker_removal
from ..enforcers.network_control import NetworkControl
from ..enforcers.process_control import ProcessControl
from ..hawk_client import HawkClient, HawkApiError, HawkUnavailable
from ..policy import PolicyStore
from ..signals import Signal, SignalKind

_EVICT_LABEL = "Evict notetaker"
_DISMISS_LABEL = "Dismiss"
_BANNER_COOLDOWN_SECONDS = 15 * 60


@dataclass
class DetectedNotetaker:
    signature: NotetakerSignature
    pids: list[int] = field(default_factory=list)
    process_names: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    audio_signal_bases: list[str] = field(default_factory=list)
    meeting_platforms: list[str] = field(default_factory=list)
    in_meeting: bool = False
    local_audio: bool = False  # listening to laptop audio rather than joined to the call

    def to_signal(self) -> Signal:
        return Signal(
            kind=SignalKind.NOTETAKER,
            subject=self.signature.id,
            attributes={
                "name": self.signature.name,
                "vendor": self.signature.vendor,
                "category": self.signature.category,
                "pids": self.pids,
                "process_names": sorted(set(self.process_names)),
                "domains": sorted(set(self.domains)),
                "audio_signal_bases": sorted(set(self.audio_signal_bases)),
                "meeting_platforms": sorted(set(self.meeting_platforms)),
                "in_meeting": self.in_meeting,
                "local_audio_capture": self.local_audio,
            },
            confidence=0.95 if self.pids else 0.6,
        )

    def to_telemetry_event(
        self,
        config: AgentConfig,
        *,
        outcome: NotetakerOutcome | None = None,
    ) -> dict[str, Any]:
        """Return a browser-telemetry-compatible event for the local API.

        Endpoint-local recorders are intentionally reported as endpoint-audio
        signals, not visible meeting participants. Hawk can warn, terminate the
        local process where allowed, or request external mic/egress controls; it
        must not claim it removed an invisible bot from Teams/Meet.
        """
        provider = self.signature.id
        label = self.signature.name
        domains = sorted(set([*self.domains, *self.signature.domains]))
        domain = domains[0] if domains else "endpoint.local"
        control_applied = bool(outcome and outcome.evicted)
        mic_capability = AudioControl(mdm_backed=config.allow_mic_revocation).capability()
        mic_action = next(
            (
                action
                for action in (outcome.actions if outcome else [])
                if action.get("type") == "revoke_mic"
            ),
            None,
        )
        mic_revocation_performed = bool(mic_action and mic_action.get("performed"))
        microphone_control_mode = (
            ControlMode.EXTERNAL_ACTION_TRIGGERED
            if mic_revocation_performed
            else ControlMode.EXTERNAL_REQUIRED
        )
        platform_action_types = {
            "remove_meeting_participant",
            "disable_meeting_transcription",
            "disable_meeting_recording",
            "harden_meeting_admission",
        }
        platform_actions = [
            action
            for action in (outcome.actions if outcome else [])
            if action.get("type") in platform_action_types
        ]
        platform_action_triggered = any(bool(action.get("performed")) for action in platform_actions)
        meeting_platform_control_mode = (
            ControlMode.EXTERNAL_ACTION_TRIGGERED
            if platform_action_triggered
            else ControlMode.EXTERNAL_REQUIRED
            if platform_actions
            else ControlMode.TELEMETRY_ONLY
        )
        meeting_platforms = sorted(
            {
                *self.meeting_platforms,
                *[
                    str(action.get("platform"))
                    for action in platform_actions
                    if action.get("platform")
                ],
            }
        )
        meeting_platform_provider_paths = sorted(
            {
                str(action.get("provider_control_path"))
                for action in platform_actions
                if action.get("provider_control_path")
            }
        )
        meeting_platform_operator_steps = [
            step
            for action in platform_actions
            if not action.get("performed")
            for step in action.get("operator_steps", [])
        ]
        if control_applied:
            event_type = "device_audio_notetaker_control_applied"
            action_taken = "block:device_audio_notetaker_control_applied"
            control_mode = ControlMode.EXTERNAL_ACTION_TRIGGERED
        else:
            event_type = "device_audio_notetaker_detected" if self.local_audio else "meeting_ai_notetaker_detected"
            action_taken = "warn:device_audio_notetaker_detected" if self.local_audio else "warn:meeting_ai_notetaker_detected"
            control_mode = (
                str(outcome.decision.control_mode)
                if outcome and outcome.decision.control_mode
                else ControlMode.EXTERNAL_REQUIRED
            )
            if self.local_audio:
                control_mode = ControlMode.EXTERNAL_REQUIRED

        meeting_surface = "endpoint_audio" if self.local_audio else "endpoint_meeting"
        meeting_signal_source = "endpoint_audio" if self.local_audio else "endpoint_agent"
        participant_visible = False if self.local_audio else bool(self.in_meeting)
        audio_signal_bases = sorted(set(self.audio_signal_bases)) or (
            ["known_recorder_process"] if self.local_audio else []
        )
        endpoint_audio_signal_basis = ",".join(audio_signal_bases) if audio_signal_bases else "not_applicable"
        input_signal_types = sorted(
            {
                "meeting_ai_notetaker_endpoint_audio" if self.local_audio else "meeting_ai_notetaker_visible",
                f"notetaker_provider:{provider}",
                f"notetaker_label:{label}",
                f"participant_visible:{str(participant_visible).lower()}",
                f"meeting_signal_source:{meeting_signal_source}",
                f"control_mode:{control_mode}",
                *(
                    [f"meeting_platform_control:{meeting_platform_control_mode}"]
                    if platform_actions
                    else []
                ),
                *[f"meeting_platform_provider:{path}" for path in meeting_platform_provider_paths],
                *[f"endpoint_audio_basis:{basis}" for basis in audio_signal_bases],
            }
        )
        return {
            "browser": "endpoint-agent",
            "extension_name": "Hawk Endpoint Agent",
            "extension_version": "endpoint-agent",
            "endpoint_id": config.endpoint_id,
            "hostname": config.hostname,
            "os_type": config.os_type,
            "os_version": config.os_version,
            "event_type": event_type,
            "domain": domain,
            "url": f"endpoint://{config.endpoint_id or 'unknown-endpoint'}/notetaker/{provider}",
            "page_title": "Endpoint AI notetaker control",
            "action_taken": action_taken,
            "source_surface": "endpoint-agent",
            "meeting_surface": meeting_surface,
            "notetaker_provider": provider,
            "notetaker_label": label,
            "participant_visible": participant_visible,
            "meeting_signal_source": meeting_signal_source,
            "control_mode": control_mode,
            "raw_audio_captured": False,
            "audio_content_captured": False,
            "endpoint_audio_signal_basis": endpoint_audio_signal_basis,
            "microphone_permission_state": "unknown",
            "microphone_revocation_available": bool(mic_capability.get("can_revoke_mic")),
            "microphone_control_authority": mic_capability.get("control_authority"),
            "microphone_control_mode": microphone_control_mode,
            "microphone_control_requirements": mic_capability.get("control_requirements") or [],
            "meeting_platforms": meeting_platforms,
            "meeting_platform_control_available": platform_action_triggered,
            "meeting_platform_control_mode": meeting_platform_control_mode,
            "meeting_platform_provider_paths": meeting_platform_provider_paths,
            "meeting_platform_operator_steps": meeting_platform_operator_steps,
            "local_process_control_available": bool(config.allow_process_termination),
            "input_signal_types": input_signal_types,
            "prompt_preview_redacted": (
                "Local AI notetaker process detected from endpoint process/audio heuristics; no raw audio captured."
                if self.local_audio
                else "AI notetaker detected from endpoint meeting context; no raw audio captured."
            ),
        }


@dataclass
class NotetakerOutcome:
    notetaker: str
    decision: Decision
    banner_shown: bool = False
    evicted: bool = False
    actions: list[dict[str, Any]] = field(default_factory=list)


class NotetakerController:
    def __init__(
        self,
        config: AgentConfig,
        *,
        banner_fn: Callable[..., BannerResult] = show_banner,
    ) -> None:
        self._config = config
        self._banner_fn = banner_fn
        self._proc = ProcessControl(enabled=config.allow_process_termination)
        self._audio = AudioControl(mdm_backed=config.allow_mic_revocation)
        self._net = NetworkControl(enabled=config.allow_network_block)
        self._last_banner_at: dict[str, float] = {}

    # -- detection ---------------------------------------------------------
    def detect(
        self,
        *,
        processes: list[ProcessInfo],
        connections: list[Connection],
        audio_candidates: list[AudioCandidate],
        meeting: MeetingContext,
    ) -> list[DetectedNotetaker]:
        detected: dict[str, DetectedNotetaker] = {}
        meeting_platforms = normalize_meeting_platforms(meeting.signals)

        def _entry(sig: NotetakerSignature) -> DetectedNotetaker:
            if sig.id not in detected:
                detected[sig.id] = DetectedNotetaker(
                    signature=sig,
                    in_meeting=meeting.active,
                    meeting_platforms=meeting_platforms,
                )
            return detected[sig.id]

        for proc in processes:
            for sig in match_notetaker(process_name=f"{proc.name} {proc.cmdline}"):
                entry = _entry(sig)
                if proc.pid and proc.pid not in entry.pids:
                    entry.pids.append(proc.pid)
                entry.process_names.append(proc.name)

        for conn in connections:
            for sig in match_notetaker(domain=conn.remote_host):
                entry = _entry(sig)
                entry.domains.append(conn.remote_host)

        candidates_by_pid: dict[int, list[AudioCandidate]] = {}
        for candidate in audio_candidates:
            candidates_by_pid.setdefault(candidate.pid, []).append(candidate)
        for entry in detected.values():
            # A local recorder, or a notetaker present on-device but no meeting is
            # active, is "listening to the laptop" rather than a room participant.
            is_local_recorder = entry.signature.category == NotetakerCategory.LOCAL_RECORDER
            matched_candidates = [candidate for pid in entry.pids for candidate in candidates_by_pid.get(pid, [])]
            has_capturing_pid = bool(matched_candidates)
            entry.audio_signal_bases.extend(candidate.basis for candidate in matched_candidates)
            if is_local_recorder and not entry.audio_signal_bases:
                entry.audio_signal_bases.append("known_recorder_process")
            entry.local_audio = bool(is_local_recorder or has_capturing_pid or (entry.pids and not entry.in_meeting))
        return list(detected.values())

    # -- decision (server-authoritative) ----------------------------------
    def evaluate(self, detected: DetectedNotetaker, *, client: HawkClient, policy: PolicyStore) -> Decision:
        signal = detected.to_signal()
        payload = {
            "endpoint_id": self._config.endpoint_id,
            "hostname": self._config.hostname,
            "notetaker": signal.subject,
            "signal": signal.as_dict(),
        }
        try:
            response = client.evaluate_notetaker(payload)
        except (HawkUnavailable, HawkApiError):
            base = policy.fail_secure_decision(surface="notetaker", reason="backend_unreachable")
            np = policy.notetaker_policy()
            # Even under fail-secure we always surface a banner for a notetaker.
            action = str(np.get("action") or base.action or Action.WARN)
            return Decision(
                action=action if action in {Action.ALLOW, Action.WARN, Action.BLOCK} else Action.WARN,
                control_mode=ControlMode.WARNED,
                reason=base.reason,
                source=base.source,
                threat_types=["ai_notetaker"],
                detail={"eviction_allowed": bool(np.get("allow_eviction", True)), "banner": True},
            )
        action = str(response.get("decision") or response.get("action") or Action.WARN).lower()
        if action not in {Action.ALLOW, Action.WARN, Action.BLOCK, Action.HOLD}:
            action = Action.WARN
        return Decision(
            action=action,
            control_mode=ControlMode.WARNED if action == Action.WARN else ControlMode.INLINE_PREVENTED,
            reason=str(response.get("reason") or "notetaker_policy"),
            source="backend",
            threat_types=["ai_notetaker"],
            evidence_ref=response.get("evidence_node_id") or response.get("audit_log_id"),
            detail={
                "eviction_allowed": bool(response.get("eviction_allowed", True)),
                "banner": bool(response.get("banner", True)),
                "auto_evict": bool(response.get("auto_evict", False)),
            },
        )

    # -- enforcement -------------------------------------------------------
    def enforce(
        self,
        detected: DetectedNotetaker,
        decision: Decision,
        *,
        mode: str | None = None,
    ) -> NotetakerOutcome:
        outcome = NotetakerOutcome(notetaker=detected.signature.name, decision=decision)
        active_mode = mode or self._config.agent_mode
        if active_mode != "enforce":
            decision.enforced = False
            decision.detail = {**decision.detail, "would_action": decision.action, "endpoint_mode": active_mode}
            if decision.action in {Action.BLOCK, Action.REDACT}:
                decision.control_mode = ControlMode.MONITOR_WOULD_BLOCK
            elif decision.action == Action.HOLD:
                decision.control_mode = ControlMode.MONITOR_WOULD_REVIEW
            elif decision.action == Action.WARN:
                decision.control_mode = ControlMode.MONITOR_WOULD_WARN
            else:
                decision.control_mode = ControlMode.MONITOR_WOULD_ALLOW
            return outcome

        eviction_allowed = bool(decision.detail.get("eviction_allowed", True)) and self._config.notetaker_allow_eviction
        auto_evict = bool(decision.detail.get("auto_evict", False))
        should_evict = auto_evict or (decision.is_blocking and not detected.local_audio)
        banner_enabled = bool(decision.detail.get("banner", decision.action != Action.ALLOW))

        if banner_enabled:
            now = time.monotonic()
            last_banner_at = self._last_banner_at.get(detected.signature.id)
            outside_cooldown = last_banner_at is None or now - last_banner_at >= _BANNER_COOLDOWN_SECONDS
            if outside_cooldown:
                self._last_banner_at[detected.signature.id] = now

                buttons = [_DISMISS_LABEL]
                if eviction_allowed:
                    buttons.append(_EVICT_LABEL)

                where = "listening to this laptop's audio" if detected.local_audio else "in your meeting"
                message = (
                    f"{detected.signature.name} (AI notetaker) was detected {where}. "
                    "This recording may capture confidential discussion."
                )
                result = self._banner_fn(
                    title="Hawk — AI notetaker detected",
                    message=message,
                    actions=buttons,
                    default_action=_EVICT_LABEL if (eviction_allowed and decision.is_blocking) else _DISMISS_LABEL,
                )
                outcome.banner_shown = result.shown or result.headless
                if result.choice == _EVICT_LABEL:
                    should_evict = True

        if should_evict and eviction_allowed:
            outcome.evicted = self._evict(detected, outcome)
            if outcome.evicted:
                outcome.decision.enforced = True
                outcome.decision.control_mode = ControlMode.EXTERNAL_ACTION_TRIGGERED
            elif outcome.decision.is_blocking:
                outcome.decision.control_mode = ControlMode.EXTERNAL_REQUIRED
        return outcome

    def _evict(self, detected: DetectedNotetaker, outcome: NotetakerOutcome) -> bool:
        evicted_any = False
        for pid in detected.pids:
            result = self._proc.terminate(pid)
            outcome.actions.append({"type": "terminate_process", "pid": pid, **result.__dict__})
            evicted_any = evicted_any or result.performed

        mic = self._audio.revoke(process_name=detected.signature.name)
        outcome.actions.append({"type": "revoke_mic", **mic.__dict__})

        if detected.domains or detected.signature.domains:
            domains = sorted(set([*detected.domains, *detected.signature.domains]))
            net = self._net.block_domains(domains)
            outcome.actions.append({"type": "block_egress", **net.__dict__})
        if detected.in_meeting and not detected.local_audio:
            outcome.actions.extend(plan_notetaker_removal(detected.meeting_platforms, detected.signature.name))
        return evicted_any
