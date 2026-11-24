# Codex local signing repair — 1 October 2026

Status: local installation and synthetic callback checks passed. Hook activation and real-client acceptance remain pending. This is experimental telemetry-only operation, not repository enforcement or production approval.

## Cause

The existing bank-profile hook rejected the ad-hoc-signed device helper before contacting Hawk. API readiness was not the failing condition. The previous generic failure text hid the device-key error. The bank profile correctly continues rejecting unsigned/ad-hoc helpers.

## Applied repair

After explicit local-profile deployment approval, installed a separately packaged Codex 0.154.0 development profile against the isolated loopback API on port 8002. The profile accepts the reviewed, hash-pinned ad-hoc helper and uses the existing hardware-backed key after a successful signing proof. No key was created. The original bank enrollment/configuration was preserved.

Replaced all 12 Hawk hook command definitions with the durable reviewed helper and separate local-test configuration. Unrelated hook definitions and Codex settings were preserved. No hook trust or activation operation was performed. The user had disabled hooks; that app setting was not independently inspected.

The local credential and policy freshness expire at **2026-10-02 07:29:15 UTC / 11:29:15 Asia/Dubai**. Automatic renewal is not implemented by this operator.

## Verification

- 76 focused signing/runtime tests passed.
- 49 local operator tests passed, including the 9-case correction subset.
- Clean package has 122 files including its manifest; exact bytes were checked before deployment and imports.
- One synthetic benign pre-tool callback was hardware-key signed, authenticated by Hawk, and returned Allow with enforced=false and control_mode=telemetry_only.
- Evidence ID: `15110835-9010-444b-9c89-b328ac256dbe`. Tenant, integration, and callback event hash matched.
- Missing-key and unavailable-API probes both returned Codex PreToolUse denial. These were manual helper invocations, not proof that a real Codex client obeyed them.
- Readback confirmed 12 updated Hawk commands, unrelated hooks preserved, bank config unchanged, and Codex settings unchanged.
- No actual tool or model action was executed by these probes. Main services and database schema were not changed.

## Still required

The user must review/trust the changed definitions and enable hooks using Codex's own controls. Then real Codex CLI and desktop activity must be verified separately. Read/Edit/Commit/Pull/Push enforcement, policy-change causality, restart/reconnect, revocation, managed distribution, renewal, and production acceptance are not established by this repair. The development monitor must not be presented as active repository protection.

The old hook file is backed up in the private local-test backup directory recorded by `~/.hawk/native-control/codex-local-test.operator.json`. Do not blindly restore old commands: they still point at the bank configuration that rejects this unsigned helper. Disable hooks before any controlled rollback.

See `verification.json` for the sanitized result and artifact fingerprints. No credentials, key tags, public key material, signatures, or prompt content are included.
