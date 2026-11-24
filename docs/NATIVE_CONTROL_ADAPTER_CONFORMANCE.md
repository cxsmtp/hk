# Native Control Adapter Conformance

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


Run:

```text
cd apps/api
.venv/bin/python -m pytest tests/test_native_control_adapter_foundation.py -q
```

`NativeControlAdapterConformanceSuite().run(adapter)` checks descriptor/manifest binding, strict claims, version support, tenant/integration isolation, normalized event identity, raw-payload boundary, safe validation, block translation, configuration preservation, rollback/uninstall, structured blind spots, and absence of arbitrary execution methods.

The reference results are intentionally synthetic:

- `reference.native-bound`: A5; pre-action tool blocking, parameter/target binding, and externally verified synthetic execution observation.
- `reference.middleware`: A3; blocking and tool visibility without independent post-execution verification.
- `reference.observe-only`: A2; observation only.
- `reference.adversarial-false-a4`: rejected because it claims bound parameters without the required normalized proof.

Mandatory selector proofs:

- A5 is selected for a requirement demanding pre-execution parameter/target binding and post-execution verification.
- If A5 becomes unhealthy, Hawk returns `CONTROL_REQUIREMENT_UNSATISFIED`; it does not silently fall back to A3/A2.
- For an A2 observation-only requirement, the least-friction eligible verified point may be selected.

Production CI must call `require_adapter_conformance(adapter)`. Exemptions are not automatic; a missing behavior must become an explicit manifest limitation and capability reduction before review.
