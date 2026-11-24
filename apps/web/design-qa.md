# Hawk Akto-clarity UI design QA

QA date: 2026-08-10

Scope: shared platform presentation grammar, Agent Governance, Policy Control Room, policy composer, and advanced-policy progressive disclosure.

Preview: `http://localhost:3001/protect`

API: `http://127.0.0.1:8000`

Browser: Google Chrome

## Visual sources

- Akto identity violations: `docs/research/akto-ux-audit-2026-08-10/screenshots/04-ai-agent-identity-demo-03-all-violations.png`
- Akto policy composer: `docs/research/akto-ux-audit-2026-08-10/screenshots/04-ai-agent-identity-demo-07-create-policy.png`
- Approved Hawk design specification: `docs/superpowers/specs/2026-08-10-hawk-progressive-disclosure-ui-design.md`
- Implementation plan: `docs/superpowers/plans/2026-08-10-akto-platform-clarity-extension.md`

## Rendered implementation evidence

- Agent Governance desktop: `artifacts/product-design/akto-platform-clarity-final/hawk-ai-iam-truthful-unavailable.png`
- Agent Governance violations: `artifacts/product-design/akto-platform-clarity-final/hawk-ai-iam-violations-final-top.png`
- Agent Governance mobile: `artifacts/product-design/akto-platform-clarity-final/hawk-ai-iam-mobile-final.png`
- Policy Control Room: `artifacts/product-design/akto-platform-clarity-final/hawk-protect-truthful-unavailable.png`
- Policy composer: `artifacts/product-design/akto-platform-clarity-final/hawk-policy-composer.png`
- Source and implementation comparison: `artifacts/product-design/akto-platform-clarity-final/akto-hawk-final-comparison.png`

## Side-by-side assessment

The Akto identity and policy references were inspected beside the Hawk implementation in one comparison image. Hawk now follows the reference's useful operational patterns—compact hierarchy, list-first investigation, clear views, connected metrics, direct filters, visible runtime status, and an overlaid policy composer—while retaining Hawk's dark control-plane identity and evidence language.

The Agent Governance violations view adds real Recharts area and donut visualizations when enforcement data exists. When the API cannot be authenticated, those panels explicitly say the data is unavailable; they do not draw fabricated trends. The Policy Control Room similarly renders Unknown instead of zero when its initial load fails.

## Interaction and responsive QA

- Agent Governance switches between Identities and Violations without route loss.
- Policy links connect directly to `/protect`.
- Create policy opens a labelled wide drawer with Intent, Scope, Action, Validate, and Publish steps.
- The composer preserves the existing immutable publish APIs and requires enforcement confirmation for approval/block decisions.
- Policy preview uses runtime-equivalent exact selectors for users, agents, surfaces, tools, and action types; missing event fields are Unknown rather than a match.
- Advanced policy tuning, scoped rules, and pack creation are collapsed behind explicit disclosures on `/policies`.
- Desktop page width: `scrollWidth === clientWidth` at 1200 px.
- Mobile page width: `scrollWidth === clientWidth` at 390 px.
- Mobile identity metrics render as a compact 2 × 2 strip.
- Chrome console errors after the final Agent Governance and Protect pass: none.

## Comparison fixes

1. P1 truthfulness: failed Agent Governance and Protect loads appeared as zero. Fixed with explicit loading, stale, unavailable, and Unknown presentation in the two mission-critical workspaces.
2. P1 policy preview: fuzzy substring matching could overstate observed impact. Fixed with exact runtime-like matching and separate people, agent, tool, surface, and action selectors.
3. P2 workflow density: policy creation displaced the policy list. Fixed with a list-first control room and wide drawer composer.
4. P2 identity clarity: violations were buried inside per-agent detail. Fixed with first-class Identities, Violations, and Policies views plus drill-down.
5. P2 visual hierarchy: violations lacked Akto-style visual analysis. Fixed with evidence-backed trend and decision-distribution charts and conservative unavailable states.
6. P2 mobile density: four identity metrics stacked vertically. Fixed with a 2 × 2 responsive strip and no horizontal clipping.

No P0, P1, or P2 findings remain in this QA scope.

## Verification evidence

- `node --test tests/*.test.mjs`: 127 passed, 0 failed.
- `npx tsc --noEmit`: passed.
- `npm run lint`: passed with zero warnings.
- `npm run build`: passed; 47 application routes generated.
- Final Chrome console error log: empty.
- Pre-build caches were moved, not deleted. The final pre-build cache is `apps/web/.next.pre-truthful-load-states-20260810T144212+0400`.

## Truthful remaining platform migration

The shared page header, connected KPI strip, flat operational sections, lifecycle workspace headers, specialist disclosures, and wide drawer capability now improve their existing consumers across the platform. The following legacy dense pages still need the same explicit unavailable/stale request-state migration before the whole platform can be declared complete: Interaction Security, Simulations, Auditor, Discovery Findings, and Integrations. That work is not claimed as complete in this QA scope.

The local API and UI are running. The browser's current saved API token is invalid, so the final screenshots intentionally show Unknown/unavailable states rather than invented data.

final result: passed
