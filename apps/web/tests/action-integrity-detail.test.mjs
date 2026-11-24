import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { actionDetailHref, actionDetailApiPath } from "../src/lib/action-integrity-links.mjs";
import { buildActionIntegrityViewModel } from "../src/lib/action-integrity-view-model.mjs";

assert.equal(actionDetailHref("event/unsafe"), null);
assert.equal(actionDetailHref("event-1"), "/runtime-intelligence/action-trace/event-1");
assert.equal(actionDetailApiPath("event-1"), "/action-integrity/actions/event-1");
assert.equal(actionDetailHref("event%2Fkept-literal"), "/runtime-intelligence/action-trace/event%252Fkept-literal");

const view = buildActionIntegrityViewModel({ identity: { runtime_event_id: "event-1" } });
assert.equal(view.browserHref, "/runtime-intelligence/action-trace/event-1");
assert.equal(view.apiPath, "/action-integrity/actions/event-1");

const actionTrace = readFileSync("src/app/runtime-intelligence/action-trace/[id]/page.tsx", "utf8");
assert.doesNotMatch(actionTrace, /decodeURIComponent\(String\(params\.id/);
