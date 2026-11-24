const validRuntimeEventId = (value) =>
  typeof value === "string" && value.length > 0 && value.length <= 128 && !value.includes("/");

export const actionDetailHref = (runtimeEventId) =>
  validRuntimeEventId(runtimeEventId)
    ? `/runtime-intelligence/action-trace/${encodeURIComponent(runtimeEventId)}`
    : null;

export const actionDetailApiPath = (runtimeEventId) =>
  validRuntimeEventId(runtimeEventId)
    ? `/action-integrity/actions/${encodeURIComponent(runtimeEventId)}`
    : null;
