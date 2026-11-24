import { actionDetailApiPath, actionDetailHref } from "./action-integrity-links.mjs";

export const buildActionIntegrityViewModel = (detail) => {
  const runtimeEventId = detail?.identity?.runtime_event_id;
  return {
    detail,
    apiPath: actionDetailApiPath(runtimeEventId),
    browserHref: actionDetailHref(runtimeEventId),
  };
};
