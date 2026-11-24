export function buildActionIntegrityViewModel(detail: { identity?: { runtime_event_id?: string } }): {
  detail: unknown;
  apiPath: string | null;
  browserHref: string | null;
};
