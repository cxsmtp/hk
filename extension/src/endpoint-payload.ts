function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function text(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function recordAt(value: Record<string, unknown>, key: string): Record<string, unknown> {
  const nested = value[key];
  return isRecord(nested) ? nested : {};
}

function firstText(...values: unknown[]): string | undefined {
  for (const value of values) {
    const candidate = text(value);
    if (candidate) return candidate;
  }
  return undefined;
}

function isPlaceholderIdentity(value: unknown): boolean {
  const token = String(value || "").trim().toLowerCase();
  return ["", "unknown", "desktop-native", "desktop_native", "native", "endpoint-agent", "endpoint_agent"].includes(token);
}

export function endpointInteractionPayload(payload: Record<string, unknown>): Record<string, unknown> {
  const legacy = recordAt(payload, "legacy_interaction_payload");
  const source = Object.keys(legacy).length ? legacy : payload;
  const aiAction = recordAt(payload, "ai_action");
  const surface = recordAt(aiAction, "surface");
  const context = recordAt(payload, "context");
  const pageContext = recordAt(context, "page_context");
  const appContext = recordAt(context, "app_context");
  const appProfile = recordAt(payload, "app_profile");

  const domain = firstText(
    source.domain,
    payload.domain,
    surface.domain,
    pageContext.domain,
    appContext.app_domain,
    appProfile.domain,
  );
  const url = firstText(
    source.url,
    payload.url,
    surface.url,
    pageContext.url,
  );
  const application = firstText(
    source.application,
    source.ai_app,
    payload.application,
    payload.ai_app,
    surface.application,
    appContext.app_name,
    appContext.app_id,
    appProfile.name,
    domain,
  );
  const sourceSurface = firstText(
    source.source_surface,
    payload.source_surface,
    surface.source_surface,
    "browser",
  );
  const pageTitle = firstText(source.page_title, payload.page_title, pageContext.title);
  const browserType = firstText(source.browser_type, payload.browser_type, payload.browser, "chrome");

  const appIdentity = !isPlaceholderIdentity(domain) ? domain : application;

  return {
    prompt: firstText(source.raw_prompt, source.prompt_preview_redacted, payload.raw_prompt, payload.prompt_preview_redacted) || "",
    ai_system_id: firstText(source.ai_system_id, payload.ai_system_id),
    domain,
    url,
    application,
    ai_app: appIdentity,
    source_surface: sourceSurface,
    browser_type: browserType,
    page_title: pageTitle,
    context_summary: firstText(source.prompt_preview_redacted, payload.prompt_preview_redacted),
  };
}

export function endpointDataTransferPayload(payload: Record<string, unknown>): Record<string, unknown> {
  const copy = recordAt(payload, "copy_context");
  const paste = recordAt(payload, "paste_context");
  return {
    copied_text: firstText(copy.copied_text_preview_redacted, copy.copied_text_hash) || "",
    source_domain: firstText(copy.source_domain),
    destination_domain: firstText(paste.destination_domain),
    destination_app: firstText(paste.destination_app_name),
  };
}
