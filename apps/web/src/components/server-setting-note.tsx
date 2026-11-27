"use client";

import { SET_BY_SERVER } from "@/lib/settings-console";

/**
 * Beside a setting of the whole server, for a workspace admin who may read it but not change it: only the server's
 * administrators (the owners and admins of its first workspace) change it (app/core/installation.py). Nothing is shown
 * to them, or while it is not yet known.
 */
export function ServerSettingNote({ readOnly }: { readOnly: boolean }) {
  if (!readOnly) return null;
  return (
    <div className="callout" role="note" data-ui="server-setting-note">
      <b>{SET_BY_SERVER}</b> This setting applies to every workspace on this server, so it is shown read-only here.
    </div>
  );
}
