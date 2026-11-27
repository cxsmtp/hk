import { redirect } from "next/navigation";

import { SETTINGS_ENTRY } from "@/lib/settings-menu";

/** /settings typed by hand opens Settings where the main menu does: People, which every role may see. */
export default function SettingsIndexPage() {
  redirect(SETTINGS_ENTRY.href);
}
