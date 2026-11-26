import "../ftr-settings.css";

import { AppShell } from "@/components/app-shell";
import { GuideIndex, GuidePage } from "@/components/guide/guide-view";

/**
 * Settings → Guide: the administrator's guide inside the console (lib/guide), one page per topic. Its first page says
 * for whom it is and lists the topics. For everyone signed in; what only owners and admins can do is marked.
 */
export default function GuideIndexPage() {
  return (
    <AppShell>
      <GuidePage>
        <GuideIndex />
      </GuidePage>
    </AppShell>
  );
}
