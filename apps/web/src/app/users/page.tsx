import { AppShell } from "@/components/app-shell";
import { PageHeader } from "@/components/page-header";
import { UserVisibilityWorkspace } from "@/components/users/user-visibility-workspace";

export default function UsersPage() {
  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="Assets / user context"
          title="Users"
          description="Tenant-scoped AI activity, policy context, prompts, actions, and evidence. Full source content is never part of the ordinary view."
        />
        <UserVisibilityWorkspace />
      </div>
    </AppShell>
  );
}
