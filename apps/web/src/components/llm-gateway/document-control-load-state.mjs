function listState(settled) {
  if (settled.status === "rejected") return { status: "error", items: [] };
  const items = settled.value?.items || [];
  return { status: items.length ? "ready" : "empty", items };
}

export async function loadGatewayChoiceLists(listAISystems, listPolicyPacks) {
  const [systemsResult, packsResult] = await Promise.allSettled([
    listAISystems(),
    listPolicyPacks(),
  ]);
  return {
    systems: listState(systemsResult),
    packs: listState(packsResult),
  };
}

export async function loadGatewayPolicyVersions(listPolicyVersions, packId) {
  if (!packId) return { status: "empty", items: [] };
  try {
    const payload = await listPolicyVersions(packId);
    const items = [...(payload?.items || [])].sort(
      (a, b) => Date.parse(b.created_at) - Date.parse(a.created_at),
    );
    return { status: items.length ? "ready" : "empty", items };
  } catch {
    return { status: "error", items: [] };
  }
}
