export type GatewayListStatus = "ready" | "empty" | "error";
export type GatewayChoiceList<T> = { status: GatewayListStatus; items: T[] };

export function loadGatewayChoiceLists<TSystem, TPack>(
  listAISystems: () => Promise<{ items?: TSystem[] }>,
  listPolicyPacks: () => Promise<{ items?: TPack[] }>,
): Promise<{ systems: GatewayChoiceList<TSystem>; packs: GatewayChoiceList<TPack> }>;

export function loadGatewayPolicyVersions<TVersion extends { id: string; created_at: string }>(
  listPolicyVersions: (packId: string) => Promise<{ items?: TVersion[] }>,
  packId: string,
): Promise<GatewayChoiceList<TVersion>>;
