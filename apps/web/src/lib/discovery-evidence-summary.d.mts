export function summarizeDiscoveryEvidence(signals?: Array<{ id?: string; created_at?: string; raw_fingerprint?: Record<string, unknown> }>, now?: number): {
  count: number; states: string[]; latest: number | null; olderThanDay: boolean; devices: number; imported: boolean; protection: string;
};
