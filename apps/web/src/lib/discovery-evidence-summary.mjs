const labels = { installed: "Installed", configured: "Configured", running: "Running", process_running: "Running", connection_observed: "Connection observed", interaction_observed: "Interaction observed" };

export function summarizeDiscoveryEvidence(signals = [], now = Date.now()) {
  const seen = new Set();
  const rows = signals.filter((signal) => {
    if (!signal.id) return true;
    if (seen.has(signal.id)) return false;
    seen.add(signal.id);
    return true;
  });
  const states = [...new Set(rows.map((row) => labels[row.raw_fingerprint?.observation_state] || "Observation type unknown"))].sort();
  const times = rows.map((row) => Date.parse(row.raw_fingerprint?.observed_at || row.created_at || "")).filter(Number.isFinite);
  const latest = times.length ? Math.max(...times) : null;
  return { count: rows.length, states: states.length ? states : ["No evidence loaded"],
    latest, olderThanDay: latest !== null && now - latest > 86400000,
    devices: new Set(rows.map((row) => row.raw_fingerprint?.device_reference).filter(Boolean)).size,
    imported: rows.some((row) => row.raw_fingerprint?.provenance === "customer_uploaded_export"),
    protection: "Not established by discovery evidence" };
}
