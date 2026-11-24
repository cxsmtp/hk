export type GovernanceTruthState = "verified" | "monitor_only" | "not_covered" | "unknown";

export type RiverEventKind = "action" | "alert" | "intervention" | "enforcement" | "proof";

export type GovernanceSurfaceRow = {
  id: string;
  label: string;
  state: GovernanceTruthState;
  eventCount: number;
  decisionCount: number;
  evidenceLabel: string;
  controlLabel: string;
  drilldown: string;
  applications: string[];
};

export type EvidenceRiverEvent = {
  id: string;
  timestamp: string | null;
  kind: RiverEventKind;
  surface: string;
  application: string;
  action: string;
  actor: string;
  decision: string;
  evidenceState: "verified" | "incomplete" | "unknown";
  summary: string;
  traceHref: string | null;
  evidenceHref: string | null;
  findingHref: string | null;
};

export type GovernanceOverviewModel = {
  discovery: {
    observedEvents: number;
    observedAssets: number;
    totalEstateKnown: false;
    categories: Array<{ label: string; value: number }>;
  };
  protect: {
    inlineVerified: number;
    monitorOnly: number;
    notCovered: number;
    unknown: number;
    totalSurfaces: number;
  };
  validate: {
    executedRuns: number;
    passedRuns: number;
    failedRuns: number;
    passRate: number | null;
    profile: Array<{ control: string; observed: number; simulated: number }>;
  };
  prove: {
    evidenceLinkedActions: number;
    incompleteActions: number;
    unknownActions: number;
  };
  surfaces: GovernanceSurfaceRow[];
  interventions: Array<{ label: string; value: number }>;
  river: EvidenceRiverEvent[];
};
