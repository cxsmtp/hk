export type BrainCitationType = "evidence_node" | "snapshot";

export type BrainClaim = {
  id: string;
  text: string;
};

export type BrainCitation = {
  type: BrainCitationType;
  id: string;
  supports: string[];
  note?: string;
  ts?: string;
};

export type BrainProposedAction = {
  tool: string;
  args: Record<string, unknown>;
};

export type BrainAnswerContract = {
  answer: string;
  claims: BrainClaim[];
  citations: BrainCitation[];
  controls: string[];
  frameworks: string[];
  confidence: number;
  missing_evidence: string[];
  proposed_actions: BrainProposedAction[];
};

