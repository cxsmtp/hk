"""Autonomous Discovery Verification contracts and services."""

from app.services.hmair.adv.contracts import (
    ADVStateProjection,
    DiscoveryStage,
    VerificationOutcome,
    VerificationTaskResult,
)
from app.services.hmair.adv.state_machine import ADVStateConflict, ADVStateMachine
from app.services.hmair.adv.policy import (
    VerificationPolicyConflict,
    VerificationPolicyResolver,
    VerificationPolicySelection,
    create_verification_policy,
)
from app.services.hmair.adv.planner import (
    InitialVerificationCoordinator,
    InitialVerificationPlanning,
    VerificationPlan,
    VerificationPlanner,
    VerificationPlanningConflict,
)
from app.services.hmair.adv.results import (
    VerificationResultConflict,
    VerificationResultValidator,
)
from app.services.hmair.adv.reconciler import (
    VerificationEvidenceReconciler,
    VerificationReconciliationConflict,
)
from app.services.hmair.adv.assertions import (
    RequirementEvaluation,
    VerificationAssertionConflict,
    VerificationAssertionEngine,
    evaluate_requirements,
)
from app.services.hmair.adv.projection import (
    EcosystemVerificationProjection,
    VerificationProjectionConflict,
    VerificationProjectionService,
)
from app.services.hmair.adv.continuous_validation import (
    ContinuousValidationConflict,
    ContinuousValidationService,
    DueVerification,
)

__all__ = [
    "ADVStateConflict",
    "ADVStateMachine",
    "ADVStateProjection",
    "DiscoveryStage",
    "VerificationOutcome",
    "VerificationTaskResult",
    "VerificationPolicyConflict",
    "VerificationPolicyResolver",
    "VerificationPolicySelection",
    "create_verification_policy",
    "InitialVerificationCoordinator",
    "InitialVerificationPlanning",
    "VerificationPlan",
    "VerificationPlanner",
    "VerificationPlanningConflict",
    "VerificationResultConflict",
    "VerificationResultValidator",
    "VerificationEvidenceReconciler",
    "VerificationReconciliationConflict",
    "RequirementEvaluation",
    "VerificationAssertionConflict",
    "VerificationAssertionEngine",
    "evaluate_requirements",
    "EcosystemVerificationProjection",
    "VerificationProjectionConflict",
    "VerificationProjectionService",
    "ContinuousValidationConflict",
    "ContinuousValidationService",
    "DueVerification",
]
