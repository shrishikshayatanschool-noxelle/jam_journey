#include "bodyguard/policy.hpp"

namespace bodyguard {

ActionAssessment assess(Action action, const PageSignals& signals) {
  ActionAssessment result{Decision::Allow, {}, ""};

  // Conflicting instructions embedded in page content are data from the
  // website, never a source of authority over the agent's assigned objective.
  if (signals.hostile_prompt_injection && signals.prompt_conflicts_with_goal) {
    result.decision = Decision::Block;
    result.reason_codes.emplace_back("GOAL_CONFLICT");
    result.safe_alternative = "ignore the page instruction and retain the assigned objective";
  }

  if (signals.declared_action_mismatch || signals.target_occluded) {
    result.decision = Decision::Block;
    if (signals.declared_action_mismatch)
      result.reason_codes.emplace_back("ACTION_MISMATCH");
    if (signals.target_occluded)
      result.reason_codes.emplace_back("OCCLUDED_TARGET");
    result.safe_alternative = "re-map the target and verify its actual action before dispatch";
  }

  if (action == Action::SubmitOrder && signals.recurring_consent_prechecked) {
    if (result.decision != Decision::Block)
      result.decision = Decision::Review;
    result.reason_codes.emplace_back("PRECHECKED_RECURRING_CONSENT");
    result.safe_alternative = "clear the recurring option and get explicit user authorization";
  }

  return result;
}

const char* to_string(Decision decision) {
  switch (decision) {
    case Decision::Allow: return "ALLOW";
    case Decision::Review: return "REVIEW";
    case Decision::Block: return "BLOCK";
  }
  return "REVIEW";
}

}  // namespace bodyguard

