#pragma once

#include <string>
#include <vector>

namespace bodyguard {

enum class Action { DownloadReport, SubmitOrder, DismissDialog };
enum class Decision { Allow, Review, Block };

// Signals are collected by the browser adapter immediately before dispatch.
// This policy library does not itself connect to a browser or inspect websites.
struct PageSignals {
  bool declared_action_mismatch = false;
  bool target_occluded = false;
  bool recurring_consent_prechecked = false;
  bool hostile_prompt_injection = false;
  bool prompt_conflicts_with_goal = false;
};

struct ActionAssessment {
  Decision decision;
  std::vector<std::string> reason_codes;
  std::string safe_alternative;
};

ActionAssessment assess(Action action, const PageSignals& signals);
const char* to_string(Decision decision);

}  // namespace bodyguard

