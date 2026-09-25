#include "bodyguard/policy.hpp"

#include <iostream>
#include <string>

int main(int argc, char** argv) {
  bodyguard::PageSignals signals;
  bodyguard::Action action = bodyguard::Action::DownloadReport;

  for (int i = 1; i < argc; ++i) {
    const std::string arg(argv[i]);
    if (arg == "--fake-action") signals.declared_action_mismatch = true;
    else if (arg == "--occluded-target") signals.target_occluded = true;
    else if (arg == "--prechecked-subscription") signals.recurring_consent_prechecked = true;
    else if (arg == "--prompt-injection") signals.hostile_prompt_injection = true;
    else if (arg == "--goal-conflict") signals.prompt_conflicts_with_goal = true;
    else if (arg == "--submit-order") action = bodyguard::Action::SubmitOrder;
    else if (arg == "--dismiss-dialog") action = bodyguard::Action::DismissDialog;
    else if (arg == "--help") {
      std::cout << "Usage: bodyguard-policy [--submit-order|--dismiss-dialog] "
                   "[--fake-action] [--occluded-target] [--prechecked-subscription] "
                   "[--prompt-injection] [--goal-conflict]\n";
      return 0;
    } else {
      std::cerr << "Unknown option: " << arg << '\n';
      return 2;
    }
  }

  const auto result = bodyguard::assess(action, signals);
  std::cout << "{\"decision\":\"" << bodyguard::to_string(result.decision)
            << "\",\"reason_codes\":[";
  for (std::size_t i = 0; i < result.reason_codes.size(); ++i) {
    if (i) std::cout << ',';
    std::cout << '"' << result.reason_codes[i] << '"';
  }
  std::cout << "],\"safe_alternative\":\"" << result.safe_alternative << "\"}\n";
  return result.decision == bodyguard::Decision::Block ? 1 : 0;
}

