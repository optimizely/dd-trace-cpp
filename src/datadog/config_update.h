#pragma once

#include <unordered_map>

#include "json_fwd.hpp"
#include "optional.h"
#include "trace_sampler_config.h"

namespace datadog {
namespace tracing {

// The `ConfigUpdate` struct serves as a container for configuration that can
// exclusively be changed remotely.
//
// Configurations can be `nullopt` to signal the absence of a value from the
// remote configuration value.
struct ConfigUpdate {
  Optional<bool> report_traces;
  Optional<double> trace_sampling_rate;
  Optional<std::vector<StringView>> tags;
  const nlohmann::json* trace_sample_rules;
};

}  // namespace tracing
}  // namespace datadog
