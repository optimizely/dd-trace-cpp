#pragma once

#include <mutex>

#include "clock.h"
#include "span_sampler_config.h"

namespace datadog {
namespace tracing {

class SpanSampler {
  std::mutex mutex_;

 public:
  explicit SpanSampler(const FinalizedSpanSamplerConfig& config,
                       const Clock& clock);
};

}  // namespace tracing
}  // namespace datadog
