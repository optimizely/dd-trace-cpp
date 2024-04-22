#include "config_manager.h"

#include "parse_util.h"
#include "string_util.h"
#include "trace_sampler.h"

namespace datadog {
namespace tracing {

ConfigManager::ConfigManager(const FinalizedTracerConfig& config)
    : clock_(config.clock),
      default_metadata_(config.metadata),
      trace_sampler_(
          std::make_shared<TraceSampler>(config.trace_sampler, clock_)),
      span_defaults_(std::make_shared<SpanDefaults>(config.defaults)),
      report_traces_(config.report_traces) {
  auto found = config.trace_sampler.rules.find(catch_all);
  if (found != config.trace_sampler.rules.cend()) {
    sampling_rate_ = found->second.rate;
  }
}

std::shared_ptr<TraceSampler> ConfigManager::trace_sampler() {
  std::lock_guard<std::mutex> lock(mutex_);
  return trace_sampler_;
}

std::shared_ptr<const SpanDefaults> ConfigManager::span_defaults() {
  std::lock_guard<std::mutex> lock(mutex_);
  return span_defaults_.value();
}

bool ConfigManager::report_traces() {
  std::lock_guard<std::mutex> lock(mutex_);
  return report_traces_.value();
}

std::vector<ConfigMetadata> ConfigManager::update(const ConfigUpdate& conf) {
  std::vector<ConfigMetadata> metadata;

  std::lock_guard<std::mutex> lock(mutex_);

  auto trace_sampling_rules = trace_sampling_rules_;

  if (!conf.trace_sampling_rate && sampling_rate_) {
    metadata.emplace_back(default_metadata_[ConfigName::TRACE_SAMPLING_RATE]);
  } else {
    ConfigMetadata trace_sampling_metadata(
        ConfigName::TRACE_SAMPLING_RATE,
        to_string(*conf.trace_sampling_rate, 1),
        ConfigMetadata::Origin::REMOTE_CONFIG);

    auto maybe_rate = Rate::from(*conf.trace_sampling_rate);
    if (auto error = maybe_rate.if_error()) {
      trace_sampling_metadata.error = *error;
    } else {
      trace_sampling_rules[catch_all] =
          SamplingResult{*maybe_rate, SamplingMechanism::RULE};
    }

    metadata.emplace_back(std::move(trace_sampling_metadata));
  }

  if (!conf.trace_sample_rules) {
    auto found = default_metadata_.find(ConfigName::TRACE_SAMPLING_RULES);
    if (found != default_metadata_.cend()) {
      metadata.emplace_back(found->second);
    }
  } else {
    // ConfigMetadata trace_sampling_metadata(
    //     ConfigName::TRACE_SAMPLING_RULES,
    //     to_string(*conf.trace_sampling_rate, 1),
    //     ConfigMetadata::Origin::REMOTE_CONFIG);

    auto maybe_rules = parse_rules(*conf.trace_sample_rules);
    if (auto error = maybe_rules.if_error()) {
      // TBD
    }

    for (auto& cfg_rule : *maybe_rules) {
      SpanMatcher matcher = (SpanMatcher)cfg_rule;
      auto maybe_rate = Rate::from(cfg_rule.sample_rate);
      trace_sampling_rules_.emplace(
          std::move(matcher),
          SamplingResult{*maybe_rate, SamplingMechanism::REMOTE_USER_RULE});
    }

    // metadata.emplace_back(std::move(tbd)):
  }

  trace_sampler_->set_rules(trace_sampling_rules_);

  if (!conf.tags) {
    reset_config(ConfigName::TAGS, span_defaults_, metadata);
  } else {
    ConfigMetadata tags_metadata(ConfigName::TAGS, join(*conf.tags, ","),
                                 ConfigMetadata::Origin::REMOTE_CONFIG);

    auto parsed_tags = parse_tags(*conf.tags);
    if (auto error = parsed_tags.if_error()) {
      tags_metadata.error = *error;
    }

    if (*parsed_tags != span_defaults_.value()->tags) {
      auto new_span_defaults =
          std::make_shared<SpanDefaults>(*span_defaults_.value());
      new_span_defaults->tags = std::move(*parsed_tags);

      span_defaults_ = new_span_defaults;
      metadata.emplace_back(std::move(tags_metadata));
    }
  }

  if (!conf.report_traces) {
    reset_config(ConfigName::REPORT_TRACES, report_traces_, metadata);
  } else {
    if (conf.report_traces != report_traces_.value()) {
      report_traces_ = *conf.report_traces;
      metadata.emplace_back(ConfigName::REPORT_TRACES,
                            to_string(*conf.report_traces),
                            ConfigMetadata::Origin::REMOTE_CONFIG);
    }
  }

  return metadata;
}

template <typename T>
void ConfigManager::reset_config(ConfigName name, T& conf,
                                 std::vector<ConfigMetadata>& metadata) {
  if (conf.is_original_value()) return;

  conf.reset();
  metadata.emplace_back(default_metadata_[name]);
}

std::vector<ConfigMetadata> ConfigManager::reset() { return update({}); }

nlohmann::json ConfigManager::config_json() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return nlohmann::json{{"defaults", to_json(*span_defaults_.value())},
                        {"trace_sampler", trace_sampler_->config_json()},
                        {"report_traces", report_traces_.value()}};
}

}  // namespace tracing
}  // namespace datadog
