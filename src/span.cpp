#include "span.h"

#include <cassert>

#include "span_data.h"
#include "trace_segment.h"

namespace datadog {
namespace tracing {

Span::Span(SpanData* data, const std::shared_ptr<TraceSegment>& trace_segment,
           const std::function<std::uint64_t()>& generate_span_id,
           const Clock& clock)
    : trace_segment_(trace_segment),
      data_(data),
      generate_span_id_(generate_span_id),
      clock_(clock) {
  assert(trace_segment_);
  assert(data_);
  assert(generate_span_id_);
  assert(clock_);
}

std::variant<Span, Error> Span::create_child(const SpanConfig& config) const {
  if (finished()) {
    return Error{Error::CREATE_CHILD_ON_FINISHED_SPAN,
                 "Cannot create child of finished span."};
  }

  auto span_data = std::make_unique<SpanData>();
  span_data->apply_config(trace_segment_->defaults(), config, clock_);
  span_data->trace_id = data_->trace_id;
  span_data->parent_id = data_->span_id;
  span_data->span_id = generate_span_id_();

  const auto span_data_ptr = span_data.get();
  trace_segment_->register_span(std::move(span_data));
  // TODO: Consider making `generate_span_id` a method of `TraceSegment`.
  return Span(span_data_ptr, trace_segment_, generate_span_id_, clock_);
}

std::optional<std::string_view> Span::lookup_tag(std::string_view name) const {
  if (finished()) {
    return std::nullopt;
  }

  // TODO: special cases for special tags.

  const auto found = data_->tags.find(std::string(name));
  if (found == data_->tags.end()) {
    return std::nullopt;
  }
  return found->second;
}

void Span::set_tag(std::string_view name, std::string_view value) {
  if (finished()) {
    return;
  }

  data_->tags.insert_or_assign(std::string(name), std::string(value));
}

void Span::remove_tag(std::string_view name) {
  if (finished()) {
    return;
  }

  data_->tags.erase(std::string(name));
}

TraceSegment& Span::trace_segment() { return *trace_segment_; }

const TraceSegment& Span::trace_segment() const { return *trace_segment_; }

void Span::finish() {
  if (finished()) {
    // idempotent
    return;
  }
  trace_segment_->span_finished();
  data_ = nullptr;
}

bool Span::finished() const { return data_ == nullptr; }

}  // namespace tracing
}  // namespace datadog
