// These are tests for `Span`.  `Span` is a container for labels associated with
// an extent in time.  `Span` is also responsible for injecting trace context
// for propagation.

#include <datadog/clock.h>
#include <datadog/null_collector.h>
#include <datadog/optional.h>
#include <datadog/span.h>
#include <datadog/span_config.h>
#include <datadog/tag_propagation.h>
#include <datadog/trace_segment.h>
#include <datadog/tracer.h>

#include <charconv>
#include <chrono>
#include <cstdint>
#include <functional>
#include <limits>
#include <string>

#include "matchers.h"
#include "mocks/collectors.h"
#include "mocks/dict_readers.h"
#include "mocks/dict_writers.h"
#include "mocks/loggers.h"
#include "test.h"

using namespace datadog::tracing;

TEST_CASE("set_tag") {
  TracerConfig config;
  config.defaults.service = "testsvc";
  const auto collector = std::make_shared<MockCollector>();
  config.collector = collector;
  config.logger = std::make_shared<MockLogger>();

  auto finalized_config = finalize_config(config);
  REQUIRE(finalized_config);
  Tracer tracer{*finalized_config};

  SECTION("tags end up in the collector") {
    {
      auto span = tracer.create_span();
      span.set_tag("foo", "lemon");
      span.set_tag("foo.bar", "mint");
      span.set_tag("foo.baz", "blueberry");
    }

    REQUIRE(collector->chunks.size() == 1);
    const auto& chunk = collector->chunks.front();
    REQUIRE(chunk.size() == 1);
    const auto& span_ptr = chunk.front();
    REQUIRE(span_ptr);
    const auto& span = *span_ptr;
    REQUIRE(span.tags.at("foo") == "lemon");
    REQUIRE(span.tags.at("foo.bar") == "mint");
    REQUIRE(span.tags.at("foo.baz") == "blueberry");
  }

  SECTION("tags can be overwritten") {
    {
      SpanConfig config;
      config.tags = {
          {"color", "purple"},
          {"turtle.depth", "all the way down"},
      };
      auto span = tracer.create_span(config);
      span.set_tag("color", "green");
      span.set_tag("bonus", "applied");
    }

    REQUIRE(collector->chunks.size() == 1);
    const auto& chunk = collector->chunks.front();
    REQUIRE(chunk.size() == 1);
    const auto& span_ptr = chunk.front();
    REQUIRE(span_ptr);
    const auto& span = *span_ptr;
    REQUIRE(span.tags.at("color") == "green");
    REQUIRE(span.tags.at("turtle.depth") == "all the way down");
    REQUIRE(span.tags.at("bonus") == "applied");
  }

  SECTION("can't set internal tags directly") {
    {
      auto span = tracer.create_span();
      span.set_tag("foo", "lemon");
      span.set_tag("_dd.secret.sauce", "thousand islands");
      span.set_tag("_dd_not_internal", "");
      // _dd.p.dm will end up in the tags due to how sampling works
      // span.set_tag("_dd.p.dm", "-4");
      span.set_tag("_dd.chipmunk", "");
    }

    REQUIRE(collector->chunks.size() == 1);
    const auto& chunk = collector->chunks.front();
    REQUIRE(chunk.size() == 1);
    const auto& span_ptr = chunk.front();
    REQUIRE(span_ptr);
    const auto& span = *span_ptr;
    REQUIRE(span.tags.at("foo") == "lemon");
    REQUIRE(span.tags.count("_dd.secret.sauce") == 0);
    REQUIRE(span.tags.at("_dd_not_internal") == "");
    REQUIRE(span.tags.count("_dd.chipmunk") == 0);
  }
}

TEST_CASE("lookup_tag") {
  TracerConfig config;
  config.defaults.service = "testsvc";
  config.collector = std::make_shared<MockCollector>();
  config.logger = std::make_shared<MockLogger>();

  auto finalized_config = finalize_config(config);
  REQUIRE(finalized_config);
  Tracer tracer{*finalized_config};

  SECTION("not found is null") {
    auto span = tracer.create_span();
    REQUIRE(!span.lookup_tag("nope"));
    REQUIRE(!span.lookup_tag("also nope"));
  }

  SECTION("lookup after set") {
    auto span = tracer.create_span();
    span.set_tag("color", "purple");
    span.set_tag("turtle.depth", "all the way down");

    REQUIRE(span.lookup_tag("color") == "purple");
    REQUIRE(span.lookup_tag("turtle.depth") == "all the way down");
  }

  SECTION("lookup after config") {
    SpanConfig config;
    config.tags = {
        {"color", "purple"},
        {"turtle.depth", "all the way down"},
    };
    auto span = tracer.create_span(config);

    REQUIRE(span.lookup_tag("color") == "purple");
    REQUIRE(span.lookup_tag("turtle.depth") == "all the way down");
  }

  SECTION("internal tags redacted") {
    auto span = tracer.create_span();
    REQUIRE(!span.lookup_tag("_dd.this"));
    REQUIRE(!span.lookup_tag("_dd.that"));
    REQUIRE(!span.lookup_tag("_dd.the.other.thing"));
  }
}

TEST_CASE("remove_tag") {
  TracerConfig config;
  config.defaults.service = "testsvc";
  config.collector = std::make_shared<MockCollector>();
  config.logger = std::make_shared<MockLogger>();

  auto finalized_config = finalize_config(config);
  REQUIRE(finalized_config);
  Tracer tracer{*finalized_config};

  SECTION("doesn't have to be there already") {
    auto span = tracer.create_span();
    span.remove_tag("not even there");
  }

  SECTION("after removal, lookup yields null") {
    SpanConfig config;
    config.tags = {{"mayfly", "carpe diem"}};
    auto span = tracer.create_span(config);
    span.set_tag("foo", "bar");

    span.remove_tag("mayfly");
    span.remove_tag("foo");

    REQUIRE(!span.lookup_tag("mayfly"));
    REQUIRE(!span.lookup_tag("foo"));
  }
}

TEST_CASE("span duration") {
  TracerConfig config;
  config.defaults.service = "testsvc";
  auto collector = std::make_shared<MockCollector>();
  config.collector = collector;
  config.logger = std::make_shared<MockLogger>();

  auto finalized_config = finalize_config(config);
  REQUIRE(finalized_config);
  Tracer tracer{*finalized_config};

  SECTION("start time is adjustable") {
    {
      SpanConfig config;
      config.start = default_clock() - std::chrono::seconds(3);
      auto span = tracer.create_span(config);
      (void)span;
    }

    REQUIRE(collector->chunks.size() == 1);
    const auto& chunk = collector->chunks.front();
    REQUIRE(chunk.size() == 1);
    const auto& span_ptr = chunk.front();
    REQUIRE(span_ptr);
    const auto& span = *span_ptr;

    REQUIRE(span.duration >= std::chrono::seconds(3));
  }

  SECTION("end time is adjustable") {
    {
      auto span = tracer.create_span();
      span.set_end_time(span.start_time().tick + std::chrono::seconds(2));
    }

    REQUIRE(collector->chunks.size() == 1);
    const auto& chunk = collector->chunks.front();
    REQUIRE(chunk.size() == 1);
    const auto& span_ptr = chunk.front();
    REQUIRE(span_ptr);
    const auto& span = *span_ptr;

    REQUIRE(span.duration == std::chrono::seconds(2));
  }
}

TEST_CASE(".error() and .set_error*()") {
  struct TestCase {
    std::string name;
    std::function<void(Span&)> mutate;
    bool expected_error;
    Optional<StringView> expected_error_message;
    Optional<StringView> expected_error_type;
    Optional<StringView> expected_error_stack;
  };

  auto test_case = GENERATE(values<TestCase>(
      {{"No error → no error.", [](Span&) {}, false, nullopt, nullopt, nullopt},
       {"set_error(true) → error", [](Span& span) { span.set_error(true); },
        true, nullopt, nullopt, nullopt},
       {"set_error_message → error and error message",
        [](Span& span) { span.set_error_message("oops!"); }, true, "oops!",
        nullopt, nullopt},
       {"set_error_type → error and error type",
        [](Span& span) { span.set_error_type("errno"); }, true, nullopt,
        "errno", nullopt},
       {"set_error_stack → error and error stack",
        [](Span& span) { span.set_error_stack("this is C++, fool"); }, true,
        nullopt, nullopt, "this is C++, fool"},
       {"set all of them → error, error message, error type, and error stack",
        [](Span& span) {
          span.set_error_message("oops!");
          span.set_error_type("errno");
          span.set_error_stack("this is C++, fool");
        },
        true, "oops!", "errno", "this is C++, fool"},
       {"set_error(false) → no error, no error tags, and no error stack",
        [](Span& span) {
          span.set_error_message("this will go away");
          span.set_error_type("as will this");
          span.set_error_stack("this too");
          span.set_error(false);
        },
        false, nullopt, nullopt, nullopt}}));

  TracerConfig config;
  config.defaults.service = "testsvc";
  auto collector = std::make_shared<MockCollector>();
  config.collector = collector;
  config.logger = std::make_shared<MockLogger>();

  auto finalized_config = finalize_config(config);
  REQUIRE(finalized_config);
  Tracer tracer{*finalized_config};

  CAPTURE(test_case.name);
  {
    auto span = tracer.create_span();
    test_case.mutate(span);
    REQUIRE(span.error() == test_case.expected_error);
  }

  REQUIRE(collector->chunks.size() == 1);
  const auto& chunk = collector->chunks.front();
  REQUIRE(chunk.size() == 1);
  const auto& span_ptr = chunk.front();
  REQUIRE(span_ptr);
  const auto& span = *span_ptr;

  auto found = span.tags.find("error.msg");
  if (test_case.expected_error_message) {
    REQUIRE(found != span.tags.end());
    REQUIRE(found->second == *test_case.expected_error_message);
  } else {
    REQUIRE(found == span.tags.end());
  }

  found = span.tags.find("error.type");
  if (test_case.expected_error_type) {
    REQUIRE(found != span.tags.end());
    REQUIRE(found->second == *test_case.expected_error_type);
  } else {
    REQUIRE(found == span.tags.end());
  }
}

TEST_CASE("property setters") {
  TracerConfig config;
  config.defaults.service = "testsvc";
  auto collector = std::make_shared<MockCollector>();
  config.collector = collector;
  config.logger = std::make_shared<MockLogger>();

  auto finalized_config = finalize_config(config);
  REQUIRE(finalized_config);
  Tracer tracer{*finalized_config};

  SECTION("set_service_name") {
    {
      auto span = tracer.create_span();
      span.set_service_name("wobble");
    }
    auto& span = collector->first_span();
    REQUIRE(span.service == "wobble");
  }

  SECTION("set_service_type") {
    {
      auto span = tracer.create_span();
      span.set_service_type("wobble");
    }
    auto& span = collector->first_span();
    REQUIRE(span.service_type == "wobble");
  }

  SECTION("set_name") {
    {
      auto span = tracer.create_span();
      span.set_name("wobble");
    }
    auto& span = collector->first_span();
    REQUIRE(span.name == "wobble");
  }

  SECTION("set_resource_name") {
    {
      auto span = tracer.create_span();
      span.set_resource_name("wobble");
    }
    auto& span = collector->first_span();
    REQUIRE(span.resource == "wobble");
  }
}

namespace {

template <typename Integer>
std::string hex(Integer value) {
  // 4 bits per hex digit char, and then +1 char for possible minus sign
  char buffer[std::numeric_limits<Integer>::digits / 4 + 1];

  const int base = 16;
  auto result =
      std::to_chars(std::begin(buffer), std::end(buffer), value, base);
  assert(result.ec == std::errc());

  return std::string{std::begin(buffer), result.ptr};
}

}  // namespace

// Trace context injection is implemented in `TraceSegment`, but it's part of
// the interface of `Span`, so the test is here.
TEST_CASE("injection") {
  TracerConfig config;
  config.defaults.service = "testsvc";
  config.collector = std::make_shared<MockCollector>();
  config.logger = std::make_shared<MockLogger>();
  config.injection_styles = {PropagationStyle::DATADOG, PropagationStyle::B3};

  auto finalized_config = finalize_config(config);
  REQUIRE(finalized_config);
  auto generator = []() { return 42; };
  Tracer tracer{*finalized_config, generator, default_clock};

  SECTION("trace ID, parent ID ,and sampling priority") {
    auto span = tracer.create_span();
    const int priority = 3;  // 😱
    span.trace_segment().override_sampling_priority(priority);
    MockDictWriter writer;
    span.inject(writer);

    const auto& headers = writer.items;
    REQUIRE(headers.at("x-datadog-trace-id") ==
            std::to_string(span.trace_id()));
    REQUIRE(headers.at("x-datadog-parent-id") == std::to_string(span.id()));
    REQUIRE(headers.at("x-datadog-sampling-priority") ==
            std::to_string(priority));
    REQUIRE(headers.at("x-b3-traceid") == hex(span.trace_id()));
    REQUIRE(headers.at("x-b3-spanid") == hex(span.id()));
    REQUIRE(headers.at("x-b3-sampled") == std::to_string(int(priority > 0)));
  }

  SECTION("origin and trace tags") {
    SECTION("empty trace tags") {
      const std::unordered_map<std::string, std::string> headers{
          {"x-datadog-trace-id", "123"},
          {"x-datadog-sampling-priority", "0"},
          {"x-datadog-origin", "Egypt"},
          {"x-datadog-tags", ""}};
      MockDictReader reader{headers};
      auto span = tracer.extract_span(reader);
      REQUIRE(span);
      MockDictWriter writer;
      span->inject(writer);

      REQUIRE(writer.items.at("x-datadog-origin") == "Egypt");
      // empty trace tags → x-datadog-tags is not set
      REQUIRE(writer.items.count("x-datadog-tags") == 0);
    }

    SECTION("lots of trace tags") {
      const std::string trace_tags =
          "foo=bar,34=43,54-46=my-number,_dd.p.not_excluded=foo";
      const std::unordered_map<std::string, std::string> headers{
          {"x-datadog-trace-id", "123"},
          {"x-datadog-sampling-priority", "0"},
          {"x-datadog-origin", "Egypt"},
          {"x-datadog-tags", trace_tags}};
      MockDictReader reader{headers};
      auto span = tracer.extract_span(reader);
      REQUIRE(span);
      MockDictWriter writer;
      span->inject(writer);

      REQUIRE(writer.items.at("x-datadog-origin") == "Egypt");
      REQUIRE(writer.items.count("x-datadog-tags") == 1);
      const auto output = decode_tags(writer.items.at("x-datadog-tags"));
      const auto input = decode_tags(trace_tags);
      REQUIRE(output);
      REQUIRE(input);
      // Trace tags that don't begin with "_dd.p." are excluded from the parsed
      // trace tags, so check only that the output is a subset of the input.
      REQUIRE_THAT(*input, ContainsSubset(*output));
    }
  }
}

TEST_CASE("injection can be disabled using the \"none\" style") {
  TracerConfig config;
  config.defaults.service = "testsvc";
  config.defaults.name = "spanny";
  config.collector = std::make_shared<MockCollector>();
  config.logger = std::make_shared<MockLogger>();
  config.injection_styles = {PropagationStyle::NONE};

  const auto finalized_config = finalize_config(config);
  REQUIRE(finalized_config);
  Tracer tracer{*finalized_config};

  const auto span = tracer.create_span();
  MockDictWriter writer;
  span.inject(writer);
  const std::unordered_map<std::string, std::string> empty;
  REQUIRE(writer.items == empty);
}

TEST_CASE("injecting W3C traceparent header") {
  TracerConfig config;
  config.defaults.service = "testsvc";
  config.collector = std::make_shared<NullCollector>();
  config.logger = std::make_shared<NullLogger>();
  config.injection_styles = {PropagationStyle::W3C};

  SECTION("extracted from W3C traceparent") {
    config.extraction_styles = {PropagationStyle::W3C};
    const auto finalized_config = finalize_config(config);
    REQUIRE(finalized_config);

    // Override the tracer's ID generator to always return `expected_parent_id`.
    constexpr std::uint64_t expected_parent_id = 0xcafebabe;
    Tracer tracer{*finalized_config, [=]() { return expected_parent_id; },
                  default_clock};

    const std::unordered_map<std::string, std::string> input_headers{
        // https://www.w3.org/TR/trace-context/#examples-of-http-traceparent-headers
        {"traceparent",
         "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
    };
    const MockDictReader reader{input_headers};
    const auto maybe_span = tracer.extract_span(reader);
    REQUIRE(maybe_span);
    const auto& span = *maybe_span;
    REQUIRE(span.id() == expected_parent_id);

    MockDictWriter writer;
    span.inject(writer);
    const auto& output_headers = writer.items;
    const auto found = output_headers.find("traceparent");
    REQUIRE(found != output_headers.end());
    // The "00000000cafebabe" is the zero-padded `expected_parent_id`.
    const StringView expected =
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00000000cafebabe-01";
    REQUIRE(found->second == expected);
  }

  SECTION("not extracted from W3C traceparent") {
    const auto finalized_config = finalize_config(config);
    REQUIRE(finalized_config);

    // Override the tracer's ID generator to always return a fixed value.
    // This will be both the trace ID and the parent (root) span ID.
    constexpr std::uint64_t expected_id = 0xcafebabe;
    Tracer tracer{*finalized_config, [=]() { return expected_id; },
                  default_clock};

    auto span = tracer.create_span();

    // Let's test the effect sampling priority plays on the resulting
    // traceparent, too.
    struct TestCase {
      int sampling_priority;
      std::string expected_flags;
    };
    const auto& [sampling_priority, expected_flags] = GENERATE(
        values<TestCase>({{-1, "00"}, {0, "00"}, {1, "01"}, {2, "01"}}));

    CAPTURE(sampling_priority);
    CAPTURE(expected_flags);

    span.trace_segment().override_sampling_priority(sampling_priority);

    MockDictWriter writer;
    span.inject(writer);
    const auto& output_headers = writer.items;
    const auto found = output_headers.find("traceparent");
    REQUIRE(found != output_headers.end());
    // The "cafebabe"s come from `expected_id`.
    const std::string expected =
        "00-000000000000000000000000cafebabe-00000000cafebabe-" +
        expected_flags;
    REQUIRE(found->second == expected);
  }
}

TEST_CASE("injecting W3C tracestate header") {
  // Concerns:
  // - the basics:
  //   - sampling priority
  //   - origin
  //   - trace tags
  //   - extra fields (extracted from W3C)
  //   - all of the above
  // - character substitutions:
  //   - in origin
  //   - in trace tag key
  //   - in trace tag value
  //     - special tilde ("~") behavior
  // - length limit:
  //   - at origin
  //   - at a trace tag (extract extra fields from W3C)
  //   - at the extra fields (extracted from W3C)

  TracerConfig config;
  config.defaults.service = "testsvc";
  // The order of the extraction styles doesn't matter for this test, because
  // it'll either be one or the other in the test cases.
  config.extraction_styles = {PropagationStyle::DATADOG, PropagationStyle::W3C};
  config.injection_styles = {PropagationStyle::W3C};
  // If one of these test cases results in a local sampling decision, let it be
  // "drop."
  config.trace_sampler.sample_rate = 0.0;
  const auto logger = std::make_shared<MockLogger>();
  config.logger = logger;
  config.collector = std::make_shared<NullCollector>();

  const auto finalized_config = finalize_config(config);
  REQUIRE(finalized_config);
  Tracer tracer{*finalized_config};

  struct TestCase {
    int line;
    std::string name;
    std::unordered_map<std::string, std::string> input_headers;
    std::string expected_tracestate;
  };

  // clang-format off
  auto test_case = GENERATE(values<TestCase>({
    {__LINE__, "sampling priority",
     {{"x-datadog-trace-id", "1"}, {"x-datadog-parent-id", "1"},
      {"x-datadog-sampling-priority", "2"}},
     "dd=s:2"},

    {__LINE__, "origin",
     {{"x-datadog-trace-id", "1"}, {"x-datadog-parent-id", "1"},
      {"x-datadog-origin", "France"}},
      // The "s:-1" comes from the 0% sample rate.
     "dd=s:-1;o:France"},

    {__LINE__, "trace tags",
     {{"x-datadog-trace-id", "1"}, {"x-datadog-parent-id", "1"},
      {"x-datadog-tags", "_dd.p.foo=x,_dd.p.bar=y"}},
      // The "s:-1" comes from the 0% sample rate.
     "dd=s:-1;t.foo:x;t.bar:y"},
  }));
  // clang-format on

  CAPTURE(test_case.name);
  CAPTURE(test_case.line);
  CAPTURE(test_case.input_headers);
  CAPTURE(test_case.expected_tracestate);
  CAPTURE(logger->entries);

  MockDictReader reader{test_case.input_headers};
  const auto span = tracer.extract_span(reader);
  REQUIRE(span);

  MockDictWriter writer;
  span->inject(writer);

  CAPTURE(writer.items);
  const auto found = writer.items.find("tracestate");
  REQUIRE(found != writer.items.end());

  REQUIRE(found->second == test_case.expected_tracestate);

  REQUIRE(logger->error_count() == 0);
}
