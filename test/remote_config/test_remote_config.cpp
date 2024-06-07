#include "catch.hpp"
#include "datadog/json.hpp"
#include "datadog/remote_config/remote_config.h"

namespace rc = datadog::remote_config;
using namespace datadog::tracing;

#define REMOTE_CONFIG_TEST(x) TEST_CASE(x, "[remote_config]")

namespace {
struct FakeListener : public rc::Listener {
  rc::Products products{0};
  rc::Capabilities capabilities{0};
  size_t count_on_update{0};
  size_t count_on_revert{0};
  size_t count_on_post_process{0};
  std::function<Optional<std::string>(const Configuration&)> update_callback{
      nullptr};

  FakeListener() {}
  ~FakeListener() = default;

  rc::Products get_products() override { return products; }

  rc::Capabilities get_capabilities() override { return capabilities; }

  void on_revert(const Configuration&) override { ++count_on_revert; }

  Optional<std::string> on_update(const Configuration& conf) override {
    ++count_on_update;
    if (update_callback) {
      return update_callback(conf);
    }

    return nullopt;
  }

  void on_post_process() override { ++count_on_post_process; }
};
}  // namespace

REMOTE_CONFIG_TEST("initial state payload") {
  // Verify the initial payload structure for a remote configuration instance.
  const TracerSignature tracer_signature{
      /* runtime_id = */ RuntimeID::generate(),
      /* service = */ "testsvc",
      /* environment = */ "test"};

  auto tracing_listener = std::make_shared<FakeListener>();
  tracing_listener->products = rc::product::APM_TRACING;
  tracing_listener->capabilities = rc::capability::APM_TRACING_SAMPLE_RATE |
                                   rc::capability::APM_TRACING_TAGS;

  auto asm_listener = std::make_shared<FakeListener>();
  asm_listener->products = rc::product::ASM | rc::product::ASM_DD |
                           rc::product::ASM_DATA | rc::product::ASM_FEATURES;
  asm_listener->capabilities =
      rc::capability::ASM_ACTIVATION | rc::capability::ASM_CUSTOM_RULES;

  const std::vector<std::string_view> expected_products{
      "APM_TRACING", "ASM", "ASM_DATA", "ASM_DD", "ASM_FEATURES"};
  const std::vector<uint8_t> expected_capabilities{0, 0, 0, 0, 0, 0, 145, 2};

  rc::Manager rc(tracer_signature, {tracing_listener, asm_listener});

  const auto payload = rc.make_request_payload();

  CHECK(payload["client"]["is_tracer"] == true);
  CHECK(payload["client"]["products"] == expected_products);
  CHECK(payload["client"]["capabilities"] == expected_capabilities);
  CHECK(payload["client"]["client_tracer"]["language"] == "cpp");
  CHECK(payload["client"]["client_tracer"]["service"] == "testsvc");
  CHECK(payload["client"]["client_tracer"]["env"] == "test");
  CHECK(payload["client"]["client_tracer"]["runtime_id"] ==
        tracer_signature.runtime_id.string());
  CHECK(payload["client"]["client_tracer"]["tracer_version"] ==
        tracer_signature.library_version);
  CHECK(payload["client"]["state"]["root_version"] == 1);
  CHECK(payload["client"]["state"]["targets_version"] == 0);
  CHECK(payload["client"]["state"]["backend_client_state"] == "");

  CHECK(payload.contains("error") == false);
  CHECK(payload["client"]["state"].contains("config_states") == false);
}

// TODO: test all combination of product and capabilities generation

REMOTE_CONFIG_TEST("response processing") {
  const TracerSignature tracer_signature{
      /* runtime_id = */ RuntimeID::generate(),
      /* service = */ "testsvc",
      /* environment = */ "test"};

  SECTION("ill formatted input",
          "inputs not following the Remote Configuration JSON schema should "
          "generate an error") {
    // clang-format off
    auto test_case = GENERATE(values<std::string>({
      // Missing all fields
      "{}",
      // `targets` field is empty
      R"({ "targets": "" })",
      // `targets` field is not base64 encoded
      R"({ "targets": "Hello, Mars!" })",
      // `targets` field is not a JSON base64 encoded
      // decode("bm90IGpzb24=") == "not json"
      R"({ "targets": "bm90IGpzb24=" })",
      // `targets` field JSON base64 encoded do not follow the expected
      // schema
      // decode("eyJmb28iOiAiYmFyIn0=") == "{"foo": "bar"}"
      R"({ "targets": "eyJmb28iOiAiYmFyIn0=" })",
      // `targets` is missing the `targets` field.
      //
      // decode("eyJzaWduZWQiOiB7InZlcnNpb24iOiAyLCAiY3VzdG9tIjogeyJvcGFxdWVfYmFja2VuZF9zdGF0ZSI6ICIxNSJ9fX0=")
      // == "{"signed": {"version": 2, "custom": {"opaque_backend_state": "15"}}}" 
      R"({
          "targets": "eyJzaWduZWQiOiB7InZlcnNpb24iOiAyLCAiY3VzdG9tIjogeyJvcGFxdWVfYmFja2VuZF9zdGF0ZSI6ICIxNSJ9fX0=",
          "client_configs": ["employee/APM_TRACING/missing_target/conf"]
      })",
      // `/targets/targets` have no `datadog` entry
      // {"signed": {"version": 2, "targets": {"foo": {}, "bar": {}},"custom": {"opaque_backend_state": "15"}}} 
      R"({
          "targets": "eyJzaWduZWQiOiB7InZlcnNpb24iOiAyLCAidGFyZ2V0cyI6IHsiZm9vIjoge30sICJiYXIiOiB7fX0sImN1c3RvbSI6IHsib3BhcXVlX2JhY2tlbmRfc3RhdGUiOiAiMTUifX19",
          "client_configs": ["employee/APM_TRACING/missing_client_entry/conf"]
      })",
      // `targets` OK but no `target_files` field.
      // {"signed": {"version": 2, "targets": {"foo/APM_TRACING/30": {}, "bar": {}},"custom": {"opaque_backend_state": "15"}}} 
      R"({
          "targets": "eyJzaWduZWQiOiB7InZlcnNpb24iOiAyLCAidGFyZ2V0cyI6IHsiZW1wbG95ZWUvQVBNX1RSQUNJTkcvdmFsaWRfY29uZl9wYXRoL2NvbmZpZyI6IHt9LCAiYmFyIjoge319LCJjdXN0b20iOiB7Im9wYXF1ZV9iYWNrZW5kX3N0YXRlIjogIjE1In19fQ==",
          "client_configs": ["employee/APM_TRACING/valid_conf_path/config"]
      })",
      // `targets` OK. `target_files` field is empty.
      // {"signed": {"version": 2, "targets": {"foo/APM_TRACING/30": {}, "bar": {}},"custom": {"opaque_backend_state": "15"}}} 
      R"({
          "targets": "eyJzaWduZWQiOiB7InZlcnNpb24iOiAyLCAidGFyZ2V0cyI6IHsiZW1wbG95ZWUvQVBNX1RSQUNJTkcvdmFsaWRfY29uZl9wYXRoL2NvbmZpZyI6IHt9LCAiYmFyIjoge319LCJjdXN0b20iOiB7Im9wYXF1ZV9iYWNrZW5kX3N0YXRlIjogIjE1In19fQ==",
          "client_configs": ["employee/APM_TRACING/valid_conf_path/config"],
          "target_files": []
      })",
      // `targets` OK. `target_files` field is not an array.
      // {"signed": {"version": 2, "targets": {"foo/APM_TRACING/30": {}, "bar": {}},"custom": {"opaque_backend_state": "15"}}} 
      R"({
          "targets": "eyJzaWduZWQiOiB7InZlcnNpb24iOiAyLCAidGFyZ2V0cyI6IHsiZW1wbG95ZWUvQVBNX1RSQUNJTkcvdmFsaWRfY29uZl9wYXRoL2NvbmZpZyI6IHt9LCAiYmFyIjoge319LCJjdXN0b20iOiB7Im9wYXF1ZV9iYWNrZW5kX3N0YXRlIjogIjE1In19fQ==",
          "client_configs": ["employee/APM_TRACING/valid_conf_path/config"],
          "target_files": 15
      })",
      // `targets` OK. `target_files` field content is not base64 encoded.
      // {"signed": {"version": 2, "targets": {"foo/APM_TRACING/30": {}, "bar": {}},"custom": {"opaque_backend_state": "15"}}} 
      R"({
          "targets": "eyJzaWduZWQiOiB7InZlcnNpb24iOiAyLCAidGFyZ2V0cyI6IHsiZW1wbG95ZWUvQVBNX1RSQUNJTkcvdmFsaWRfY29uZl9wYXRoL2NvbmZpZyI6IHt9LCAiYmFyIjoge319LCJjdXN0b20iOiB7Im9wYXF1ZV9iYWNrZW5kX3N0YXRlIjogIjE1In19fQ==",
          "client_configs": ["employee/APM_TRACING/valid_conf_path/config"],
          "target_files": [{"path": "employee/APM_TRACING/valid_conf_path/config", "raw": "Hello, Uranus!"}]
      })",
      // `targets` OK. `target_files` field content is not a JSON base64 encoded.
      // decode("bm90IGpzb24=") == "not json"
      // {"signed": {"version": 2, "targets": {"foo/APM_TRACING/30": {}, "bar": {}},"custom": {"opaque_backend_state": "15"}}} 
      R"({
          "targets": "eyJzaWduZWQiOiB7InZlcnNpb24iOiAyLCAidGFyZ2V0cyI6IHsiZW1wbG95ZWUvQVBNX1RSQUNJTkcvdmFsaWRfY29uZl9wYXRoL2NvbmZpZyI6IHt9LCAiYmFyIjoge319LCJjdXN0b20iOiB7Im9wYXF1ZV9iYWNrZW5kX3N0YXRlIjogIjE1In19fQ==",
          "client_configs": ["employee/APM_TRACING/valid_conf_path/config"],
          "target_files": [{"path": "employee/APM_TRACING/valid_conf_path/config", "raw": "bm90IGpzb24="}]
      })",
      // `targets` OK. `target_files` field JSON base64 content do not follow the expected schema.
      // decode("eyJmb28iOiAiYmFyIn0=") == "{"foo": "bar"}"
      // {"signed": {"version": 2, "targets": {"foo/APM_TRACING/30": {}, "bar": {}},"custom": {"opaque_backend_state": "15"}}} 
      R"({
          "targets": "eyJzaWduZWQiOiB7InZlcnNpb24iOiAyLCAidGFyZ2V0cyI6IHsiZW1wbG95ZWUvQVBNX1RSQUNJTkcvdmFsaWRfY29uZl9wYXRoL2NvbmZpZyI6IHt9LCAiYmFyIjoge319LCJjdXN0b20iOiB7Im9wYXF1ZV9iYWNrZW5kX3N0YXRlIjogIjE1In19fQ==",
          "client_configs": ["employee/APM_TRACING/valid_conf_path/config"],
          "target_files": [{"path": "employee/APM_TRACING/valid_conf_path/config", "raw": "eyJmb28iOiAiYmFyIn0="}]
      })",
    }));
    // clang-format on

    CAPTURE(test_case);
    const auto response_json =
        nlohmann::json::parse(/* input = */ test_case,
                              /* parser_callback = */ nullptr,
                              /* allow_exceptions = */ false);
    REQUIRE(!response_json.is_discarded());

    rc::Manager rc(tracer_signature, {});

    rc.process_response(response_json);

    // Next payload should contains an error.
    const auto payload = rc.make_request_payload();
    CHECK(payload.contains("/client/state/has_error"_json_pointer) == true);
    CHECK(payload.contains("/client/state/error"_json_pointer) == true);
  }

  SECTION(
      "configuration updates targetting the wrong tracer reports an error") {
    // clang-format off
    auto test_case = GENERATE(values<std::string>({
      // "service_target": { "service": "not-testsvc", "env": "test" }
      R"({
        "targets":
        "ewogICAgInNpZ25lZCI6IHsKICAgICAgICAiY3VzdG9tIjogewogICAgICAgICAgICAiYWdlbnRfcmVmcmVzaF9pbnRlcnZhbCI6IDUsCiAgICAgICAgICAgICJvcGFxdWVfYmFja2VuZF9zdGF0ZSI6ICJleUoyWlhKemFXOXVJam95TENKemRHRjBaU0k2ZXlKbWFXeGxYMmhoYzJobGN5STZleUprWVhSaFpHOW5MekV3TURBeE1qVTROREF2UVZCTlgxUlNRVU5KVGtjdk9ESTNaV0ZqWmpoa1ltTXpZV0l4TkRNMFpETXlNV05pT0RGa1ptSm1OMkZtWlRZMU5HRTBZall4TVRGalpqRTJOakJpTnpGalkyWTRPVGM0TVRrek9DOHlPVEE0Tm1Ka1ltVTFNRFpsTmpoaU5UQm1NekExTlRneU0yRXpaR0UxWTJVd05USTRaakUyTkRCa05USmpaamc0TmpFNE1UWmhZV0U1Wm1ObFlXWTBJanBiSW05WVpESnBlVU16ZUM5b1JXc3hlWFZoWTFoR04xbHFjWEpwVGs5QldVdHVaekZ0V0UwMU5WWktUSGM5SWwxOWZYMD0iCiAgICAgICAgfSwKICAgICAgICAic3BlY192ZXJzaW9uIjogIjEuMC4wIiwKICAgICAgICAidGFyZ2V0cyI6IHsKICAgICAgICAgICAgImVtcGxveWVlL0FQTV9UUkFDSU5HL3Rlc3RfcmNfd3JvbmdfdGFyZ2V0L3NlcnZpY2VfbmFtZSI6IHsKICAgICAgICAgICAgICAgICJoYXNoZXMiOiB7CiAgICAgICAgICAgICAgICAgICAgInNoYTI1NiI6ICJhMTc3NzY4YjIwYjdjN2Y4NDQ5MzVjYWU2OWM1YzVlZDg4ZWFhZTIzNGUwMTgyYTc4MzU5OTczMzllNTUyNGJjIgogICAgICAgICAgICAgICAgfSwKICAgICAgICAgICAgICAgICJsZW5ndGgiOiAzNzQKICAgICAgICAgICAgfQogICAgICAgIH0sCiAgICAgICAgInZlcnNpb24iOiA2NjIwNDMyMAogICAgfQp9",
        "client_configs": ["employee/APM_TRACING/test_rc_wrong_target/service_name"],
        "target_files": [
          {
            "path": "employee/APM_TRACING/test_rc_wrong_target/service_name",
            "raw":
            "eyAiaWQiOiAiODI3ZWFjZjhkYmMzYWIxNDM0ZDMyMWNiODFkZmJmN2FmZTY1NGE0YjYxMTFjZjE2NjBiNzFjY2Y4OTc4MTkzOCIsICJyZXZpc2lvbiI6IDE2OTgxNjcxMjYwNjQsICJzY2hlbWFfdmVyc2lvbiI6ICJ2MS4wLjAiLCAiYWN0aW9uIjogImVuYWJsZSIsICJsaWJfY29uZmlnIjogeyAibGlicmFyeV9sYW5ndWFnZSI6ICJhbGwiLCAibGlicmFyeV92ZXJzaW9uIjogImxhdGVzdCIsICJzZXJ2aWNlX25hbWUiOiAidGVzdHN2YyIsICJlbnYiOiAidGVzdCIsICJ0cmFjaW5nX2VuYWJsZWQiOiB0cnVlLCAidHJhY2luZ19zYW1wbGluZ19yYXRlIjogMC42IH0sICJzZXJ2aWNlX3RhcmdldCI6IHsgInNlcnZpY2UiOiAibm90LXRlc3RzdmMiLCAiZW52IjogInRlc3QiIH0gfQ=="
          }
        ]
      })",
      // "service_target": { "service": "testsvc", "env": "dev" }
      R"({
        "targets":
        "ewogICAgInNpZ25lZCI6IHsKICAgICAgICAiY3VzdG9tIjogewogICAgICAgICAgICAiYWdlbnRfcmVmcmVzaF9pbnRlcnZhbCI6IDUsCiAgICAgICAgICAgICJvcGFxdWVfYmFja2VuZF9zdGF0ZSI6ICJleUoyWlhKemFXOXVJam95TENKemRHRjBaU0k2ZXlKbWFXeGxYMmhoYzJobGN5STZleUprWVhSaFpHOW5MekV3TURBeE1qVTROREF2UVZCTlgxUlNRVU5KVGtjdk9ESTNaV0ZqWmpoa1ltTXpZV0l4TkRNMFpETXlNV05pT0RGa1ptSm1OMkZtWlRZMU5HRTBZall4TVRGalpqRTJOakJpTnpGalkyWTRPVGM0TVRrek9DOHlPVEE0Tm1Ka1ltVTFNRFpsTmpoaU5UQm1NekExTlRneU0yRXpaR0UxWTJVd05USTRaakUyTkRCa05USmpaamc0TmpFNE1UWmhZV0U1Wm1ObFlXWTBJanBiSW05WVpESnBlVU16ZUM5b1JXc3hlWFZoWTFoR04xbHFjWEpwVGs5QldVdHVaekZ0V0UwMU5WWktUSGM5SWwxOWZYMD0iCiAgICAgICAgfSwKICAgICAgICAic3BlY192ZXJzaW9uIjogIjEuMC4wIiwKICAgICAgICAidGFyZ2V0cyI6IHsKICAgICAgICAgICAgImVtcGxveWVlL0FQTV9UUkFDSU5HL3Rlc3RfcmNfd3JvbmdfdGFyZ2V0L2Vudl9uYW1lIjogewogICAgICAgICAgICAgICAgImhhc2hlcyI6IHsKICAgICAgICAgICAgICAgICAgICAic2hhMjU2IjogImExNzc3NjhiMjBiN2M3Zjg0NDkzNWNhZTY5YzVjNWVkODhlYWFlMjM0ZTAxODJhNzgzNTk5NzMzOWU1NTI0YmMiCiAgICAgICAgICAgICAgICB9LAogICAgICAgICAgICAgICAgImxlbmd0aCI6IDM3NAogICAgICAgICAgICB9CiAgICAgICAgfSwKICAgICAgICAidmVyc2lvbiI6IDY2MjA0MzIwCiAgICB9Cn0=",
        "client_configs": ["employee/APM_TRACING/test_rc_wrong_target/env_name"],
        "target_files": [
          {
            "path": "employee/APM_TRACING/test_rc_wrong_target/env_name",
            "raw":
            "eyAiaWQiOiAiODI3ZWFjZjhkYmMzYWIxNDM0ZDMyMWNiODFkZmJmN2FmZTY1NGE0YjYxMTFjZjE2NjBiNzFjY2Y4OTc4MTkzOCIsICJyZXZpc2lvbiI6IDE2OTgxNjcxMjYwNjQsICJzY2hlbWFfdmVyc2lvbiI6ICJ2MS4wLjAiLCAiYWN0aW9uIjogImVuYWJsZSIsICJsaWJfY29uZmlnIjogeyAibGlicmFyeV9sYW5ndWFnZSI6ICJhbGwiLCAibGlicmFyeV92ZXJzaW9uIjogImxhdGVzdCIsICJzZXJ2aWNlX25hbWUiOiAidGVzdHN2YyIsICJlbnYiOiAidGVzdCIsICJ0cmFjaW5nX2VuYWJsZWQiOiB0cnVlLCAidHJhY2luZ19zYW1wbGluZ19yYXRlIjogMC42IH0sICJzZXJ2aWNlX3RhcmdldCI6IHsgInNlcnZpY2UiOiAidGVzdHN2YyIsICJlbnYiOiAiZGV2IiB9IH0="
          }
        ]
      })"
    }));
    // clang-format on

    CAPTURE(test_case);

    const auto response_json =
        nlohmann::json::parse(/* input = */ test_case,
                              /* parser_callback = */ nullptr,
                              /* allow_exceptions = */ false);

    REQUIRE(!response_json.is_discarded());

    auto tracing_listener = std::make_shared<FakeListener>();
    tracing_listener->products = rc::product::APM_TRACING;

    rc::Manager rc(tracer_signature, {tracing_listener});
    rc.process_response(response_json);

    CHECK(tracing_listener->count_on_update == 0);
    CHECK(tracing_listener->count_on_revert == 0);
    CHECK(tracing_listener->count_on_post_process == 1);

    // Verify next request set the config status
    const auto payload = rc.make_request_payload();
    REQUIRE(payload.contains("/client/state/config_states"_json_pointer) ==
            true);

    constexpr auto error_state = 3;
    const auto& config_states =
        payload.at("/client/state/config_states"_json_pointer);
    REQUIRE(config_states.size() == 1);
    CHECK(config_states[0]["product"] == "APM_TRACING");
    CHECK(config_states[0]["apply_state"] == error_state);
  }

  SECTION("update dispatch") {
    // Verify configuration updates are dispatched to the correct listener
    std::string_view rc_response = R"({
        "targets": "ewogICAgInNpZ25lZCI6IHsKICAgICAgICAiY3VzdG9tIjogewogICAgICAgICAgICAiYWdlbnRfcmVmcmVzaF9pbnRlcnZhbCI6IDUsCiAgICAgICAgICAgICJvcGFxdWVfYmFja2VuZF9zdGF0ZSI6ICJleUoyWlhKemFXOXVJam95TENKemRHRjBaU0k2ZXlKbWFXeGxYMmhoYzJobGN5STZleUprWVhSaFpHOW5MekV3TURBeE1qVTROREF2UVZCTlgxUlNRVU5KVGtjdk9ESTNaV0ZqWmpoa1ltTXpZV0l4TkRNMFpETXlNV05pT0RGa1ptSm1OMkZtWlRZMU5HRTBZall4TVRGalpqRTJOakJpTnpGalkyWTRPVGM0TVRrek9DOHlPVEE0Tm1Ka1ltVTFNRFpsTmpoaU5UQm1NekExTlRneU0yRXpaR0UxWTJVd05USTRaakUyTkRCa05USmpaamc0TmpFNE1UWmhZV0U1Wm1ObFlXWTBJanBiSW05WVpESnBlVU16ZUM5b1JXc3hlWFZoWTFoR04xbHFjWEpwVGs5QldVdHVaekZ0V0UwMU5WWktUSGM5SWwxOWZYMD0iCiAgICAgICAgfSwKICAgICAgICAic3BlY192ZXJzaW9uIjogIjEuMC4wIiwKICAgICAgICAidGFyZ2V0cyI6IHsKICAgICAgICAgICAgImVtcGxveWVlL0FQTV9UUkFDSU5HL3Rlc3RfcmNfdXBkYXRlL2xpYl91cGRhdGUiOiB7CiAgICAgICAgICAgICAgICAiaGFzaGVzIjogewogICAgICAgICAgICAgICAgICAgICJzaGEyNTYiOiAiYTE3Nzc2OGIyMGI3YzdmODQ0OTM1Y2FlNjljNWM1ZWQ4OGVhYWUyMzRlMDE4MmE3ODM1OTk3MzM5ZTU1MjRiYyIKICAgICAgICAgICAgICAgIH0sCiAgICAgICAgICAgICAgICAibGVuZ3RoIjogMzc0CiAgICAgICAgICAgIH0sCiAgICAgICAgICAgICJlbXBsb3llZS9BR0VOVF9UQVNLL3Rlc3RfcmNfdXBkYXRlL2ZsYXJlX3Rhc2siOiB7CiAgICAgICAgICAgICAgICAiaGFzaGVzIjogewogICAgICAgICAgICAgICAgICAgICJzaGEyNTYiOiAiNDE5NGNlNmY3MTEzOTU5NDZiZTgzN2JmNWViYTk0ODkxYjdiZGU3OTg5MTFlZDVlZmZmNjU5OWQyMWFiOTY5NiIKICAgICAgICAgICAgICAgIH0sCiAgICAgICAgICAgICAgICAibGVuZ3RoIjogMzc0CiAgICAgICAgICAgIH0sCiAgICAgICAgICAgICJlbXBsb3llZS9BR0VOVF9DT05GSUcvdGVzdF9yY191cGRhdGUvZmxhcmVfY29uZiI6IHsKICAgICAgICAgICAgICAgICJoYXNoZXMiOiB7CiAgICAgICAgICAgICAgICAgICAgInNoYTI1NiI6ICIyZDc4YWU3MzZhM2ZjNDU1YjcyMzFkYWY5OTQ1ZjhkZjcwNGYxNzI1YjUwZGRlNDZkMGNiY2RjM2YwZTExZDQxIgogICAgICAgICAgICAgICAgfSwKICAgICAgICAgICAgICAgICJsZW5ndGgiOiAzNzQKICAgICAgICAgICAgfQogICAgIAogICAgICAgIH0sCiAgICAgICAgInZlcnNpb24iOiA2NjIwNDMyMAogICAgfQp9",
        "client_configs": [
            "employee/APM_TRACING/test_rc_update/lib_update",
            "employee/AGENT_TASK/test_rc_update/flare_task",
            "employee/AGENT_CONFIG/test_rc_update/flare_conf"
        ],
        "target_files": [
          {
            "path": "employee/AGENT_CONFIG/test_rc_update/flare_conf",
            "raw": "eyAiaWQiOiAiODI3ZWFjZjhkYmMzYWIxNDM0ZDMyMWNiODFkZmJmN2FmZTY1NGE0YjYxMTFjZjE2NjBiNzFjY2Y4OTc4MTkzOCIsICJyZXZpc2lvbiI6IDE2OTgxNjcxMjYwNjQsICJzY2hlbWFfdmVyc2lvbiI6ICJ2MS4wLjAiLCAiYWN0aW9uIjogImVuYWJsZSIsICJsaWJfY29uZmlnIjogeyAibGlicmFyeV9sYW5ndWFnZSI6ICJhbGwiLCAibGlicmFyeV92ZXJzaW9uIjogImxhdGVzdCIsICJzZXJ2aWNlX25hbWUiOiAidGVzdHN2YyIsICJlbnYiOiAidGVzdCIsICJ0cmFjaW5nX2VuYWJsZWQiOiB0cnVlLCAidHJhY2luZ19zYW1wbGluZ19yYXRlIjogMC42IH0sICJzZXJ2aWNlX3RhcmdldCI6IHsgInNlcnZpY2UiOiAidGVzdHN2YyIsICJlbnYiOiAidGVzdCIgfSB9"
          },
          {
            "path": "employee/APM_TRACING/test_rc_update/lib_update",
            "raw": "eyAiaWQiOiAiODI3ZWFjZjhkYmMzYWIxNDM0ZDMyMWNiODFkZmJmN2FmZTY1NGE0YjYxMTFjZjE2NjBiNzFjY2Y4OTc4MTkzOCIsICJyZXZpc2lvbiI6IDE2OTgxNjcxMjYwNjQsICJzY2hlbWFfdmVyc2lvbiI6ICJ2MS4wLjAiLCAiYWN0aW9uIjogImVuYWJsZSIsICJsaWJfY29uZmlnIjogeyAibGlicmFyeV9sYW5ndWFnZSI6ICJhbGwiLCAibGlicmFyeV92ZXJzaW9uIjogImxhdGVzdCIsICJzZXJ2aWNlX25hbWUiOiAidGVzdHN2YyIsICJlbnYiOiAidGVzdCIsICJ0cmFjaW5nX2VuYWJsZWQiOiB0cnVlLCAidHJhY2luZ19zYW1wbGluZ19yYXRlIjogMC42IH0sICJzZXJ2aWNlX3RhcmdldCI6IHsgInNlcnZpY2UiOiAidGVzdHN2YyIsICJlbnYiOiAidGVzdCIgfSB9"
          },
          {
            "path": "employee/AGENT_TASK/test_rc_update/flare_task",
            "raw": "eyAiaWQiOiAiODI3ZWFjZjhkYmMzYWIxNDM0ZDMyMWNiODFkZmJmN2FmZTY1NGE0YjYxMTFjZjE2NjBiNzFjY2Y4OTc4MTkzOCIsICJyZXZpc2lvbiI6IDE2OTgxNjcxMjYwNjQsICJzY2hlbWFfdmVyc2lvbiI6ICJ2MS4wLjAiLCAiYWN0aW9uIjogImVuYWJsZSIsICJsaWJfY29uZmlnIjogeyAibGlicmFyeV9sYW5ndWFnZSI6ICJhbGwiLCAibGlicmFyeV92ZXJzaW9uIjogImxhdGVzdCIsICJzZXJ2aWNlX25hbWUiOiAidGVzdHN2YyIsICJlbnYiOiAidGVzdCIsICJ0cmFjaW5nX2VuYWJsZWQiOiB0cnVlLCAidHJhY2luZ19zYW1wbGluZ19yYXRlIjogMC42IH0sICJzZXJ2aWNlX3RhcmdldCI6IHsgInNlcnZpY2UiOiAidGVzdHN2YyIsICJlbnYiOiAidGVzdCIgfSB9"
          }
        ]
    })";

    const auto response_json =
        nlohmann::json::parse(/* input = */ rc_response,
                              /* parser_callback = */ nullptr,
                              /* allow_exceptions = */ false);

    REQUIRE(!response_json.is_discarded());

    auto tracing_listener = std::make_shared<FakeListener>();
    tracing_listener->products = rc::product::APM_TRACING;

    auto agent_listener = std::make_shared<FakeListener>();
    agent_listener->products =
        rc::product::AGENT_TASK | rc::product::AGENT_CONFIG;

    tracing_listener->update_callback =
        ([](const rc::Listener::Configuration& conf) {
          CHECK(conf.path == "employee/APM_TRACING/test_rc_update/lib_update");
          return "test error message";
        });

    rc::Manager rc(tracer_signature, {tracing_listener, agent_listener});
    rc.process_response(response_json);

    CHECK(tracing_listener->count_on_update == 1);
    CHECK(tracing_listener->count_on_revert == 0);
    CHECK(tracing_listener->count_on_post_process == 1);

    CHECK(agent_listener->count_on_update == 2);
    CHECK(agent_listener->count_on_revert == 0);
    CHECK(agent_listener->count_on_post_process == 1);

    SECTION("config states are reported on next payload") {
      const auto payload = rc.make_request_payload();
      REQUIRE(payload.contains("/client/state/config_states"_json_pointer) ==
              true);

      constexpr auto error_state = 3;
      constexpr auto acknowledged_state = 2;

      const auto& config_states =
          payload.at("/client/state/config_states"_json_pointer);
      REQUIRE(config_states.size() == 3);

      for (const auto& config_state : config_states) {
        if (config_state["product"] == "APM_TRACING") {
          CHECK(config_state["apply_state"] == error_state);
          CHECK(config_state["apply_error"] == "test error message");
        } else {
          CHECK(config_state["apply_state"] == acknowledged_state);
          CHECK(!config_state.contains("apply_error"));
        }
      }
    }

    SECTION("same config update should not trigger listeners") {
      rc.process_response(response_json);
      CHECK(tracing_listener->count_on_update == 1);
      CHECK(tracing_listener->count_on_revert == 0);
      CHECK(tracing_listener->count_on_post_process == 2);

      CHECK(agent_listener->count_on_update == 2);
      CHECK(agent_listener->count_on_revert == 0);
      CHECK(agent_listener->count_on_post_process == 2);
    }

    SECTION("new version of a config calls listeners") {
      std::string_view new_rc_response = R"({
          "targets": "ewogICAgInNpZ25lZCI6IHsKICAgICAgICAiY3VzdG9tIjogewogICAgICAgICAgICAiYWdlbnRfcmVmcmVzaF9pbnRlcnZhbCI6IDUsCiAgICAgICAgICAgICJvcGFxdWVfYmFja2VuZF9zdGF0ZSI6ICJleUoyWlhKemFXOXVJam95TENKemRHRjBaU0k2ZXlKbWFXeGxYMmhoYzJobGN5STZleUprWVhSaFpHOW5MekV3TURBeE1qVTROREF2UVZCTlgxUlNRVU5KVGtjdk9ESTNaV0ZqWmpoa1ltTXpZV0l4TkRNMFpETXlNV05pT0RGa1ptSm1OMkZtWlRZMU5HRTBZall4TVRGalpqRTJOakJpTnpGalkyWTRPVGM0TVRrek9DOHlPVEE0Tm1Ka1ltVTFNRFpsTmpoaU5UQm1NekExTlRneU0yRXpaR0UxWTJVd05USTRaakUyTkRCa05USmpaamc0TmpFNE1UWmhZV0U1Wm1ObFlXWTBJanBiSW05WVpESnBlVU16ZUM5b1JXc3hlWFZoWTFoR04xbHFjWEpwVGs5QldVdHVaekZ0V0UwMU5WWktUSGM5SWwxOWZYMD0iCiAgICAgICAgfSwKICAgICAgICAic3BlY192ZXJzaW9uIjogIjEuMC4wIiwKICAgICAgICAidGFyZ2V0cyI6IHsKICAgICAgICAgICAgImVtcGxveWVlL0FQTV9UUkFDSU5HL3Rlc3RfcmNfdXBkYXRlL2xpYl91cGRhdGUiOiB7CiAgICAgICAgICAgICAgICAiaGFzaGVzIjogewogICAgICAgICAgICAgICAgICAgICJzaGEyNTYiOiAiM2I5NDIxY2FhYTVkNzUzMTg0NWY3YzMwN2FkN2M2MTU1ZDgxOTVkMjcwOTEzMzY0OTI2YzlmNjQxZTkyNDE0NyIKICAgICAgICAgICAgICAgIH0sCiAgICAgICAgICAgICAgICAibGVuZ3RoIjogMzc0CiAgICAgICAgICAgIH0sCiAgICAgICAgICAgICJlbXBsb3llZS9BR0VOVF9UQVNLL3Rlc3RfcmNfdXBkYXRlL2ZsYXJlX3Rhc2siOiB7CiAgICAgICAgICAgICAgICAiaGFzaGVzIjogewogICAgICAgICAgICAgICAgICAgICJzaGEyNTYiOiAiNTY3NzQ4MWE4YzIxZDZjNzQwODI5ZmQxMDYxMDBmNDZmN2M1MWY1MjY1YjBiYTU0MGJjMTk4YmQ4MzM5Zjg3MiIKICAgICAgICAgICAgICAgIH0sCiAgICAgICAgICAgICAgICAibGVuZ3RoIjogMzc0CiAgICAgICAgICAgIH0sCiAgICAgICAgICAgICJlbXBsb3llZS9BR0VOVF9DT05GSUcvdGVzdF9yY191cGRhdGUvZmxhcmVfY29uZiI6IHsKICAgICAgICAgICAgICAgICJoYXNoZXMiOiB7CiAgICAgICAgICAgICAgICAgICAgInNoYTI1NiI6ICJlNjhlYzhkOWIxMWE4Y2Q1OGM4Y2E1ZTE0MjVkNjE2M2RiOTQ3ZWFhMzVmNzM4NTYxYzQ4NmUxNDRlOTRmYzUyIgogICAgICAgICAgICAgICAgfSwKICAgICAgICAgICAgICAgICJsZW5ndGgiOiAzNzQKICAgICAgICAgICAgfQogICAgICAgIH0sCiAgICAgICAgInZlcnNpb24iOiA2NjIwNDMyMAogICAgfQp9",
          "client_configs": [
              "employee/APM_TRACING/test_rc_update/lib_update",
              "employee/AGENT_TASK/test_rc_update/flare_task",
              "employee/AGENT_CONFIG/test_rc_update/flare_conf"
          ],
          "target_files": [
            {
              "path": "employee/AGENT_CONFIG/test_rc_update/flare_conf",
              "raw": "eyAiaWQiOiAiODI3ZWFjZjhkYmMzYWIxNDM0ZDMyMWNiODFkZmJmN2FmZTY1NGE0YjYxMTFjZjE2NjBiNzFjY2Y4OTc4MTkzOCIsICJyZXZpc2lvbiI6IDE2OTgxNjcxMjYwNjQsICJzY2hlbWFfdmVyc2lvbiI6ICJ2MS4wLjAiLCAiYWN0aW9uIjogImVuYWJsZSIsICJsaWJfY29uZmlnIjogeyAibGlicmFyeV9sYW5ndWFnZSI6ICJhbGwiLCAibGlicmFyeV92ZXJzaW9uIjogImxhdGVzdCIsICJzZXJ2aWNlX25hbWUiOiAidGVzdHN2YyIsICJlbnYiOiAidGVzdCIsICJ0cmFjaW5nX2VuYWJsZWQiOiB0cnVlLCAidHJhY2luZ19zYW1wbGluZ19yYXRlIjogMC42IH0sICJzZXJ2aWNlX3RhcmdldCI6IHsgInNlcnZpY2UiOiAidGVzdHN2YyIsICJlbnYiOiAidGVzdCIgfSB9"
            },
            {
              "path": "employee/APM_TRACING/test_rc_update/lib_update",
              "raw": "eyAiaWQiOiAiODI3ZWFjZjhkYmMzYWIxNDM0ZDMyMWNiODFkZmJmN2FmZTY1NGE0YjYxMTFjZjE2NjBiNzFjY2Y4OTc4MTkzOCIsICJyZXZpc2lvbiI6IDE2OTgxNjcxMjYwNjQsICJzY2hlbWFfdmVyc2lvbiI6ICJ2MS4wLjAiLCAiYWN0aW9uIjogImVuYWJsZSIsICJsaWJfY29uZmlnIjogeyAibGlicmFyeV9sYW5ndWFnZSI6ICJhbGwiLCAibGlicmFyeV92ZXJzaW9uIjogImxhdGVzdCIsICJzZXJ2aWNlX25hbWUiOiAidGVzdHN2YyIsICJlbnYiOiAidGVzdCIsICJ0cmFjaW5nX2VuYWJsZWQiOiB0cnVlLCAidHJhY2luZ19zYW1wbGluZ19yYXRlIjogMC42IH0sICJzZXJ2aWNlX3RhcmdldCI6IHsgInNlcnZpY2UiOiAidGVzdHN2YyIsICJlbnYiOiAidGVzdCIgfSB9"
            },
            {
              "path": "employee/AGENT_TASK/test_rc_update/flare_task",
              "raw": "eyAiaWQiOiAiODI3ZWFjZjhkYmMzYWIxNDM0ZDMyMWNiODFkZmJmN2FmZTY1NGE0YjYxMTFjZjE2NjBiNzFjY2Y4OTc4MTkzOCIsICJyZXZpc2lvbiI6IDE2OTgxNjcxMjYwNjQsICJzY2hlbWFfdmVyc2lvbiI6ICJ2MS4wLjAiLCAiYWN0aW9uIjogImVuYWJsZSIsICJsaWJfY29uZmlnIjogeyAibGlicmFyeV9sYW5ndWFnZSI6ICJhbGwiLCAibGlicmFyeV92ZXJzaW9uIjogImxhdGVzdCIsICJzZXJ2aWNlX25hbWUiOiAidGVzdHN2YyIsICJlbnYiOiAidGVzdCIsICJ0cmFjaW5nX2VuYWJsZWQiOiB0cnVlLCAidHJhY2luZ19zYW1wbGluZ19yYXRlIjogMC42IH0sICJzZXJ2aWNlX3RhcmdldCI6IHsgInNlcnZpY2UiOiAidGVzdHN2YyIsICJlbnYiOiAidGVzdCIgfSB9"
            }
          ]
      })";

      const auto response_json =
          nlohmann::json::parse(/* input = */ new_rc_response,
                                /* parser_callback = */ nullptr,
                                /* allow_exceptions = */ false);

      REQUIRE(!response_json.is_discarded());

      rc.process_response(response_json);

      CHECK(tracing_listener->count_on_update == 2);
      CHECK(tracing_listener->count_on_revert == 0);
      CHECK(tracing_listener->count_on_post_process == 2);

      CHECK(agent_listener->count_on_update == 4);
      CHECK(agent_listener->count_on_revert == 0);
      CHECK(agent_listener->count_on_post_process == 2);
    }

    SECTION("revert configuration update") {
      SECTION("partial revert") {
        // Removed `employee/APM_TRACING/test_rc_update/lib_update`
        // configuration update This should trigger a revert on `APM_TRACING`
        // listeners.
        std::string_view rc_partial_revert_response = R"({
            "targets": "ewogICAgInNpZ25lZCI6IHsKICAgICAgICAiY3VzdG9tIjogewogICAgICAgICAgICAiYWdlbnRfcmVmcmVzaF9pbnRlcnZhbCI6IDUsCiAgICAgICAgICAgICJvcGFxdWVfYmFja2VuZF9zdGF0ZSI6ICJleUoyWlhKemFXOXVJam95TENKemRHRjBaU0k2ZXlKbWFXeGxYMmhoYzJobGN5STZleUprWVhSaFpHOW5MekV3TURBeE1qVTROREF2UVZCTlgxUlNRVU5KVGtjdk9ESTNaV0ZqWmpoa1ltTXpZV0l4TkRNMFpETXlNV05pT0RGa1ptSm1OMkZtWlRZMU5HRTBZall4TVRGalpqRTJOakJpTnpGalkyWTRPVGM0TVRrek9DOHlPVEE0Tm1Ka1ltVTFNRFpsTmpoaU5UQm1NekExTlRneU0yRXpaR0UxWTJVd05USTRaakUyTkRCa05USmpaamc0TmpFNE1UWmhZV0U1Wm1ObFlXWTBJanBiSW05WVpESnBlVU16ZUM5b1JXc3hlWFZoWTFoR04xbHFjWEpwVGs5QldVdHVaekZ0V0UwMU5WWktUSGM5SWwxOWZYMD0iCiAgICAgICAgfSwKICAgICAgICAic3BlY192ZXJzaW9uIjogIjEuMC4wIiwKICAgICAgICAidGFyZ2V0cyI6IHsKICAgICAgICAgICAgImVtcGxveWVlL0FHRU5UX1RBU0svdGVzdF9yY191cGRhdGUvZmxhcmVfdGFzayI6IHsKICAgICAgICAgICAgICAgICJoYXNoZXMiOiB7CiAgICAgICAgICAgICAgICAgICAgInNoYTI1NiI6ICI0MTk0Y2U2ZjcxMTM5NTk0NmJlODM3YmY1ZWJhOTQ4OTFiN2JkZTc5ODkxMWVkNWVmZmY2NTk5ZDIxYWI5Njk2IgogICAgICAgICAgICAgICAgfSwKICAgICAgICAgICAgICAgICJsZW5ndGgiOiAzNzQKICAgICAgICAgICAgfSwKICAgICAgICAgICAgImVtcGxveWVlL0FHRU5UX0NPTkZJRy90ZXN0X3JjX3VwZGF0ZS9mbGFyZV9jb25mIjogewogICAgICAgICAgICAgICAgImhhc2hlcyI6IHsKICAgICAgICAgICAgICAgICAgICAic2hhMjU2IjogIjJkNzhhZTczNmEzZmM0NTViNzIzMWRhZjk5NDVmOGRmNzA0ZjE3MjViNTBkZGU0NmQwY2JjZGMzZjBlMTFkNDEiCiAgICAgICAgICAgICAgICB9LAogICAgICAgICAgICAgICAgImxlbmd0aCI6IDM3NAogICAgICAgICAgICB9CiAgICAgCiAgICAgICAgfSwKICAgICAgICAidmVyc2lvbiI6IDY2MjA0MzIwCiAgICB9Cn0=",
            "client_configs": [
                "employee/AGENT_TASK/test_rc_update/flare_task",
                "employee/AGENT_CONFIG/test_rc_update/flare_conf"
            ],
            "target_files": [
              {
                "path": "employee/AGENT_CONFIG/test_rc_update/flare_conf",
                "raw": "eyAiaWQiOiAiODI3ZWFjZjhkYmMzYWIxNDM0ZDMyMWNiODFkZmJmN2FmZTY1NGE0YjYxMTFjZjE2NjBiNzFjY2Y4OTc4MTkzOCIsICJyZXZpc2lvbiI6IDE2OTgxNjcxMjYwNjQsICJzY2hlbWFfdmVyc2lvbiI6ICJ2MS4wLjAiLCAiYWN0aW9uIjogImVuYWJsZSIsICJsaWJfY29uZmlnIjogeyAibGlicmFyeV9sYW5ndWFnZSI6ICJhbGwiLCAibGlicmFyeV92ZXJzaW9uIjogImxhdGVzdCIsICJzZXJ2aWNlX25hbWUiOiAidGVzdHN2YyIsICJlbnYiOiAidGVzdCIsICJ0cmFjaW5nX2VuYWJsZWQiOiB0cnVlLCAidHJhY2luZ19zYW1wbGluZ19yYXRlIjogMC42IH0sICJzZXJ2aWNlX3RhcmdldCI6IHsgInNlcnZpY2UiOiAidGVzdHN2YyIsICJlbnYiOiAidGVzdCIgfSB9"
              },
              {
                "path": "employee/AGENT_TASK/test_rc_update/flare_task",
                "raw": "eyAiaWQiOiAiODI3ZWFjZjhkYmMzYWIxNDM0ZDMyMWNiODFkZmJmN2FmZTY1NGE0YjYxMTFjZjE2NjBiNzFjY2Y4OTc4MTkzOCIsICJyZXZpc2lvbiI6IDE2OTgxNjcxMjYwNjQsICJzY2hlbWFfdmVyc2lvbiI6ICJ2MS4wLjAiLCAiYWN0aW9uIjogImVuYWJsZSIsICJsaWJfY29uZmlnIjogeyAibGlicmFyeV9sYW5ndWFnZSI6ICJhbGwiLCAibGlicmFyeV92ZXJzaW9uIjogImxhdGVzdCIsICJzZXJ2aWNlX25hbWUiOiAidGVzdHN2YyIsICJlbnYiOiAidGVzdCIsICJ0cmFjaW5nX2VuYWJsZWQiOiB0cnVlLCAidHJhY2luZ19zYW1wbGluZ19yYXRlIjogMC42IH0sICJzZXJ2aWNlX3RhcmdldCI6IHsgInNlcnZpY2UiOiAidGVzdHN2YyIsICJlbnYiOiAidGVzdCIgfSB9"
              }
            ]
        })";

        const auto response_json =
            nlohmann::json::parse(/* input = */ rc_partial_revert_response,
                                  /* parser_callback = */ nullptr,
                                  /* allow_exceptions = */ false);

        REQUIRE(!response_json.is_discarded());

        rc.process_response(response_json);

        CHECK(tracing_listener->count_on_update == 1);
        CHECK(tracing_listener->count_on_revert == 1);
        CHECK(tracing_listener->count_on_post_process == 2);

        CHECK(agent_listener->count_on_update == 2);
        CHECK(agent_listener->count_on_revert == 0);
        CHECK(agent_listener->count_on_post_process == 2);
      }

      SECTION("missing client_configs field triggers a full revert") {
        std::string_view rc_revert_response = R"({
          "targets": "ewogICAgInNpZ25lZCI6IHsKICAgICAgICAiY3VzdG9tIjogewogICAgICAgICAgICAiYWdlbnRfcmVmcmVzaF9pbnRlcnZhbCI6IDUsCiAgICAgICAgICAgICJvcGFxdWVfYmFja2VuZF9zdGF0ZSI6ICJleUoyWlhKemFXOXVJam95TENKemRHRjBaU0k2ZXlKbWFXeGxYMmhoYzJobGN5STZleUprWVhSaFpHOW5MekV3TURBeE1qVTROREF2UVZCTlgxUlNRVU5KVGtjdk9ESTNaV0ZqWmpoa1ltTXpZV0l4TkRNMFpETXlNV05pT0RGa1ptSm1OMkZtWlRZMU5HRTBZall4TVRGalpqRTJOakJpTnpGalkyWTRPVGM0TVRrek9DOHlPVEE0Tm1Ka1ltVTFNRFpsTmpoaU5UQm1NekExTlRneU0yRXpaR0UxWTJVd05USTRaakUyTkRCa05USmpaamc0TmpFNE1UWmhZV0U1Wm1ObFlXWTBJanBiSW05WVpESnBlVU16ZUM5b1JXc3hlWFZoWTFoR04xbHFjWEpwVGs5QldVdHVaekZ0V0UwMU5WWktUSGM5SWwxOWZYMD0iCiAgICAgICAgfSwKICAgICAgICAic3BlY192ZXJzaW9uIjogIjEuMC4wIiwKICAgICAgICAidGFyZ2V0cyI6IHsKICAgICAgICAgICAgImVtcGxveWVlL0FQTV9UUkFDSU5HL3Rlc3RfcmNfdXBkYXRlL2xpYl91cGRhdGUiOiB7CiAgICAgICAgICAgICAgICAiaGFzaGVzIjogewogICAgICAgICAgICAgICAgICAgICJzaGEyNTYiOiAiYTE3Nzc2OGIyMGI3YzdmODQ0OTM1Y2FlNjljNWM1ZWQ4OGVhYWUyMzRlMDE4MmE3ODM1OTk3MzM5ZTU1MjRiYyIKICAgICAgICAgICAgICAgIH0sCiAgICAgICAgICAgICAgICAibGVuZ3RoIjogMzc0CiAgICAgICAgICAgIH0sCiAgICAgICAgICAgICJlbXBsb3llZS9BR0VOVF9UQVNLL3Rlc3RfcmNfdXBkYXRlL2ZsYXJlX3Rhc2siOiB7CiAgICAgICAgICAgICAgICAiaGFzaGVzIjogewogICAgICAgICAgICAgICAgICAgICJzaGEyNTYiOiAiNDE5NGNlNmY3MTEzOTU5NDZiZTgzN2JmNWViYTk0ODkxYjdiZGU3OTg5MTFlZDVlZmZmNjU5OWQyMWFiOTY5NiIKICAgICAgICAgICAgICAgIH0sCiAgICAgICAgICAgICAgICAibGVuZ3RoIjogMzc0CiAgICAgICAgICAgIH0sCiAgICAgICAgICAgICJlbXBsb3llZS9BR0VOVF9DT05GSUcvdGVzdF9yY191cGRhdGUvZmxhcmVfY29uZiI6IHsKICAgICAgICAgICAgICAgICJoYXNoZXMiOiB7CiAgICAgICAgICAgICAgICAgICAgInNoYTI1NiI6ICIyZDc4YWU3MzZhM2ZjNDU1YjcyMzFkYWY5OTQ1ZjhkZjcwNGYxNzI1YjUwZGRlNDZkMGNiY2RjM2YwZTExZDQxIgogICAgICAgICAgICAgICAgfSwKICAgICAgICAgICAgICAgICJsZW5ndGgiOiAzNzQKICAgICAgICAgICAgfQogICAgIAogICAgICAgIH0sCiAgICAgICAgInZlcnNpb24iOiA2NjIwNDMyMAogICAgfQp9",
          "target_files": [{}]
        })";

        const auto response_json =
            nlohmann::json::parse(/* input = */ rc_revert_response,
                                  /* parser_callback = */ nullptr,
                                  /* allow_exceptions = */ false);

        REQUIRE(!response_json.is_discarded());

        rc.process_response(response_json);

        CHECK(tracing_listener->count_on_update == 1);
        CHECK(tracing_listener->count_on_revert == 1);
        CHECK(tracing_listener->count_on_post_process == 2);

        CHECK(agent_listener->count_on_update == 2);
        CHECK(agent_listener->count_on_revert == 2);
        CHECK(agent_listener->count_on_post_process == 2);
      }
    }
  }
}
