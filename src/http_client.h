#pragma once

#include <functional>
#include <iosfwd>
#include <optional>
#include <string_view>
#include <variant>

#include "error.h"

namespace datadog {
namespace tracing {

class DictReader;
class DictWriter;

class HTTPClient {
 public:
  struct URL {
    std::string scheme;     // http, https, or unix
    std::string authority;  // domain:port or /path/to/socket
    std::string path;       // resource, e.g. /v0.4/traces

    static std::variant<URL, Error> parse(std::string_view);
  };

  using HeadersSetter = std::function<void(DictWriter& headers)>;
  using ResponseHandler = std::function<void(
      int status, const DictReader& headers, std::string body)>;
  // `ErrorHandler` is for errors encountered by `HTTPClient`, not for
  // error-indicating HTTP responses.
  using ErrorHandler = std::function<void(Error)>;

  virtual std::optional<Error> post(const URL& url, HeadersSetter set_headers,
                                    std::string body,
                                    ResponseHandler on_response,
                                    ErrorHandler on_error) = 0;

  virtual ~HTTPClient() = default;
};

std::ostream& operator<<(std::ostream&, const HTTPClient::URL&);

}  // namespace tracing
}  // namespace datadog
