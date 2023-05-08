// Read lines from standard input, interpreting each as a file path.
//
// If the path does not exist, print an error.
//
// If the path exists and is a regular file, print the SHA256 digest of the
// file's contents.
//
// If the path exists and is a directory, calculate the SHA256 digest of the
// directory from the names and digests of its children, combined in some
// canonical format.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "picosha2.h"

namespace fs = std::filesystem;

using Digest = std::array<char, picosha2::k_digest_size>;

// Return the specified `digest` formatted as a lower case hexadecimal string.
std::string hex(const Digest &digest) {
  std::string result;
  for (std::size_t i = 0; i < digest.size(); ++i) {
    char buf[2 + 1];
    std::snprintf(buf, sizeof buf, "%02x",
                  static_cast<unsigned char>(digest[i]));
    result.append(buf, 2);
  }
  return result;
}

// Store into the specified `digest` the SHA256 digest of the contents of the
// specified `file`.  Return zero on success, or a nonzero value if an error
// occurs.
int sha256(Digest &digest, const fs::path &file) {
  std::ifstream in(file);
  if (!in) {
    return 1;
  }
  picosha2::hash256(in, digest.begin(), digest.end());
  return 0;
}

// Return the SHA256 digest of a directory having the specified `children`.
// This function will sort  `children` in place.
Digest sha256(std::vector<std::pair<fs::path, Digest>> &children) {
  std::sort(children.begin(), children.end());

  std::vector<char> descriptor;
  for (const auto &record : children) {
    const std::string path = record.first.filename().u8string();
    const Digest &hash = record.second;
    descriptor.insert(descriptor.end(), path.begin(), path.end());
    descriptor.insert(descriptor.end(), hash.begin(), hash.end());
  }

  Digest digest;
  picosha2::hash256(descriptor, digest);
  return digest;
}

int sha256_traced(Digest &digest, const fs::path &path) try {
  if (fs::is_directory(path)) {
    // Directory: Calculate hash of children, and then combine them.
    std::vector<std::pair<fs::path, Digest>> children;
    const auto options = fs::directory_options::skip_permission_denied;
    for (const auto &entry : fs::directory_iterator(path, options)) {
      if (!(entry.is_regular_file() || entry.is_directory())) {
        continue;
      }
      Digest hash;
      const fs::path &child = entry;
      if (sha256_traced(hash, child)) {
        return 1;
      }
      children.emplace_back(child, hash);
    }
    digest = sha256(children);
    return 0;
  } else if (fs::is_regular_file(path)) {
    // Regular file: Calculate hash of file contents.
    return sha256(digest, path);
  } else {
    // Other kind of file (neither directory nor regular file): Ignore.
    return 1;
  }
} catch (const fs::filesystem_error &) {
  return 1;
} catch (const std::ios_base::failure &) {
  return 1;
}

int main() {
  const std::string prompt = "enter a file or directory (ctrl+d to quit): ";
  std::string input_path;
  while (std::cout << prompt << std::flush,
         std::getline(std::cin, input_path)) {
    const fs::path path(input_path);

    if (!fs::exists(path)) {
      std::cerr << "The file " << path << " does not exist.\n";
      continue;
    }

    Digest digest;
    if (sha256_traced(digest, path)) {
      std::cerr << "Unable to calculate the sha256 hash of " << path << ".\n";
    } else {
      const std::string hex_digest = hex(digest);
      std::cout << "sha256(" << path << "): " << hex_digest << std::endl;
    }
  }

  std::cout << "\n";
}
