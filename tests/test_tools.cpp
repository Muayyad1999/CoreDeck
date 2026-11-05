#include <filesystem>
#include <set>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include "core/tools.h"

using namespace CoreDeck::Core;
using namespace CoreDeck;

TEST_CASE("SplitSearchPath splits and unquotes", "[tools]") {
    REQUIRE(SplitSearchPath("/usr/bin:/bin:/opt/x", ':') == std::vector<std::string>{"/usr/bin", "/bin", "/opt/x"});

    // Empty entries dropped.
    REQUIRE(SplitSearchPath("::/a::", ':') == std::vector<std::string>{"/a"});

    // Windows-style with a quoted entry.
    REQUIRE(SplitSearchPath("C:\\tools;\"C:\\Program Files\\x\"", ';') == std::vector<std::string>{"C:\\tools", "C:\\Program Files\\x"});

    REQUIRE(SplitSearchPath("", ':').empty());
}

TEST_CASE("ExecutableCandidates keeps a name that already has an extension", "[tools]") {
    // A name with its own extension is tried as-is on every platform.
    const auto withExt = ExecutableCandidates("apktool.bat");
    REQUIRE(withExt.front() == "apktool.bat");

    // A plain name always includes itself as a candidate.
    const auto plain = ExecutableCandidates("apktool");
    bool hasPlain = false;
    for (const auto &c: plain) {
        if (c == "apktool") {
            hasPlain = true;
        }
    }
    REQUIRE(hasPlain);
}

TEST_CASE("ReToolRegistry is well-formed", "[tools]") {
    const auto &registry = ReToolRegistry();
    REQUIRE_FALSE(registry.empty());

    std::set<std::string> keys;
    for (const auto &spec: registry) {
        REQUIRE_FALSE(spec.Key.empty());
        REQUIRE_FALSE(spec.Name.empty());
        REQUIRE_FALSE(spec.UsedFor.empty());
        REQUIRE_FALSE(spec.ExeNames.empty());
        REQUIRE_FALSE(spec.InstallHint.empty());
        REQUIRE(keys.insert(spec.Key).second); // unique key
    }

    // The tools nothing works without are marked required.
    for (const auto &spec: registry) {
        if (spec.Key == "adb" || spec.Key == "java") {
            REQUIRE_FALSE(spec.Optional);
        }
    }
}

TEST_CASE("ResolveExecutable honors an existing override path", "[tools]") {
    // An override that points at a real file resolves to it; this source file
    // itself is a guaranteed-present stand-in.
    const std::string existing = __FILE__;
    if (std::filesystem::exists(existing)) {
        const auto resolved = ResolveExecutable({"definitely-not-a-real-tool-xyz"}, existing);
        REQUIRE(resolved.has_value());
    }

    // A bogus name with no override does not resolve.
    REQUIRE_FALSE(ResolveExecutable({"definitely-not-a-real-tool-xyz"}).has_value());
}
