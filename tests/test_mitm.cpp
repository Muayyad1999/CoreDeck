#include <string>

#include <catch2/catch_test_macros.hpp>

#include "core/mitm.h"

using namespace CoreDeck::Core;
using namespace CoreDeck;

TEST_CASE("MonkeyLaunchArgs builds the launcher intent argv", "[mitm]") {
    const auto args = MonkeyLaunchArgs("com.example.app");
    REQUIRE(args == std::vector<std::string>{"monkey", "-p", "com.example.app", "-c", "android.intent.category.LAUNCHER", "1"});
}

TEST_CASE("ValidateMitmOptions requires at least one step", "[mitm]") {
    MitmOptions opts;
    opts.TrustCert = false;
    opts.SetProxyStep = false;
    opts.Launch = false;
    std::string error;
    REQUIRE_FALSE(ValidateMitmOptions(opts, error));
    REQUIRE_FALSE(error.empty());
}

TEST_CASE("ValidateMitmOptions enforces each step's input", "[mitm]") {
    std::string error;

    SECTION("trust needs a cert") {
        MitmOptions opts;
        opts.TrustCert = true;
        opts.SetProxyStep = false;
        opts.Launch = false;
        REQUIRE_FALSE(ValidateMitmOptions(opts, error));
    }
    SECTION("proxy needs a target") {
        MitmOptions opts;
        opts.TrustCert = false;
        opts.SetProxyStep = true;
        opts.Launch = false;
        REQUIRE_FALSE(ValidateMitmOptions(opts, error));
    }
    SECTION("launch needs a package") {
        MitmOptions opts;
        opts.TrustCert = false;
        opts.SetProxyStep = false;
        opts.Launch = true;
        REQUIRE_FALSE(ValidateMitmOptions(opts, error));
    }
}

TEST_CASE("ValidateMitmOptions accepts a complete plan", "[mitm]") {
    MitmOptions opts;
    opts.TrustCert = true;
    opts.CertPath = "/tmp/burp.pem";
    opts.SetProxyStep = true;
    opts.ProxyTarget = "10.0.2.2:8080";
    opts.Launch = true;
    opts.Package = "com.example.app";
    std::string error;
    REQUIRE(ValidateMitmOptions(opts, error));
    REQUIRE(error.empty());
}

TEST_CASE("MitmResult::AllOk is false when empty and tracks step failures", "[mitm]") {
    MitmResult empty;
    REQUIRE_FALSE(empty.AllOk());

    MitmResult mixed;
    mixed.Steps.push_back({"a", true, ""});
    mixed.Steps.push_back({"b", false, "boom"});
    REQUIRE_FALSE(mixed.AllOk());

    MitmResult good;
    good.Steps.push_back({"a", true, ""});
    REQUIRE(good.AllOk());
}
