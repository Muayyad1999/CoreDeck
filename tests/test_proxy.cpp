#include <string>

#include <catch2/catch_test_macros.hpp>

#include "core/proxy.h"

using namespace CoreDeck::Core;
using namespace CoreDeck;

TEST_CASE("NormalizeProxyTarget assumes the emulator host for a bare port", "[proxy]") {
    REQUIRE(NormalizeProxyTarget("8080") == "10.0.2.2:8080");
    REQUIRE(NormalizeProxyTarget("192.168.1.5:8888") == "192.168.1.5:8888");
    REQUIRE(NormalizeProxyTarget("  8080  ") == "10.0.2.2:8080");
    REQUIRE(NormalizeProxyTarget("").empty());
}

TEST_CASE("IsProxyEnabledValue treats :0 / empty / null as off", "[proxy]") {
    REQUIRE(IsProxyEnabledValue("10.0.2.2:8080"));
    REQUIRE_FALSE(IsProxyEnabledValue(":0"));
    REQUIRE_FALSE(IsProxyEnabledValue(""));
    REQUIRE_FALSE(IsProxyEnabledValue("null"));
    REQUIRE_FALSE(IsProxyEnabledValue("  \n"));
}

TEST_CASE("ParseIptablesDnat keeps only the DNAT rules", "[proxy]") {
    const std::string output =
        "-P OUTPUT ACCEPT\n"
        "-A OUTPUT -p tcp -m tcp --dport 80 -j DNAT --to-destination 10.0.2.2:8080\n"
        "-A OUTPUT -p tcp -m tcp --dport 443 -j DNAT --to-destination 10.0.2.2:8080\n"
        "-A OUTPUT -j ACCEPT\n";
    const auto rules = ParseIptablesDnat(output);
    REQUIRE(rules.size() == 2);
    REQUIRE(rules.at(0).find("--dport 80") != std::string::npos);
    REQUIRE(rules.at(1).find("--dport 443") != std::string::npos);
}

TEST_CASE("ParseProxyStatus combines the setting and the nat rules", "[proxy]") {
    const auto on = ParseProxyStatus("10.0.2.2:8080\n", "-A OUTPUT -j DNAT --to-destination 10.0.2.2:8080\n");
    REQUIRE(on.Enabled);
    REQUIRE(on.HttpProxy == "10.0.2.2:8080");
    REQUIRE(on.DnatRules.size() == 1);

    const auto off = ParseProxyStatus(":0\n", "");
    REQUIRE_FALSE(off.Enabled);
    REQUIRE(off.DnatRules.empty());
}
