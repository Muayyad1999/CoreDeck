#include <string>

#include <catch2/catch_test_macros.hpp>

#include "core/frida.h"

using namespace CoreDeck::Core;
using namespace CoreDeck;

TEST_CASE("AbiToFridaArch maps Android ABIs to frida arch suffixes", "[frida]") {
    REQUIRE(AbiToFridaArch("arm64-v8a") == "arm64");
    REQUIRE(AbiToFridaArch("armeabi-v7a") == "arm");
    REQUIRE(AbiToFridaArch("x86_64") == "x86_64");
    REQUIRE(AbiToFridaArch("x86") == "x86");
    REQUIRE(AbiToFridaArch("mips") == "arm64"); // fallback
}

TEST_CASE("FridaServer asset name and URL", "[frida]") {
    REQUIRE(FridaServerAssetName("16.1.4", "x86_64") == "frida-server-16.1.4-android-x86_64");
    REQUIRE(FridaServerDownloadUrl("16.1.4", "arm64-v8a") == "https://github.com/frida/frida/releases/download/16.1.4/frida-server-16.1.4-android-arm64.xz");
}

TEST_CASE("ParseFridaVersion keeps the version token", "[frida]") {
    REQUIRE(ParseFridaVersion("16.1.4\n") == "16.1.4");
    REQUIRE(ParseFridaVersion("  16.1.4  ") == "16.1.4");
    REQUIRE(ParseFridaVersion("") == "");
}

TEST_CASE("ParseFridaPs reads pid/name rows and drops the header", "[frida]") {
    const std::string output =
        " PID  Name\n"
        "----  ------------------\n"
        "1234  com.example.app\n"
        " 567  system_server\n"
        "\n";
    const auto rows = ParseFridaPs(output);
    REQUIRE(rows.size() == 2);
    REQUIRE(rows.at(0).Pid == 1234);
    REQUIRE(rows.at(0).Name == "com.example.app");
    REQUIRE(rows.at(1).Pid == 567);
    REQUIRE(rows.at(1).Name == "system_server");
}
