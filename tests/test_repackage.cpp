#include <string>

#include <catch2/catch_test_macros.hpp>

#include "core/repackage.h"

using namespace CoreDeck::Core;
using namespace CoreDeck;

TEST_CASE("ParsePmPath strips the package: prefix", "[repackage]") {
    const std::string out =
        "package:/data/app/~~abc==/com.example.app-1/base.apk\n"
        "package:/data/app/~~abc==/com.example.app-1/split_config.arm64_v8a.apk\r\n"
        "\n"
        "package:/data/app/~~abc==/com.example.app-1/split_config.xxhdpi.apk\n";
    const auto paths = ParsePmPath(out);
    REQUIRE(paths.size() == 3);
    REQUIRE(paths[0] == "/data/app/~~abc==/com.example.app-1/base.apk");
    REQUIRE(paths[1] == "/data/app/~~abc==/com.example.app-1/split_config.arm64_v8a.apk");
    REQUIRE(paths[2] == "/data/app/~~abc==/com.example.app-1/split_config.xxhdpi.apk");
}

TEST_CASE("ParsePmPath ignores non-package lines", "[repackage]") {
    REQUIRE(ParsePmPath("unknown command\n").empty());
    REQUIRE(ParsePmPath("").empty());
}

TEST_CASE("ApkEditorMergeArgs builds the merge argv", "[repackage]") {
    REQUIRE(ApkEditorMergeArgs("/in/dir", "/out/app.apk") == std::vector<std::string>{"m", "-i", "/in/dir", "-o", "/out/app.apk", "-f"});
    REQUIRE(ApkEditorMergeArgs("/in/dir", "/out/app.apk", false) == std::vector<std::string>{"m", "-i", "/in/dir", "-o", "/out/app.apk"});
}

TEST_CASE("ApkMitmOutputPath mirrors apk-mitm's naming", "[repackage]") {
    REQUIRE(ApkMitmOutputPath("/tmp/com.example-merged.apk") == "/tmp/com.example-merged-patched.apk");
    // Case-insensitive .APK extension is handled.
    REQUIRE(ApkMitmOutputPath("/tmp/App.APK") == "/tmp/App-patched.apk");
}

TEST_CASE("ObjectionOutputPath mirrors objection's naming", "[repackage]") {
    REQUIRE(ObjectionOutputPath("/tmp/com.example-merged.apk") == "/tmp/com.example-merged.objection.apk");
}

TEST_CASE("ObjectionPatchArgs builds the gadget-inject argv", "[repackage]") {
    REQUIRE(ObjectionPatchArgs("/tmp/app.apk", "arm64-v8a", true) == std::vector<std::string>{"patchapk", "-s", "/tmp/app.apk", "-a", "arm64-v8a", "-N"});
    REQUIRE(ObjectionPatchArgs("/tmp/app.apk", "x86_64", false) == std::vector<std::string>{"patchapk", "-s", "/tmp/app.apk", "-a", "x86_64"});
}

TEST_CASE("ChooseMethod resolves Auto by app type and passes others through", "[repackage]") {
    REQUIRE(ChooseMethod(PinningMethod::Auto, true) == PinningMethod::FlutterStatic);
    REQUIRE(ChooseMethod(PinningMethod::Auto, false) == PinningMethod::ApkMitm);
    REQUIRE(ChooseMethod(PinningMethod::ApkMitm, true) == PinningMethod::ApkMitm);
    REQUIRE(ChooseMethod(PinningMethod::FlutterStatic, false) == PinningMethod::FlutterStatic);
    REQUIRE(ChooseMethod(PinningMethod::Gadget, true) == PinningMethod::Gadget);
    REQUIRE(ChooseMethod(PinningMethod::Reflutter, false) == PinningMethod::Reflutter);
    REQUIRE(ChooseMethod(PinningMethod::None, true) == PinningMethod::None);
}

TEST_CASE("PinningMethodLabel is stable", "[repackage]") {
    REQUIRE(std::string(PinningMethodLabel(PinningMethod::ApkMitm)) == "apk-mitm");
    REQUIRE(std::string(PinningMethodLabel(PinningMethod::FlutterStatic)) == "flutter-static");
    REQUIRE(std::string(PinningMethodLabel(PinningMethod::Gadget)) == "gadget");
    REQUIRE(std::string(PinningMethodLabel(PinningMethod::Reflutter)) == "reflutter");
    REQUIRE(std::string(PinningMethodLabel(PinningMethod::None)) == "none");
}

TEST_CASE("RepackageResult::AllOk tracks step failures", "[repackage]") {
    RepackageResult empty;
    REQUIRE_FALSE(empty.AllOk());

    RepackageResult good;
    good.Steps.push_back({"Merge", true, ""});
    good.Steps.push_back({"Sign", true, ""});
    REQUIRE(good.AllOk());

    RepackageResult bad;
    bad.Steps.push_back({"Merge", true, ""});
    bad.Steps.push_back({"Patch", false, "boom"});
    REQUIRE_FALSE(bad.AllOk());
}
