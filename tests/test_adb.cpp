#include <algorithm>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include "core/adb.h"

using namespace CoreDeck::Core;
using namespace CoreDeck;

TEST_CASE("ParseAdbDevices keeps serials with their state and drops the header", "[adb]") {
    const auto devices = ParseAdbDevices(
        "List of devices attached\r\n"
        "emulator-5554\tdevice\n"
        "0a388e9341237def\toffline\r\n"
        "R58M30abcdef\tunauthorized\n"
    );

    REQUIRE(devices.size() == 3);
    REQUIRE(devices.at(0).Serial == "emulator-5554");
    REQUIRE(devices.at(0).State == "device");
    REQUIRE(devices.at(0).Online());
    REQUIRE(devices.at(1).Serial == "0a388e9341237def");
    REQUIRE(devices.at(1).State == "offline");
    REQUIRE_FALSE(devices.at(1).Online());
    REQUIRE(devices.at(2).State == "unauthorized");
    REQUIRE_FALSE(devices.at(2).Online());
}

TEST_CASE("ParseAdbDevices ignores daemon notices and blank lines", "[adb]") {
    const auto devices = ParseAdbDevices(
        "* daemon not running; starting now at tcp:5037\n"
        "* daemon started successfully\n"
        "\n"
        "emulator-5556\tdevice\n"
    );

    REQUIRE(devices.size() == 1);
    REQUIRE(devices.at(0).Serial == "emulator-5556");
    REQUIRE(devices.at(0).State == "device");
}

TEST_CASE("ParseAdbDevices captures multi-word states", "[adb]") {
    const auto devices = ParseAdbDevices(
        "List of devices attached\n"
        "1234abcd\tno permissions (udev rules); see [http://example]\n"
    );

    REQUIRE(devices.size() == 1);
    REQUIRE(devices.at(0).Serial == "1234abcd");
    REQUIRE(devices.at(0).State == "no permissions (udev rules); see [http://example]");
    REQUIRE_FALSE(devices.at(0).Online());
}

TEST_CASE("ParseAdbDevices returns nothing when only the header is present", "[adb]") {
    REQUIRE(ParseAdbDevices("List of devices attached\n").empty());
}

TEST_CASE("ParsePackageList strips the package prefix and skips noise", "[adb]") {
    const auto packages = ParsePackageList(
        "package:com.example.app\r\n"
        "package:org.foo.bar\n"
        "some unrelated line\n"
        "package:\n"
    );

    REQUIRE(packages.size() == 2);
    REQUIRE(packages.at(0) == "com.example.app");
    REQUIRE(packages.at(1) == "org.foo.bar");
}

TEST_CASE("ParsePackagePaths keeps only user-installed locations", "[adb]") {
    const auto packages = ParsePackagePaths(
        "package:/data/app/~~tok==/com.example.app-1/base.apk=com.example.app\n"
        "package:/system/app/Chrome/Chrome.apk=com.android.chrome\n"
        "package:/mnt/expand/DEADBEEF/app/com.sideload.tool-1/base.apk=com.sideload.tool\n"
        "package:/product/app/Foo/Foo.apk=com.vendor.foo\n"
    );

    REQUIRE(packages.size() == 2);
    REQUIRE(packages.at(0) == "com.example.app");
    REQUIRE(packages.at(1) == "com.sideload.tool");
}

TEST_CASE("IsVendorPackage matches Google/Samsung/OS namespaces only", "[adb]") {
    REQUIRE(IsVendorPackage("com.google.android.gms"));
    REQUIRE(IsVendorPackage("com.android.chrome"));
    REQUIRE(IsVendorPackage("com.android.vending"));
    REQUIRE(IsVendorPackage("com.samsung.android.app"));
    REQUIRE(IsVendorPackage("com.sec.android.app.launcher"));
    REQUIRE(IsVendorPackage("com.knox.vpn"));

    REQUIRE_FALSE(IsVendorPackage("com.example.app"));
    REQUIRE_FALSE(IsVendorPackage("org.foo.bar"));
    // Not a blanket com.android.* filter - only the enumerated OS apps.
    REQUIRE_FALSE(IsVendorPackage("com.android.unknownthirdparty"));
}

TEST_CASE("DiscoverUserPackages unions -3 and -f, drops vendor, sorts and dedups", "[adb]") {
    const std::string thirdParty =
        "package:org.foo.bar\n"
        "package:com.example.app\n"
        "package:com.google.android.gms\n";
    const std::string withPaths =
        "package:/data/app/com.example.app-1/base.apk=com.example.app\n" // duplicate of -3
        "package:/system/app/Chrome/Chrome.apk=com.android.chrome\n" // filtered by path
        "package:/mnt/expand/X/app/com.sideload.tool-1/base.apk=com.sideload.tool\n";

    const auto filtered = DiscoverUserPackages(thirdParty, withPaths, "", false);
    REQUIRE(filtered.size() == 3);
    REQUIRE(filtered.at(0) == "com.example.app");
    REQUIRE(filtered.at(1) == "com.sideload.tool");
    REQUIRE(filtered.at(2) == "org.foo.bar");

    const auto withVendor = DiscoverUserPackages(thirdParty, withPaths, "", true);
    REQUIRE(withVendor.size() == 4);
    REQUIRE(std::find(withVendor.begin(), withVendor.end(), "com.google.android.gms") != withVendor.end());
}

TEST_CASE("DiscoverUserPackages falls back to the full list when -3 and -f are empty", "[adb]") {
    const std::string all =
        "package:com.foo\n"
        "package:com.google.android.gms\n";

    const auto filtered = DiscoverUserPackages("", "", all, false);
    REQUIRE(filtered.size() == 1);
    REQUIRE(filtered.at(0) == "com.foo");

    const auto withVendor = DiscoverUserPackages("", "", all, true);
    REQUIRE(withVendor.size() == 2);
}

TEST_CASE("ResolveAdbPath builds a platform-tools path or stays empty", "[adb]") {
    SdkInfo empty;
    REQUIRE(ResolveAdbPath(empty).empty());

    SdkInfo sdk;
    sdk.SdkPath = "/opt/android-sdk";
    const std::string adb = ResolveAdbPath(sdk);
    REQUIRE(adb.find("platform-tools") != std::string::npos);
    REQUIRE(adb.find("adb") != std::string::npos);
}
