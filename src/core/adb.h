//
// Created by CoreDeck RE toolbench on 03/11/2026.
//

#ifndef COREDECK_ADB_H
#define COREDECK_ADB_H

#include <string>
#include <vector>

#include "core/sdk.h"

namespace CoreDeck::Core {
    struct AdbDevice {
        std::string Serial;
        std::string State; // "device", "offline", "unauthorized", "no permissions", ...

        bool Online() const {
            return State == "device";
        }
    };

    struct AdbResult {
        bool Started = false;
        int ExitCode = -1;
        std::string Output;

        bool Ok() const {
            return Started && ExitCode == 0;
        }
    };

    // A device plus the identifying props apkkit's `devices` command prints.
    struct DeviceSummary {
        std::string Serial;
        std::string State;
        std::string Model; // ro.product.model
        std::string Release; // ro.build.version.release
        std::string Sdk; // ro.build.version.sdk
        std::string Abi; // ro.product.cpu.abi

        bool Online() const {
            return State == "device";
        }
    };

    // Resolve <sdk>/platform-tools/adb[.exe]. Empty when the SDK path is unknown.
    std::string ResolveAdbPath(const SdkInfo &sdk);

    // ----------------------------------------------------------------------- //
    // Pure parsers (no process, no device) - the unit-tested core.
    // ----------------------------------------------------------------------- //

    // Parse `adb devices` output into serial/state pairs, dropping the header
    // line and daemon notices.
    std::vector<AdbDevice> ParseAdbDevices(const std::string &output);

    // Parse `pm list packages` output: strip the `package:` prefix off each line.
    std::vector<std::string> ParsePackageList(const std::string &output);

    // Parse `pm list packages -f` output (`package:<path>=<name>`): keep only
    // names whose APK lives under a user-install location (/data/app, /mnt/expand).
    std::vector<std::string> ParsePackagePaths(const std::string &output);

    // True when a package belongs to a known OS/Google/Samsung vendor namespace.
    bool IsVendorPackage(const std::string &package);

    // Replicate apkkit's `discover_packages`: union of third-party (`-3`) and
    // user-located (`-f`) packages, falling back to the full list when both are
    // empty, then drop vendor packages unless includeVendor is set. Sorted, unique.
    std::vector<std::string> DiscoverUserPackages(
        const std::string &thirdPartyOutput,
        const std::string &withPathsOutput,
        const std::string &allOutput,
        bool includeVendor = false
    );

    // ----------------------------------------------------------------------- //
    // Thin adb wrappers (argv only - never a shell, never quoting).
    // ----------------------------------------------------------------------- //

    std::vector<AdbDevice> Devices(const SdkInfo &sdk);

    // Devices() enriched with model/version/abi props (one getprop round-trip per
    // online device). Offline/unauthorized devices are returned without props.
    std::vector<DeviceSummary> DescribeDevices(const SdkInfo &sdk);

    AdbResult Shell(const SdkInfo &sdk, const std::string &serial, const std::vector<std::string> &args);

    // su -c on a rooted AVD. Builds {"-s",serial,"shell","su","-c",command} as argv -
    // the C++ fix for apkkit's _su single-quote problem.
    AdbResult ShellSu(const SdkInfo &sdk, const std::string &serial, const std::string &command);

    AdbResult Install(
        const SdkInfo &sdk,
        const std::string &serial,
        const std::string &apkPath,
        const std::vector<std::string> &extraArgs = {}
    );

    AdbResult Uninstall(const SdkInfo &sdk, const std::string &serial, const std::string &package, bool keepData = false);

    AdbResult Pull(const SdkInfo &sdk, const std::string &serial, const std::string &remotePath, const std::string &localPath);

    AdbResult Push(const SdkInfo &sdk, const std::string &serial, const std::string &localPath, const std::string &remotePath);

    AdbResult Forward(const SdkInfo &sdk, const std::string &serial, const std::string &local, const std::string &remote);

    std::string GetProp(const SdkInfo &sdk, const std::string &serial, const std::string &name);

    // Convenience: resolve the user-installed packages on a device end to end.
    std::vector<std::string> ListUserPackages(const SdkInfo &sdk, const std::string &serial, bool includeVendor = false);
}

#endif // COREDECK_ADB_H
