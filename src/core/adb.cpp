//
// Created by CoreDeck RE toolbench on 03/11/2026.
//

#include <algorithm>
#include <array>
#include <cctype>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "core/adb.h"
#include "platform/paths.h"
#include "platform/process.h"

namespace CoreDeck::Core {
    namespace {
        constexpr std::array<std::string_view, 2> USER_APK_PREFIXES = {
            "/data/app/",
            "/mnt/expand/",
        };

        // Ported verbatim from apkkit's VENDOR_PREFIXES - OS/Google/Samsung namespaces.
        constexpr std::array<std::string_view, 17> VENDOR_PREFIXES = {
            "com.google.",
            "com.android.chrome",
            "com.android.vending",
            "com.chrome.",
            "com.waze",
            "com.niksoftware.snapseed",
            "com.samsung.",
            "com.sec.",
            "com.sem.",
            "com.osp.",
            "com.sac.",
            "com.wssnps",
            "com.knox.",
            "com.samsungapps",
            "com.enhance.gameservice",
            "com.dsi.ant",
            "com.monotype.android",
        };

        std::string TrimTrailing(std::string value) {
            while (!value.empty() && (value.back() == '\r' || value.back() == '\n' || value.back() == ' ' ||
                                      value.back() == '\t')) {
                value.pop_back();
            }
            return value;
        }

        std::string TrimLeading(std::string value) {
            std::size_t start = 0;
            while (start < value.size() && (value[start] == ' ' || value[start] == '\t')) {
                ++start;
            }
            return value.substr(start);
        }

        std::string Trim(const std::string &value) {
            return TrimTrailing(TrimLeading(value));
        }

        bool StartsWith(std::string_view value, std::string_view prefix) {
            return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
        }

        AdbResult ToAdbResult(const Platform::CommandResult &result) {
            return AdbResult{result.Started, result.ExitCode, result.Output};
        }

        std::vector<std::string> WithSerial(const std::string &serial, std::vector<std::string> args) {
            std::vector<std::string> full;
            full.reserve(args.size() + 2);
            if (!serial.empty()) {
                full.emplace_back("-s");
                full.push_back(serial);
            }
            full.insert(full.end(), std::make_move_iterator(args.begin()), std::make_move_iterator(args.end()));
            return full;
        }

        AdbResult RunAdb(const SdkInfo &sdk, std::vector<std::string> args) {
            const std::string adbPath = ResolveAdbPath(sdk);
            if (adbPath.empty()) {
                return AdbResult{false, -1, ""};
            }
            return ToAdbResult(Platform::RunCommandArgsResult(adbPath, args, "", sdk.ToolEnv));
        }
    }

    std::string ResolveAdbPath(const SdkInfo &sdk) {
        if (sdk.SdkPath.empty()) {
            return "";
        }
        return Platform::JoinPaths({sdk.SdkPath, "platform-tools", Platform::WithExecutableExtension("adb")});
    }

    std::vector<AdbDevice> ParseAdbDevices(const std::string &output) {
        std::vector<AdbDevice> devices;
        std::istringstream stream(output);
        std::string raw;
        while (std::getline(stream, raw)) {
            const std::string line = Trim(raw);
            if (line.empty()) {
                continue;
            }
            // Daemon notices ("* daemon not running; starting now...") and the header.
            if (line.front() == '*' || StartsWith(line, "List of devices attached") ||
                StartsWith(line, "adb server")) {
                continue;
            }

            const std::size_t split = line.find_first_of(" \t");
            if (split == std::string::npos) {
                // A serial with no state - keep it with an empty state rather than drop it.
                devices.push_back(AdbDevice{line, ""});
                continue;
            }

            AdbDevice device;
            device.Serial = line.substr(0, split);
            device.State = Trim(line.substr(split + 1));
            if (!device.Serial.empty()) {
                devices.push_back(std::move(device));
            }
        }
        return devices;
    }

    std::vector<std::string> ParsePackageList(const std::string &output) {
        constexpr std::string_view PREFIX = "package:";
        std::vector<std::string> packages;
        std::istringstream stream(output);
        std::string raw;
        while (std::getline(stream, raw)) {
            const std::string line = Trim(raw);
            if (!StartsWith(line, PREFIX)) {
                continue;
            }
            const std::string name = Trim(line.substr(PREFIX.size()));
            if (!name.empty()) {
                packages.push_back(name);
            }
        }
        return packages;
    }

    std::vector<std::string> ParsePackagePaths(const std::string &output) {
        constexpr std::string_view PREFIX = "package:";
        std::vector<std::string> packages;
        std::istringstream stream(output);
        std::string raw;
        while (std::getline(stream, raw)) {
            const std::string line = Trim(raw);
            if (!StartsWith(line, PREFIX)) {
                continue;
            }
            const std::string body = Trim(line.substr(PREFIX.size()));
            const std::size_t eq = body.rfind('=');
            if (eq == std::string::npos) {
                continue;
            }
            const std::string path = body.substr(0, eq);
            const std::string name = Trim(body.substr(eq + 1));
            if (name.empty()) {
                continue;
            }
            const bool userLocated = std::any_of(
                USER_APK_PREFIXES.begin(),
                USER_APK_PREFIXES.end(),
                [&path](const std::string_view prefix) { return StartsWith(path, prefix); }
            );
            if (userLocated) {
                packages.push_back(name);
            }
        }
        return packages;
    }

    bool IsVendorPackage(const std::string &package) {
        return std::any_of(
            VENDOR_PREFIXES.begin(),
            VENDOR_PREFIXES.end(),
            [&package](const std::string_view prefix) { return StartsWith(package, prefix); }
        );
    }

    std::vector<std::string> DiscoverUserPackages(
        const std::string &thirdPartyOutput,
        const std::string &withPathsOutput,
        const std::string &allOutput,
        const bool includeVendor
    ) {
        std::vector<std::string> merged = ParsePackageList(thirdPartyOutput);
        const std::vector<std::string> located = ParsePackagePaths(withPathsOutput);
        merged.insert(merged.end(), located.begin(), located.end());

        if (merged.empty()) {
            merged = ParsePackageList(allOutput);
        }

        if (!includeVendor) {
            merged.erase(
                std::remove_if(
                    merged.begin(),
                    merged.end(),
                    [](const std::string &package) { return IsVendorPackage(package); }
                ),
                merged.end()
            );
        }

        std::sort(merged.begin(), merged.end());
        merged.erase(std::unique(merged.begin(), merged.end()), merged.end());
        return merged;
    }

    std::vector<AdbDevice> Devices(const SdkInfo &sdk) {
        const AdbResult result = RunAdb(sdk, {"devices"});
        if (!result.Started) {
            return {};
        }
        return ParseAdbDevices(result.Output);
    }

    std::vector<DeviceSummary> DescribeDevices(const SdkInfo &sdk) {
        std::vector<DeviceSummary> summaries;
        for (const AdbDevice &device: Devices(sdk)) {
            DeviceSummary summary;
            summary.Serial = device.Serial;
            summary.State = device.State;
            if (device.Online()) {
                summary.Model = GetDeviceProp(sdk, device.Serial, "ro.product.model");
                summary.Release = GetDeviceProp(sdk, device.Serial, "ro.build.version.release");
                summary.Sdk = GetDeviceProp(sdk, device.Serial, "ro.build.version.sdk");
                summary.Abi = GetDeviceProp(sdk, device.Serial, "ro.product.cpu.abi");
            }
            summaries.push_back(std::move(summary));
        }
        return summaries;
    }

    AdbResult Shell(const SdkInfo &sdk, const std::string &serial, const std::vector<std::string> &args) {
        std::vector<std::string> full;
        full.reserve(args.size() + 1);
        full.emplace_back("shell");
        full.insert(full.end(), args.begin(), args.end());
        return RunAdb(sdk, WithSerial(serial, std::move(full)));
    }

    AdbResult ShellSu(const SdkInfo &sdk, const std::string &serial, const std::string &command) {
        return RunAdb(sdk, WithSerial(serial, {"shell", "su", "-c", command}));
    }

    AdbResult Install(
        const SdkInfo &sdk,
        const std::string &serial,
        const std::string &apkPath,
        const std::vector<std::string> &extraArgs
    ) {
        std::vector<std::string> args;
        args.reserve(extraArgs.size() + 2);
        args.emplace_back("install");
        args.insert(args.end(), extraArgs.begin(), extraArgs.end());
        args.push_back(apkPath);
        return RunAdb(sdk, WithSerial(serial, std::move(args)));
    }

    AdbResult Uninstall(const SdkInfo &sdk, const std::string &serial, const std::string &package, const bool keepData) {
        std::vector<std::string> args;
        args.emplace_back("uninstall");
        if (keepData) {
            args.emplace_back("-k");
        }
        args.push_back(package);
        return RunAdb(sdk, WithSerial(serial, std::move(args)));
    }

    AdbResult Pull(const SdkInfo &sdk, const std::string &serial, const std::string &remotePath, const std::string &localPath) {
        return RunAdb(sdk, WithSerial(serial, {"pull", remotePath, localPath}));
    }

    AdbResult Push(const SdkInfo &sdk, const std::string &serial, const std::string &localPath, const std::string &remotePath) {
        return RunAdb(sdk, WithSerial(serial, {"push", localPath, remotePath}));
    }

    AdbResult Forward(const SdkInfo &sdk, const std::string &serial, const std::string &local, const std::string &remote) {
        return RunAdb(sdk, WithSerial(serial, {"forward", local, remote}));
    }

    std::string GetDeviceProp(const SdkInfo &sdk, const std::string &serial, const std::string &name) {
        const AdbResult result = Shell(sdk, serial, {"getprop", name});
        if (!result.Ok()) {
            return "";
        }
        return Trim(result.Output);
    }

    std::vector<std::string> ListUserPackages(const SdkInfo &sdk, const std::string &serial, const bool includeVendor) {
        const AdbResult thirdParty = Shell(sdk, serial, {"pm", "list", "packages", "-3"});
        const AdbResult withPaths = Shell(sdk, serial, {"pm", "list", "packages", "-f"});
        const AdbResult all = Shell(sdk, serial, {"pm", "list", "packages"});
        return DiscoverUserPackages(thirdParty.Output, withPaths.Output, all.Output, includeVendor);
    }
}
