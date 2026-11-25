//
// Created by CoreDeck RE toolbench on 25/11/2026.
//

#include <filesystem>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "core/adb.h"
#include "core/fastboot.h"
#include "platform/paths.h"
#include "platform/process.h"

namespace CoreDeck::Core::Re {
    namespace {
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

        FastbootResult ToFastbootResult(const Platform::CommandResult &result) {
            return FastbootResult{result.Started, result.ExitCode, result.Output};
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

        FastbootResult RunFastboot(const SdkInfo &sdk, std::vector<std::string> args) {
            const std::string path = ResolveFastbootPath(sdk);
            if (path.empty()) {
                return FastbootResult{false, -1, ""};
            }
            return ToFastbootResult(Platform::RunCommandArgsResult(path, args, "", sdk.ToolEnv));
        }
    }

    const char *LockStateName(const LockState state) {
        switch (state) {
            case LockState::Locked:
                return "locked";
            case LockState::Unlocked:
                return "unlocked";
            case LockState::Unknown:
            default:
                return "unknown";
        }
    }

    std::string ResolveFastbootPath(const SdkInfo &sdk) {
        if (sdk.SdkPath.empty()) {
            return "";
        }
        return Platform::JoinPaths({sdk.SdkPath, "platform-tools", Platform::WithExecutableExtension("fastboot")});
    }

    bool IsFastbootAvailable(const SdkInfo &sdk) {
        const std::string path = ResolveFastbootPath(sdk);
        if (path.empty()) {
            return false;
        }
        std::error_code ec;
        return std::filesystem::exists(path, ec);
    }

    std::vector<FastbootDevice> ParseFastbootDevices(const std::string &output) {
        std::vector<FastbootDevice> devices;
        std::istringstream stream(output);
        std::string raw;
        while (std::getline(stream, raw)) {
            const std::string line = Trim(raw);
            if (line.empty()) {
                continue;
            }
            // Daemon notices / "no permissions" hints and the occasional header.
            if (line.front() == '*' || StartsWith(line, "List of devices")) {
                continue;
            }
            const std::size_t split = line.find_first_of(" \t");
            if (split == std::string::npos) {
                devices.push_back(FastbootDevice{line, ""});
                continue;
            }
            FastbootDevice device;
            device.Serial = line.substr(0, split);
            device.State = Trim(line.substr(split + 1));
            if (!device.Serial.empty()) {
                devices.push_back(std::move(device));
            }
        }
        return devices;
    }

    std::string ParseGetVarValue(const std::string &output, const std::string &name) {
        constexpr std::string_view BOOTLOADER = "(bootloader) ";
        std::istringstream stream(output);
        std::string raw;
        while (std::getline(stream, raw)) {
            std::string line = Trim(raw);
            if (StartsWith(line, BOOTLOADER)) {
                line = Trim(line.substr(BOOTLOADER.size()));
            }
            const std::size_t colon = line.find(':');
            if (colon == std::string::npos) {
                continue;
            }
            if (Trim(line.substr(0, colon)) == name) {
                return Trim(line.substr(colon + 1));
            }
        }
        return "";
    }

    LockState ParseUnlockedValue(const std::string &value) {
        const std::string trimmed = Trim(value);
        if (trimmed == "yes" || trimmed == "true" || trimmed == "1") {
            return LockState::Unlocked;
        }
        if (trimmed == "no" || trimmed == "false" || trimmed == "0") {
            return LockState::Locked;
        }
        return LockState::Unknown;
    }

    BootloaderVars ParseBootloaderVars(const std::string &output) {
        BootloaderVars vars;
        const std::string unlocked = ParseGetVarValue(output, "unlocked");
        if (!unlocked.empty()) {
            vars.Unlocked = ParseUnlockedValue(unlocked);
        }
        vars.Product = ParseGetVarValue(output, "product");
        vars.CurrentSlot = ParseGetVarValue(output, "current-slot");
        vars.SerialNo = ParseGetVarValue(output, "serialno");
        return vars;
    }

    std::vector<std::string> BuildGetVarArgs(const std::string &var) {
        return {"getvar", var};
    }

    std::vector<std::string> BuildFlashArgs(const std::string &partition, const std::string &imagePath) {
        return {"flash", partition, imagePath};
    }

    std::vector<std::string> BuildFlashingUnlockArgs() {
        return {"flashing", "unlock"};
    }

    std::vector<std::string> BuildFlashingLockArgs() {
        return {"flashing", "lock"};
    }

    std::vector<std::string> BuildRebootArgs(const std::string &target) {
        if (target.empty() || target == "system") {
            return {"reboot"};
        }
        return {"reboot", target};
    }

    std::vector<FastbootDevice> FastbootDevices(const SdkInfo &sdk) {
        const FastbootResult result = RunFastboot(sdk, {"devices"});
        if (!result.Started) {
            return {};
        }
        return ParseFastbootDevices(result.Output);
    }

    std::string GetVar(const SdkInfo &sdk, const std::string &serial, const std::string &var) {
        const FastbootResult result = RunFastboot(sdk, WithSerial(serial, BuildGetVarArgs(var)));
        if (!result.Started) {
            return "";
        }
        return ParseGetVarValue(result.Output, var);
    }

    BootloaderVars GetBootloaderVars(const SdkInfo &sdk, const std::string &serial) {
        const FastbootResult result = RunFastboot(sdk, WithSerial(serial, {"getvar", "all"}));
        if (!result.Started) {
            return {};
        }
        return ParseBootloaderVars(result.Output);
    }

    FastbootResult FlashingUnlock(const SdkInfo &sdk, const std::string &serial) {
        return RunFastboot(sdk, WithSerial(serial, BuildFlashingUnlockArgs()));
    }

    FastbootResult FlashingLock(const SdkInfo &sdk, const std::string &serial) {
        return RunFastboot(sdk, WithSerial(serial, BuildFlashingLockArgs()));
    }

    FastbootResult Flash(
        const SdkInfo &sdk, const std::string &serial, const std::string &partition, const std::string &imagePath
    ) {
        return RunFastboot(sdk, WithSerial(serial, BuildFlashArgs(partition, imagePath)));
    }

    FastbootResult Reboot(const SdkInfo &sdk, const std::string &serial, const std::string &target) {
        return RunFastboot(sdk, WithSerial(serial, BuildRebootArgs(target)));
    }

    FastbootResult RebootToBootloaderViaAdb(const SdkInfo &sdk, const std::string &serial) {
        const std::string adbPath = ResolveAdbPath(sdk);
        if (adbPath.empty()) {
            return FastbootResult{false, -1, ""};
        }
        std::vector<std::string> args;
        if (!serial.empty()) {
            args.emplace_back("-s");
            args.push_back(serial);
        }
        args.emplace_back("reboot");
        args.emplace_back("bootloader");
        return ToFastbootResult(Platform::RunCommandArgsResult(adbPath, args, "", sdk.ToolEnv));
    }
}
