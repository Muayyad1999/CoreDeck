//
// Created by CoreDeck RE toolbench on 25/11/2026.
//
// fastboot helper: the bootloader-mode counterpart to adb.{h,cpp}. Resolves the
// platform-tools fastboot binary, parses `fastboot devices` / `getvar`, and wraps
// the handful of commands the device-root flow drives (reboot, flashing unlock,
// flash a partition). Argv only - never a shell, never quoting.
//

#ifndef COREDECK_FASTBOOT_H
#define COREDECK_FASTBOOT_H

#include <cstdint>
#include <string>
#include <vector>

#include "core/sdk.h"

namespace CoreDeck::Core::Re {
    struct FastbootDevice {
        std::string Serial;
        std::string State; // "fastboot" (bootloader/fastbootd both report "fastboot")

        bool Online() const {
            return State == "fastboot";
        }
    };

    struct FastbootResult {
        bool Started = false;
        int ExitCode = -1;
        std::string Output;

        bool Ok() const {
            return Started && ExitCode == 0;
        }
    };

    enum class LockState : std::uint8_t {
        Unknown, // getvar unavailable or the device didn't report it
        Locked, // unlocked: no
        Unlocked, // unlocked: yes
    };

    const char *LockStateName(LockState state);

    // The bootloader facts the wizard surfaces, from `fastboot getvar all` (or a
    // few single getvar calls). Fields stay empty/Unknown when not reported.
    struct BootloaderVars {
        LockState Unlocked = LockState::Unknown;
        std::string Product; // getvar product (board/codename, e.g. "shiba")
        std::string CurrentSlot; // getvar current-slot ("a"/"b"), empty on A-only
        std::string SerialNo; // getvar serialno
    };

    // Resolve <sdk>/platform-tools/fastboot[.exe]. Empty when the SDK path is unknown.
    std::string ResolveFastbootPath(const SdkInfo &sdk);

    // True when the resolved fastboot binary exists on disk.
    bool IsFastbootAvailable(const SdkInfo &sdk);

    // ----------------------------------------------------------------------- //
    // Pure parsers (no process, no device) - the unit-tested core.
    // ----------------------------------------------------------------------- //

    // Parse `fastboot devices` output (<serial>\tfastboot per line), dropping the
    // header/notice lines.
    std::vector<FastbootDevice> ParseFastbootDevices(const std::string &output);

    // Read one variable out of getvar output. Lines look like "unlocked: yes" or
    // "(bootloader) unlocked: yes"; the "(bootloader) " prefix is tolerated. Returns
    // the first match's value (trimmed), or empty when the variable is absent.
    std::string ParseGetVarValue(const std::string &output, const std::string &name);

    // Classify a `getvar unlocked` value ("yes"/"no") into a LockState.
    LockState ParseUnlockedValue(const std::string &value);

    // Read unlocked/product/current-slot/serialno out of `getvar all` (or several
    // concatenated single-getvar outputs).
    BootloaderVars ParseBootloaderVars(const std::string &output);

    // ----------------------------------------------------------------------- //
    // Argv builders (pure) - unit-tested, reused by the wrappers.
    // ----------------------------------------------------------------------- //

    std::vector<std::string> BuildGetVarArgs(const std::string &var);
    std::vector<std::string> BuildFlashArgs(const std::string &partition, const std::string &imagePath);
    std::vector<std::string> BuildFlashingUnlockArgs();
    std::vector<std::string> BuildFlashingLockArgs();
    // target: ""/"system" -> {"reboot"}; "bootloader"/"fastboot"/"recovery" -> {"reboot", target}.
    std::vector<std::string> BuildRebootArgs(const std::string &target);

    // ----------------------------------------------------------------------- //
    // Thin fastboot wrappers (argv only).
    // ----------------------------------------------------------------------- //

    std::vector<FastbootDevice> FastbootDevices(const SdkInfo &sdk);

    std::string GetVar(const SdkInfo &sdk, const std::string &serial, const std::string &var);

    BootloaderVars GetBootloaderVars(const SdkInfo &sdk, const std::string &serial);

    // `fastboot flashing unlock` - WIPES the device. The caller confirms first.
    FastbootResult FlashingUnlock(const SdkInfo &sdk, const std::string &serial);
    FastbootResult FlashingLock(const SdkInfo &sdk, const std::string &serial);

    FastbootResult Flash(
        const SdkInfo &sdk, const std::string &serial, const std::string &partition, const std::string &imagePath
    );

    // target per BuildRebootArgs.
    FastbootResult Reboot(const SdkInfo &sdk, const std::string &serial, const std::string &target = "");

    // Bridge from adb (normal) mode into the bootloader: `adb -s <serial> reboot
    // bootloader`. Uses the adb binary; the device then appears to FastbootDevices.
    FastbootResult RebootToBootloaderViaAdb(const SdkInfo &sdk, const std::string &serial);
}

#endif // COREDECK_FASTBOOT_H
