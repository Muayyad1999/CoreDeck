//
// Created by CoreDeck RE toolbench on 25/11/2026.
//

#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <miniz.h>

#include "core/adb.h"
#include "core/avd_root.h"
#include "core/device_root.h"
#include "core/fastboot.h"
#include "platform/paths.h"

namespace CoreDeck::Core {
    namespace {
        constexpr const char *DEVICE_WORK_DIR = "/data/local/tmp/coredeck-magisk";

        std::optional<std::vector<std::uint8_t>> ReadFileBytes(const std::string &path) {
            std::ifstream file(path, std::ios::binary);
            if (!file) {
                return std::nullopt;
            }
            return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        }

        bool WriteFileBytes(const std::string &path, const std::vector<std::uint8_t> &bytes, std::string &error) {
            std::ofstream file(path, std::ios::binary | std::ios::trunc);
            if (!file) {
                error = "Cannot open " + path + " for writing.";
                return false;
            }
            if (!bytes.empty()) {
                file.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            }
            if (!file) {
                error = "Write failed for " + path + ".";
                return false;
            }
            return true;
        }

        std::string BaseName(const std::string &path) {
            const std::size_t slash = path.find_last_of("/\\");
            return slash == std::string::npos ? path : path.substr(slash + 1);
        }

        std::string Lower(std::string value) {
            std::transform(value.begin(), value.end(), value.begin(), [](const unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            return value;
        }

        std::vector<std::string> ZipEntryNames(mz_zip_archive &zip) {
            std::vector<std::string> names;
            const mz_uint count = mz_zip_reader_get_num_files(&zip);
            for (mz_uint i = 0; i < count; ++i) {
                char nameBuf[1024];
                const mz_uint len = mz_zip_reader_get_filename(&zip, i, nameBuf, sizeof(nameBuf));
                if (len == 0) {
                    continue;
                }
                names.emplace_back(nameBuf, len > 0 ? len - 1 : 0);
            }
            return names;
        }

        // basename matches "image-*.zip" (the inner Pixel factory image archive).
        std::string FindInnerImageZip(const std::vector<std::string> &names) {
            for (const std::string &name: names) {
                const std::string base = Lower(BaseName(name));
                if (base.size() > 10 && base.compare(0, 6, "image-") == 0 &&
                    base.compare(base.size() - 4, 4, ".zip") == 0) {
                    return name;
                }
            }
            return "";
        }

        bool ExtractZipEntryToFile(
            mz_zip_archive &zip, const std::string &entryName, const std::string &destPath, std::string &error
        ) {
            const int index = mz_zip_reader_locate_file(&zip, entryName.c_str(), nullptr, 0);
            if (index < 0) {
                error = "Zip entry not found: " + entryName;
                return false;
            }
            if (mz_zip_reader_extract_to_file(&zip, static_cast<mz_uint>(index), destPath.c_str(), 0) == MZ_FALSE) {
                error = "Failed to extract " + entryName;
                return false;
            }
            return true;
        }

        std::string WaitForFastbootSerial(const SdkInfo &sdk, const std::string &preferred, const int timeoutSeconds) {
            for (int elapsed = 0; elapsed < timeoutSeconds; elapsed += 2) {
                const std::vector<Re::FastbootDevice> devices = Re::FastbootDevices(sdk);
                for (const Re::FastbootDevice &d: devices) {
                    if (!preferred.empty() && d.Serial == preferred) {
                        return d.Serial;
                    }
                }
                if (!devices.empty() && preferred.empty()) {
                    return devices.front().Serial;
                }
                if (devices.size() == 1 && !preferred.empty()) {
                    // The serial can differ between adb and fastboot on some devices.
                    return devices.front().Serial;
                }
                std::this_thread::sleep_for(std::chrono::seconds(2));
            }
            const std::vector<Re::FastbootDevice> devices = Re::FastbootDevices(sdk);
            return devices.empty() ? "" : devices.front().Serial;
        }

        bool WaitForAdbOnline(const SdkInfo &sdk, const std::string &serial, const int timeoutSeconds) {
            for (int elapsed = 0; elapsed < timeoutSeconds; elapsed += 2) {
                for (const Re::AdbDevice &d: Re::Devices(sdk)) {
                    if (d.Online() && (serial.empty() || d.Serial == serial)) {
                        return true;
                    }
                }
                std::this_thread::sleep_for(std::chrono::seconds(2));
            }
            return false;
        }
    }

    const char *BootTargetPartition(const BootTarget target) {
        return target == BootTarget::InitBoot ? "init_boot" : "boot";
    }

    BootTarget BootTargetForImageName(const std::string &fileName) {
        return Lower(BaseName(fileName)).find("init_boot") != std::string::npos ? BootTarget::InitBoot
                                                                                : BootTarget::Boot;
    }

    std::string PickBootImageEntry(const std::vector<std::string> &entryNames) {
        std::string boot;
        for (const std::string &name: entryNames) {
            const std::string base = Lower(BaseName(name));
            if (base == "init_boot.img") {
                return name; // preferred on modern devices
            }
            if (base == "boot.img" && boot.empty()) {
                boot = name;
            }
        }
        return boot;
    }

    const std::vector<std::uint8_t> *MagiskPatchKit::Find(const std::string &name) const {
        for (const auto &[key, bytes]: Files) {
            if (key == name) {
                return &bytes;
            }
        }
        return nullptr;
    }

    std::optional<MagiskPatchKit> ExtractMagiskPatchKit(const std::vector<std::uint8_t> &apkBytes, const std::string &abi) {
        mz_zip_archive zip = {};
        if (mz_zip_reader_init_mem(&zip, apkBytes.data(), apkBytes.size(), 0) == MZ_FALSE) {
            return std::nullopt;
        }
        MagiskPatchKit kit;
        const std::string libDir = "lib/" + abi + "/";
        const mz_uint count = mz_zip_reader_get_num_files(&zip);
        for (mz_uint i = 0; i < count; ++i) {
            char nameBuf[512];
            const mz_uint len = mz_zip_reader_get_filename(&zip, i, nameBuf, sizeof(nameBuf));
            if (len == 0) {
                continue;
            }
            const std::string name(nameBuf, len > 0 ? len - 1 : 0);

            std::string key;
            if (name.size() > libDir.size() && name.compare(0, libDir.size(), libDir) == 0) {
                const std::string base = name.substr(libDir.size()); // lib<X>.so
                if (base.size() > 6 && base.compare(0, 3, "lib") == 0 && base.compare(base.size() - 3, 3, ".so") == 0) {
                    key = base.substr(3, base.size() - 6);
                }
            } else if (name == "assets/boot_patch.sh") {
                key = "boot_patch.sh";
            } else if (name == "assets/util_functions.sh") {
                key = "util_functions.sh";
            } else if (name == "assets/stub.apk") {
                key = "stub.apk";
            }
            if (key.empty()) {
                continue;
            }
            std::size_t outSize = 0;
            void *data = mz_zip_reader_extract_to_heap(&zip, i, &outSize, 0);
            if (data == nullptr) {
                continue;
            }
            kit.Files.emplace_back(
                key,
                std::vector<std::uint8_t>(static_cast<std::uint8_t *>(data), static_cast<std::uint8_t *>(data) + outSize)
            );
            mz_free(data);
        }
        mz_zip_reader_end(&zip);
        if (!kit.Has("magiskboot") || !kit.Has("boot_patch.sh")) {
            return std::nullopt;
        }
        return kit;
    }

    std::optional<ExtractedBootImage> ExtractBootImageFromFactoryZip(
        const std::string &zipPath, const std::string &destDir, std::string &error
    ) {
        std::error_code ec;
        std::filesystem::create_directories(destDir, ec);

        mz_zip_archive zip = {};
        if (mz_zip_reader_init_file(&zip, zipPath.c_str(), 0) == MZ_FALSE) {
            error = "Could not open the zip: " + zipPath;
            return std::nullopt;
        }
        const std::vector<std::string> names = ZipEntryNames(zip);

        // Case 1: the zip carries boot/init_boot.img directly (inner image zip or OTA).
        const std::string direct = PickBootImageEntry(names);
        if (!direct.empty()) {
            const std::string dest = Platform::JoinPaths({destDir, BaseName(direct)});
            const bool ok = ExtractZipEntryToFile(zip, direct, dest, error);
            mz_zip_reader_end(&zip);
            if (!ok) {
                return std::nullopt;
            }
            return ExtractedBootImage{dest, BootTargetForImageName(direct), direct};
        }

        // Case 2: a Pixel-style factory zip whose inner image-*.zip holds the images.
        const std::string inner = FindInnerImageZip(names);
        if (inner.empty()) {
            mz_zip_reader_end(&zip);
            error = "No boot/init_boot.img and no inner image-*.zip found in the archive.";
            return std::nullopt;
        }
        const std::string innerPath = Platform::JoinPaths({destDir, BaseName(inner)});
        const bool extracted = ExtractZipEntryToFile(zip, inner, innerPath, error);
        mz_zip_reader_end(&zip);
        if (!extracted) {
            return std::nullopt;
        }

        mz_zip_archive innerZip = {};
        if (mz_zip_reader_init_file(&innerZip, innerPath.c_str(), 0) == MZ_FALSE) {
            std::filesystem::remove(innerPath, ec);
            error = "Could not open the inner image archive.";
            return std::nullopt;
        }
        const std::vector<std::string> innerNames = ZipEntryNames(innerZip);
        const std::string entry = PickBootImageEntry(innerNames);
        if (entry.empty()) {
            mz_zip_reader_end(&innerZip);
            std::filesystem::remove(innerPath, ec);
            error = "The inner image archive has no boot/init_boot.img.";
            return std::nullopt;
        }
        const std::string dest = Platform::JoinPaths({destDir, BaseName(entry)});
        const bool ok = ExtractZipEntryToFile(innerZip, entry, dest, error);
        mz_zip_reader_end(&innerZip);
        std::filesystem::remove(innerPath, ec);
        if (!ok) {
            return std::nullopt;
        }
        return ExtractedBootImage{dest, BootTargetForImageName(entry), entry};
    }

    std::string BuildBootPatchCommand(const std::string &workDir, const std::string &bootImgName, const bool stripVerity) {
        const std::string keep = stripVerity ? "false" : "true";
        return "cd " + workDir + " && chmod -R 755 . && ASH_STANDALONE=1 KEEPVERITY=" + keep +
               " KEEPFORCEENCRYPT=" + keep + " RECOVERYMODE=false ./busybox sh ./boot_patch.sh ./" + bootImgName;
    }

    const char *DeviceRootStageLabel(const DeviceRootStage stage) {
        switch (stage) {
            case DeviceRootStage::ResolveMagisk:
                return "Resolve Magisk";
            case DeviceRootStage::AcquireBootImg:
                return "Acquire boot image";
            case DeviceRootStage::PatchBoot:
                return "Patch boot image";
            case DeviceRootStage::RebootBootloader:
                return "Reboot to bootloader";
            case DeviceRootStage::FlashBoot:
                return "Flash patched boot";
            case DeviceRootStage::RebootSystem:
                return "Reboot to system";
            case DeviceRootStage::Verify:
                return "Verify root";
            case DeviceRootStage::Done:
                return "Done";
            case DeviceRootStage::Failed:
                return "Failed";
            case DeviceRootStage::Idle:
            default:
                return "Idle";
        }
    }

    std::optional<std::string> PatchBootImageOnDevice(
        const SdkInfo &sdk, const DeviceRootPlan &plan, std::string &error
    ) {
        const auto apk = ReadFileBytes(plan.MagiskApkPath);
        if (!apk) {
            error = "Cannot read the Magisk apk: " + plan.MagiskApkPath;
            return std::nullopt;
        }
        const auto kit = ExtractMagiskPatchKit(*apk, plan.Abi);
        if (!kit) {
            error = "Magisk apk has no patch kit for ABI " + plan.Abi + ".";
            return std::nullopt;
        }
        if (!std::filesystem::exists(plan.BootImagePath)) {
            error = "Boot image not found: " + plan.BootImagePath;
            return std::nullopt;
        }

        const std::string hostDir = Platform::JoinPaths({Platform::GetConfigDirectory(), "device-root"});
        const std::string kitDir = Platform::JoinPaths({hostDir, "kit"});
        std::error_code ec;
        std::filesystem::create_directories(kitDir, ec);

        // Fresh device work dir.
        Re::Shell(sdk, plan.Serial, {std::string("rm -rf ") + DEVICE_WORK_DIR + " && mkdir -p " + DEVICE_WORK_DIR});

        // Stage the kit on the host, then push each file to the device.
        for (const auto &[name, bytes]: kit->Files) {
            const std::string localPath = Platform::JoinPaths({kitDir, name});
            std::string writeError;
            if (!WriteFileBytes(localPath, bytes, writeError)) {
                error = writeError;
                return std::nullopt;
            }
            const Re::AdbResult push =
                Re::Push(sdk, plan.Serial, localPath, std::string(DEVICE_WORK_DIR) + "/" + name);
            if (!push.Ok()) {
                error = "Failed to push " + name + " to the device.";
                return std::nullopt;
            }
        }

        // Push the stock boot image under a fixed name.
        const Re::AdbResult pushBoot =
            Re::Push(sdk, plan.Serial, plan.BootImagePath, std::string(DEVICE_WORK_DIR) + "/boot.img");
        if (!pushBoot.Ok()) {
            error = "Failed to push the boot image to the device.";
            return std::nullopt;
        }

        // Patch non-interactively with Magisk's own boot_patch.sh.
        const std::string command = BuildBootPatchCommand(DEVICE_WORK_DIR, "boot.img", plan.StripVerity);
        const Re::AdbResult patch = Re::Shell(sdk, plan.Serial, {command});

        const Re::AdbResult check = Re::Shell(
            sdk,
            plan.Serial,
            {std::string("[ -f ") + DEVICE_WORK_DIR + "/new-boot.img ] && echo COREDECK_OK || echo COREDECK_MISSING"}
        );
        if (check.Output.find("COREDECK_OK") == std::string::npos) {
            std::string tail = patch.Output;
            if (tail.size() > 400) {
                tail = tail.substr(tail.size() - 400);
            }
            error = "boot_patch.sh did not produce new-boot.img. Output:\n" + tail;
            return std::nullopt;
        }

        const std::string patchedPath = Platform::JoinPaths({hostDir, "new-boot.img"});
        const Re::AdbResult pull =
            Re::Pull(sdk, plan.Serial, std::string(DEVICE_WORK_DIR) + "/new-boot.img", patchedPath);
        if (!pull.Ok() || !std::filesystem::exists(patchedPath)) {
            error = "Failed to pull the patched boot image from the device.";
            return std::nullopt;
        }

        Re::Shell(sdk, plan.Serial, {std::string("rm -rf ") + DEVICE_WORK_DIR}); // best-effort cleanup
        return patchedPath;
    }

    std::optional<DeviceRootPlan> PlanDeviceRoot(
        const SdkInfo &sdk,
        const std::string &serial,
        const std::string &magiskApkPath,
        const std::string &bootImagePath,
        std::string &error
    ) {
        if (serial.empty()) {
            error = "No device is selected.";
            return std::nullopt;
        }
        if (magiskApkPath.empty()) {
            error = "Fetch Magisk first.";
            return std::nullopt;
        }
        if (bootImagePath.empty() || !std::filesystem::exists(bootImagePath)) {
            error = "Select a boot image (boot.img / init_boot.img) or a factory image first.";
            return std::nullopt;
        }
        const std::string abi = Re::GetDeviceProp(sdk, serial, "ro.product.cpu.abi");
        if (abi.empty()) {
            error = "Could not read the device ABI (ro.product.cpu.abi).";
            return std::nullopt;
        }
        DeviceRootPlan plan;
        plan.Serial = serial;
        plan.FastbootSerial = serial;
        plan.Abi = abi;
        plan.MagiskApkPath = magiskApkPath;
        plan.BootImagePath = bootImagePath;
        plan.Target = BootTargetForImageName(bootImagePath);
        return plan;
    }

    bool RootDevice(const SdkInfo &sdk, const DeviceRootPlan &plan, DeviceRootProgress &progress) {
        progress.Set(DeviceRootStage::AcquireBootImg, 0.10F, "Checking the boot image");
        if (!std::filesystem::exists(plan.BootImagePath)) {
            progress.Fail("Boot image not found: " + plan.BootImagePath);
            return false;
        }

        progress.Set(DeviceRootStage::PatchBoot, 0.30F, "Patching the boot image on the device");
        std::string patchError;
        const auto patched = PatchBootImageOnDevice(sdk, plan, patchError);
        if (!patched) {
            progress.Fail(patchError);
            return false;
        }

        progress.Set(DeviceRootStage::RebootBootloader, 0.55F, "Rebooting to the bootloader");
        Re::RebootToBootloaderViaAdb(sdk, plan.Serial);
        const std::string fastbootSerial = WaitForFastbootSerial(sdk, plan.FastbootSerial, 60);
        if (fastbootSerial.empty()) {
            progress.Fail("The device did not enter fastboot. Check the USB connection and drivers.");
            return false;
        }

        progress.Set(DeviceRootStage::FlashBoot, 0.75F, std::string("Flashing ") + BootTargetPartition(plan.Target));
        const Re::FastbootResult flash = Re::Flash(sdk, fastbootSerial, BootTargetPartition(plan.Target), *patched);
        if (!flash.Ok()) {
            std::string tail = flash.Output;
            if (tail.size() > 300) {
                tail = tail.substr(tail.size() - 300);
            }
            progress.Fail("fastboot flash failed:\n" + tail);
            return false;
        }

        progress.Set(DeviceRootStage::RebootSystem, 0.88F, "Rebooting to the system");
        Re::Reboot(sdk, fastbootSerial, "");
        if (!WaitForAdbOnline(sdk, plan.Serial, 120)) {
            progress.Fail("The device did not come back online after flashing.");
            return false;
        }

        progress.Set(DeviceRootStage::Verify, 0.95F, "Verifying root");
        Re::Shell(sdk, plan.Serial, {"true"}); // settle wait-for-device
        if (CheckRoot(sdk, plan.Serial) == RootStatus::Rooted) {
            progress.Set(DeviceRootStage::Done, 1.0F, "Rooted: su returned uid=0");
            return true;
        }
        progress.Fail(
            "Flashed, but su is not granted yet. Open the Magisk app once to finish setup (it may prompt to "
            "complete installation and reboot), then re-check root."
        );
        return false;
    }
}
