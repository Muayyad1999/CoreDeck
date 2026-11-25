//
// Created by CoreDeck RE toolbench on 25/11/2026.
//
// Physical-device rooting with Magisk, the hardware counterpart to avd_root
// (which roots emulators host-side). Here the boot image is patched ON the
// device by driving Magisk's own boot_patch.sh + magiskboot over adb (the
// binaries are Android ELF, so they can't run on the desktop host), then the
// patched image is flashed with fastboot. Reuses ResolveMagisk / CheckRoot from
// avd_root.h. For rooting a device you own for authorized testing.
//

#ifndef COREDECK_DEVICE_ROOT_H
#define COREDECK_DEVICE_ROOT_H

#include <atomic>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "core/fastboot.h"
#include "core/sdk.h"

namespace CoreDeck::Core {
    // ----------------------------------------------------------------------- //
    // Boot image target partition
    // ----------------------------------------------------------------------- //
    // Modern Pixels (7/8+) keep the ramdisk in init_boot, so Magisk patches
    // init_boot.img and it is flashed to the init_boot partition. Older devices
    // keep it in boot. The partition is chosen from which image the user supplies.
    enum class BootTarget : std::uint8_t { Boot,
                                           InitBoot };

    const char *BootTargetPartition(BootTarget target); // "boot" / "init_boot"

    // Pure: init_boot.img -> InitBoot, anything else -> Boot (case-insensitive,
    // matches on the file's base name).
    BootTarget BootTargetForImageName(const std::string &fileName);

    // Pure: from a zip's entry names, pick the boot image to extract. Prefers
    // init_boot.img over boot.img, matching on each entry's base name. Empty when
    // neither is present.
    std::string PickBootImageEntry(const std::vector<std::string> &entryNames);

    // ----------------------------------------------------------------------- //
    // Magisk patch kit (binaries + scripts pulled from the Magisk apk)
    // ----------------------------------------------------------------------- //
    struct MagiskPatchKit {
        // canonical on-device name -> bytes (magiskboot, magiskinit, magisk32,
        // magisk64, busybox, init-ld, stub.apk, boot_patch.sh, util_functions.sh).
        std::vector<std::pair<std::string, std::vector<std::uint8_t>>> Files;

        const std::vector<std::uint8_t> *Find(const std::string &name) const;
        bool Has(const std::string &name) const {
            return Find(name) != nullptr;
        }
    };

    // Extract the patch kit for one ABI from the Magisk apk bytes: lib/<abi>/lib*.so
    // (stripped to the bare name) plus assets/{boot_patch.sh,util_functions.sh,
    // stub.apk}. Returns nullopt when magiskboot or boot_patch.sh are missing.
    std::optional<MagiskPatchKit> ExtractMagiskPatchKit(const std::vector<std::uint8_t> &apkBytes, const std::string &abi);

    // ----------------------------------------------------------------------- //
    // Boot image acquisition from a factory image / OTA zip
    // ----------------------------------------------------------------------- //
    struct ExtractedBootImage {
        std::string LocalPath; // the extracted boot/init_boot.img on disk
        BootTarget Target = BootTarget::Boot;
        std::string EntryName; // the zip entry it came from
    };

    // Find and extract boot/init_boot.img from a Pixel-style factory zip (whose
    // inner image-<device>-<build>.zip holds the images) or a flat OTA/image zip
    // that carries them directly. Writes the image into destDir. error set on
    // failure. Uses miniz; no external unzip.
    std::optional<ExtractedBootImage> ExtractBootImageFromFactoryZip(
        const std::string &zipPath, const std::string &destDir, std::string &error
    );

    // ----------------------------------------------------------------------- //
    // On-device boot_patch.sh driver
    // ----------------------------------------------------------------------- //
    // Pure: the one-line shell command run via `adb shell` to patch the pushed
    // boot image non-interactively. cds into workDir, makes the kit executable, and
    // runs `./busybox sh ./boot_patch.sh ./<bootImgName>` with KEEPVERITY /
    // KEEPFORCEENCRYPT set from stripVerity. boot_patch.sh writes new-boot.img.
    std::string BuildBootPatchCommand(const std::string &workDir, const std::string &bootImgName, bool stripVerity);

    // ----------------------------------------------------------------------- //
    // Orchestration (mirrors avd_root's RootStage / RootProgress)
    // ----------------------------------------------------------------------- //
    enum class DeviceRootStage : std::uint8_t {
        Idle,
        ResolveMagisk,
        AcquireBootImg,
        PatchBoot,
        RebootBootloader,
        FlashBoot,
        RebootSystem,
        Verify,
        Done,
        Failed,
    };

    const char *DeviceRootStageLabel(DeviceRootStage stage);

    struct DeviceRootProgress {
        std::atomic<DeviceRootStage> Stage{DeviceRootStage::Idle};
        std::atomic<float> Fraction{0.0F};
        std::mutex Mutex;
        std::string Detail;
        std::string Error;

        void Set(const DeviceRootStage stage, const float fraction, const std::string &detail) {
            Stage.store(stage);
            Fraction.store(fraction);
            std::lock_guard<std::mutex> lock(Mutex);
            Detail = detail;
        }
        void Fail(const std::string &error) {
            Stage.store(DeviceRootStage::Failed);
            std::lock_guard<std::mutex> lock(Mutex);
            Error = error;
        }
    };

    struct DeviceRootPlan {
        std::string Serial; // adb serial (device in normal mode)
        std::string FastbootSerial; // serial once in bootloader; defaults to Serial
        std::string Abi; // device ABI (ro.product.cpu.abi)
        std::string MagiskApkPath; // resolved Magisk .apk
        std::string BootImagePath; // host path to the stock boot/init_boot.img
        BootTarget Target = BootTarget::Boot;
        bool StripVerity = true;
    };

    // Patch the boot image on the device over adb and return the local patched
    // image path (new-boot.img pulled to the host). error set on failure.
    std::optional<std::string> PatchBootImageOnDevice(
        const SdkInfo &sdk, const DeviceRootPlan &plan, std::string &error
    );

    // Build a plan from device facts. error set on failure (missing ABI / boot img).
    std::optional<DeviceRootPlan> PlanDeviceRoot(
        const SdkInfo &sdk,
        const std::string &serial,
        const std::string &magiskApkPath,
        const std::string &bootImagePath,
        std::string &error
    );

    // Full guided pipeline: patch boot on device -> reboot to bootloader -> flash
    // the patched image -> reboot to system -> verify su. The bootloader must
    // already be unlocked. EXPERIMENTAL / device-modifying; use a device you own.
    bool RootDevice(const SdkInfo &sdk, const DeviceRootPlan &plan, DeviceRootProgress &progress);
}

#endif // COREDECK_DEVICE_ROOT_H
