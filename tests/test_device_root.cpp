#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <miniz.h>

#include "core/device_root.h"

using namespace CoreDeck::Core;
using namespace CoreDeck;

namespace {
    struct ZipEntry {
        std::string Name;
        std::vector<std::uint8_t> Data;
    };

    std::vector<std::uint8_t> MakeZipInMemory(const std::vector<ZipEntry> &entries) {
        mz_zip_archive zip = {};
        mz_zip_writer_init_heap(&zip, 0, 0);
        for (const ZipEntry &entry: entries) {
            mz_zip_writer_add_mem(
                &zip, entry.Name.c_str(), entry.Data.data(), entry.Data.size(), MZ_DEFAULT_LEVEL
            );
        }
        void *buf = nullptr;
        std::size_t size = 0;
        mz_zip_writer_finalize_heap_archive(&zip, &buf, &size);
        std::vector<std::uint8_t> out(static_cast<std::uint8_t *>(buf), static_cast<std::uint8_t *>(buf) + size);
        mz_zip_writer_end(&zip);
        mz_free(buf);
        return out;
    }

    void WriteZipFile(const std::string &path, const std::vector<ZipEntry> &entries) {
        mz_zip_archive zip = {};
        mz_zip_writer_init_file(&zip, path.c_str(), 0);
        for (const ZipEntry &entry: entries) {
            mz_zip_writer_add_mem(
                &zip, entry.Name.c_str(), entry.Data.data(), entry.Data.size(), MZ_DEFAULT_LEVEL
            );
        }
        mz_zip_writer_finalize_archive(&zip);
        mz_zip_writer_end(&zip);
    }

    std::vector<std::uint8_t> Bytes(const std::string &s) {
        return std::vector<std::uint8_t>(s.begin(), s.end());
    }

    std::vector<std::uint8_t> ReadAll(const std::string &path) {
        std::ifstream f(path, std::ios::binary);
        return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    }
}

TEST_CASE("BootTarget maps image names to partitions", "[device_root]") {
    REQUIRE(BootTargetForImageName("boot.img") == BootTarget::Boot);
    REQUIRE(BootTargetForImageName("/path/to/init_boot.img") == BootTarget::InitBoot);
    REQUIRE(BootTargetForImageName("INIT_BOOT.IMG") == BootTarget::InitBoot);
    REQUIRE(std::string(BootTargetPartition(BootTarget::Boot)) == "boot");
    REQUIRE(std::string(BootTargetPartition(BootTarget::InitBoot)) == "init_boot");
}

TEST_CASE("PickBootImageEntry prefers init_boot over boot", "[device_root]") {
    REQUIRE(PickBootImageEntry({"boot.img", "init_boot.img", "vendor_boot.img"}) == "init_boot.img");
    REQUIRE(PickBootImageEntry({"dir/boot.img", "dir/dtbo.img"}) == "dir/boot.img");
    REQUIRE(PickBootImageEntry({"system.img", "vbmeta.img"}).empty());
}

TEST_CASE("BuildBootPatchCommand is non-interactive and sets verity flags", "[device_root]") {
    const std::string strip =
        BuildBootPatchCommand("/data/local/tmp/coredeck-magisk", "boot.img", true);
    REQUIRE(strip ==
            "cd /data/local/tmp/coredeck-magisk && chmod -R 755 . && ASH_STANDALONE=1 "
            "KEEPVERITY=false KEEPFORCEENCRYPT=false RECOVERYMODE=false ./busybox sh ./boot_patch.sh ./boot.img");

    const std::string keep =
        BuildBootPatchCommand("/data/local/tmp/coredeck-magisk", "boot.img", false);
    REQUIRE(keep.find("KEEPVERITY=true KEEPFORCEENCRYPT=true") != std::string::npos);
}

TEST_CASE("DeviceRootStageLabel labels the stages", "[device_root]") {
    REQUIRE(std::string(DeviceRootStageLabel(DeviceRootStage::PatchBoot)) == "Patch boot image");
    REQUIRE(std::string(DeviceRootStageLabel(DeviceRootStage::FlashBoot)) == "Flash patched boot");
    REQUIRE(std::string(DeviceRootStageLabel(DeviceRootStage::Done)) == "Done");
}

TEST_CASE("ExtractMagiskPatchKit pulls binaries and scripts for the ABI", "[device_root]") {
    const std::vector<std::uint8_t> apk = MakeZipInMemory({
        {"lib/arm64-v8a/libmagiskboot.so", Bytes("MAGISKBOOT")},
        {"lib/arm64-v8a/libmagiskinit.so", Bytes("MAGISKINIT")},
        {"lib/arm64-v8a/libmagisk64.so", Bytes("MAGISK64")},
        {"lib/arm64-v8a/libbusybox.so", Bytes("BUSYBOX")},
        {"lib/x86_64/libmagiskboot.so", Bytes("WRONGABI")},
        {"assets/boot_patch.sh", Bytes("#!/sbin/sh\n")},
        {"assets/util_functions.sh", Bytes("# util\n")},
        {"assets/stub.apk", Bytes("STUB")},
    });

    const auto kit = ExtractMagiskPatchKit(apk, "arm64-v8a");
    REQUIRE(kit.has_value());
    REQUIRE(kit->Has("magiskboot"));
    REQUIRE(kit->Has("magiskinit"));
    REQUIRE(kit->Has("magisk64"));
    REQUIRE(kit->Has("busybox"));
    REQUIRE(kit->Has("boot_patch.sh"));
    REQUIRE(kit->Has("util_functions.sh"));
    REQUIRE(kit->Has("stub.apk"));

    const auto *boot = kit->Find("magiskboot");
    REQUIRE(boot != nullptr);
    REQUIRE(std::string(boot->begin(), boot->end()) == "MAGISKBOOT");

    // Missing magiskboot/boot_patch.sh -> nullopt.
    const std::vector<std::uint8_t> incomplete = MakeZipInMemory({
        {"lib/arm64-v8a/libmagiskinit.so", Bytes("X")},
        {"assets/util_functions.sh", Bytes("Y")},
    });
    REQUIRE_FALSE(ExtractMagiskPatchKit(incomplete, "arm64-v8a").has_value());
}

TEST_CASE("ExtractBootImageFromFactoryZip handles nested and flat archives", "[device_root]") {
    const std::filesystem::path dir =
        std::filesystem::temp_directory_path() / "coredeck_device_root_test";
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    std::filesystem::create_directories(dir, ec);

    SECTION("nested Pixel-style factory zip prefers init_boot") {
        const std::vector<std::uint8_t> innerZip = MakeZipInMemory({
            {"boot.img", Bytes("STOCK-BOOT")},
            {"init_boot.img", Bytes("STOCK-INIT-BOOT")},
            {"vendor_boot.img", Bytes("VB")},
        });
        const std::string outerPath = (dir / "shiba-factory.zip").string();
        WriteZipFile(outerPath, {
            {"shiba-ap4a/bootloader-shiba.img", Bytes("BL")},
            {"shiba-ap4a/flash-all.sh", Bytes("#!/bin/sh")},
            {"shiba-ap4a/image-shiba-ap4a.zip", innerZip},
        });

        const std::string destDir = (dir / "out").string();
        std::string error;
        const auto result = ExtractBootImageFromFactoryZip(outerPath, destDir, error);
        REQUIRE(result.has_value());
        REQUIRE(result->Target == BootTarget::InitBoot);
        REQUIRE(std::filesystem::path(result->LocalPath).filename() == "init_boot.img");
        REQUIRE(ReadAll(result->LocalPath) == Bytes("STOCK-INIT-BOOT"));
        // The temporary inner image zip is cleaned up.
        REQUIRE_FALSE(std::filesystem::exists(std::filesystem::path(destDir) / "image-shiba-ap4a.zip"));
    }

    SECTION("flat archive with boot.img directly") {
        const std::string flatPath = (dir / "ota.zip").string();
        WriteZipFile(flatPath, {{"boot.img", Bytes("FLAT-BOOT")}});

        const std::string destDir = (dir / "out2").string();
        std::string error;
        const auto result = ExtractBootImageFromFactoryZip(flatPath, destDir, error);
        REQUIRE(result.has_value());
        REQUIRE(result->Target == BootTarget::Boot);
        REQUIRE(ReadAll(result->LocalPath) == Bytes("FLAT-BOOT"));
    }

    SECTION("archive with no boot image fails cleanly") {
        const std::string badPath = (dir / "nope.zip").string();
        WriteZipFile(badPath, {{"system.img", Bytes("S")}, {"readme.txt", Bytes("hi")}});

        const std::string destDir = (dir / "out3").string();
        std::string error;
        const auto result = ExtractBootImageFromFactoryZip(badPath, destDir, error);
        REQUIRE_FALSE(result.has_value());
        REQUIRE_FALSE(error.empty());
    }

    std::filesystem::remove_all(dir, ec);
}
