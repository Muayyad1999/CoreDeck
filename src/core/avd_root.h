//
// Created by CoreDeck RE toolbench on 04/11/2026.
//
// AVD rooting (Magisk, host-side ramdisk patch). This header exposes the
// pure, unit-testable primitives (ramdisk codecs, cpio newc, Magisk release
// resolution, APK introspection, root verification) plus the orchestration
// types. The byte-exact Magisk patch and the live cold-boot pipeline land in
// a follow-up increment (they need ramdisk fixtures for the parity test).
//

#ifndef COREDECK_AVD_ROOT_H
#define COREDECK_AVD_ROOT_H

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "core/avd_manager.h"
#include "core/emulator.h"
#include "core/sdk.h"

namespace CoreDeck::Core {
    // ----------------------------------------------------------------------- //
    // Ramdisk compression
    // ----------------------------------------------------------------------- //
    enum class RamdiskFormat : std::uint8_t {
        Unknown,
        Raw, // uncompressed cpio
        Gzip,
        Lz4Legacy,
        Xz,
    };

    const char *RamdiskFormatName(RamdiskFormat format);

    // Detect by magic bytes (gzip 1f 8b, lz4-legacy 02 21 4c 18, xz fd 37 7a 58 5a 00,
    // raw cpio "070701"). Unknown otherwise.
    RamdiskFormat DetectRamdiskFormat(const std::vector<std::uint8_t> &data);

    // gzip (RFC 1952) over miniz raw deflate. Return nullopt on malformed input.
    std::optional<std::vector<std::uint8_t>> GzipInflate(const std::vector<std::uint8_t> &data);
    std::vector<std::uint8_t> GzipDeflate(const std::vector<std::uint8_t> &data, int level = 9);

    // LZ4 "legacy" frame (magic 0x184C2102, 8 MiB blocks). This is the format the
    // Android build system and magiskboot use for ramdisks.
    std::optional<std::vector<std::uint8_t>> Lz4LegacyDecompress(const std::vector<std::uint8_t> &data);
    std::vector<std::uint8_t> Lz4LegacyCompress(const std::vector<std::uint8_t> &data);

    // Store-mode XZ (valid .xz via uncompressed LZMA2 chunks; no LZMA needed).
    // Used for Magisk's overlay.d payloads; the output decompresses with any xz tool.
    std::vector<std::uint8_t> XzStoreCompress(const std::vector<std::uint8_t> &data);

    // ----------------------------------------------------------------------- //
    // cpio (newc / "070701")
    // ----------------------------------------------------------------------- //
    struct CpioEntry {
        std::string Name;
        std::uint32_t Ino = 0; // preserved for byte-identical round-trip
        std::uint32_t Mode = 0; // full st_mode (type + perms)
        std::uint32_t Nlink = 1;
        std::uint32_t Uid = 0;
        std::uint32_t Gid = 0;
        std::uint32_t Mtime = 0;
        std::uint32_t DevMajor = 0;
        std::uint32_t DevMinor = 0;
        std::uint32_t RdevMajor = 0;
        std::uint32_t RdevMinor = 0;
        std::vector<std::uint8_t> Data;

        bool IsDirectory() const {
            return (Mode & 0170000U) == 0040000U;
        }
        bool IsSymlink() const {
            return (Mode & 0170000U) == 0120000U;
        }
    };

    using CpioArchive = std::vector<CpioEntry>;

    // Parse a newc cpio stream up to (and stopping at) the TRAILER!!! marker.
    std::optional<CpioArchive> ParseCpioNewc(const std::vector<std::uint8_t> &data);

    // Serialize to a newc stream (ending with the TRAILER!!! record, 4-byte padded).
    std::vector<std::uint8_t> SerializeCpioNewc(const CpioArchive &archive);

    // Merge concatenated archives; on a name collision the later entry wins
    // (matches the kernel's unpack order for Android's generic+vendor ramdisks).
    CpioArchive MergeCpio(const std::vector<CpioArchive> &archives);

    // ----------------------------------------------------------------------- //
    // Magisk release + APK
    // ----------------------------------------------------------------------- //
    enum class MagiskChannel : std::uint8_t { Stable,
                                              Prerelease };

    struct MagiskRelease {
        std::string Tag;
        MagiskChannel Channel = MagiskChannel::Stable;
        std::string Url; // browser_download_url of the .apk asset
        std::string FileName;
        std::uint64_t Size = 0;
    };

    // Pick the newest matching release from a GitHub /releases JSON payload.
    // includePrerelease=false skips prereleases/drafts.
    std::optional<MagiskRelease> ParseMagiskReleases(const std::string &json, bool includePrerelease);

    struct MagiskApkInfo {
        std::vector<std::string> Abis; // from lib/<abi>/
    };

    // Introspect a Magisk .apk (a zip): the ABIs present under lib/. Works on the
    // raw apk bytes; no aapt. (minSdk parse from the binary manifest lands with the
    // patch increment, where it gates the install.)
    std::optional<MagiskApkInfo> ParseMagiskApk(const std::vector<std::uint8_t> &apkBytes);

    // Dependency seam so resolution is unit-testable without a network.
    struct MagiskResolveDeps {
        // GET a URL, return the body (e.g. the GitHub releases JSON), or nullopt.
        std::function<std::optional<std::string>(const std::string &url)> HttpGet;
        // Download a URL to a local path with progress; return false on failure.
        std::function<bool(const std::string &url, const std::string &destPath, std::string &error)> Download;
        // SHA-256 of a local file (lowercase hex).
        std::function<std::string(const std::string &path)> FileSha256;
        // Directory to cache downloaded archives under.
        std::string CacheDir;
    };

    MagiskResolveDeps DefaultMagiskResolveDeps();

    struct ResolvedMagisk {
        MagiskRelease Release;
        std::string LocalPath; // cached .apk on disk
        std::string Sha256; // of the downloaded file (lowercase hex)
        MagiskApkInfo Info;
    };

    // Resolve newest release, download+cache+hash it, and introspect the apk.
    // allowDownload=false only uses the cache / a user-provided override path.
    std::optional<ResolvedMagisk> ResolveMagisk(
        const MagiskResolveDeps &deps,
        bool includePrerelease,
        bool allowDownload,
        const std::string &overridePath,
        std::string &error
    );

    // ----------------------------------------------------------------------- //
    // Magisk ramdisk patch (host-side; reproduces Magisk's boot_patch cpio ops)
    // ----------------------------------------------------------------------- //
    // Binaries pulled from the Magisk apk, keyed by canonical name
    // (magiskinit, magisk32, magisk64, init-ld, stub, busybox).
    struct MagiskFiles {
        std::vector<std::pair<std::string, std::vector<std::uint8_t>>> Files;

        const std::vector<std::uint8_t> *Find(const std::string &name) const;
        bool Has(const std::string &name) const {
            return Find(name) != nullptr;
        }
    };

    // Extract the Magisk binaries for one ABI from the apk bytes (lib/<abi>/lib*.so,
    // plus assets/stub.apk when present).
    std::optional<MagiskFiles> ExtractMagiskFiles(const std::vector<std::uint8_t> &apkBytes, const std::string &abi);

    // True when a ramdisk cpio already carries a Magisk patch (.backup dir present).
    bool IsRamdiskPatched(const CpioArchive &archive);

    // Reproduce Magisk's boot_patch on a stock ramdisk cpio: if already patched,
    // revert to stock first; back up the stock /init to .backup/init; install
    // magiskinit as /init (0750); add overlay.d/sbin/{magisk,stub,init-ld}.xz;
    // record .backup/.magisk config and .backup/.rmlist; optionally strip verity /
    // forceencrypt flags from fstab entries. Returns the patched archive.
    // NOTE: modeled on magiskboot; needs an on-device boot test and a parity test
    // against real magiskboot output before it is trusted as byte-compatible.
    CpioArchive ApplyMagiskPatch(const CpioArchive &stock, const MagiskFiles &magisk, bool stripVerity);

    // Undo ApplyMagiskPatch on an in-memory archive (restore .backup/init, drop
    // every path listed in .backup/.rmlist and the .backup dir).
    CpioArchive RevertMagiskPatch(const CpioArchive &patched);

    // File-level: read ramdisk.img, decompress, patch, recompress in the original
    // format, and write atomically, keeping a once-only pristine ".stock" backup.
    // Concatenated (multi-archive) and xz ramdisks are rejected with a clear error.
    bool PatchRamdiskImageFile(
        const std::string &ramdiskPath, const MagiskFiles &magisk, bool stripVerity, std::string &error
    );

    // Restore ramdisk.img from the once-only pristine ".stock" backup.
    bool RestoreRamdiskImageFile(const std::string &ramdiskPath, std::string &error);

    // Locate the ramdisk.img of the AVD's system image (empty when not found).
    std::string FindSystemImageRamdisk(const AvdInfo &avd);

    // ----------------------------------------------------------------------- //
    // Root verification
    // ----------------------------------------------------------------------- //
    enum class RootStatus : std::uint8_t {
        Unknown, // adb/su unavailable or no device
        NotRooted, // su returned non-root / denied
        Rooted, // su -c id => uid=0(root)
    };

    const char *RootStatusName(RootStatus status);

    // True when `id` output reports uid=0 (root).
    bool ParseRootId(const std::string &idOutput);

    // Run `adb -s <serial> shell su -c id` and classify the result.
    RootStatus CheckRoot(const SdkInfo &sdk, const std::string &serial);

    // ----------------------------------------------------------------------- //
    // Orchestration types (pipeline lands next increment; kept here so the
    // Context work-struct and window are stable against it)
    // ----------------------------------------------------------------------- //
    enum class RootStage : std::uint8_t {
        Idle,
        ResolveMagisk,
        StartEmulator,
        ReadPreinit,
        WriteMagiskEnv,
        PatchRamdisk,
        ColdReboot,
        GrantSu,
        Verify,
        Done,
        Failed,
    };

    const char *RootStageLabel(RootStage stage);

    // Live progress, owned by the GUI work-struct (shared_ptr), written by the
    // worker thread. Non-copyable (atomics + mutex).
    struct RootProgress {
        std::atomic<RootStage> Stage{RootStage::Idle};
        std::atomic<float> Fraction{0.0F};
        std::mutex Mutex;
        std::string Detail;
        std::string Error;

        void Set(RootStage stage, float fraction, const std::string &detail) {
            Stage.store(stage);
            Fraction.store(fraction);
            std::lock_guard<std::mutex> lock(Mutex);
            Detail = detail;
        }
        void Fail(const std::string &error) {
            Stage.store(RootStage::Failed);
            std::lock_guard<std::mutex> lock(Mutex);
            Error = error;
        }
    };

    struct RootPlan {
        AvdInfo Avd;
        std::string Serial; // a running device serial for this AVD
        std::string MagiskApkPath; // resolved Magisk .apk
        std::string Abi; // chosen ABI
        std::string RamdiskPath; // system image ramdisk.img
        bool StripVerity = true;
    };

    // Resolve the ABI and ramdisk path for the AVD. error set on failure.
    std::optional<RootPlan> PlanRoot(
        const SdkInfo &sdk, const AvdInfo &avd, const std::string &magiskApkPath, std::string &error
    );

    // Execute the host-side root end to end (patch ramdisk, cold reboot, verify su).
    // EXPERIMENTAL: performs device-modifying steps; validate on a disposable AVD.
    // A pristine ramdisk backup is taken before any write so RestoreAvd can recover.
    bool RootAvd(const SdkInfo &sdk, EmulatorManager &emulator, const RootPlan &plan, RootProgress &progress);

    // Restore an AVD to stock from the once-only ramdisk backup.
    bool RestoreAvd(const SdkInfo &sdk, const AvdInfo &avd, std::string &error);
}

#endif // COREDECK_AVD_ROOT_H
