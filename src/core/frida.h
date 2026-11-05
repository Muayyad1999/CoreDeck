//
// Created by CoreDeck RE toolbench on 05/11/2026.
//
// frida-server helper: resolve the matching frida-server release, download +
// decompress (.xz) + cache it, push it to a rooted AVD and run it, and list
// processes via the host frida-ps. For instrumenting apps on an AVD you own.
//

#ifndef COREDECK_FRIDA_H
#define COREDECK_FRIDA_H

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "core/sdk.h"

namespace CoreDeck::Core {
    struct FridaProcess {
        int Pid = 0;
        std::string Name;
    };

    // Map an Android ABI to frida's release arch suffix.
    std::string AbiToFridaArch(const std::string &abi);

    // "frida-server-<version>-android-<arch>"
    std::string FridaServerAssetName(const std::string &version, const std::string &abi);
    std::string FridaServerDownloadUrl(const std::string &version, const std::string &abi);

    // Trim `frida --version` output to the bare version string.
    std::string ParseFridaVersion(const std::string &fridaVersionOutput);

    // Parse `frida-ps` tabular output into pid/name rows.
    std::vector<FridaProcess> ParseFridaPs(const std::string &fridaPsOutput);

    // Run the host `frida --version`; empty when frida isn't installed.
    std::string DetectHostFridaVersion();

    struct FridaServerDeps {
        std::function<bool(const std::string &url, const std::string &dest, std::string &error)> Download;
        std::string CacheDir;
    };
    FridaServerDeps DefaultFridaServerDeps();

    // Resolve the frida-server binary for abi+version: download the .xz, decompress
    // it, and cache the binary. allowDownload=false only uses the cache.
    std::optional<std::string> ResolveFridaServer(
        const FridaServerDeps &deps,
        const std::string &version,
        const std::string &abi,
        bool allowDownload,
        std::string &error
    );

    // Push the binary to the device and start it as root (optionally on a TCP port).
    bool StartFridaServer(
        const SdkInfo &sdk,
        const std::string &serial,
        const std::string &binaryPath,
        const std::string &devName,
        int port,
        std::string &error
    );

    bool StopFridaServer(const SdkInfo &sdk, const std::string &serial, const std::string &devName);

    // List processes on the device via the host `frida-ps -D <serial>`.
    std::vector<FridaProcess> FridaPs(const std::string &serial, std::string &error);
}

#endif // COREDECK_FRIDA_H
