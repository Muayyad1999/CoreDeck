//
// Created by CoreDeck RE toolbench on 05/11/2026.
//
// frida-server helper: resolve the matching frida-server release, download +
// decompress (.xz) + cache it, push it to a rooted AVD and run it, and list
// processes via the host frida-ps. For instrumenting apps on an AVD you own.
//

#ifndef COREDECK_FRIDA_H
#define COREDECK_FRIDA_H

#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "core/sdk.h"
#include "platform/log_buffer.h"
#include "platform/process.h"

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

    // ----------------------------------------------------------------------- //
    // Hook runner (run a frida session with scripts, stream its output)
    // ----------------------------------------------------------------------- //
    struct FridaScript {
        std::string Name; // display name
        std::string Category; // "dev" or "sensitive"
        std::string Filename; // suggested file name
        std::string Content; // the Frida JS
    };

    // Bundled, generic observability scripts (operate on the app you choose).
    std::vector<FridaScript> BundledFridaScripts();

    bool SaveFridaScript(
        const std::string &dir, const std::string &filename, const std::string &content, std::string &error
    );

    // Build the host `frida` argv: spawn (-f) or attach (-n) the package on the
    // device, loading each script with -l.
    std::vector<std::string> BuildFridaHookArgs(
        const std::string &serial, const std::string &package, const std::vector<std::string> &scriptPaths, bool attach
    );

    // A running frida session whose stdout is streamed into a log buffer.
    struct FridaHookSession {
        std::shared_ptr<Platform::LogBuffer> Log;
        std::shared_ptr<std::atomic<bool>> StopFlag;
        ProcessId Pid{};
        std::thread Reader;
        std::atomic<bool> Running{false};

        FridaHookSession() = default;
        ~FridaHookSession(); // stops + joins so exit never terminates a live thread
        FridaHookSession(const FridaHookSession &) = delete;
        FridaHookSession &operator=(const FridaHookSession &) = delete;
    };

    // Spawn the host `frida` with the given scripts and stream its output into
    // session.Log. Requires the host frida tools on PATH.
    bool StartFridaHook(
        const std::string &serial,
        const std::string &package,
        const std::vector<std::string> &scriptPaths,
        bool attach,
        FridaHookSession &session,
        std::string &error
    );

    // Signal stop, kill the frida process tree, and join the reader thread.
    void StopFridaHook(FridaHookSession &session);
}

#endif // COREDECK_FRIDA_H
