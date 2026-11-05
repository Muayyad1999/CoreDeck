//
// Created by CoreDeck RE toolbench on 05/11/2026.
//

#include <cctype>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "core/frida.h"
#include "core/adb.h"
#include "core/xz.h"
#include "platform/http_download.h"
#include "platform/paths.h"
#include "platform/process.h"

namespace CoreDeck::Core {
    namespace {
        std::string Trim(const std::string &value) {
            std::size_t start = 0;
            std::size_t end = value.size();
            while (start < end && std::isspace(static_cast<unsigned char>(value[start]))) {
                ++start;
            }
            while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
                --end;
            }
            return value.substr(start, end - start);
        }

        std::optional<std::vector<std::uint8_t>> ReadFileBytes(const std::string &path) {
            std::ifstream file(path, std::ios::binary);
            if (!file) {
                return std::nullopt;
            }
            return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        }
    }

    std::string AbiToFridaArch(const std::string &abi) {
        if (abi == "arm64-v8a") {
            return "arm64";
        }
        if (abi == "armeabi-v7a") {
            return "arm";
        }
        if (abi == "x86_64") {
            return "x86_64";
        }
        if (abi == "x86") {
            return "x86";
        }
        return "arm64";
    }

    std::string FridaServerAssetName(const std::string &version, const std::string &abi) {
        return "frida-server-" + version + "-android-" + AbiToFridaArch(abi);
    }

    std::string FridaServerDownloadUrl(const std::string &version, const std::string &abi) {
        return "https://github.com/frida/frida/releases/download/" + version + "/" +
               FridaServerAssetName(version, abi) + ".xz";
    }

    std::string ParseFridaVersion(const std::string &fridaVersionOutput) {
        const std::string trimmed = Trim(fridaVersionOutput);
        // Keep the first whitespace-delimited token (the version).
        const std::size_t space = trimmed.find_first_of(" \t\r\n");
        return space == std::string::npos ? trimmed : trimmed.substr(0, space);
    }

    std::vector<FridaProcess> ParseFridaPs(const std::string &fridaPsOutput) {
        std::vector<FridaProcess> processes;
        std::istringstream stream(fridaPsOutput);
        std::string line;
        while (std::getline(stream, line)) {
            const std::string trimmed = Trim(line);
            if (trimmed.empty()) {
                continue;
            }
            // Skip the header row ("PID  Name") and the separator ("----  ----").
            if (trimmed.rfind("PID", 0) == 0 || trimmed.find_first_not_of("- \t") == std::string::npos) {
                continue;
            }
            std::istringstream row(trimmed);
            std::string pidText;
            row >> pidText;
            bool numeric = !pidText.empty();
            for (const char c: pidText) {
                if (std::isdigit(static_cast<unsigned char>(c)) == 0) {
                    numeric = false;
                    break;
                }
            }
            if (!numeric) {
                continue;
            }
            std::string name;
            std::getline(row, name);
            FridaProcess process;
            process.Pid = std::stoi(pidText);
            process.Name = Trim(name);
            processes.push_back(std::move(process));
        }
        return processes;
    }

    std::string DetectHostFridaVersion() {
        const Platform::CommandResult result = Platform::RunCommandArgsResult("frida", {"--version"});
        if (!result.Started || result.ExitCode != 0) {
            return "";
        }
        return ParseFridaVersion(result.Output);
    }

    FridaServerDeps DefaultFridaServerDeps() {
        FridaServerDeps deps;
        deps.Download = [](const std::string &url, const std::string &dest, std::string &error) {
            return Platform::HttpDownloadToFile(
                url,
                dest,
                "CoreDeck",
                [](std::uint64_t, std::uint64_t) { return true; },
                error
            );
        };
        deps.CacheDir = Platform::JoinPaths({Platform::GetConfigDirectory(), "frida"});
        return deps;
    }

    std::optional<std::string> ResolveFridaServer(
        const FridaServerDeps &deps,
        const std::string &version,
        const std::string &abi,
        const bool allowDownload,
        std::string &error
    ) {
        if (version.empty()) {
            error = "No frida version given, and the host `frida` was not found.";
            return std::nullopt;
        }
        if (deps.CacheDir.empty()) {
            error = "No cache directory is configured.";
            return std::nullopt;
        }
        std::error_code ec;
        std::filesystem::create_directories(deps.CacheDir, ec);

        const std::string name = FridaServerAssetName(version, abi);
        const std::string cached = Platform::JoinPaths({deps.CacheDir, name});
        if (std::filesystem::exists(cached)) {
            return cached;
        }
        if (!allowDownload) {
            error = "frida-server is not cached and downloads are disabled.";
            return std::nullopt;
        }
        if (!deps.Download) {
            error = "No downloader is configured.";
            return std::nullopt;
        }

        const std::string xzPath = cached + ".xz";
        std::string downloadError;
        if (!deps.Download(FridaServerDownloadUrl(version, abi), xzPath, downloadError)) {
            error = "Download failed: " + downloadError;
            return std::nullopt;
        }
        const auto xzBytes = ReadFileBytes(xzPath);
        if (!xzBytes) {
            error = "Could not read the downloaded archive.";
            return std::nullopt;
        }
        const auto binary = XzDecompress(*xzBytes);
        if (!binary) {
            error = "Could not decompress the frida-server archive.";
            return std::nullopt;
        }
        {
            std::ofstream out(cached, std::ios::binary | std::ios::trunc);
            if (!out) {
                error = "Could not write the frida-server binary to the cache.";
                return std::nullopt;
            }
            out.write(reinterpret_cast<const char *>(binary->data()), static_cast<std::streamsize>(binary->size()));
        }
        std::filesystem::remove(xzPath, ec);
        return cached;
    }

    bool StartFridaServer(
        const SdkInfo &sdk,
        const std::string &serial,
        const std::string &binaryPath,
        const std::string &devName,
        const int port,
        std::string &error
    ) {
        const std::string devPath = "/data/local/tmp/" + devName;
        const AdbResult push = Push(sdk, serial, binaryPath, devPath);
        if (!push.Ok()) {
            error = "adb push failed: " + push.Output;
            return false;
        }
        const AdbResult chmod = ShellSu(sdk, serial, "chmod 755 " + devPath);
        if (!chmod.Ok()) {
            error = "Could not chmod frida-server (is the AVD rooted?). " + chmod.Output;
            return false;
        }
        const std::string listen = port > 0 ? (" -l 0.0.0.0:" + std::to_string(port)) : "";
        ShellSu(sdk, serial, "nohup " + devPath + listen + " >/dev/null 2>&1 &");
        return true;
    }

    bool StopFridaServer(const SdkInfo &sdk, const std::string &serial, const std::string &devName) {
        const AdbResult result =
            ShellSu(sdk, serial, "pkill -f frida-server; pkill -f /data/local/tmp/" + devName);
        return result.Started;
    }

    std::vector<FridaProcess> FridaPs(const std::string &serial, std::string &error) {
        const Platform::CommandResult result = Platform::RunCommandArgsResult("frida-ps", {"-D", serial});
        if (!result.Started) {
            error = "Could not run frida-ps. Install frida on the host (pip install frida-tools).";
            return {};
        }
        if (result.ExitCode != 0) {
            error = Trim(result.Output);
            return {};
        }
        return ParseFridaPs(result.Output);
    }
}
