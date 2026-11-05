//
// Created by CoreDeck RE toolbench on 05/11/2026.
//

#include "core/tools.h"

#include <cstdlib>
#include <filesystem>
#include <utility>

#include "core/adb.h"

namespace CoreDeck::Core {
    namespace {
#if defined(_WIN32)
        constexpr char kPathSeparator = ';';
        constexpr bool kWindows = true;
#else
        constexpr char kPathSeparator = ':';
        constexpr bool kWindows = false;
#endif

        bool HasExtension(const std::string &name) {
            const std::size_t dot = name.find_last_of('.');
            const std::size_t slash = name.find_last_of("/\\");
            if (dot == std::string::npos) {
                return false;
            }
            return slash == std::string::npos || dot > slash;
        }

        std::string EnvOrEmpty(const char *key) {
            const char *value = std::getenv(key);
            return value != nullptr ? std::string(value) : std::string();
        }
    }

    std::vector<std::string> ExecutableCandidates(const std::string &name) {
        if (!kWindows || HasExtension(name)) {
            return {name};
        }
        return {name + ".exe", name + ".bat", name + ".cmd", name};
    }

    std::vector<std::string> SplitSearchPath(const std::string &value, const char separator) {
        std::vector<std::string> parts;
        std::string current;
        for (const char c: value) {
            if (c == separator) {
                if (!current.empty()) {
                    parts.push_back(current);
                }
                current.clear();
            } else {
                current.push_back(c);
            }
        }
        if (!current.empty()) {
            parts.push_back(current);
        }
        // Strip surrounding quotes a Windows PATH entry may carry.
        for (std::string &part: parts) {
            if (part.size() >= 2 && part.front() == '"' && part.back() == '"') {
                part = part.substr(1, part.size() - 2);
            }
        }
        return parts;
    }

    std::optional<std::string> ResolveExecutable(
        const std::vector<std::string> &exeNames, const std::string &overridePath
    ) {
        namespace fs = std::filesystem;
        std::error_code ec;

        if (!overridePath.empty() && fs::exists(overridePath, ec) && !fs::is_directory(overridePath, ec)) {
            return fs::absolute(overridePath, ec).string();
        }

        const std::vector<std::string> dirs = SplitSearchPath(EnvOrEmpty("PATH"), kPathSeparator);
        for (const std::string &base: exeNames) {
            for (const std::string &candidate: ExecutableCandidates(base)) {
                for (const std::string &dir: dirs) {
                    const fs::path full = fs::path(dir) / candidate;
                    if (fs::exists(full, ec) && !fs::is_directory(full, ec)) {
                        return full.string();
                    }
                }
            }
        }
        return std::nullopt;
    }

    const std::vector<ReToolSpec> &ReToolRegistry() {
        static const std::vector<ReToolSpec> registry = {
            {
                "adb",
                "adb",
                "Everything device-side (Devices, Proxy, Frida, App Data, MITM)",
                {"adb"},
                ReToolSource::PlatformTools,
                false,
                {
                    "Android platform-tools (adb).",
                    "Download: https://developer.android.com/tools/releases/platform-tools",
                    "Unzip and add the platform-tools folder to PATH, or set the SDK path in Preferences.",
                },
            },
            {
                "java",
                "java",
                "APK Signer, Jar Signer, Keytool, and apktool",
                {"java"},
                ReToolSource::Path,
                false,
                {
                    "A Java runtime (JDK).",
                    "Get Temurin: https://adoptium.net",
                    "Verify: java -version",
                },
            },
            {
                "aapt2",
                "aapt2",
                "APK Analyzer (manifest, package, permissions)",
                {"aapt2", "aapt"},
                ReToolSource::BuildTools,
                true,
                {
                    "aapt2 ships with the Android build-tools.",
                    "Install build-tools in Preferences > Android SDK, or add <sdk>/build-tools/<ver> to PATH.",
                },
            },
            {
                "apksigner",
                "apksigner",
                "APK Signer (sign a rebuilt/patched APK)",
                {"apksigner"},
                ReToolSource::BuildTools,
                true,
                {
                    "apksigner ships with the Android build-tools.",
                    "Install build-tools in Preferences > Android SDK, or add <sdk>/build-tools/<ver> to PATH.",
                },
            },
            {
                "zipalign",
                "zipalign",
                "APK Signer (align before signing)",
                {"zipalign"},
                ReToolSource::BuildTools,
                true,
                {
                    "zipalign ships with the Android build-tools.",
                    "Install build-tools in Preferences > Android SDK, or add <sdk>/build-tools/<ver> to PATH.",
                },
            },
            {
                "apktool",
                "apktool",
                "Hardening (decode to smali, scan, rebuild)",
                {"apktool"},
                ReToolSource::Path,
                true,
                {
                    "apktool disassembles an APK to smali and decodes resources.",
                    "Guide: https://apktool.org/docs/install",
                    "Windows: put apktool.bat + apktool.jar in one PATH folder. Verify: apktool --version",
                },
            },
            {
                "jadx",
                "jadx",
                "Decompile to readable Java (run externally)",
                {"jadx"},
                ReToolSource::Path,
                true,
                {
                    "jadx decompiles an APK/DEX to Java.",
                    "Download: https://github.com/skylot/jadx/releases",
                    "Unzip and add jadx/bin to PATH (jadx / jadx-gui).",
                },
            },
            {
                "frida",
                "frida",
                "Frida tooling (host side of Frida / Frida Hook)",
                {"frida"},
                ReToolSource::Path,
                true,
                {
                    "Frida tools (the frida CLI and frida-ps).",
                    "Install: pip install frida-tools  (Windows: py -m pip install frida-tools)",
                    "Verify: frida --version",
                },
            },
            {
                "frida-ps",
                "frida-ps",
                "Frida window (list device processes)",
                {"frida-ps"},
                ReToolSource::Path,
                true,
                {
                    "frida-ps comes with the Frida tools.",
                    "Install: pip install frida-tools",
                },
            },
            {
                "objection",
                "objection",
                "Gadget inject on an UNROOTED device (run externally)",
                {"objection"},
                ReToolSource::Path,
                true,
                {
                    "objection patches an APK with the Frida gadget - no root needed.",
                    "Install: pip install objection  (also pulls in frida). Verify: objection version",
                },
            },
            {
                "blutter",
                "blutter",
                "Flutter window (Dart static analysis)",
                {"blutter", "blutter.py"},
                ReToolSource::Path,
                true,
                {
                    "Blutter recovers Dart names + disassembly from a Flutter app.",
                    "Clone & build: git clone https://github.com/worawit/blutter",
                    "Needs Python3 (pyelftools, requests), cmake, ninja, capstone, icu.",
                    "Point the Flutter window at blutter.py.",
                },
            },
        };
        return registry;
    }

    std::vector<ReToolStatus> DetectReTools(const SdkInfo &sdk) {
        return DetectReTools(sdk, {});
    }

    std::vector<ReToolStatus> DetectReTools(
        const SdkInfo &sdk, const std::vector<std::pair<std::string, std::string>> &overrides
    ) {
        namespace fs = std::filesystem;
        std::error_code ec;

        const auto overrideFor = [&overrides](const std::string &key) -> std::string {
            for (const auto &[k, v]: overrides) {
                if (k == key) {
                    return v;
                }
            }
            return "";
        };

        std::vector<ReToolStatus> out;
        out.reserve(ReToolRegistry().size());
        for (const ReToolSpec &spec: ReToolRegistry()) {
            ReToolStatus status;
            status.Spec = spec;

            const std::string overridePath = overrideFor(spec.Key);
            std::string sdkPath; // a path the SDK already resolved for this tool

            switch (spec.Source) {
                case ReToolSource::PlatformTools:
                    if (spec.Key == "adb") {
                        sdkPath = ResolveAdbPath(sdk);
                    }
                    break;
                case ReToolSource::BuildTools:
                    if (spec.Key == "apksigner") {
                        sdkPath = sdk.ApksignerPath;
                    } else if (spec.Key == "zipalign") {
                        sdkPath = sdk.ZipalignPath;
                    } else if (spec.Key == "aapt2") {
                        sdkPath = sdk.Aapt2Path;
                    }
                    break;
                case ReToolSource::Path:
                    break;
            }

            if (!overridePath.empty() && fs::exists(overridePath, ec) && !fs::is_directory(overridePath, ec)) {
                status.Found = true;
                status.ResolvedPath = fs::absolute(overridePath, ec).string();
            } else if (!sdkPath.empty() && fs::exists(sdkPath, ec) && !fs::is_directory(sdkPath, ec)) {
                status.Found = true;
                status.ResolvedPath = sdkPath;
            } else if (const auto resolved = ResolveExecutable(spec.ExeNames, overridePath)) {
                status.Found = true;
                status.ResolvedPath = *resolved;
            }

            out.push_back(std::move(status));
        }
        return out;
    }
}
