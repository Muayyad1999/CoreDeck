//
// Created by CoreDeck RE toolbench on 05/11/2026.
//

#include <array>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "core/checks.h"
#include "platform/process.h"

namespace CoreDeck::Core {
    namespace {
        struct Pattern {
            const char *Label;
            const char *Regex;
        };

        // smali patterns that usually mean "detect X then bail" (ported from apkkit).
        const std::array<Pattern, 7> CHECK_PATTERNS = {{
            {"root", R"("/system/(xbin|bin)/su"|"su"|magisk|Superuser|RootBeer|test-keys|which su)"},
            {"emulator", R"(goldfish|ranchu|generic_x86|sdk_gphone|ro\.kernel\.qemu|"unknown"|Genymotion)"},
            {"signature-tamper",
             R"(GET_SIGNATURES|getSignatures|signingInfo|GET_SIGNING_CERTIFICATES|PackageManager;->getPackageInfo)"},
            {"integrity", R"(SafetyNet|DroidGuard|IntegrityManager|attest)"},
            {"frida", R"(frida|gadget|re\.frida|LIBFRIDA|27042|linjector)"},
            {"debugger", R"(isDebuggerConnected|waitingForDebugger|Debug;->)"},
            {"self-close",
             R"(Ljava/lang/System;->exit|Ljava/lang/Runtime;->halt|Landroid/os/Process;->killProcess|->finishAffinity)"},
        }};

        const std::vector<std::pair<std::string, std::regex>> &CompiledPatterns() {
            static const std::vector<std::pair<std::string, std::regex>> compiled = [] {
                std::vector<std::pair<std::string, std::regex>> out;
                for (const Pattern &p: CHECK_PATTERNS) {
                    out.emplace_back(p.Label, std::regex(p.Regex, std::regex::icase | std::regex::optimize));
                }
                return out;
            }();
            return compiled;
        }

        const std::regex &KillRegex() {
            static const std::regex kill(
                R"(^\s*invoke-\w+\s*\{[^}]*\},\s*L(java/lang/System;->exit\(I\)V|java/lang/Runtime;->halt\(I\)V|android/os/Process;->killProcess\(I\)V|android/app/Activity;->finishAffinity\(\)V))",
                std::regex::optimize
            );
            return kill;
        }

        std::string TrimCopy(const std::string &s) {
            std::size_t a = 0;
            std::size_t b = s.size();
            while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) {
                ++a;
            }
            while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) {
                --b;
            }
            return s.substr(a, b - a);
        }
    }

    std::vector<CheckFinding> ScanSmaliText(const std::string &smali) {
        std::vector<CheckFinding> findings;
        std::istringstream stream(smali);
        std::string line;
        int number = 0;
        const auto &patterns = CompiledPatterns();
        while (std::getline(stream, line)) {
            ++number;
            for (const auto &[label, regex]: patterns) {
                if (std::regex_search(line, regex)) {
                    findings.push_back(CheckFinding{label, number, TrimCopy(line)});
                }
            }
        }
        return findings;
    }

    bool IsSelfKillLine(const std::string &line) {
        return std::regex_search(line, KillRegex());
    }

    std::pair<std::string, int> NeutralizeSmaliText(const std::string &smali) {
        std::istringstream stream(smali);
        std::string line;
        std::string out;
        int count = 0;
        bool first = true;
        while (std::getline(stream, line)) {
            if (!first) {
                out.push_back('\n');
            }
            first = false;
            if (IsSelfKillLine(line)) {
                out += "# [coredeck neutralized] " + line;
                ++count;
            } else {
                out += line;
            }
        }
        if (!smali.empty() && smali.back() == '\n') {
            out.push_back('\n');
        }
        return {out, count};
    }

    std::string ResolveApktool(const std::string &configuredPath) {
        if (!configuredPath.empty() && std::filesystem::exists(configuredPath)) {
            return configuredPath;
        }
        return "apktool"; // resolved on PATH
    }

    ScanResult DecodeAndScan(
        const std::string &apktool, const std::string &apkPath, const std::string &decodedDir
    ) {
        namespace fs = std::filesystem;
        ScanResult result;
        result.DecodedDir = decodedDir;

        if (!fs::is_directory(decodedDir)) {
            const Platform::CommandResult decode =
                Platform::RunCommandArgsResult(apktool, {"d", apkPath, "-o", decodedDir, "-f"});
            if (!decode.Started) {
                result.Message = "Could not run apktool. Install it and set its path.";
                return result;
            }
            if (decode.ExitCode != 0) {
                result.Message = "apktool decode failed: " + decode.Output;
                return result;
            }
        }

        std::error_code ec;
        for (fs::recursive_directory_iterator it(decodedDir, ec), end; it != end; it.increment(ec)) {
            if (ec || !it->is_regular_file(ec) || it->path().extension() != ".smali") {
                continue;
            }
            ++result.SmaliFiles;
            std::ifstream file(it->path(), std::ios::binary);
            if (!file) {
                continue;
            }
            const std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            const std::string rel = fs::relative(it->path(), decodedDir, ec).string();
            for (CheckFinding finding: ScanSmaliText(text)) {
                finding.Text = rel + ":" + std::to_string(finding.Line) + "  " + finding.Text;
                result.Findings.push_back(std::move(finding));
            }
        }
        result.Ok = true;
        result.Message = result.Findings.empty()
                             ? "No obvious checks found in smali (native check, or packed)."
                             : "Scan complete.";
        return result;
    }

    NeutralizeResult NeutralizeAndBuild(
        const std::string &apktool, const std::string &decodedDir, const std::string &outApk
    ) {
        namespace fs = std::filesystem;
        NeutralizeResult result;
        if (!fs::is_directory(decodedDir)) {
            result.Message = "Decode the APK first.";
            return result;
        }
        std::error_code ec;
        for (fs::recursive_directory_iterator it(decodedDir, ec), end; it != end; it.increment(ec)) {
            if (ec || !it->is_regular_file(ec) || it->path().extension() != ".smali") {
                continue;
            }
            std::string text;
            {
                std::ifstream file(it->path(), std::ios::binary);
                if (!file) {
                    continue;
                }
                text.assign((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            }
            auto [patched, count] = NeutralizeSmaliText(text);
            if (count > 0) {
                std::ofstream out(it->path(), std::ios::binary | std::ios::trunc);
                if (out) {
                    out.write(patched.data(), static_cast<std::streamsize>(patched.size()));
                    result.Patched += count;
                }
            }
        }

        const Platform::CommandResult build =
            Platform::RunCommandArgsResult(apktool, {"b", decodedDir, "-o", outApk});
        if (!build.Started) {
            result.Message = "Could not run apktool to rebuild.";
            return result;
        }
        if (build.ExitCode != 0) {
            result.Message = "apktool build failed: " + build.Output;
            return result;
        }
        result.Ok = true;
        result.OutApk = outApk;
        result.Message = "Neutralized " + std::to_string(result.Patched) +
                         " self-kill call(s). Sign the output with APK Signer.";
        return result;
    }
}
