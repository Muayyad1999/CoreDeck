//
// Created by CoreDeck RE toolbench on 05/11/2026.
//

#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include <miniz.h>

#include "core/flutter.h"
#include "platform/paths.h"
#include "platform/process.h"

namespace CoreDeck::Core {
    namespace {
        bool EndsWith(const std::string &value, const std::string &suffix) {
            return value.size() >= suffix.size() && value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
        }
    }

    bool IsFlutterLib(const std::string &libName) {
        return EndsWith(libName, "libapp.so") || EndsWith(libName, "libflutter.so");
    }

    bool ApkIsFlutter(const std::vector<std::uint8_t> &apkBytes) {
        mz_zip_archive zip = {};
        if (mz_zip_reader_init_mem(&zip, apkBytes.data(), apkBytes.size(), 0) == MZ_FALSE) {
            return false;
        }
        bool found = false;
        const mz_uint count = mz_zip_reader_get_num_files(&zip);
        for (mz_uint i = 0; i < count && !found; ++i) {
            char name[512];
            const mz_uint len = mz_zip_reader_get_filename(&zip, i, name, sizeof(name));
            if (len > 0 && IsFlutterLib(std::string(name, len - 1))) {
                found = true;
            }
        }
        mz_zip_reader_end(&zip);
        return found;
    }

    std::string ResolveBlutter(const std::string &configuredPath) {
        namespace fs = std::filesystem;
        if (!configuredPath.empty() && fs::exists(configuredPath)) {
            return configuredPath;
        }
        if (const char *env = std::getenv("BLUTTER_PY"); env != nullptr && fs::exists(env)) { // NOLINT
            return env;
        }
        const std::string home = Platform::GetHomeDirectory();
        for (const std::string &guess:
             {Platform::JoinPaths({".", "blutter", "blutter.py"}),
              Platform::JoinPaths({home, "blutter", "blutter.py"})}) {
            if (fs::exists(guess)) {
                return guess;
            }
        }
        return "";
    }

    std::string ResolvePython() {
        for (const char *candidate: {"python3", "python"}) {
            const Platform::CommandResult result = Platform::RunCommandArgsResult(candidate, {"--version"});
            if (result.Started && result.ExitCode == 0) {
                return candidate;
            }
        }
        return "";
    }

    std::vector<std::string> BuildBlutterArgs(
        const std::string &blutterPy, const std::string &libDir, const std::string &outDir, const bool rebuild, const bool noAnalysis
    ) {
        std::vector<std::string> args = {blutterPy, libDir, outDir};
        if (rebuild) {
            args.emplace_back("--rebuild");
        }
        if (noAnalysis) {
            args.emplace_back("--no-analysis");
        }
        return args;
    }

    std::string ExtractFlutterLibs(const std::vector<std::uint8_t> &apkBytes, const std::string &destDir) {
        namespace fs = std::filesystem;
        mz_zip_archive zip = {};
        if (mz_zip_reader_init_mem(&zip, apkBytes.data(), apkBytes.size(), 0) == MZ_FALSE) {
            return "";
        }
        const std::string libDir = Platform::JoinPaths({destDir, "lib", "arm64-v8a"});
        std::error_code ec;
        fs::create_directories(libDir, ec);

        bool hasLibApp = false;
        const std::string prefix = "lib/arm64-v8a/";
        const mz_uint count = mz_zip_reader_get_num_files(&zip);
        for (mz_uint i = 0; i < count; ++i) {
            char name[512];
            const mz_uint len = mz_zip_reader_get_filename(&zip, i, name, sizeof(name));
            if (len == 0) {
                continue;
            }
            const std::string entry(name, len - 1);
            if (entry.size() <= prefix.size() || entry.compare(0, prefix.size(), prefix) != 0) {
                continue;
            }
            const std::string base = entry.substr(prefix.size());
            if (base.empty() || base.find('/') != std::string::npos) {
                continue; // only direct files
            }
            std::size_t outSize = 0;
            void *data = mz_zip_reader_extract_to_heap(&zip, i, &outSize, 0);
            if (data == nullptr) {
                continue;
            }
            const std::string outPath = Platform::JoinPaths({libDir, base});
            std::ofstream out(outPath, std::ios::binary | std::ios::trunc);
            if (out) {
                out.write(static_cast<const char *>(data), static_cast<std::streamsize>(outSize));
            }
            mz_free(data);
            if (base == "libapp.so") {
                hasLibApp = true;
            }
        }
        mz_zip_reader_end(&zip);
        return hasLibApp ? libDir : "";
    }

    namespace {
        std::optional<std::vector<std::uint8_t>> ReadFileBytes(const std::string &path) {
            std::ifstream file(path, std::ios::binary);
            if (!file) {
                return std::nullopt;
            }
            return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        }
    }

    BlutterRun RunBlutter(
        const std::string &apkPath, const std::string &blutterPy, const std::string &workDir, const bool noAnalysis
    ) {
        BlutterRun run;
        if (blutterPy.empty()) {
            run.Message = "Blutter was not found. Set its path, or install worawit/blutter.";
            return run;
        }
        const auto apk = ReadFileBytes(apkPath);
        if (!apk) {
            run.Message = "Could not read the APK: " + apkPath;
            return run;
        }
        const std::string libDir = ExtractFlutterLibs(*apk, Platform::JoinPaths({workDir, "_libs"}));
        if (libDir.empty()) {
            run.Message = "No lib/arm64-v8a/libapp.so in the APK (Blutter needs the arm64 Flutter libs).";
            return run;
        }
        const std::string python = ResolvePython();
        if (python.empty()) {
            run.Message = "No python interpreter found on PATH.";
            return run;
        }
        run.OutDir = Platform::JoinPaths({workDir, "out"});
        std::error_code ec;
        std::filesystem::create_directories(run.OutDir, ec);

        Platform::RunCommandArgsResult(python, BuildBlutterArgs(blutterPy, libDir, run.OutDir, false, noAnalysis));
        run.Outputs = BlutterOutputs(run.OutDir);
        run.Ok = !run.Outputs.empty();
        run.Message = run.Ok ? "Done." : "Blutter produced no output (see its console / try --no-analysis).";
        return run;
    }

    std::vector<std::string> BlutterOutputs(const std::string &outDir) {
        namespace fs = std::filesystem;
        std::vector<std::string> present;
        for (const char *file: {"blutter_frida.js", "pp.txt", "objs.txt"}) {
            if (fs::exists(Platform::JoinPaths({outDir, file}))) {
                present.emplace_back(file);
            }
        }
        for (const char *dir: {"asm", "ida_script"}) {
            if (fs::is_directory(Platform::JoinPaths({outDir, dir}))) {
                present.push_back(std::string(dir) + "/");
            }
        }
        return present;
    }
}
