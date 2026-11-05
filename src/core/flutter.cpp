//
// Created by CoreDeck RE toolbench on 05/11/2026.
//

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
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

    // --------------------------------------------------- Flutter TLS static patch //

    namespace {
        int HexNibble(const char c) {
            if (c >= '0' && c <= '9') {
                return c - '0';
            }
            if (c >= 'a' && c <= 'f') {
                return c - 'a' + 10;
            }
            if (c >= 'A' && c <= 'F') {
                return c - 'A' + 10;
            }
            return 0;
        }

        std::uint16_t U16(const std::vector<std::uint8_t> &d, const std::size_t o) {
            return static_cast<std::uint16_t>(d[o]) | (static_cast<std::uint16_t>(d[o + 1]) << 8);
        }
        std::uint32_t U32(const std::vector<std::uint8_t> &d, const std::size_t o) {
            return static_cast<std::uint32_t>(d[o]) | (static_cast<std::uint32_t>(d[o + 1]) << 8) |
                   (static_cast<std::uint32_t>(d[o + 2]) << 16) | (static_cast<std::uint32_t>(d[o + 3]) << 24);
        }
        std::uint64_t U64(const std::vector<std::uint8_t> &d, const std::size_t o) {
            std::uint64_t v = 0;
            for (int i = 0; i < 8; ++i) {
                v |= static_cast<std::uint64_t>(d[o + i]) << (8 * i);
            }
            return v;
        }

        // NVISO masked signatures for ssl_verify_peer_cert (Android arm64).
        // Credit: https://github.com/NVISOsecurity/disable-flutter-tls-verification
        const std::array<const char *, 4> FLUTTER_SSL_PATTERNS = {
            "F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9",
            "F? 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 F4 03 00 AA 68 1A 40 F9",
            "FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? 7? 06 94 68 1A 40 F9 15 15 41 F9 B5 00 00 B4 B6 4A 40 F9",
            "FF ?3 01 D1 F? ?? 01 A9 ?? ?? ?? 94 ?? ?? ?? 52 48 00 00 39 1A 50 40 F9 DA 02 00 B4 48 03 40 F9",
        };
    }

    MaskedPattern ParseMaskedPattern(const std::string &pattern) {
        MaskedPattern result;
        std::istringstream stream(pattern);
        std::string token;
        while (stream >> token) {
            if (token.size() < 2) {
                continue;
            }
            std::uint8_t value = 0;
            std::uint8_t mask = 0;
            if (token[0] != '?') {
                value |= static_cast<std::uint8_t>(HexNibble(token[0]) << 4);
                mask |= 0xF0;
            }
            if (token[1] != '?') {
                value |= static_cast<std::uint8_t>(HexNibble(token[1]));
                mask |= 0x0F;
            }
            result.Values.push_back(value);
            result.Masks.push_back(mask);
        }
        return result;
    }

    std::optional<std::size_t> MaskedSearch(
        const std::vector<std::uint8_t> &data, const MaskedPattern &pattern, const std::size_t begin, const std::size_t end
    ) {
        const std::size_t len = pattern.Values.size();
        if (len == 0) {
            return std::nullopt;
        }
        const std::size_t limit = std::min(end, data.size());
        if (limit < len) {
            return std::nullopt;
        }
        for (std::size_t pos = begin; pos + len <= limit; ++pos) {
            bool match = true;
            for (std::size_t i = 0; i < len; ++i) {
                if ((data[pos + i] & pattern.Masks[i]) != pattern.Values[i]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return pos;
            }
        }
        return std::nullopt;
    }

    std::vector<std::pair<std::size_t, std::size_t>> ElfExecRanges(const std::vector<std::uint8_t> &data) {
        std::vector<std::pair<std::size_t, std::size_t>> ranges;
        if (data.size() < 64 || data[0] != 0x7F || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' ||
            data[4] != 2) {
            return {{0, data.size()}};
        }
        const std::uint64_t phoff = U64(data, 0x20);
        const std::uint16_t phentsize = U16(data, 0x36);
        const std::uint16_t phnum = U16(data, 0x38);
        for (std::uint16_t i = 0; i < phnum; ++i) {
            const std::size_t b = static_cast<std::size_t>(phoff) + static_cast<std::size_t>(i) * phentsize;
            if (b + 0x28 > data.size()) {
                break;
            }
            if (U32(data, b) != 1) { // PT_LOAD
                continue;
            }
            if ((U32(data, b + 4) & 0x1U) == 0) { // PF_X
                continue;
            }
            const std::uint64_t offset = U64(data, b + 8);
            const std::uint64_t filesz = U64(data, b + 0x20);
            ranges.emplace_back(static_cast<std::size_t>(offset), static_cast<std::size_t>(offset + filesz));
        }
        return ranges.empty() ? std::vector<std::pair<std::size_t, std::size_t>>{{0, data.size()}} : ranges;
    }

    std::optional<std::size_t> FindFlutterSslOffset(const std::vector<std::uint8_t> &libflutter) {
        const auto ranges = ElfExecRanges(libflutter);
        for (const char *patternText: FLUTTER_SSL_PATTERNS) {
            const MaskedPattern pattern = ParseMaskedPattern(patternText);
            for (const auto &[start, end]: ranges) {
                if (const auto offset = MaskedSearch(libflutter, pattern, start, end)) {
                    return offset;
                }
            }
        }
        return std::nullopt;
    }

    std::vector<std::uint8_t> PatchFlutterSsl(const std::vector<std::uint8_t> &libflutter, const std::size_t offset) {
        std::vector<std::uint8_t> patched = libflutter;
        static const std::array<std::uint8_t, 8> NOP_RET = {0x00, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6};
        if (offset + NOP_RET.size() <= patched.size()) {
            std::memcpy(patched.data() + offset, NOP_RET.data(), NOP_RET.size());
        }
        return patched;
    }

    std::optional<std::vector<std::uint8_t>> ExtractApkEntry(
        const std::vector<std::uint8_t> &apkBytes, const std::string &entryName
    ) {
        mz_zip_archive zip = {};
        if (mz_zip_reader_init_mem(&zip, apkBytes.data(), apkBytes.size(), 0) == MZ_FALSE) {
            return std::nullopt;
        }
        const int index = mz_zip_reader_locate_file(&zip, entryName.c_str(), nullptr, 0);
        if (index < 0) {
            mz_zip_reader_end(&zip);
            return std::nullopt;
        }
        std::size_t size = 0;
        void *data = mz_zip_reader_extract_to_heap(&zip, static_cast<mz_uint>(index), &size, 0);
        mz_zip_reader_end(&zip);
        if (data == nullptr) {
            return std::nullopt;
        }
        std::vector<std::uint8_t> out(static_cast<std::uint8_t *>(data), static_cast<std::uint8_t *>(data) + size);
        mz_free(data);
        return out;
    }

    std::optional<std::vector<std::uint8_t>> ReplaceApkEntry(
        const std::vector<std::uint8_t> &apkBytes, const std::string &entryName, const std::vector<std::uint8_t> &newContent
    ) {
        mz_zip_archive reader = {};
        if (mz_zip_reader_init_mem(&reader, apkBytes.data(), apkBytes.size(), 0) == MZ_FALSE) {
            return std::nullopt;
        }
        mz_zip_archive writer = {};
        if (mz_zip_writer_init_heap(&writer, 0, 0) == MZ_FALSE) {
            mz_zip_reader_end(&reader);
            return std::nullopt;
        }

        bool replaced = false;
        bool ok = true;
        const mz_uint count = mz_zip_reader_get_num_files(&reader);
        for (mz_uint i = 0; i < count && ok; ++i) {
            mz_zip_archive_file_stat stat = {};
            if (mz_zip_reader_file_stat(&reader, i, &stat) == MZ_FALSE) {
                ok = false;
                break;
            }
            const mz_uint level = stat.m_method == 0 ? MZ_NO_COMPRESSION : MZ_DEFAULT_COMPRESSION;
            if (mz_zip_reader_is_file_a_directory(&reader, i)) {
                mz_zip_writer_add_mem(&writer, stat.m_filename, nullptr, 0, 0);
                continue;
            }
            if (entryName == stat.m_filename) {
                ok = mz_zip_writer_add_mem(
                         &writer,
                         stat.m_filename,
                         newContent.data(),
                         newContent.size(),
                         level
                     ) == MZ_TRUE;
                replaced = true;
                continue;
            }
            std::size_t size = 0;
            void *data = mz_zip_reader_extract_to_heap(&reader, i, &size, 0);
            if (data == nullptr) {
                ok = false;
                break;
            }
            ok = mz_zip_writer_add_mem(&writer, stat.m_filename, data, size, level) == MZ_TRUE;
            mz_free(data);
        }
        mz_zip_reader_end(&reader);

        if (!ok || !replaced) {
            mz_zip_writer_end(&writer);
            return std::nullopt;
        }
        void *buf = nullptr;
        std::size_t bufSize = 0;
        if (mz_zip_writer_finalize_heap_archive(&writer, &buf, &bufSize) == MZ_FALSE) {
            mz_zip_writer_end(&writer);
            return std::nullopt;
        }
        std::vector<std::uint8_t> out(static_cast<std::uint8_t *>(buf), static_cast<std::uint8_t *>(buf) + bufSize);
        mz_zip_writer_end(&writer);
        mz_free(buf);
        return out;
    }

    FlutterPatchResult PatchFlutterTls(const std::string &apkPath, const std::string &outPath) {
        FlutterPatchResult result;
        const auto apk = ReadFileBytes(apkPath);
        if (!apk) {
            result.Message = "Could not read the APK: " + apkPath;
            return result;
        }
        const auto lib = ExtractApkEntry(*apk, "lib/arm64-v8a/libflutter.so");
        if (!lib) {
            result.Message = "No lib/arm64-v8a/libflutter.so (not a Flutter app, or the arm64 split is missing).";
            return result;
        }
        const auto offset = FindFlutterSslOffset(*lib);
        if (!offset) {
            result.Message = "Could not locate ssl_verify_peer_cert (unsupported Flutter version).";
            return result;
        }
        const auto patched = PatchFlutterSsl(*lib, *offset);
        const auto newApk = ReplaceApkEntry(*apk, "lib/arm64-v8a/libflutter.so", patched);
        if (!newApk) {
            result.Message = "Failed to rewrite the APK.";
            return result;
        }
        {
            std::ofstream out(outPath, std::ios::binary | std::ios::trunc);
            if (!out) {
                result.Message = "Could not write " + outPath;
                return result;
            }
            out.write(reinterpret_cast<const char *>(newApk->data()), static_cast<std::streamsize>(newApk->size()));
        }
        result.Ok = true;
        result.Offset = *offset;
        result.OutPath = outPath;
        result.Message = "Patched. Sign the output with APK Signer before installing.";
        return result;
    }
}
