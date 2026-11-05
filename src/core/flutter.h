//
// Created by CoreDeck RE toolbench on 05/11/2026.
//
// Flutter static analysis via Blutter (worawit/blutter): dump Dart names,
// disassembly and object pools from an APK you are authorized to analyse.
// Blutter is a user-installed tool (resolved, not bundled).
//

#ifndef COREDECK_FLUTTER_H
#define COREDECK_FLUTTER_H

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace CoreDeck::Core {
    // A lib name belongs to a Flutter app (libapp.so / libflutter.so).
    bool IsFlutterLib(const std::string &libName);

    // True if the apk (zip bytes) contains a Flutter native lib.
    bool ApkIsFlutter(const std::vector<std::uint8_t> &apkBytes);

    // Resolve blutter.py: configured path, then $BLUTTER_PY, then common guesses.
    std::string ResolveBlutter(const std::string &configuredPath);

    // Resolve a python interpreter (python3, then python); empty if none runs.
    std::string ResolvePython();

    // Args passed to python: [blutter.py, libDir, outDir, (--rebuild), (--no-analysis)].
    std::vector<std::string> BuildBlutterArgs(
        const std::string &blutterPy, const std::string &libDir, const std::string &outDir, bool rebuild, bool noAnalysis
    );

    // Extract lib/arm64-v8a/*.so from an apk into destDir; return the lib dir
    // (containing libapp.so) or empty if there is no arm64 libapp.so.
    std::string ExtractFlutterLibs(const std::vector<std::uint8_t> &apkBytes, const std::string &destDir);

    // Output artifacts present in a blutter output dir (blutter_frida.js, asm, ...).
    std::vector<std::string> BlutterOutputs(const std::string &outDir);

    struct BlutterRun {
        bool Ok = false;
        std::string Message;
        std::string OutDir;
        std::vector<std::string> Outputs;
    };

    // Extract the apk's arm64 Flutter libs under workDir, run blutter, and report
    // the output dir + artifacts. Success is judged by artifacts on disk, since
    // blutter can exit non-zero yet still write the full dump.
    BlutterRun RunBlutter(
        const std::string &apkPath, const std::string &blutterPy, const std::string &workDir, bool noAnalysis
    );

    // ----------------------------------------------------------------------- //
    // Flutter TLS static patch [sensitive] (NOP ssl_verify_peer_cert in
    // libflutter.so) - for intercepting your own/authorized app's traffic.
    // ----------------------------------------------------------------------- //
    struct MaskedPattern {
        std::vector<std::uint8_t> Values;
        std::vector<std::uint8_t> Masks;
    };

    // Parse a nibble-masked pattern like "F? 43 ?? D1".
    MaskedPattern ParseMaskedPattern(const std::string &pattern);

    // First offset in [begin, end) where (data[i] & mask) == value for the pattern.
    std::optional<std::size_t> MaskedSearch(
        const std::vector<std::uint8_t> &data, const MaskedPattern &pattern, std::size_t begin, std::size_t end
    );

    // File [start,end) ranges of executable PT_LOAD segments in an ELF64 (whole
    // file when not an ELF).
    std::vector<std::pair<std::size_t, std::size_t>> ElfExecRanges(const std::vector<std::uint8_t> &data);

    // Locate ssl_verify_peer_cert in an arm64 libflutter.so (NVISO signatures).
    std::optional<std::size_t> FindFlutterSslOffset(const std::vector<std::uint8_t> &libflutter);

    // Replace 8 bytes at offset with "mov w0,#0 ; ret". Returns a patched copy.
    std::vector<std::uint8_t> PatchFlutterSsl(const std::vector<std::uint8_t> &libflutter, std::size_t offset);

    // Read one apk entry's bytes.
    std::optional<std::vector<std::uint8_t>> ExtractApkEntry(
        const std::vector<std::uint8_t> &apkBytes, const std::string &entryName
    );

    // Rewrite an apk replacing one entry, preserving each entry's store/deflate
    // method (so resources.arsc stays STORED for Android R+).
    std::optional<std::vector<std::uint8_t>> ReplaceApkEntry(
        const std::vector<std::uint8_t> &apkBytes, const std::string &entryName, const std::vector<std::uint8_t> &newContent
    );

    struct FlutterPatchResult {
        bool Ok = false;
        std::string Message;
        std::string OutPath;
        std::size_t Offset = 0;
    };

    // Static Flutter TLS bypass: patch lib/arm64-v8a/libflutter.so and write a new
    // (unsigned) apk to outPath. Sign it afterwards with APK Signer.
    FlutterPatchResult PatchFlutterTls(const std::string &apkPath, const std::string &outPath);
}

#endif // COREDECK_FLUTTER_H
