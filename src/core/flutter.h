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
}

#endif // COREDECK_FLUTTER_H
