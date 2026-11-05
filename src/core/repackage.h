//
// Created by CoreDeck RE toolbench on 05/11/2026.
//
// Static repackage / pinning-disable pipeline [sensitive]: pull a package's
// split APKs off a device, merge them (APKEditor), strip certificate pinning
// statically (apk-mitm for native apps, the libflutter TLS patch for Flutter),
// sign, and optionally install - for an app you own or are authorized to test.
//

#ifndef COREDECK_REPACKAGE_H
#define COREDECK_REPACKAGE_H

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "core/jdk.h"
#include "core/sdk.h"

namespace CoreDeck::Core {
    enum class PinningMethod {
        Auto, // Flutter -> libflutter static patch; native -> apk-mitm
        FlutterStatic, // libflutter.so TLS patch only
        ApkMitm, // apk-mitm (native static pinning strip + user-CA trust)
        None, // merge + sign only, no pinning change
    };

    enum class RepackageSource {
        Device, // pull split APKs by package from a device
        Directory, // a folder of already-pulled split APKs
        SingleApk, // one already-merged APK on disk
    };

    struct RepackageOptions {
        RepackageSource Source = RepackageSource::Device;
        std::string Serial; // device, when Source == Device
        std::string Package; // package, when Source == Device
        std::string InputPath; // dir or apk, when Source != Device
        std::string WorkDir; // where intermediates/outputs are written
        PinningMethod Method = PinningMethod::Auto;
        std::string ApkEditorJar; // override; else env / guesses
        bool Sign = true; // sign the result with a managed debug keystore
        bool Install = false;
        bool Grant = true;
    };

    struct RepackageStepResult {
        std::string Name;
        bool Ok = false;
        std::string Detail;
    };

    struct RepackageResult {
        std::vector<RepackageStepResult> Steps;
        std::string FinalApk; // the last apk produced (signed when Sign)
        std::string MethodUsed; // concrete method label (e.g. "apk-mitm")
        bool IsFlutter = false;

        bool AllOk() const {
            if (Steps.empty()) {
                return false;
            }
            for (const auto &step: Steps) {
                if (!step.Ok) {
                    return false;
                }
            }
            return true;
        }
    };

    struct RepackageProgress {
        std::mutex Mutex;
        std::vector<std::string> Lines;
        bool Finished = false;

        void Log(const std::string &line) {
            std::lock_guard<std::mutex> lock(Mutex);
            Lines.push_back(line);
        }
    };

    // ----------------------------------------------------------------------- //
    // Pure helpers (no process, no filesystem) - unit-tested.
    // ----------------------------------------------------------------------- //

    // Parse `pm path <pkg>` output: strip the "package:" prefix off each line.
    std::vector<std::string> ParsePmPath(const std::string &output);

    // argv for APKEditor's merge: `m -i <inputDir> -o <outApk> [-f]`.
    std::vector<std::string> ApkEditorMergeArgs(
        const std::string &inputDir, const std::string &outApk, bool force = true
    );

    // apk-mitm writes "<base>-patched.apk" beside its input.
    std::string ApkMitmOutputPath(const std::string &inputApk);

    // Resolve Auto to a concrete method given the detected app type.
    PinningMethod ChooseMethod(PinningMethod requested, bool isFlutter);

    const char *PinningMethodLabel(PinningMethod method);

    // ----------------------------------------------------------------------- //
    // Tool resolution (touches env / filesystem).
    // ----------------------------------------------------------------------- //

    // APKEditor.jar: an override, then $APKEDITOR_JAR, then a few common spots.
    std::optional<std::string> ResolveApkEditorJar(const std::string &overridePath = "");

    // apk-mitm: {path} if on PATH, else {npx,--yes,apk-mitm} if npx is present,
    // else empty.
    std::vector<std::string> ResolveApkMitm();

    // ----------------------------------------------------------------------- //
    // Orchestration (drives adb / java / apk-mitm / signer).
    // ----------------------------------------------------------------------- //

    RepackageResult RunRepackage(
        const SdkInfo &sdk,
        const JdkInfo &jdk,
        const RepackageOptions &options,
        const std::shared_ptr<RepackageProgress> &progress = nullptr
    );
}

#endif // COREDECK_REPACKAGE_H
