//
// Created by CoreDeck RE toolbench on 05/11/2026.
//

#include "core/repackage.h"

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "core/adb.h"
#include "core/apk_signer.h"
#include "core/flutter.h"
#include "core/keytool.h"
#include "core/tools.h"
#include "platform/paths.h"
#include "platform/process.h"

namespace CoreDeck::Core {
    namespace {
        std::string Trim(const std::string &s) {
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

        std::string EnvOrEmpty(const char *key) {
            const char *value = std::getenv(key);
            return value != nullptr ? std::string(value) : std::string();
        }

        std::optional<std::vector<std::uint8_t>> ReadFileBytes(const std::string &path) {
            std::ifstream file(path, std::ios::binary);
            if (!file) {
                return std::nullopt;
            }
            return std::vector<std::uint8_t>(
                (std::istreambuf_iterator<char>(file)),
                std::istreambuf_iterator<char>()
            );
        }

        void Log(const std::shared_ptr<RepackageProgress> &progress, const std::string &line) {
            if (progress) {
                progress->Log(line);
            }
        }

        // reFlutter writes a "<name>.RE.apk"; apkkit globs the input's dir and the
        // cwd. Return the most recently written match, or empty.
        std::string FindNewestReApk(const std::vector<std::string> &dirs) {
            namespace fs = std::filesystem;
            std::error_code ec;
            std::string best;
            fs::file_time_type bestTime{};
            for (const std::string &dir: dirs) {
                if (dir.empty() || !fs::is_directory(dir, ec)) {
                    continue;
                }
                for (fs::directory_iterator it(dir, ec), end; it != end; it.increment(ec)) {
                    if (ec || !it->is_regular_file(ec)) {
                        continue;
                    }
                    const std::string name = it->path().filename().string();
                    if (name.size() < 7) {
                        continue;
                    }
                    std::string lower;
                    for (const char c: name) {
                        lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
                    }
                    if (lower.size() >= 7 && lower.compare(lower.size() - 7, 7, ".re.apk") == 0) {
                        const fs::file_time_type t = fs::last_write_time(it->path(), ec);
                        if (best.empty() || t > bestTime) {
                            best = it->path().string();
                            bestTime = t;
                        }
                    }
                }
            }
            return best;
        }

        std::string StemNoApk(const std::string &path) {
            namespace fs = std::filesystem;
            fs::path p(path);
            std::string name = p.filename().string();
            if (name.size() >= 4) {
                const std::string ext = name.substr(name.size() - 4);
                std::string extLower;
                for (const char c: ext) {
                    extLower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
                }
                if (extLower == ".apk") {
                    name = name.substr(0, name.size() - 4);
                }
            }
            return (p.parent_path() / name).string();
        }
    }

    std::vector<std::string> ParsePmPath(const std::string &output) {
        std::vector<std::string> paths;
        std::istringstream stream(output);
        std::string line;
        while (std::getline(stream, line)) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            const std::string trimmed = Trim(line);
            const std::string prefix = "package:";
            if (trimmed.rfind(prefix, 0) == 0) {
                const std::string path = Trim(trimmed.substr(prefix.size()));
                if (!path.empty()) {
                    paths.push_back(path);
                }
            }
        }
        return paths;
    }

    std::vector<std::string> ApkEditorMergeArgs(
        const std::string &inputDir, const std::string &outApk, const bool force
    ) {
        std::vector<std::string> args = {"m", "-i", inputDir, "-o", outApk};
        if (force) {
            args.push_back("-f");
        }
        return args;
    }

    std::string ApkMitmOutputPath(const std::string &inputApk) {
        return StemNoApk(inputApk) + "-patched.apk";
    }

    std::string ObjectionOutputPath(const std::string &inputApk) {
        return StemNoApk(inputApk) + ".objection.apk";
    }

    std::vector<std::string> ObjectionPatchArgs(
        const std::string &apkPath, const std::string &abi, const bool addNsc
    ) {
        std::vector<std::string> args = {"patchapk", "-s", apkPath, "-a", abi};
        if (addNsc) {
            args.push_back("-N"); // network-security-config trusting user CAs
        }
        return args;
    }

    PinningMethod ChooseMethod(const PinningMethod requested, const bool isFlutter) {
        if (requested != PinningMethod::Auto) {
            return requested;
        }
        return isFlutter ? PinningMethod::FlutterStatic : PinningMethod::ApkMitm;
    }

    const char *PinningMethodLabel(const PinningMethod method) {
        switch (method) {
            case PinningMethod::Auto:
                return "auto";
            case PinningMethod::FlutterStatic:
                return "flutter-static";
            case PinningMethod::ApkMitm:
                return "apk-mitm";
            case PinningMethod::Gadget:
                return "gadget";
            case PinningMethod::Reflutter:
                return "reflutter";
            case PinningMethod::None:
                return "none";
        }
        return "auto";
    }

    std::optional<std::string> ResolveApkEditorJar(const std::string &overridePath) {
        namespace fs = std::filesystem;
        std::error_code ec;
        const auto usable = [&](const std::string &p) {
            return !p.empty() && fs::exists(p, ec) && !fs::is_directory(p, ec);
        };
        if (usable(overridePath)) {
            return fs::absolute(overridePath, ec).string();
        }
        const std::string env = EnvOrEmpty("APKEDITOR_JAR");
        if (usable(env)) {
            return fs::absolute(env, ec).string();
        }
        const std::vector<std::string> guesses = {
            Platform::JoinPaths({Platform::GetConfigDirectory(), "APKEditor.jar"}),
            (fs::current_path(ec) / "APKEditor.jar").string(),
        };
        for (const std::string &g: guesses) {
            if (usable(g)) {
                return fs::absolute(g, ec).string();
            }
        }
        return std::nullopt;
    }

    std::vector<std::string> ResolveApkMitm() {
        if (const auto direct = ResolveExecutable({"apk-mitm"})) {
            return {*direct};
        }
        if (const auto npx = ResolveExecutable({"npx"})) {
            return {*npx, "--yes", "apk-mitm"};
        }
        return {};
    }

    namespace {
        // Sign an apk with a managed debug keystore (created once under the config
        // dir). Returns the signed path, or empty with an error.
        std::string SignWithDebugKey(
            const SdkInfo &sdk,
            const JdkInfo &jdk,
            const std::string &inputApk,
            std::string &error,
            const std::shared_ptr<RepackageProgress> &progress
        ) {
            namespace fs = std::filesystem;
            const std::string dir = Platform::JoinPaths({Platform::GetConfigDirectory(), "repackage"});
            std::error_code ec;
            fs::create_directories(dir, ec);
            const std::string keystore = Platform::JoinPaths({dir, "debug.p12"});
            const std::string storePass = "coredeck";
            const std::string alias = "coredeck";

            if (!fs::exists(keystore, ec)) {
                Log(progress, "Creating a debug keystore at " + keystore);
                CreateKeystoreRequest req;
                req.KeystorePath = keystore;
                req.StoreType = KeystoreType::Pkcs12;
                req.Alias = alias;
                req.Algorithm = KeyAlgorithm::Rsa;
                req.StorePassword = storePass;
                req.KeyPassword = storePass;
                req.CommonName = "CoreDeck Debug";
                req.Organization = "CoreDeck";
                req.Jdk = jdk;
                const CreateKeystoreResult created = CreateKeystore(req);
                if (created.Status != KeytoolStatus::Ok) {
                    error = created.ToolMissing
                                ? "keytool not found (needs a JDK)."
                                : ("Could not create a debug keystore: " + created.Output);
                    return "";
                }
            }

            const std::string outApk = StemNoApk(inputApk) + "-signed.apk";
            ApkSignRequest req;
            req.ApksignerPath = sdk.ApksignerPath;
            req.ZipalignPath = sdk.ZipalignPath;
            req.InputPath = inputApk;
            req.OutputPath = outApk;
            req.KeystorePath = keystore;
            req.KeystoreType = "PKCS12";
            req.KeyAlias = alias;
            req.StorePassword = storePass;
            req.KeyPassword = storePass;
            req.Align = true;
            req.Jdk = jdk;
            const ApkSignResult signedResult = SignApk(req);
            if (signedResult.Status != ApkSignStatus::Signed) {
                error = signedResult.Output.empty() ? "Signing failed." : signedResult.Output;
                return "";
            }
            return outApk;
        }
    }

    RepackageResult RunRepackage(
        const SdkInfo &sdk,
        const JdkInfo &jdk,
        const RepackageOptions &options,
        const std::shared_ptr<RepackageProgress> &progress
    ) {
        namespace fs = std::filesystem;
        RepackageResult result;
        std::error_code ec;

        const std::string workDir =
            options.WorkDir.empty() ? Platform::JoinPaths({Platform::GetConfigDirectory(), "repackage"}) : options.WorkDir;
        fs::create_directories(workDir, ec);

        const auto fail = [&](const std::string &name, const std::string &detail) {
            result.Steps.push_back({name, false, detail});
            Log(progress, "[x] " + name + ": " + detail);
            if (progress) {
                progress->Finished = true;
            }
            return result;
        };
        const auto pass = [&](const std::string &name, const std::string &detail) {
            result.Steps.push_back({name, true, detail});
            Log(progress, "[ok] " + name + (detail.empty() ? "" : (": " + detail)));
        };

        // ---- Step 1: obtain a single, merged APK --------------------------- //
        std::string mergedApk;

        if (options.Source == RepackageSource::SingleApk) {
            if (!fs::exists(options.InputPath, ec) || fs::is_directory(options.InputPath, ec)) {
                return fail("Input", "Not an APK file: " + options.InputPath);
            }
            mergedApk = options.InputPath;
            pass("Input", mergedApk);
        } else {
            std::string splitsDir;

            if (options.Source == RepackageSource::Device) {
                if (options.Serial.empty() || options.Package.empty()) {
                    return fail("Pull", "A device and a package are required.");
                }
                Log(progress, "pm path " + options.Package);
                const AdbResult pm = Shell(sdk, options.Serial, {"pm", "path", options.Package});
                if (!pm.Ok()) {
                    return fail("Pull", "pm path failed: " + pm.Output);
                }
                const std::vector<std::string> remotePaths = ParsePmPath(pm.Output);
                if (remotePaths.empty()) {
                    return fail("Pull", "No APK paths returned for " + options.Package + ".");
                }
                splitsDir = Platform::JoinPaths({workDir, options.Package});
                fs::create_directories(splitsDir, ec);
                for (const std::string &remote: remotePaths) {
                    const std::string base = fs::path(remote).filename().string();
                    const std::string local = Platform::JoinPaths({splitsDir, base});
                    Log(progress, "pull " + base);
                    const AdbResult pull = Pull(sdk, options.Serial, remote, local);
                    if (!pull.Ok()) {
                        return fail("Pull", "adb pull failed for " + base + ": " + pull.Output);
                    }
                }
                pass("Pull", std::to_string(remotePaths.size()) + " APK(s) -> " + splitsDir);
            } else { // Directory
                if (!fs::is_directory(options.InputPath, ec)) {
                    return fail("Input", "Not a directory: " + options.InputPath);
                }
                splitsDir = options.InputPath;
                pass("Input", splitsDir);
            }

            // ---- Step 2: merge splits (APKEditor) -------------------------- //
            const std::optional<std::string> jar = ResolveApkEditorJar(options.ApkEditorJar);
            if (!jar.has_value()) {
                return fail(
                    "Merge",
                    "APKEditor.jar not found. Download it from "
                    "https://github.com/REAndroid/APKEditor/releases and set its path (or $APKEDITOR_JAR)."
                );
            }
            const std::string java = jdk.IsValid ? JdkExecutablePath(jdk, "java") : std::string("java");
            const std::string name = options.Source == RepackageSource::Device ? options.Package : fs::path(splitsDir).filename().string();
            mergedApk = Platform::JoinPaths({workDir, (name.empty() ? "app" : name) + "-merged.apk"});
            std::vector<std::string> javaArgs = {"-jar", *jar};
            for (const std::string &a: ApkEditorMergeArgs(splitsDir, mergedApk)) {
                javaArgs.push_back(a);
            }
            Log(progress, "java -jar APKEditor m ...");
            const Platform::CommandResult merge = Platform::RunCommandArgsResult(java, javaArgs);
            if (!merge.Started) {
                return fail("Merge", "Could not run java. Install a JDK or set it in Preferences.");
            }
            if (merge.ExitCode != 0 || !fs::exists(mergedApk, ec)) {
                return fail("Merge", "APKEditor merge failed: " + merge.Output);
            }
            pass("Merge", mergedApk);
        }

        // ---- Step 3: detect app type + patch ------------------------------- //
        bool isFlutter = false;
        if (const auto bytes = ReadFileBytes(mergedApk)) {
            isFlutter = ApkIsFlutter(*bytes);
        }
        result.IsFlutter = isFlutter;
        Log(progress, std::string("app type: ") + (isFlutter ? "Flutter" : "native"));

        const PinningMethod method = ChooseMethod(options.Method, isFlutter);
        result.MethodUsed = PinningMethodLabel(method);

        std::string patchedApk = mergedApk;
        bool alreadySigned = false; // apk-mitm re-signs its own output

        if (method == PinningMethod::None) {
            pass("Patch", "skipped (no pinning change)");
        } else if (method == PinningMethod::FlutterStatic) {
            const std::string out = StemNoApk(mergedApk) + "-flutterpatched.apk";
            Log(progress, "static libflutter TLS patch ...");
            const FlutterPatchResult fp = PatchFlutterTls(mergedApk, out);
            if (!fp.Ok) {
                return fail("Patch", "Flutter static patch failed: " + fp.Message);
            }
            patchedApk = fp.OutPath;
            pass("Patch", "libflutter patched @ off " + std::to_string(fp.Offset));
        } else if (method == PinningMethod::ApkMitm) {
            const std::vector<std::string> runner = ResolveApkMitm();
            if (runner.empty()) {
                return fail(
                    "Patch",
                    "apk-mitm not found. Install Node.js and `npm install -g apk-mitm` (or have npx available)."
                );
            }
            std::vector<std::string> args(runner.begin() + 1, runner.end());
            args.push_back(mergedApk);
            Log(progress, "apk-mitm ...");
            const Platform::CommandResult mitm = Platform::RunCommandArgsResult(runner.front(), args);
            if (!mitm.Started) {
                return fail("Patch", "Could not run apk-mitm.");
            }
            const std::string out = ApkMitmOutputPath(mergedApk);
            if (mitm.ExitCode != 0 || !fs::exists(out, ec)) {
                return fail("Patch", "apk-mitm failed: " + mitm.Output);
            }
            patchedApk = out;
            alreadySigned = true; // apk-mitm zipaligns + signs with its own debug key
            pass("Patch", out);
        } else if (method == PinningMethod::Gadget) {
            const auto objection = ResolveExecutable({"objection"});
            if (!objection.has_value()) {
                return fail(
                    "Patch",
                    "objection not found. Install it with `pip install objection` (it needs apktool on PATH too)."
                );
            }
            std::string abi = "arm64-v8a";
            if (!options.Serial.empty()) {
                const std::string detected = GetDeviceProp(sdk, options.Serial, "ro.product.cpu.abi");
                if (!detected.empty()) {
                    abi = detected;
                }
            }
            Log(progress, "objection patchapk (gadget, abi " + abi + ") ...");
            const Platform::CommandResult inject =
                Platform::RunCommandArgsResult(*objection, ObjectionPatchArgs(mergedApk, abi, options.AddNsc));
            if (!inject.Started) {
                return fail("Patch", "Could not run objection.");
            }
            const std::string out = ObjectionOutputPath(mergedApk);
            if (inject.ExitCode != 0 || !fs::exists(out, ec)) {
                return fail("Patch", "objection patchapk failed: " + inject.Output);
            }
            patchedApk = out;
            alreadySigned = true; // objection zipaligns + signs its output
            pass("Patch", out);
        } else { // Reflutter
            const auto reflutter = ResolveExecutable({"reflutter"});
            if (!reflutter.has_value()) {
                return fail(
                    "Patch",
                    "reflutter not found. Install it with `pip install reflutter`."
                );
            }
            Log(progress, "reFlutter (set the device proxy to <your-ip>:8083 afterwards) ...");
            const Platform::CommandResult re = Platform::RunCommandArgsResult(*reflutter, {mergedApk});
            if (!re.Started) {
                return fail("Patch", "Could not run reflutter.");
            }
            const std::string out = FindNewestReApk({fs::path(mergedApk).parent_path().string(), fs::current_path(ec).string()});
            if (re.ExitCode != 0 || out.empty()) {
                return fail("Patch", "reFlutter produced no *.RE.apk: " + re.Output);
            }
            patchedApk = out; // reFlutter output is unsigned -> signed below
            pass("Patch", out);
        }

        result.FinalApk = patchedApk;

        // ---- Step 4: sign (unless apk-mitm already did) -------------------- //
        if (options.Sign && !alreadySigned) {
            std::string error;
            const std::string signedApk = SignWithDebugKey(sdk, jdk, patchedApk, error, progress);
            if (signedApk.empty()) {
                return fail("Sign", error);
            }
            result.FinalApk = signedApk;
            pass("Sign", signedApk);
        } else if (alreadySigned) {
            pass("Sign", "done by apk-mitm");
        }

        // ---- Step 5: install ---------------------------------------------- //
        if (options.Install) {
            if (options.Serial.empty()) {
                return fail("Install", "No device selected.");
            }
            if (!options.Package.empty()) {
                Uninstall(sdk, options.Serial, options.Package);
            }
            std::vector<std::string> extra;
            if (options.Grant) {
                extra.push_back("-g");
            }
            Log(progress, "adb install -r " + result.FinalApk);
            const AdbResult install = Install(sdk, options.Serial, result.FinalApk, extra);
            if (!install.Ok()) {
                return fail("Install", "adb install failed: " + install.Output);
            }
            pass("Install", "installed");
        }

        if (progress) {
            progress->Finished = true;
        }
        return result;
    }
}
