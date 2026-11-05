//
// Created by CoreDeck RE toolbench on 05/11/2026.
//
// Anti-analysis check scanner [sensitive]: find root/emulator/tamper/integrity/
// frida/debugger self-checks in smali, and (opt-in) comment out the narrow set
// of self-kill invokes. For assessing anti-tamper on an app you are authorized
// to test. Drives apktool (user-installed) for decode/rebuild.
//

#ifndef COREDECK_CHECKS_H
#define COREDECK_CHECKS_H

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace CoreDeck::Core {
    struct CheckFinding {
        std::string Label; // root / emulator / signature-tamper / integrity / frida / debugger / self-close
        int Line = 0;
        std::string Text;
    };

    // Scan one smali file's text for the known anti-analysis patterns.
    std::vector<CheckFinding> ScanSmaliText(const std::string &smali);

    // True when the line is a void self-kill invoke (System.exit / Runtime.halt /
    // Process.killProcess / Activity.finishAffinity) - the only lines neutralize
    // comments out.
    bool IsSelfKillLine(const std::string &line);

    // Comment out every self-kill line. Returns the rewritten text and the count.
    std::pair<std::string, int> NeutralizeSmaliText(const std::string &smali);

    // ---- orchestration (drives apktool) ----
    std::string ResolveApktool(const std::string &configuredPath);

    struct ScanResult {
        bool Ok = false;
        std::string Message;
        std::string DecodedDir;
        std::vector<CheckFinding> Findings; // aggregated; Text carries "relpath:line"
        int SmaliFiles = 0;
    };

    // apktool d the apk (unless decodedDir already exists), then scan all smali.
    ScanResult DecodeAndScan(const std::string &apktool, const std::string &apkPath, const std::string &decodedDir);

    struct NeutralizeResult {
        bool Ok = false;
        std::string Message;
        int Patched = 0;
        std::string OutApk; // rebuilt (unsigned) apk
    };

    // Comment out self-kill invokes across the decoded tree, then apktool b to
    // outApk. Sign it afterwards with APK Signer.
    NeutralizeResult NeutralizeAndBuild(
        const std::string &apktool, const std::string &decodedDir, const std::string &outApk
    );
}

#endif // COREDECK_CHECKS_H
