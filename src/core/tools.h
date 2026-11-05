//
// Created by CoreDeck RE toolbench on 05/11/2026.
//
// External reverse-engineering tool registry ("doctor"): which third-party
// tools the Research features can use, whether they resolve on this machine,
// and how to install the missing ones. Read-only - it never installs anything.
//

#ifndef COREDECK_TOOLS_H
#define COREDECK_TOOLS_H

#include <optional>
#include <string>
#include <vector>

#include "core/sdk.h"

namespace CoreDeck::Core {
    // Where a tool is expected to live, which decides how it is resolved.
    enum class ReToolSource {
        Path, // on PATH (java, apktool, jadx, frida, objection, blutter, ...)
        PlatformTools, // <sdk>/platform-tools (adb)
        BuildTools, // <sdk>/build-tools/<ver> (aapt2, apksigner, zipalign)
    };

    struct ReToolSpec {
        std::string Key; // stable id, e.g. "apktool"
        std::string Name; // display name
        std::string UsedFor; // which CoreDeck feature uses it
        std::vector<std::string> ExeNames; // PATH base names to try (no extension)
        ReToolSource Source = ReToolSource::Path;
        bool Optional = true; // false for the handful nothing works without
        std::vector<std::string> InstallHint; // human lines, incl. a URL
    };

    struct ReToolStatus {
        ReToolSpec Spec;
        bool Found = false;
        std::string ResolvedPath; // absolute path or bare name that resolved
    };

    // ----------------------------------------------------------------------- //
    // Pure helpers (no filesystem, no process) - unit-tested.
    // ----------------------------------------------------------------------- //

    // Filenames to try for an executable base name: on Windows this appends the
    // PATHEXT-style suffixes (.exe/.bat/.cmd) when the name has no extension; on
    // POSIX it is just the name.
    std::vector<std::string> ExecutableCandidates(const std::string &name);

    // Split a search-path string (PATH / PATHEXT) on the given separator,
    // dropping empty entries and surrounding quotes.
    std::vector<std::string> SplitSearchPath(const std::string &value, char separator);

    // The registry itself (static data).
    const std::vector<ReToolSpec> &ReToolRegistry();

    // ----------------------------------------------------------------------- //
    // Resolution (touches the filesystem).
    // ----------------------------------------------------------------------- //

    // Resolve an executable: an override path if it exists, else the first
    // candidate found on PATH.
    std::optional<std::string> ResolveExecutable(
        const std::vector<std::string> &exeNames, const std::string &overridePath = ""
    );

    // Detect every registry tool against this machine / SDK. overrides maps a
    // tool Key to a user-configured path.
    std::vector<ReToolStatus> DetectReTools(const SdkInfo &sdk);
    std::vector<ReToolStatus> DetectReTools(
        const SdkInfo &sdk, const std::vector<std::pair<std::string, std::string>> &overrides
    );
}

#endif // COREDECK_TOOLS_H
