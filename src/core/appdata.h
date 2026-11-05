//
// Created by CoreDeck RE toolbench on 05/11/2026.
//
// App private-data reader [sensitive]: on a rooted AVD, list / grep / pull a
// package's /data/data (shared_prefs, databases, files). For an app you
// installed on your own emulator to test. The grep pattern is user-supplied -
// no built-in secret/credential keyword list.
//

#ifndef COREDECK_APPDATA_H
#define COREDECK_APPDATA_H

#include <string>
#include <vector>

#include "core/sdk.h"

namespace CoreDeck::Core {
    struct DataEntry {
        std::string Name;
        bool IsDir = false;
        bool IsLink = false;
        std::string Perms;
        std::string Size;
    };

    // Parse `ls -la` output (toybox/Android) into entries. Drops the total line,
    // ".", and "..".
    std::vector<DataEntry> ParseLsOutput(const std::string &output);

    // Join a package data path: /data/data/<package>[/<subPath>]. subPath must not
    // escape the package dir (no "..").
    std::string DataPath(const std::string &package, const std::string &subPath);

    // su `ls -la` of a path under the package's data dir.
    std::vector<DataEntry> ListAppData(
        const SdkInfo &sdk, const std::string &serial, const std::string &package, const std::string &subPath
    );

    // su grep for a user-supplied pattern under the package's data dir (output
    // capped). Returns matching "path:line:text" lines.
    std::vector<std::string> GrepAppData(
        const SdkInfo &sdk, const std::string &serial, const std::string &package, const std::string &pattern
    );

    // Copy a file out of /data/data via su to /data/local/tmp, then adb pull it.
    bool PullAppFile(
        const SdkInfo &sdk,
        const std::string &serial,
        const std::string &package,
        const std::string &subPath,
        const std::string &localPath,
        std::string &error
    );
}

#endif // COREDECK_APPDATA_H
