//
// Created by CoreDeck RE toolbench on 05/11/2026.
//

#include "core/appdata.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <sstream>

#include "core/adb.h"

namespace CoreDeck::Core {
    namespace {
        // Toybox `ls -la` columns before the name:
        //   perms links owner group size date time name
        // date is YYYY-MM-DD, time is HH:MM, neither has an inner space, so the
        // name begins after the 7th whitespace-separated field.
        constexpr int kNameField = 7;

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

        // A su invocation can prepend a password prompt / "su: ..." notice. Keep
        // only lines that look like `ls -la` rows.
        bool LooksLikeLsRow(const std::string &line) {
            if (line.size() < 10) {
                return false;
            }
            const char t = line[0];
            if (t != '-' && t != 'd' && t != 'l' && t != 'c' && t != 'b' && t != 's' && t != 'p') {
                return false;
            }
            // Next nine are rwx/-/s/t permission bits.
            for (int i = 1; i <= 9; ++i) {
                const char c = line[i];
                if (c != 'r' && c != 'w' && c != 'x' && c != '-' && c != 's' && c != 'S' && c != 't' && c != 'T') {
                    return false;
                }
            }
            return true;
        }
    }

    std::vector<DataEntry> ParseLsOutput(const std::string &output) {
        std::vector<DataEntry> entries;
        std::istringstream stream(output);
        std::string line;
        while (std::getline(stream, line)) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            const std::string trimmed = Trim(line);
            if (!LooksLikeLsRow(trimmed)) {
                continue; // header "total N", su notices, blank lines
            }

            // Walk fields, remembering where the name starts.
            std::size_t pos = 0;
            int field = 0;
            std::string perms;
            std::string size;
            std::size_t nameStart = std::string::npos;
            while (pos < trimmed.size()) {
                while (pos < trimmed.size() && std::isspace(static_cast<unsigned char>(trimmed[pos]))) {
                    ++pos;
                }
                if (pos >= trimmed.size()) {
                    break;
                }
                const std::size_t start = pos;
                while (pos < trimmed.size() && !std::isspace(static_cast<unsigned char>(trimmed[pos]))) {
                    ++pos;
                }
                const std::string token = trimmed.substr(start, pos - start);
                if (field == 0) {
                    perms = token;
                } else if (field == 4) {
                    size = token;
                }
                ++field;
                if (field == kNameField) {
                    while (pos < trimmed.size() && std::isspace(static_cast<unsigned char>(trimmed[pos]))) {
                        ++pos;
                    }
                    nameStart = pos;
                    break;
                }
            }
            if (nameStart == std::string::npos || nameStart >= trimmed.size()) {
                continue;
            }

            std::string name = trimmed.substr(nameStart);
            const char type = perms.empty() ? '-' : perms[0];
            if (type == 'l') {
                // "name -> target": keep the link name only.
                const std::size_t arrow = name.find(" -> ");
                if (arrow != std::string::npos) {
                    name = name.substr(0, arrow);
                }
            }
            if (name == "." || name == "..") {
                continue;
            }

            DataEntry entry;
            entry.Name = name;
            entry.IsDir = type == 'd';
            entry.IsLink = type == 'l';
            entry.Perms = perms;
            entry.Size = size;
            entries.push_back(std::move(entry));
        }

        std::sort(entries.begin(), entries.end(), [](const DataEntry &a, const DataEntry &b) {
            if (a.IsDir != b.IsDir) {
                return a.IsDir; // directories first
            }
            return a.Name < b.Name;
        });
        return entries;
    }

    std::string DataPath(const std::string &package, const std::string &subPath) {
        std::string path = "/data/data/" + package;
        std::string clean = subPath;
        // Strip leading slashes and reject traversal; the caller only ever browses
        // within the package dir.
        while (!clean.empty() && clean.front() == '/') {
            clean.erase(clean.begin());
        }
        if (clean.empty() || clean.find("..") != std::string::npos) {
            return path;
        }
        path += "/" + clean;
        return path;
    }

    std::vector<DataEntry> ListAppData(
        const SdkInfo &sdk, const std::string &serial, const std::string &package, const std::string &subPath
    ) {
        const std::string path = DataPath(package, subPath);
        const AdbResult result = ShellSu(sdk, serial, "ls -la '" + path + "'");
        if (!result.Ok()) {
            return {};
        }
        return ParseLsOutput(result.Output);
    }

    std::vector<std::string> GrepAppData(
        const SdkInfo &sdk, const std::string &serial, const std::string &package, const std::string &pattern
    ) {
        std::vector<std::string> lines;
        if (Trim(pattern).empty()) {
            return lines;
        }
        const std::string root = DataPath(package, "");
        // -r recursive, -n line numbers, -I skip binaries, -i case-insensitive. The
        // pattern is user-supplied; we single-quote it and escape embedded quotes so
        // the remote shell treats it as one literal argument to grep -E.
        std::string escaped;
        for (const char c: pattern) {
            if (c == '\'') {
                escaped += "'\\''";
            } else {
                escaped += c;
            }
        }
        const std::string command =
            "grep -rnIiE '" + escaped + "' '" + root + "' 2>/dev/null | head -n 400";
        const AdbResult result = ShellSu(sdk, serial, command);
        if (!result.Started) {
            return lines;
        }
        std::istringstream stream(result.Output);
        std::string line;
        while (std::getline(stream, line)) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            if (!Trim(line).empty()) {
                lines.push_back(line);
            }
        }
        return lines;
    }

    bool PullAppFile(
        const SdkInfo &sdk,
        const std::string &serial,
        const std::string &package,
        const std::string &subPath,
        const std::string &localPath,
        std::string &error
    ) {
        if (Trim(subPath).empty()) {
            error = "No file selected.";
            return false;
        }
        const std::string remote = DataPath(package, subPath);
        const std::string base = std::filesystem::path(remote).filename().string();
        const std::string staged = "/data/local/tmp/coredeck-pull-" + base;

        // adb pull cannot read /data/data directly, so su-copy to a world-readable
        // staging path, pull it, then clean up.
        const AdbResult copy = ShellSu(
            sdk,
            serial,
            "cp -f '" + remote + "' '" + staged + "' && chmod 644 '" + staged + "'"
        );
        if (!copy.Ok()) {
            error = copy.Output.empty() ? "su copy failed." : copy.Output;
            return false;
        }

        const AdbResult pull = Pull(sdk, serial, staged, localPath);
        ShellSu(sdk, serial, "rm -f '" + staged + "'");
        if (!pull.Ok()) {
            error = pull.Output.empty() ? "adb pull failed." : pull.Output;
            return false;
        }
        error.clear();
        return true;
    }
}
