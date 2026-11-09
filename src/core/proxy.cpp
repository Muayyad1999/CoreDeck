//
// Created by CoreDeck RE toolbench on 05/11/2026.
//

#include <cctype>
#include <sstream>
#include <string>
#include <vector>

#include "core/proxy.h"
#include "core/adb.h"

using namespace CoreDeck::Core::Re;

namespace CoreDeck::Core {
    namespace {
        std::string Trim(const std::string &value) {
            std::size_t start = 0;
            std::size_t end = value.size();
            while (start < end && std::isspace(static_cast<unsigned char>(value[start]))) {
                ++start;
            }
            while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
                --end;
            }
            return value.substr(start, end - start);
        }
    }

    std::string NormalizeProxyTarget(const std::string &target) {
        const std::string trimmed = Trim(target);
        if (trimmed.empty()) {
            return trimmed;
        }
        if (trimmed.find(':') == std::string::npos) {
            return std::string(EMULATOR_HOST) + ":" + trimmed;
        }
        return trimmed;
    }

    bool IsProxyEnabledValue(const std::string &value) {
        const std::string trimmed = Trim(value);
        return !trimmed.empty() && trimmed != ":0" && trimmed != "null" && trimmed != "0";
    }

    std::vector<std::string> ParseIptablesDnat(const std::string &iptablesOutput) {
        std::vector<std::string> rules;
        std::istringstream stream(iptablesOutput);
        std::string line;
        while (std::getline(stream, line)) {
            const std::string trimmed = Trim(line);
            if (trimmed.find("DNAT") != std::string::npos) {
                rules.push_back(trimmed);
            }
        }
        return rules;
    }

    ProxyStatus ParseProxyStatus(const std::string &httpProxyValue, const std::string &iptablesOutput) {
        ProxyStatus status;
        status.HttpProxy = Trim(httpProxyValue);
        status.Enabled = IsProxyEnabledValue(httpProxyValue);
        status.DnatRules = ParseIptablesDnat(iptablesOutput);
        return status;
    }

    bool SetProxy(
        const SdkInfo &sdk, const std::string &serial, const std::string &target, const bool transparent, std::string &error
    ) {
        const std::string normalized = NormalizeProxyTarget(target);
        if (normalized.empty()) {
            error = "Enter a proxy target (host:port, or just a port for the emulator host).";
            return false;
        }
        const AdbResult set = Shell(sdk, serial, {"settings", "put", "global", "http_proxy", normalized});
        if (!set.Ok()) {
            error = "Could not set the global proxy: " + set.Output;
            return false;
        }
        if (transparent) {
            for (const char *dport: {"80", "443"}) {
                const std::string rule = "iptables -t nat -A OUTPUT -p tcp --dport " + std::string(dport) +
                                         " -j DNAT --to-destination " + normalized;
                const AdbResult dnat = ShellSu(sdk, serial, rule);
                if (!dnat.Ok()) {
                    error = "Proxy set, but the transparent redirect (iptables) failed - is the AVD rooted? " +
                            dnat.Output;
                    return false;
                }
            }
        }
        return true;
    }

    bool ClearProxy(const SdkInfo &sdk, const std::string &serial, std::string &error) {
        const AdbResult clear = Shell(sdk, serial, {"settings", "put", "global", "http_proxy", ":0"});
        if (!clear.Ok()) {
            error = "Could not clear the global proxy: " + clear.Output;
            return false;
        }
        ShellSu(sdk, serial, "iptables -t nat -F OUTPUT"); // best-effort; needs root
        return true;
    }

    ProxyStatus GetProxyStatus(const SdkInfo &sdk, const std::string &serial) {
        const AdbResult proxy = Shell(sdk, serial, {"settings", "get", "global", "http_proxy"});
        const AdbResult iptables = ShellSu(sdk, serial, "iptables -t nat -S OUTPUT");
        return ParseProxyStatus(proxy.Output, iptables.Ok() ? iptables.Output : "");
    }
}
