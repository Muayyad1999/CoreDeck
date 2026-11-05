//
// Created by CoreDeck RE toolbench on 05/11/2026.
//
// Route an emulator's traffic at your proxy (Burp/Fiddler): the global
// http_proxy setting, plus an optional iptables DNAT for apps that ignore it
// (e.g. Flutter). For emulators you control. Parsers are pure + unit-tested.
//

#ifndef COREDECK_PROXY_H
#define COREDECK_PROXY_H

#include <string>
#include <vector>

#include "core/sdk.h"

namespace CoreDeck::Core {
    struct ProxyStatus {
        std::string HttpProxy; // raw value of global http_proxy
        bool Enabled = false; // set to a real host:port
        std::vector<std::string> DnatRules; // iptables nat OUTPUT DNAT lines
    };

    // The emulator-host alias apps use to reach the host machine.
    constexpr const char *EMULATOR_HOST = "10.0.2.2";

    // If target has no ':', treat it as a port on the emulator host (10.0.2.2:<port>).
    std::string NormalizeProxyTarget(const std::string &target);

    // True when the http_proxy value is a real target (not empty / ":0" / "null").
    bool IsProxyEnabledValue(const std::string &value);

    // Keep the DNAT lines from `iptables -t nat -S OUTPUT` output.
    std::vector<std::string> ParseIptablesDnat(const std::string &iptablesOutput);

    ProxyStatus ParseProxyStatus(const std::string &httpProxyValue, const std::string &iptablesOutput);

    // ---- device orchestration ----
    bool SetProxy(
        const SdkInfo &sdk, const std::string &serial, const std::string &target, bool transparent, std::string &error
    );
    bool ClearProxy(const SdkInfo &sdk, const std::string &serial, std::string &error);
    ProxyStatus GetProxyStatus(const SdkInfo &sdk, const std::string &serial);
}

#endif // COREDECK_PROXY_H
