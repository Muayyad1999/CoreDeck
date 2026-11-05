//
// Created by CoreDeck RE toolbench on 05/11/2026.
//
// One-click MITM [sensitive]: a thin orchestrator over the CA-trust, proxy, and
// launch building blocks, for intercepting an app you own / are authorized to
// test on an emulator you control. It does not repackage or disable pinning -
// for a pinned app, run the Frida SSL-pinning bypass or the Flutter TLS patch
// alongside it.
//

#ifndef COREDECK_MITM_H
#define COREDECK_MITM_H

#include <string>
#include <vector>

#include "core/sdk.h"

namespace CoreDeck::Core {
    struct MitmOptions {
        bool TrustCert = true;
        std::string CertPath; // PEM/DER CA to install into the system store
        bool SetProxyStep = true;
        std::string ProxyTarget; // host:port, or a bare port (emulator host)
        bool Transparent = false; // iptables DNAT for apps that ignore the proxy
        bool Launch = true;
        std::string Package;
        bool RemoveCertOnTeardown = false;
    };

    struct MitmStepResult {
        std::string Name;
        bool Ok = false;
        std::string Detail;
    };

    struct MitmResult {
        std::vector<MitmStepResult> Steps;
        std::string InstalledCertName; // "<hash>.0" when a cert was installed

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

    // ----------------------------------------------------------------------- //
    // Pure helpers (no process, no device) - the unit-tested core.
    // ----------------------------------------------------------------------- //

    // argv (after `adb -s <serial> shell`) that launches a package's launcher
    // activity via monkey.
    std::vector<std::string> MonkeyLaunchArgs(const std::string &package);

    // Validate the selected steps have what they need. Returns false with a
    // message on the first problem.
    bool ValidateMitmOptions(const MitmOptions &options, std::string &error);

    // ----------------------------------------------------------------------- //
    // Orchestration (drives cert / proxy / adb).
    // ----------------------------------------------------------------------- //

    // Run the enabled steps in order (trust CA -> set proxy -> launch), stopping
    // at the first failure. Each attempted step is recorded.
    MitmResult RunMitm(const SdkInfo &sdk, const std::string &serial, const MitmOptions &options);

    // Undo: clear the proxy, and optionally remove the installed system CA.
    MitmResult TeardownMitm(
        const SdkInfo &sdk, const std::string &serial, const MitmOptions &options, const std::string &installedCertName
    );
}

#endif // COREDECK_MITM_H
