//
// Created by CoreDeck RE toolbench on 05/11/2026.
//

#include "core/mitm.h"

#include <optional>

#include "core/adb.h"
#include "core/cert.h"
#include "core/proxy.h"

namespace CoreDeck::Core {
    std::vector<std::string> MonkeyLaunchArgs(const std::string &package) {
        return {"monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1"};
    }

    bool ValidateMitmOptions(const MitmOptions &options, std::string &error) {
        if (!options.TrustCert && !options.SetProxyStep && !options.Launch) {
            error = "Pick at least one step.";
            return false;
        }
        if (options.TrustCert && options.CertPath.empty()) {
            error = "Trust CA is on but no certificate is selected.";
            return false;
        }
        if (options.SetProxyStep && options.ProxyTarget.empty()) {
            error = "Set proxy is on but no proxy target is given.";
            return false;
        }
        if (options.Launch && options.Package.empty()) {
            error = "Launch is on but no package is given.";
            return false;
        }
        error.clear();
        return true;
    }

    MitmResult RunMitm(const SdkInfo &sdk, const std::string &serial, const MitmOptions &options) {
        MitmResult result;

        if (options.TrustCert) {
            std::string error;
            const std::optional<std::string> name = InstallCaCert(sdk, serial, options.CertPath, error);
            MitmStepResult step;
            step.Name = "Trust CA certificate";
            step.Ok = name.has_value();
            if (name.has_value()) {
                result.InstalledCertName = *name;
                step.Detail = "Installed as " + *name;
            } else {
                step.Detail = error.empty() ? "Install failed." : error;
            }
            result.Steps.push_back(step);
            if (!step.Ok) {
                return result;
            }
        }

        if (options.SetProxyStep) {
            std::string error;
            const bool ok = SetProxy(sdk, serial, options.ProxyTarget, options.Transparent, error);
            MitmStepResult step;
            step.Name = "Set proxy";
            step.Ok = ok;
            step.Detail = ok ? ("Proxy -> " + NormalizeProxyTarget(options.ProxyTarget)) : (error.empty() ? "Failed." : error);
            result.Steps.push_back(step);
            if (!ok) {
                return result;
            }
        }

        if (options.Launch) {
            const AdbResult launch = Shell(sdk, serial, MonkeyLaunchArgs(options.Package));
            MitmStepResult step;
            step.Name = "Launch app";
            step.Ok = launch.Ok();
            step.Detail = launch.Ok() ? "Started." : (launch.Output.empty() ? "Launch failed." : launch.Output);
            result.Steps.push_back(step);
        }

        return result;
    }

    MitmResult TeardownMitm(
        const SdkInfo &sdk, const std::string &serial, const MitmOptions &options, const std::string &installedCertName
    ) {
        MitmResult result;

        {
            std::string error;
            const bool ok = ClearProxy(sdk, serial, error);
            MitmStepResult step;
            step.Name = "Clear proxy";
            step.Ok = ok;
            step.Detail = ok ? "Cleared." : (error.empty() ? "Failed." : error);
            result.Steps.push_back(step);
        }

        if (options.RemoveCertOnTeardown && !installedCertName.empty()) {
            std::string error;
            const bool ok = RemoveCaCert(sdk, serial, installedCertName, error);
            MitmStepResult step;
            step.Name = "Remove CA certificate";
            step.Ok = ok;
            step.Detail = ok ? "Removed." : (error.empty() ? "Failed." : error);
            result.Steps.push_back(step);
        }

        return result;
    }
}
