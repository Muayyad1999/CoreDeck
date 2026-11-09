//
// Created by CoreDeck RE toolbench on 05/11/2026.
//

#include <chrono>
#include <cstdio>
#include <future>
#include <string>

#include "imgui.h"

#include "mitm.h"
#include "../widgets/widgets.h"
#include "../theme.h"
#include "gui/context/context.h"
#include "core/mitm.h"
#include "app/file_dialog.h"
#include "platform/i18n.h"

namespace CoreDeck::Gui {
    namespace {
        Core::MitmOptions MakeOptions(const Context &context) {
            const auto &work = context.MitmWork;
            Core::MitmOptions opts;
            opts.TrustCert = work.TrustCert;
            opts.CertPath = work.CertPath;
            opts.SetProxyStep = work.SetProxy;
            opts.ProxyTarget = work.ProxyTarget;
            opts.Transparent = work.Transparent;
            opts.Launch = work.Launch;
            opts.Package = work.Package;
            opts.RemoveCertOnTeardown = work.RemoveCertOnTeardown;
            return opts;
        }

        void StartRun(Context &context, const std::string &serial) {
            auto &work = context.MitmWork;
            if (work.Busy.load() || serial.empty()) {
                return;
            }
            const Core::MitmOptions opts = MakeOptions(context);
            std::string error;
            if (!Core::ValidateMitmOptions(opts, error)) {
                work.ValidationError = error;
                return;
            }
            work.ValidationError.clear();
            work.Busy = true;
            work.HasResult = false;
            work.WasTeardown = false;
            const Core::SdkInfo sdk = context.Host.Sdk;
            work.Future = std::async(std::launch::async, [sdk, serial, opts] {
                return Core::RunMitm(sdk, serial, opts);
            });
        }

        void StartTeardown(Context &context, const std::string &serial) {
            auto &work = context.MitmWork;
            if (work.Busy.load() || serial.empty()) {
                return;
            }
            work.ValidationError.clear();
            work.Busy = true;
            work.HasResult = false;
            work.WasTeardown = true;
            const Core::SdkInfo sdk = context.Host.Sdk;
            const Core::MitmOptions opts = MakeOptions(context);
            const std::string certName = work.InstalledCertName;
            work.Future = std::async(std::launch::async, [sdk, serial, opts, certName] {
                return Core::TeardownMitm(sdk, serial, opts, certName);
            });
        }

        void PollWork(Context &context) {
            auto &work = context.MitmWork;
            if (work.Busy.load() && work.Future.valid() &&
                work.Future.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                work.Result = work.Future.get();
                work.HasResult = true;
                work.Busy = false;
                if (!work.WasTeardown && !work.Result.InstalledCertName.empty()) {
                    work.InstalledCertName = work.Result.InstalledCertName;
                }
            }
        }
    }

    void BuildMitmWindow(Context &context) {
        PollWork(context);

        if (!context.UI.ShowMitmDialog) {
            return;
        }

        auto &work = context.MitmWork;
        const std::string title = Platform::TrWindow("One-click MITM", "MitmDialog");
        ImGui::SetNextWindowSize(EmV(34.0F, 32.0F), ImGuiCond_FirstUseEver);
        if (ImGui::Begin(title.c_str(), &context.UI.ShowMitmDialog)) {
            if (!context.Host.Sdk.IsFound) {
                ImGui::TextDisabled("%s", Platform::Tr("No Android SDK detected. Set the SDK path in Preferences."));
                ImGui::End();
                return;
            }

            const std::string &serial = context.Target.Serial;
            ImGui::TextDisabled(
                "%s",
                Platform::Tr("Trust your CA, point the device at your proxy, and launch the app - in one step, on an "
                             "emulator you control. For an app you own or are authorized to test.")
            );
            ImGui::Spacing();

            if (serial.empty()) {
                ImGui::TextDisabled("%s", Platform::Tr("Select a device in the Devices window."));
                ImGui::End();
                return;
            }
            PropertyText(Platform::Tr("Device"), serial.c_str());
            ImGui::Spacing();

            // Step 1: trust CA
            ImGui::Checkbox(Platform::Tr("Trust CA certificate (system store, rooted AVD)"), &work.TrustCert);
            if (work.TrustCert) {
                ImGui::SetNextItemWidth(Em(20.0F));
                ImGui::InputTextWithHint(
                    "##mitm_cert",
                    Platform::Tr("Path to a CA (PEM/DER), e.g. your Burp root"),
                    work.CertPath,
                    sizeof(work.CertPath)
                );
                ImGui::SameLine();
                if (PickerButton(Platform::Tr("Browse..."))) {
                    if (const auto picked = App::FileDialog::PickFile(
                            Platform::Tr("Open CA certificate"),
                            Platform::Tr("Certificates"),
                            {"*.pem", "*.crt", "*.cer", "*.der", "*.*"}
                        )) {
                        std::snprintf(work.CertPath, sizeof(work.CertPath), "%s", picked->c_str());
                    }
                }
            }

            // Step 2: proxy
            ImGui::Checkbox(Platform::Tr("Set proxy"), &work.SetProxy);
            if (work.SetProxy) {
                ImGui::SetNextItemWidth(Em(20.0F));
                ImGui::InputTextWithHint(
                    "##mitm_proxy",
                    Platform::Tr("e.g. 10.0.2.2:8080 or 8080"),
                    work.ProxyTarget,
                    sizeof(work.ProxyTarget)
                );
                ImGui::Checkbox(
                    Platform::Tr("Transparent redirect (iptables DNAT 80/443, needs root)"),
                    &work.Transparent
                );
            }

            // Step 3: launch
            ImGui::Checkbox(Platform::Tr("Launch app"), &work.Launch);
            if (work.Launch) {
                ImGui::SetNextItemWidth(Em(20.0F));
                ImGui::InputTextWithHint(
                    "##mitm_pkg",
                    Platform::Tr("e.g. com.example.app"),
                    work.Package,
                    sizeof(work.Package)
                );
            }

            ImGui::Spacing();
            ImGui::TextColored(
                HexColor(Colors::WARNING),
                "%s",
                Platform::Tr("Does not disable certificate pinning. For a pinned app, also run the Frida SSL-pinning "
                             "bypass or the Flutter TLS patch.")
            );

            const bool busy = work.Busy.load();
            if (PositiveButton(busy ? Platform::Tr("Working...") : Platform::Tr("Run MITM setup"), !busy, ImVec2(0, 0), busy)) {
                StartRun(context, serial);
            }
            ImGui::SameLine();
            ImGui::Checkbox(Platform::Tr("Remove CA on teardown"), &work.RemoveCertOnTeardown);
            if (NegativeButton(busy ? Platform::Tr("Working...") : Platform::Tr("Teardown (clear proxy)"), !busy, ImVec2(0, 0), busy)) {
                StartTeardown(context, serial);
            }

            if (!work.ValidationError.empty()) {
                ImGui::TextColored(HexColor(Colors::NEGATIVE), "%s", work.ValidationError.c_str());
            }

            if (work.HasResult) {
                ImGui::Separator();
                ImGui::TextColored(
                    HexColor(work.Result.AllOk() ? Colors::POSITIVE : Colors::NEGATIVE),
                    "%s",
                    work.Result.AllOk()
                        ? (work.WasTeardown ? Platform::Tr("Teardown done.")
                                            : Platform::Tr("MITM ready. Watch requests in your proxy."))
                        : Platform::Tr("Stopped at a failing step.")
                );
                for (const auto &step: work.Result.Steps) {
                    ImGui::TextColored(
                        HexColor(step.Ok ? Colors::POSITIVE : Colors::NEGATIVE),
                        "%s",
                        step.Ok ? "[ok]" : "[x]"
                    );
                    ImGui::SameLine();
                    ImGui::Text("%s", step.Name.c_str());
                    if (!step.Detail.empty()) {
                        ImGui::SameLine();
                        ImGui::TextDisabled("- %s", step.Detail.c_str());
                    }
                }
            }
        }
        ImGui::End();
    }
}
