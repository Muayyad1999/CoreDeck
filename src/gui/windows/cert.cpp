//
// Created by CoreDeck RE toolbench on 05/11/2026.
//

#include <chrono>
#include <future>
#include <optional>
#include <string>
#include <utility>

#include "imgui.h"

#include "cert.h"
#include "../widgets/widgets.h"
#include "../theme.h"
#include "gui/context/context.h"
#include "core/cert.h"
#include "app/file_dialog.h"
#include "platform/i18n.h"

namespace CoreDeck::Gui {
    namespace {
        void Inspect(Context &context) {
            auto &work = context.CertWork;
            const std::string path = work.CertPath;
            if (path == work.Inspected) {
                return;
            }
            work.Inspected = path;
            work.HasInfo = false;
            if (path.empty()) {
                return;
            }
            if (const auto info = Core::InspectCaCertFile(path)) {
                work.Info = *info;
                work.HasInfo = true;
            }
        }

        void StartInstall(Context &context, const std::string &serial) {
            auto &work = context.CertWork;
            if (work.InstallBusy.load() || serial.empty()) {
                return;
            }
            work.InstallBusy = true;
            work.InstallOutcome.clear();
            const Core::SdkInfo sdk = context.Host.Sdk;
            const std::string path = work.CertPath;
            work.InstallFuture = std::async(std::launch::async, [sdk, serial, path] {
                std::string error;
                auto name = Core::InstallCaCert(sdk, serial, path, error);
                return std::make_pair(std::move(name), std::move(error));
            });
        }

        void StartRemove(Context &context, const std::string &serial, const std::string &name) {
            auto &work = context.CertWork;
            if (work.RemoveBusy.load() || serial.empty() || name.empty()) {
                return;
            }
            work.RemoveBusy = true;
            work.RemoveOutcome.clear();
            const Core::SdkInfo sdk = context.Host.Sdk;
            work.RemoveFuture = std::async(std::launch::async, [sdk, serial, name] {
                std::string error;
                const bool ok = Core::RemoveCaCert(sdk, serial, name, error);
                return std::make_pair(ok, error);
            });
        }

        void PollWork(Context &context) {
            auto &work = context.CertWork;
            if (work.InstallBusy.load() && work.InstallFuture.valid() &&
                work.InstallFuture.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                auto [name, error] = work.InstallFuture.get();
                work.InstallBusy = false;
                work.InstallOk = name.has_value();
                work.InstallOutcome = name.has_value()
                                          ? Platform::TrFormat("Installed as {0} in the system store.", *name)
                                          : error;
            }
            if (work.RemoveBusy.load() && work.RemoveFuture.valid() &&
                work.RemoveFuture.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                auto [ok, error] = work.RemoveFuture.get();
                work.RemoveBusy = false;
                work.RemoveOutcome = ok ? std::string(Platform::Tr("Removed from the system store.")) : error;
            }
        }
    }

    void BuildCertWindow(Context &context) {
        PollWork(context);

        if (!context.UI.ShowCertDialog) {
            return;
        }

        auto &work = context.CertWork;
        const std::string title = Platform::TrWindow("CA Trust", "CertDialog");
        ImGui::SetNextWindowSize(EmV(30.0F, 24.0F), ImGuiCond_FirstUseEver);
        if (ImGui::Begin(title.c_str(), &context.UI.ShowCertDialog)) {
            if (!context.Host.Sdk.IsFound) {
                ImGui::TextDisabled("%s", Platform::Tr("No Android SDK detected. Set the SDK path in Preferences."));
                ImGui::End();
                return;
            }

            ImGui::TextDisabled(
                "%s",
                Platform::Tr("Install a CA into an emulator you control so its apps trust your proxy (Burp/Fiddler).")
            );
            ImGui::Spacing();

            ImGui::TextDisabled("%s", Platform::Tr("Certificate (PEM or DER)"));
            ImGui::SetNextItemWidth(-1.0F);
            ImGui::InputTextWithHint(
                "##cert_path",
                Platform::Tr("Path to a .pem / .der / .crt CA file"),
                work.CertPath,
                sizeof(work.CertPath)
            );
            if (PickerButton(Platform::Tr("Browse..."))) {
                if (const auto picked = App::FileDialog::PickFile(
                        Platform::Tr("Open certificate"),
                        Platform::Tr("Certificates"),
                        {"*.pem", "*.der", "*.crt", "*.cer"}
                    )) {
                    std::snprintf(work.CertPath, sizeof(work.CertPath), "%s", picked->c_str());
                }
            }

            Inspect(context);
            if (work.HasInfo) {
                PropertyText(Platform::Tr("Store filename"), work.Info.FileName.c_str());
            } else if (work.CertPath[0] != '\0') {
                ImGui::TextColored(HexColor(Colors::NEGATIVE), "%s", Platform::Tr("Not a valid PEM or DER certificate."));
            }

            ImGui::Separator();
            const std::string &serial = context.Target.Serial;
            ImGui::TextDisabled("%s", Platform::Tr("Target device"));
            if (serial.empty()) {
                ImGui::TextDisabled("%s", Platform::Tr("Select a device in the Devices window."));
            } else {
                PropertyText(Platform::Tr("Device"), serial.c_str());
            }

            const bool installBusy = work.InstallBusy.load();
            const bool removeBusy = work.RemoveBusy.load();
            const bool canInstall = work.HasInfo && !serial.empty() && !installBusy && !removeBusy;
            if (PositiveButton(
                    installBusy ? Platform::Tr("Installing...") : Platform::Tr("Install to system store"),
                    canInstall,
                    ImVec2(0, 0),
                    installBusy
                )) {
                StartInstall(context, serial);
            }
            ImGui::SameLine();
            const bool canRemove = work.HasInfo && !serial.empty() && !installBusy && !removeBusy;
            if (NegativeButton(
                    removeBusy ? Platform::Tr("Removing...") : Platform::Tr("Remove"),
                    canRemove,
                    ImVec2(0, 0),
                    removeBusy
                )) {
                StartRemove(context, serial, work.Info.FileName);
            }

            ImGui::TextColored(
                HexColor(Colors::WARNING),
                "%s",
                Platform::Tr("Requires a rooted AVD (su). Reboot so the store is re-read.")
            );
            if (!work.InstallOutcome.empty()) {
                ImGui::TextColored(
                    HexColor(work.InstallOk ? Colors::POSITIVE : Colors::NEGATIVE),
                    "%s",
                    work.InstallOutcome.c_str()
                );
                if (work.InstallOk) {
                    ImGui::TextDisabled(
                        "%s",
                        Platform::Tr("On Android 14+ a plain copy may not stick; use the AlwaysTrustUserCerts Magisk "
                                     "module if apps still reject it.")
                    );
                }
            }
            if (!work.RemoveOutcome.empty()) {
                ImGui::TextDisabled("%s", work.RemoveOutcome.c_str());
            }
        }
        ImGui::End();
    }
}
