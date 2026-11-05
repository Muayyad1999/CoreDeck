//
// Created by CoreDeck RE toolbench on 05/11/2026.
//

#include <chrono>
#include <future>
#include <string>
#include <utility>

#include "imgui.h"

#include "proxy.h"
#include "../widgets.h"
#include "../theme.h"
#include "gui/context.h"
#include "core/proxy.h"
#include "platform/i18n.h"

namespace CoreDeck::Gui {
    namespace {
        void StartStatus(Context &context, const std::string &serial) {
            auto &work = context.ProxyWork;
            if (work.StatusBusy.load() || serial.empty()) {
                return;
            }
            work.StatusBusy = true;
            const Core::SdkInfo sdk = context.Host.Sdk;
            work.StatusFuture =
                std::async(std::launch::async, [sdk, serial] { return Core::GetProxyStatus(sdk, serial); });
        }

        void StartApply(Context &context, const std::string &serial, const bool clear) {
            auto &work = context.ProxyWork;
            if (work.Busy.load() || serial.empty()) {
                return;
            }
            work.Busy = true;
            work.Outcome.clear();
            const Core::SdkInfo sdk = context.Host.Sdk;
            const std::string target = work.Target;
            const bool transparent = work.Transparent;
            work.Future = std::async(std::launch::async, [sdk, serial, target, transparent, clear] {
                std::string error;
                const bool ok = clear ? Core::ClearProxy(sdk, serial, error)
                                      : Core::SetProxy(sdk, serial, target, transparent, error);
                return std::make_pair(ok, error);
            });
        }

        void PollWork(Context &context) {
            auto &work = context.ProxyWork;
            if (work.Busy.load() && work.Future.valid() &&
                work.Future.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                auto [ok, error] = work.Future.get();
                work.Busy = false;
                work.OutcomeOk = ok;
                work.Outcome =
                    ok ? std::string(Platform::Tr("Done. Restart the app so it picks up the change.")) : error;
                if (ok && !context.Target.Serial.empty()) {
                    StartStatus(context, context.Target.Serial);
                }
            }
            if (work.StatusBusy.load() && work.StatusFuture.valid() &&
                work.StatusFuture.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                work.Status = work.StatusFuture.get();
                work.HasStatus = true;
                work.StatusBusy = false;
            }
        }
    }

    void BuildProxyWindow(Context &context) {
        PollWork(context);

        if (!context.UI.ShowProxyDialog) {
            return;
        }

        auto &work = context.ProxyWork;
        const std::string title = Platform::TrWindow("Proxy", "ProxyDialog");
        ImGui::SetNextWindowSize(EmV(30.0F, 24.0F), ImGuiCond_FirstUseEver);
        if (ImGui::Begin(title.c_str(), &context.UI.ShowProxyDialog)) {
            if (!context.Host.Sdk.IsFound) {
                ImGui::TextDisabled("%s", Platform::Tr("No Android SDK detected. Set the SDK path in Preferences."));
                ImGui::End();
                return;
            }

            const std::string &serial = context.Target.Serial;
            ImGui::TextDisabled("%s", Platform::Tr("Route this emulator's traffic to your proxy (Burp/Fiddler)."));
            ImGui::Spacing();

            if (serial.empty()) {
                ImGui::TextDisabled("%s", Platform::Tr("Select a device in the Devices window."));
                ImGui::End();
                return;
            }
            PropertyText(Platform::Tr("Device"), serial.c_str());

            ImGui::TextDisabled("%s", Platform::Tr("Proxy target (host:port, or just a port)"));
            ImGui::SetNextItemWidth(-1.0F);
            ImGui::InputTextWithHint(
                "##proxy_target",
                Platform::Tr("e.g. 10.0.2.2:8080 or 8080"),
                work.Target,
                sizeof(work.Target)
            );
            ImGui::Checkbox(
                Platform::Tr("Transparent redirect (iptables DNAT 80/443, needs root)"),
                &work.Transparent
            );

            const bool busy = work.Busy.load();
            if (PositiveButton(busy ? Platform::Tr("Applying...") : Platform::Tr("Apply"), !busy, ImVec2(0, 0), busy)) {
                StartApply(context, serial, false);
            }
            ImGui::SameLine();
            if (NegativeButton(busy ? Platform::Tr("Clearing...") : Platform::Tr("Clear"), !busy, ImVec2(0, 0), busy)) {
                StartApply(context, serial, true);
            }
            ImGui::SameLine();
            const bool statusBusy = work.StatusBusy.load();
            if (PositiveButton(
                    statusBusy ? Platform::Tr("Checking...") : Platform::Tr("Refresh status"),
                    !statusBusy,
                    ImVec2(0, 0),
                    statusBusy
                )) {
                StartStatus(context, serial);
            }

            if (!work.Outcome.empty()) {
                ImGui::TextColored(
                    HexColor(work.OutcomeOk ? Colors::POSITIVE : Colors::NEGATIVE),
                    "%s",
                    work.Outcome.c_str()
                );
            }

            if (work.HasStatus) {
                ImGui::Separator();
                const Core::ProxyStatus &status = work.Status;
                ImGui::TextDisabled("%s", Platform::Tr("Global proxy"));
                ImGui::SameLine();
                ImGui::TextColored(
                    HexColor(status.Enabled ? Colors::POSITIVE : Colors::TEXT_MUTED),
                    "%s",
                    status.Enabled ? status.HttpProxy.c_str() : Platform::Tr("(unset)")
                );
                ImGui::TextDisabled("%s", Platform::Tr("Transparent rules"));
                if (status.DnatRules.empty()) {
                    ImGui::SameLine();
                    ImGui::TextDisabled("%s", Platform::Tr("none"));
                } else {
                    for (const std::string &rule: status.DnatRules) {
                        ImGui::BulletText("%s", rule.c_str());
                    }
                }
            }
        }
        ImGui::End();
    }
}
