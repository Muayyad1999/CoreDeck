//
// Created by CoreDeck RE toolbench on 04/11/2026.
//

#include <array>
#include <chrono>
#include <future>
#include <optional>
#include <string>
#include <utility>

#include "imgui.h"

#include "avd_root.h"
#include "../widgets.h"
#include "../theme.h"
#include "gui/context.h"
#include "core/avd_root.h"
#include "platform/i18n.h"
#include "platform/utilities.h"

namespace CoreDeck::Gui {
    namespace {
        const Core::AvdInfo *SelectedAvd(const Context &context) {
            const int index = context.Catalog.SelectedAvd;
            if (index < 0 || index >= static_cast<int>(context.Catalog.Avds.size())) {
                return nullptr;
            }
            return &context.Catalog.Avds.at(static_cast<std::size_t>(index));
        }

        void StartResolve(Context &context) {
            auto &work = context.AvdRootWork;
            if (work.ResolveBusy.load()) {
                return;
            }
            work.ResolveBusy = true;
            work.ResolveError.clear();
            const bool prerelease = work.IncludePrerelease;
            const std::string override = work.MagiskOverride;
            work.ResolveFuture = std::async(std::launch::async, [prerelease, override] {
                const Core::MagiskResolveDeps deps = Core::DefaultMagiskResolveDeps();
                std::string error;
                auto resolved = Core::ResolveMagisk(deps, prerelease, /*allowDownload=*/true, override, error);
                return std::make_pair(std::move(resolved), std::move(error));
            });
        }

        void StartRootCheck(Context &context, const std::string &serial) {
            auto &work = context.AvdRootWork;
            if (work.RootCheckBusy.load() || serial.empty()) {
                return;
            }
            work.RootCheckBusy = true;
            work.RootCheckedSerial = serial;
            const Core::SdkInfo sdk = context.Host.Sdk;
            work.RootCheckFuture =
                std::async(std::launch::async, [sdk, serial] { return Core::CheckRoot(sdk, serial); });
        }

        void PollWork(Context &context) {
            auto &work = context.AvdRootWork;
            if (work.ResolveBusy.load() && work.ResolveFuture.valid() &&
                work.ResolveFuture.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                auto [value, error] = work.ResolveFuture.get();
                if (value.has_value()) {
                    work.Resolved = std::move(*value);
                    work.HasResolved = true;
                    work.ResolveError.clear();
                } else {
                    work.ResolveError = error.empty() ? std::string(Platform::Tr("Could not resolve Magisk.")) : error;
                }
                work.ResolveBusy = false;
            }
            if (work.RootCheckBusy.load() && work.RootCheckFuture.valid() &&
                work.RootCheckFuture.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                work.LastRootStatus = work.RootCheckFuture.get();
                work.RootCheckBusy = false;
            }
        }

        void MagiskSection(Context &context) {
            auto &work = context.AvdRootWork;
            ImGui::TextDisabled("%s", Platform::Tr("Magisk"));
            ImGui::Spacing();

            ImGui::Checkbox(Platform::Tr("Include pre-release (canary) builds"), &work.IncludePrerelease);
            ImGui::TextDisabled("%s", Platform::Tr("Local Magisk APK (optional)"));
            ImGui::SetNextItemWidth(-1.0F);
            ImGui::InputTextWithHint(
                "##magisk_override",
                Platform::Tr("Leave empty to fetch the newest release"),
                work.MagiskOverride,
                sizeof(work.MagiskOverride)
            );

            const bool busy = work.ResolveBusy.load();
            if (PositiveButton(
                    busy ? Platform::Tr("Resolving...") : Platform::Tr("Fetch Magisk"),
                    !busy,
                    ImVec2(0, 0),
                    busy
                )) {
                StartResolve(context);
            }

            if (!work.ResolveError.empty()) {
                ImGui::TextColored(HexColor(Colors::NEGATIVE), "%s", work.ResolveError.c_str());
            } else if (work.HasResolved) {
                const Core::ResolvedMagisk &r = work.Resolved;
                ImGui::Spacing();
                PropertyText(Platform::Tr("Release"), r.Release.Tag.c_str());
                PropertyText(
                    Platform::Tr("Channel"),
                    r.Release.Channel == Core::MagiskChannel::Prerelease ? Platform::Tr("pre-release")
                                                                         : Platform::Tr("stable")
                );
                if (r.Release.Size > 0) {
                    PropertyText(Platform::Tr("Size"), Platform::FormatFileSize(r.Release.Size).c_str());
                }
                if (!r.Info.Abis.empty()) {
                    std::string abis;
                    for (const std::string &abi: r.Info.Abis) {
                        if (!abis.empty()) {
                            abis += ", ";
                        }
                        abis += abi;
                    }
                    PropertyText(Platform::Tr("ABIs"), abis.c_str());
                }
                if (!r.Sha256.empty()) {
                    PropertyText("SHA-256", r.Sha256.substr(0, 16).append("...").c_str());
                }
                ImGui::TextDisabled("%s", Platform::Tr("Cached and verified. Ready for the patch step."));
            }
        }

        void RootStatusSection(Context &context) {
            auto &work = context.AvdRootWork;
            const std::string &serial = context.Target.Serial;

            ImGui::TextDisabled("%s", Platform::Tr("Root status"));
            ImGui::Spacing();

            if (serial.empty()) {
                ImGui::TextDisabled("%s", Platform::Tr("Select a device in the Devices window to verify root."));
                return;
            }

            PropertyText(Platform::Tr("Device"), serial.c_str());
            const bool busy = work.RootCheckBusy.load();
            if (PositiveButton(
                    busy ? Platform::Tr("Checking...") : Platform::Tr("Verify Root"),
                    !busy,
                    ImVec2(0, 0),
                    busy
                )) {
                StartRootCheck(context, serial);
            }

            if (!busy && work.LastRootStatus != Core::RootStatus::Unknown && work.RootCheckedSerial == serial) {
                const bool rooted = work.LastRootStatus == Core::RootStatus::Rooted;
                ImGui::SameLine();
                ImGui::TextColored(
                    HexColor(rooted ? Colors::POSITIVE : Colors::WARNING),
                    "%s",
                    rooted ? Platform::Tr("Rooted (su returned uid=0)") : Platform::Tr("Not rooted")
                );
            }
        }

        void PipelinePreview() {
            ImGui::TextDisabled("%s", Platform::Tr("Rooting pipeline"));
            ImGui::Spacing();
            constexpr std::array<Core::RootStage, 8> STAGES = {
                Core::RootStage::ResolveMagisk,
                Core::RootStage::StartEmulator,
                Core::RootStage::ReadPreinit,
                Core::RootStage::WriteMagiskEnv,
                Core::RootStage::PatchRamdisk,
                Core::RootStage::ColdReboot,
                Core::RootStage::GrantSu,
                Core::RootStage::Verify
            };
            for (const Core::RootStage stage: STAGES) {
                ImGui::BulletText("%s", Core::RootStageLabel(stage));
            }
            ImGui::TextDisabled(
                "%s",
                Platform::Tr("Guided one-click rooting (host-side ramdisk patch + cold boot) arrives next.")
            );
        }
    }

    void BuildAvdRootWindow(Context &context) {
        PollWork(context);

        if (!context.UI.ShowAvdRootDialog) {
            return;
        }

        const std::string title = Platform::TrWindow("Root AVD", "AvdRootDialog");
        ImGui::SetNextWindowSize(EmV(30.0F, 30.0F), ImGuiCond_FirstUseEver);
        if (ImGui::Begin(title.c_str(), &context.UI.ShowAvdRootDialog)) {
            if (!context.Host.Sdk.IsFound) {
                ImGui::TextDisabled("%s", Platform::Tr("No Android SDK detected. Set the SDK path in Preferences."));
                ImGui::End();
                return;
            }

            const Core::AvdInfo *avd = SelectedAvd(context);
            ImGui::TextDisabled("%s", Platform::Tr("Target AVD"));
            ImGui::Spacing();
            if (avd == nullptr) {
                ImGui::TextDisabled("%s", Platform::Tr("Select an AVD in the list to root."));
            } else {
                PropertyText(Platform::Tr("AVD"), avd->DisplayName.empty() ? avd->Name.c_str() : avd->DisplayName.c_str());
                if (!avd->Abi.empty()) {
                    PropertyText(Platform::Tr("ABI"), avd->Abi.c_str());
                }
                if (avd->IsGooglePlayImage) {
                    ImGui::TextColored(
                        HexColor(Colors::WARNING),
                        "%s",
                        Platform::Tr("This is a Google Play image. Prefer a Google APIs (AOSP) image for rooting.")
                    );
                }
            }

            ImGui::Separator();
            MagiskSection(context);
            ImGui::Separator();
            RootStatusSection(context);
            ImGui::Separator();
            PipelinePreview();
        }
        ImGui::End();
    }
}
