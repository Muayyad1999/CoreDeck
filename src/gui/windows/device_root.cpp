//
// Created by CoreDeck RE toolbench on 25/11/2026.
//

#include <array>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <future>
#include <optional>
#include <string>
#include <utility>

#include "imgui.h"

#include "device_root.h"
#include "../widgets/widgets.h"
#include "../theme.h"
#include "app/file_dialog.h"
#include "gui/context/context.h"
#include "core/avd_root.h"
#include "core/device_root.h"
#include "core/fastboot.h"
#include "platform/i18n.h"
#include "platform/paths.h"

namespace CoreDeck::Gui {
    namespace {
        bool EndsWithImg(const std::string &path) {
            return path.size() >= 4 && path.compare(path.size() - 4, 4, ".img") == 0;
        }

        std::string ExtractDir() {
            return Platform::JoinPaths({Platform::GetConfigDirectory(), "device-root", "extracted"});
        }

        void StartResolve(Context &context) {
            auto &work = context.DeviceRootWork;
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

        void StartAcquire(Context &context) {
            auto &work = context.DeviceRootWork;
            if (work.AcquireBusy.load()) {
                return;
            }
            const std::string input = work.BootImageInput;
            work.AcquireError.clear();
            if (input.empty()) {
                work.AcquireError = Platform::Tr("Choose a factory image zip or a boot/init_boot.img file.");
                return;
            }
            // A direct .img needs no extraction.
            if (EndsWithImg(input)) {
                if (!std::filesystem::exists(input)) {
                    work.AcquireError = Platform::Tr("File not found.");
                    return;
                }
                work.BootImagePath = input;
                work.BootTarget = Core::BootTargetForImageName(input);
                work.HasBootImage = true;
                return;
            }
            work.AcquireBusy = true;
            work.HasBootImage = false;
            const std::string destDir = ExtractDir();
            work.AcquireFuture = std::async(std::launch::async, [input, destDir] {
                std::string error;
                auto result = Core::ExtractBootImageFromFactoryZip(input, destDir, error);
                return std::make_pair(std::move(result), std::move(error));
            });
        }

        void StartBootloaderCheck(Context &context, const std::string &serial) {
            auto &work = context.DeviceRootWork;
            if (work.BootloaderBusy.load()) {
                return;
            }
            work.BootloaderBusy = true;
            const Core::SdkInfo sdk = context.Host.Sdk;
            work.BootloaderFuture =
                std::async(std::launch::async, [sdk, serial] { return Core::Re::GetBootloaderVars(sdk, serial); });
        }

        void StartReboot(Context &context, const std::string &serial) {
            auto &work = context.DeviceRootWork;
            if (work.ActionBusy.load()) {
                return;
            }
            work.ActionBusy = true;
            work.ActionOutcome.clear();
            const Core::SdkInfo sdk = context.Host.Sdk;
            work.ActionFuture = std::async(std::launch::async, [sdk, serial] {
                const Core::Re::FastbootResult result = Core::Re::RebootToBootloaderViaAdb(sdk, serial);
                return std::make_pair(
                    result.Ok(),
                    std::string(result.Ok() ? "Reboot to bootloader requested." : "Could not reboot to bootloader.")
                );
            });
        }

        void StartUnlock(Context &context, const std::string &serial) {
            auto &work = context.DeviceRootWork;
            if (work.ActionBusy.load()) {
                return;
            }
            work.ActionBusy = true;
            work.ActionOutcome.clear();
            const Core::SdkInfo sdk = context.Host.Sdk;
            work.ActionFuture = std::async(std::launch::async, [sdk, serial] {
                const Core::Re::FastbootResult result = Core::Re::FlashingUnlock(sdk, serial);
                return std::make_pair(
                    result.Ok(),
                    std::string(
                        result.Ok() ? "Unlock sent. Confirm on the device with the volume/power keys; it then wipes."
                                    : "fastboot flashing unlock failed. Enable OEM unlocking in Developer options."
                    )
                );
            });
        }

        void StartRootCheck(Context &context, const std::string &serial) {
            auto &work = context.DeviceRootWork;
            if (work.RootCheckBusy.load() || serial.empty()) {
                return;
            }
            work.RootCheckBusy = true;
            work.RootCheckedSerial = serial;
            const Core::SdkInfo sdk = context.Host.Sdk;
            work.RootCheckFuture =
                std::async(std::launch::async, [sdk, serial] { return Core::CheckRoot(sdk, serial); });
        }

        void StartRoot(Context &context, const std::string &serial) {
            auto &work = context.DeviceRootWork;
            if (work.RootBusy.load() || !work.HasResolved || !work.HasBootImage) {
                return;
            }
            std::string error;
            auto plan = Core::PlanDeviceRoot(
                context.Host.Sdk, serial, work.Resolved.LocalPath, work.BootImagePath, error
            );
            if (!plan) {
                work.RootOutcome = error;
                return;
            }
            plan->StripVerity = work.StripVerity;
            work.RootBusy = true;
            work.RootOutcome.clear();
            work.Progress = std::make_shared<Core::DeviceRootProgress>();
            const Core::SdkInfo sdk = context.Host.Sdk;
            const Core::DeviceRootPlan planValue = *plan;
            auto progress = work.Progress;
            work.RootFuture = std::async(std::launch::async, [sdk, planValue, progress] {
                return Core::RootDevice(sdk, planValue, *progress);
            });
        }

        void PollWork(Context &context) {
            auto &work = context.DeviceRootWork;
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
            if (work.AcquireBusy.load() && work.AcquireFuture.valid() &&
                work.AcquireFuture.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                auto [value, error] = work.AcquireFuture.get();
                if (value.has_value()) {
                    work.BootImagePath = value->LocalPath;
                    work.BootTarget = value->Target;
                    work.HasBootImage = true;
                    work.AcquireError.clear();
                } else {
                    work.AcquireError = error.empty() ? std::string(Platform::Tr("Could not find a boot image.")) : error;
                }
                work.AcquireBusy = false;
            }
            if (work.BootloaderBusy.load() && work.BootloaderFuture.valid() &&
                work.BootloaderFuture.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                work.Bootloader = work.BootloaderFuture.get();
                work.HasBootloader = true;
                work.BootloaderBusy = false;
            }
            if (work.ActionBusy.load() && work.ActionFuture.valid() &&
                work.ActionFuture.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                auto [ok, message] = work.ActionFuture.get();
                work.ActionOk = ok;
                work.ActionOutcome = message;
                work.ActionBusy = false;
            }
            if (work.RootCheckBusy.load() && work.RootCheckFuture.valid() &&
                work.RootCheckFuture.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                work.LastRootStatus = work.RootCheckFuture.get();
                work.RootCheckBusy = false;
            }
            if (work.RootBusy.load() && work.RootFuture.valid() &&
                work.RootFuture.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                const bool ok = work.RootFuture.get();
                work.RootBusy = false;
                if (work.Progress) {
                    std::lock_guard<std::mutex> lock(work.Progress->Mutex);
                    work.RootOutcome = ok ? work.Progress->Detail : work.Progress->Error;
                }
            }
        }

        void MagiskSection(Context &context) {
            auto &work = context.DeviceRootWork;
            ImGui::TextDisabled("%s", Platform::Tr("Magisk"));
            ImGui::Spacing();

            ImGui::Checkbox(Platform::Tr("Include pre-release (canary) builds"), &work.IncludePrerelease);
            ImGui::TextDisabled("%s", Platform::Tr("Local Magisk APK (optional)"));
            ImGui::SetNextItemWidth(-1.0F);
            ImGui::InputTextWithHint(
                "##device_magisk_override",
                Platform::Tr("Leave empty to fetch the newest release"),
                work.MagiskOverride,
                sizeof(work.MagiskOverride)
            );

            const bool busy = work.ResolveBusy.load();
            if (PositiveButton(
                    busy ? Platform::Tr("Resolving...") : Platform::Tr("Fetch Magisk"), !busy, ImVec2(0, 0), busy
                )) {
                StartResolve(context);
            }

            if (!work.ResolveError.empty()) {
                ImGui::TextColored(HexColor(Colors::NEGATIVE), "%s", work.ResolveError.c_str());
            } else if (work.HasResolved) {
                const Core::ResolvedMagisk &r = work.Resolved;
                PropertyText(Platform::Tr("Release"), r.Release.Tag.c_str());
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
                ImGui::TextDisabled("%s", Platform::Tr("Cached and verified. Ready for the patch step."));
            }
        }

        void BootImageSection(Context &context) {
            auto &work = context.DeviceRootWork;
            ImGui::TextDisabled("%s", Platform::Tr("Boot image"));
            ImGui::Spacing();
            ImGui::TextDisabled(
                "%s",
                Platform::Tr("Point at the factory image zip for this exact build, or a boot.img / init_boot.img you "
                             "already extracted. Get the build's image from the device maker's factory-image page.")
            );

            ImGui::SetNextItemWidth(-1.0F);
            ImGui::InputTextWithHint(
                "##device_boot_input",
                Platform::Tr("Path to a factory zip or boot/init_boot.img"),
                work.BootImageInput,
                sizeof(work.BootImageInput)
            );
            if (PickerButton(Platform::Tr("Browse..."))) {
                if (const auto picked = App::FileDialog::PickFile(
                        Platform::Tr("Open factory image or boot image"),
                        Platform::Tr("Images and archives"),
                        {"*.zip", "*.img"}
                    )) {
                    std::snprintf(work.BootImageInput, sizeof(work.BootImageInput), "%s", picked->c_str());
                }
            }
            const bool busy = work.AcquireBusy.load();
            ImGui::SameLine();
            if (PositiveButton(
                    busy ? Platform::Tr("Extracting...") : Platform::Tr("Locate boot image"), !busy, ImVec2(0, 0), busy
                )) {
                StartAcquire(context);
            }

            if (!work.AcquireError.empty()) {
                ImGui::TextColored(HexColor(Colors::NEGATIVE), "%s", work.AcquireError.c_str());
            } else if (work.HasBootImage) {
                PropertyText(Platform::Tr("Image"), FileNameOf(work.BootImagePath).c_str());
                PropertyText(Platform::Tr("Flashes to"), Core::BootTargetPartition(work.BootTarget));
            }
        }

        void BootloaderSection(Context &context, const std::string &serial) {
            auto &work = context.DeviceRootWork;
            ImGui::TextDisabled("%s", Platform::Tr("Bootloader"));
            ImGui::Spacing();

            const bool actionBusy = work.ActionBusy.load();
            if (NegativeButton(Platform::Tr("Reboot to bootloader"), !actionBusy && !serial.empty(), ImVec2(0, 0), false)) {
                StartReboot(context, serial);
            }
            ImGui::SameLine();
            const bool checkBusy = work.BootloaderBusy.load();
            if (PositiveButton(
                    checkBusy ? Platform::Tr("Reading...") : Platform::Tr("Read lock state"),
                    !checkBusy,
                    ImVec2(0, 0),
                    checkBusy
                )) {
                StartBootloaderCheck(context, serial);
            }

            if (work.HasBootloader) {
                const Core::Re::BootloaderVars &b = work.Bootloader;
                if (!b.Product.empty()) {
                    PropertyText(Platform::Tr("Product"), b.Product.c_str());
                }
                if (!b.CurrentSlot.empty()) {
                    PropertyText(Platform::Tr("Current slot"), b.CurrentSlot.c_str());
                }
                const bool unlocked = b.Unlocked == Core::Re::LockState::Unlocked;
                ImGui::TextColored(
                    HexColor(unlocked ? Colors::POSITIVE : Colors::WARNING),
                    "%s",
                    unlocked ? Platform::Tr("Bootloader unlocked") : Platform::Tr("Bootloader locked")
                );
            }

            ImGui::Spacing();
            ImGui::Checkbox(
                Platform::Tr("I understand unlocking ERASES all data on the device"), &work.ConfirmUnlock
            );
            const bool canUnlock = work.ConfirmUnlock && !actionBusy &&
                                   work.Bootloader.Unlocked != Core::Re::LockState::Unlocked;
            if (WarningButton(Platform::Tr("Unlock bootloader (wipes device)"), canUnlock, ImVec2(0, 0), false)) {
                StartUnlock(context, serial);
            }
            ImGui::TextColored(
                HexColor(Colors::WARNING),
                "%s",
                Platform::Tr("Needs the device in fastboot (bootloader) mode and OEM unlocking enabled in Developer "
                             "options. This factory-resets the phone.")
            );
            if (!work.ActionOutcome.empty()) {
                ImGui::TextColored(
                    HexColor(work.ActionOk ? Colors::POSITIVE : Colors::NEGATIVE), "%s", work.ActionOutcome.c_str()
                );
            }
        }

        void PipelineSection(Context &context, const std::string &serial) {
            auto &work = context.DeviceRootWork;
            ImGui::TextDisabled("%s", Platform::Tr("Guided root"));
            ImGui::Spacing();

            const Core::DeviceRootStage current =
                work.Progress ? work.Progress->Stage.load() : Core::DeviceRootStage::Idle;
            constexpr std::array<Core::DeviceRootStage, 6> STAGES = {
                Core::DeviceRootStage::AcquireBootImg,
                Core::DeviceRootStage::PatchBoot,
                Core::DeviceRootStage::RebootBootloader,
                Core::DeviceRootStage::FlashBoot,
                Core::DeviceRootStage::RebootSystem,
                Core::DeviceRootStage::Verify,
            };
            const bool done = current == Core::DeviceRootStage::Done;
            for (const Core::DeviceRootStage stage: STAGES) {
                const bool reached = done || static_cast<int>(current) > static_cast<int>(stage);
                const bool active = !done && current == stage;
                const ImVec4 color =
                    HexColor(active ? Colors::ACCENT_INFO : (reached ? Colors::POSITIVE : Colors::TEXT_MUTED));
                ImGui::TextColored(
                    color,
                    "%s %s",
                    reached ? "\xE2\x9C\x93" : (active ? "\xE2\x80\xA2" : "\xE2\x97\x8B"),
                    Core::DeviceRootStageLabel(stage)
                );
            }

            if (work.RootBusy.load() && work.Progress) {
                ImGui::ProgressBar(work.Progress->Fraction.load(), ImVec2(-1.0F, 0.0F));
                std::string detail;
                {
                    std::lock_guard<std::mutex> lock(work.Progress->Mutex);
                    detail = work.Progress->Detail;
                }
                if (!detail.empty()) {
                    ImGui::TextDisabled("%s", detail.c_str());
                }
            }

            ImGui::Spacing();
            ImGui::Checkbox(Platform::Tr("Strip dm-verity / forced encryption"), &work.StripVerity);
            ImGui::TextColored(
                HexColor(Colors::WARNING),
                "%s",
                Platform::Tr("Experimental: patches and flashes this device's boot partition. Unlock the bootloader "
                             "first. Use a device you own and have backed up.")
            );

            const bool rootBusy = work.RootBusy.load();
            const bool canRoot = !serial.empty() && work.HasResolved && work.HasBootImage && !rootBusy;
            if (PositiveButton(
                    rootBusy ? Platform::Tr("Rooting...") : Platform::Tr("One-click Root"), canRoot, ImVec2(0, 0), rootBusy
                )) {
                StartRoot(context, serial);
            }
            ImGui::SameLine();
            const bool checkBusy = work.RootCheckBusy.load();
            if (PositiveButton(
                    checkBusy ? Platform::Tr("Checking...") : Platform::Tr("Verify su"),
                    !checkBusy && !serial.empty(),
                    ImVec2(0, 0),
                    checkBusy
                )) {
                StartRootCheck(context, serial);
            }
            if (!checkBusy && work.LastRootStatus != Core::RootStatus::Unknown && work.RootCheckedSerial == serial) {
                const bool rooted = work.LastRootStatus == Core::RootStatus::Rooted;
                ImGui::SameLine();
                ImGui::TextColored(
                    HexColor(rooted ? Colors::POSITIVE : Colors::WARNING),
                    "%s",
                    rooted ? Platform::Tr("Rooted (uid=0)") : Platform::Tr("Not rooted")
                );
            }

            if (!work.HasResolved || !work.HasBootImage) {
                ImGui::TextDisabled("%s", Platform::Tr("Fetch Magisk and locate a boot image to enable rooting."));
            }
            if (!work.RootOutcome.empty()) {
                ImGui::TextColored(
                    HexColor(current == Core::DeviceRootStage::Done ? Colors::POSITIVE : Colors::NEGATIVE),
                    "%s",
                    work.RootOutcome.c_str()
                );
            }
        }
    }

    void BuildDeviceRootWindow(Context &context) {
        PollWork(context);

        if (!context.UI.ShowDeviceRootDialog) {
            return;
        }

        const std::string title = Platform::TrWindow("Root Device", "DeviceRootDialog");
        ImGui::SetNextWindowSize(EmV(34.0F, 36.0F), ImGuiCond_FirstUseEver);
        if (ImGui::Begin(title.c_str(), &context.UI.ShowDeviceRootDialog)) {
            if (!context.Host.Sdk.IsFound) {
                ImGui::TextDisabled("%s", Platform::Tr("No Android SDK detected. Set the SDK path in Preferences."));
                ImGui::End();
                return;
            }

            ImGui::TextDisabled(
                "%s",
                Platform::Tr("Root a physical device you own: patch its boot image with Magisk on the device, then "
                             "flash it with fastboot. Drives the official adb / fastboot and Magisk's boot_patch.sh.")
            );
            ImGui::Spacing();

            const std::string &serial = context.Target.Serial;
            ImGui::TextDisabled("%s", Platform::Tr("Target device"));
            if (serial.empty()) {
                ImGui::TextColored(
                    HexColor(Colors::WARNING), "%s", Platform::Tr("Select a device in the Devices window.")
                );
            } else {
                PropertyText(Platform::Tr("Device"), serial.c_str());
            }

            ImGui::Separator();
            MagiskSection(context);
            ImGui::Separator();
            BootImageSection(context);
            ImGui::Separator();
            BootloaderSection(context, serial);
            ImGui::Separator();
            PipelineSection(context, serial);
        }
        ImGui::End();
    }
}
