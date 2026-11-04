//
// Created by CoreDeck RE toolbench on 03/11/2026.
//

#include <algorithm>
#include <cctype>
#include <chrono>
#include <future>
#include <string>
#include <vector>

#include "imgui.h"

#include "device_panel.h"
#include "../widgets.h"
#include "../theme.h"
#include "gui/context.h"
#include "core/adb.h"
#include "platform/i18n.h"

namespace CoreDeck::Gui {
    namespace {
        std::string ToLowerCopy(const std::string &value) {
            std::string lower = value;
            std::transform(lower.begin(), lower.end(), lower.begin(), [](const unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            return lower;
        }

        void StartDeviceScan(Context &context) {
            auto &work = context.DevicePanelWork;
            if (work.DevicesBusy.load()) {
                return;
            }
            work.DevicesBusy = true;
            const Core::SdkInfo sdk = context.Host.Sdk;
            work.DevicesFuture = std::async(std::launch::async, [sdk] { return Core::DescribeDevices(sdk); });
        }

        void StartPackageScan(Context &context, const std::string &serial) {
            auto &work = context.DevicePanelWork;
            if (serial.empty() || work.PackagesBusy.load()) {
                return;
            }
            work.PackagesBusy = true;
            work.PackagesSerial = serial;
            const Core::SdkInfo sdk = context.Host.Sdk;
            const bool includeVendor = work.IncludeVendor;
            work.PackagesFuture = std::async(std::launch::async, [sdk, serial, includeVendor] {
                return Core::ListUserPackages(sdk, serial, includeVendor);
            });
        }

        void PollWork(Context &context) {
            auto &work = context.DevicePanelWork;

            if (work.DevicesBusy.load() && work.DevicesFuture.valid() &&
                work.DevicesFuture.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                work.Devices = work.DevicesFuture.get();
                work.DevicesLoaded = true;
                work.DevicesBusy = false;

                const bool stillPresent = std::any_of(
                    work.Devices.begin(),
                    work.Devices.end(),
                    [&context](const Core::DeviceSummary &device) {
                        return device.Online() && device.Serial == context.Target.Serial;
                    }
                );
                if (!context.Target.Serial.empty() && !stillPresent) {
                    context.Target.Serial.clear();
                    work.Packages.clear();
                    work.PackagesLoaded = false;
                    work.PackagesSerial.clear();
                }
            }

            if (work.PackagesBusy.load() && work.PackagesFuture.valid() &&
                work.PackagesFuture.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                work.Packages = work.PackagesFuture.get();
                work.PackagesLoaded = true;
                work.PackagesBusy = false;
            }
        }

        void SelectDevice(Context &context, const std::string &serial) {
            if (context.Target.Serial == serial) {
                return;
            }
            context.Target.Serial = serial;
            auto &work = context.DevicePanelWork;
            work.Packages.clear();
            work.PackagesLoaded = false;
            StartPackageScan(context, serial);
        }

        std::string DeviceSubtitle(const Core::DeviceSummary &device) {
            if (!device.Online()) {
                return device.State.empty() ? std::string(Platform::Tr("offline")) : device.State;
            }
            std::string subtitle = device.Model.empty() ? std::string("?") : device.Model;
            if (!device.Release.empty()) {
                subtitle += "  ";
                subtitle += Platform::TrFormat("Android {0}", device.Release);
            }
            if (!device.Abi.empty()) {
                subtitle += "  ";
                subtitle += device.Abi;
            }
            return subtitle;
        }

        void DeviceList(Context &context) {
            auto &work = context.DevicePanelWork;

            ImGui::TextDisabled("%s", Platform::Tr("Connected devices"));
            ImGui::SameLine();
            const bool devicesBusy = work.DevicesBusy.load();
            const float refreshWidth = Em(7.0F);
            ImGui::SameLine(ImGui::GetContentRegionAvail().x - refreshWidth + Em(0.5F));
            if (PositiveButton(
                    devicesBusy ? Platform::Tr("Refreshing...") : Platform::Tr("Refresh"),
                    !devicesBusy,
                    ImVec2(refreshWidth, 0),
                    devicesBusy
                )) {
                StartDeviceScan(context);
            }

            ImGui::BeginChild("##device_list", ImVec2(0, Eh(5.5F)), 1);
            if (work.Devices.empty()) {
                ImGui::TextDisabled(
                    "%s",
                    work.DevicesLoaded ? Platform::Tr("No devices attached. Start an emulator or plug in a device.")
                                       : Platform::Tr("Scanning for devices...")
                );
            } else {
                for (const Core::DeviceSummary &device: work.Devices) {
                    const bool selected = device.Serial == context.Target.Serial;
                    const std::string subtitle = DeviceSubtitle(device);
                    const ImVec4 stateColor = HexColor(device.Online() ? Colors::TEXT_MUTED : Colors::WARNING);
                    if (SelectableItem(
                            device.Serial.c_str(),
                            selected,
                            subtitle.c_str(),
                            stateColor,
                            Icons::MOBILE,
                            HexColor(Colors::TEXT_MUTED)
                        )) {
                        if (device.Online()) {
                            SelectDevice(context, device.Serial);
                        }
                    }
                }
            }
            ImGui::EndChild();
        }

        void PackageList(Context &context) {
            auto &work = context.DevicePanelWork;

            ImGui::Spacing();
            if (context.Target.Serial.empty()) {
                ImGui::TextDisabled("%s", Platform::Tr("Select a device to list its installed apps."));
                return;
            }

            const bool packagesBusy = work.PackagesBusy.load();

            ImGui::TextDisabled("%s", Platform::Tr("Installed apps"));
            ImGui::SameLine();
            const float refreshWidth = Em(7.0F);
            ImGui::SameLine(ImGui::GetContentRegionAvail().x - refreshWidth + Em(0.5F));
            if (PositiveButton(
                    packagesBusy ? Platform::Tr("Loading...") : Platform::Tr("Refresh"),
                    !packagesBusy,
                    ImVec2(refreshWidth, 0),
                    packagesBusy
                )) {
                StartPackageScan(context, context.Target.Serial);
            }

            SearchField("##package_filter", Platform::Tr("Filter apps"), work.PackageFilter, sizeof(work.PackageFilter));

            if (ImGui::Checkbox(Platform::Tr("Show system / Google / Samsung packages"), &work.IncludeVendor)) {
                StartPackageScan(context, context.Target.Serial);
            }

            const std::string needle = ToLowerCopy(work.PackageFilter);
            std::vector<const std::string *> shown;
            shown.reserve(work.Packages.size());
            for (const std::string &package: work.Packages) {
                if (needle.empty() || ToLowerCopy(package).find(needle) != std::string::npos) {
                    shown.push_back(&package);
                }
            }

            if (packagesBusy && work.Packages.empty()) {
                ImGui::TextDisabled("%s", Platform::Tr("Loading packages..."));
            } else {
                ImGui::TextDisabled("%s", Platform::TrFormatN("{0} app", "{0} apps", static_cast<int>(shown.size()), static_cast<int>(shown.size())).c_str());
            }

            ImGui::BeginChild("##package_list", ImVec2(0, 0), 1);
            if (shown.empty() && work.PackagesLoaded && !packagesBusy) {
                ImGui::TextDisabled("%s", Platform::Tr("No matching apps."));
            }
            for (const std::string *package: shown) {
                if (SelectableItem(package->c_str(), false)) {
                    ImGui::SetClipboardText(package->c_str());
                }
                HoverTooltip(Platform::Tr("Click to copy the package name"));
            }
            ImGui::EndChild();
        }
    }

    void BuildDevicePanelWindow(Context &context) {
        PollWork(context);

        if (!context.UI.ShowDevicePanel) {
            return;
        }

        auto &work = context.DevicePanelWork;
        if (!work.DevicesLoaded && !work.DevicesBusy.load() && context.Host.Sdk.IsFound) {
            StartDeviceScan(context);
        }

        const std::string title = Platform::TrWindow("Devices", "DevicePanel");
        ImGui::SetNextWindowSize(EmV(26.0F, 24.0F), ImGuiCond_FirstUseEver);
        if (ImGui::Begin(title.c_str(), &context.UI.ShowDevicePanel)) {
            if (!context.Host.Sdk.IsFound) {
                ImGui::TextDisabled("%s", Platform::Tr("No Android SDK detected. Set the SDK path in Preferences."));
            } else {
                DeviceList(context);
                ImGui::Separator();
                PackageList(context);
            }
        }
        ImGui::End();
    }
}
