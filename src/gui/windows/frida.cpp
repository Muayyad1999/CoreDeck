//
// Created by CoreDeck RE toolbench on 05/11/2026.
//

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <future>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include "imgui.h"

#include "frida.h"
#include "../widgets.h"
#include "../theme.h"
#include "gui/context.h"
#include "core/frida.h"
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

        std::string RandomName() {
            static std::mt19937 rng(std::random_device{}());
            std::uniform_int_distribution<int> dist(0, 25);
            std::string name;
            for (int i = 0; i < 8; ++i) {
                name.push_back(static_cast<char>('a' + dist(rng)));
            }
            return name;
        }

        int RandomPort() {
            static std::mt19937 rng(std::random_device{}());
            std::uniform_int_distribution<int> dist(20000, 60000);
            return dist(rng);
        }

        void StartFrida(Context &context, const std::string &serial) {
            auto &work = context.FridaWork;
            if (work.Busy.load()) {
                return;
            }
            std::string version = work.Version[0] != '\0' ? std::string(work.Version) : work.HostVersion;
            if (version.empty()) {
                work.Outcome = Platform::Tr("Enter a frida version (or install frida on the host).");
                work.OutcomeOk = false;
                return;
            }
            if (work.Stealth) {
                std::snprintf(work.DevName, sizeof(work.DevName), "%s", RandomName().c_str());
                if (work.Port == 0) {
                    work.Port = RandomPort();
                }
            }
            work.Busy = true;
            work.Outcome.clear();
            const Core::SdkInfo sdk = context.Host.Sdk;
            const std::string devName = work.DevName;
            const int port = work.Port;
            work.Future = std::async(std::launch::async, [sdk, serial, version, devName, port] {
                std::string abi = Core::GetDeviceProp(sdk, serial, "ro.product.cpu.abi");
                if (abi.empty()) {
                    abi = "arm64-v8a";
                }
                const Core::FridaServerDeps deps = Core::DefaultFridaServerDeps();
                std::string error;
                const auto path = Core::ResolveFridaServer(deps, version, abi, true, error);
                if (!path) {
                    return std::make_pair(false, error);
                }
                std::string startError;
                const bool ok = Core::StartFridaServer(sdk, serial, *path, devName, port, startError);
                std::string message = ok ? ("frida-server " + version + " started" +
                                            (port > 0 ? " on port " + std::to_string(port) : ""))
                                         : startError;
                return std::make_pair(ok, message);
            });
        }

        void StopFrida(Context &context, const std::string &serial) {
            auto &work = context.FridaWork;
            if (work.Busy.load()) {
                return;
            }
            work.Busy = true;
            work.Outcome.clear();
            const Core::SdkInfo sdk = context.Host.Sdk;
            const std::string devName = work.DevName;
            work.Future = std::async(std::launch::async, [sdk, serial, devName] {
                const bool ok = Core::StopFridaServer(sdk, serial, devName);
                return std::make_pair(ok, std::string(ok ? "frida-server stop signal sent." : "Could not stop."));
            });
        }

        void StartPs(Context &context, const std::string &serial) {
            auto &work = context.FridaWork;
            if (work.PsBusy.load()) {
                return;
            }
            work.PsBusy = true;
            work.PsError.clear();
            work.PsFuture = std::async(std::launch::async, [serial] {
                std::string error;
                auto processes = Core::FridaPs(serial, error);
                return std::make_pair(std::move(processes), std::move(error));
            });
        }

        void PollWork(Context &context) {
            auto &work = context.FridaWork;
            if (work.Busy.load() && work.Future.valid() &&
                work.Future.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                auto [ok, message] = work.Future.get();
                work.Busy = false;
                work.OutcomeOk = ok;
                work.Outcome = message;
            }
            if (work.PsBusy.load() && work.PsFuture.valid() &&
                work.PsFuture.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                auto [processes, error] = work.PsFuture.get();
                work.PsBusy = false;
                work.Processes = std::move(processes);
                work.HasProcesses = error.empty();
                work.PsError = error;
            }
        }
    }

    void BuildFridaWindow(Context &context) {
        PollWork(context);

        if (!context.UI.ShowFridaDialog) {
            return;
        }

        auto &work = context.FridaWork;
        if (!work.HostChecked) {
            work.HostVersion = Core::DetectHostFridaVersion();
            work.HostChecked = true;
        }

        const std::string title = Platform::TrWindow("Frida", "FridaDialog");
        ImGui::SetNextWindowSize(EmV(32.0F, 30.0F), ImGuiCond_FirstUseEver);
        if (ImGui::Begin(title.c_str(), &context.UI.ShowFridaDialog)) {
            if (!context.Host.Sdk.IsFound) {
                ImGui::TextDisabled("%s", Platform::Tr("No Android SDK detected. Set the SDK path in Preferences."));
                ImGui::End();
                return;
            }

            ImGui::TextDisabled(
                "%s",
                Platform::Tr("Download, push and run frida-server on a rooted emulator, and list its processes.")
            );
            ImGui::Spacing();

            PropertyText(
                Platform::Tr("Host frida"),
                work.HostVersion.empty() ? Platform::Tr("not found (pip install frida-tools)")
                                         : work.HostVersion.c_str()
            );

            const std::string &serial = context.Target.Serial;
            if (serial.empty()) {
                ImGui::TextDisabled("%s", Platform::Tr("Select a device in the Devices window."));
                ImGui::End();
                return;
            }
            PropertyText(Platform::Tr("Device"), serial.c_str());

            ImGui::TextDisabled("%s", Platform::Tr("frida-server version"));
            ImGui::SetNextItemWidth(Em(12.0F));
            ImGui::InputTextWithHint(
                "##frida_version",
                Platform::Tr("Leave empty to match the host frida"),
                work.Version,
                sizeof(work.Version)
            );
            ImGui::SetNextItemWidth(Em(8.0F));
            ImGui::InputInt(Platform::Tr("Port (0 = device mode)"), &work.Port);
            if (work.Port < 0) {
                work.Port = 0;
            }
            ImGui::Checkbox(Platform::Tr("Stealth (random name + port)"), &work.Stealth);

            const bool busy = work.Busy.load();
            if (PositiveButton(
                    busy ? Platform::Tr("Working...") : Platform::Tr("Start frida-server"),
                    !busy,
                    ImVec2(0, 0),
                    busy
                )) {
                StartFrida(context, serial);
            }
            ImGui::SameLine();
            if (NegativeButton(Platform::Tr("Stop"), !busy, ImVec2(0, 0), false)) {
                StopFrida(context, serial);
            }

            if (!work.Outcome.empty()) {
                ImGui::TextColored(
                    HexColor(work.OutcomeOk ? Colors::POSITIVE : Colors::NEGATIVE),
                    "%s",
                    work.Outcome.c_str()
                );
            }
            ImGui::TextColored(
                HexColor(Colors::WARNING),
                "%s",
                Platform::Tr("Requires a rooted AVD (su) and the host frida tools.")
            );

            ImGui::Separator();
            const bool psBusy = work.PsBusy.load();
            if (PositiveButton(
                    psBusy ? Platform::Tr("Listing...") : Platform::Tr("List processes"),
                    !psBusy,
                    ImVec2(0, 0),
                    psBusy
                )) {
                StartPs(context, serial);
            }
            if (!work.PsError.empty()) {
                ImGui::TextColored(HexColor(Colors::NEGATIVE), "%s", work.PsError.c_str());
            }
            if (work.HasProcesses) {
                SearchField("##frida_ps_filter", Platform::Tr("Filter processes"), work.PsFilter, sizeof(work.PsFilter));
                const std::string needle = ToLowerCopy(work.PsFilter);
                ImGui::BeginChild("##frida_ps_list", ImVec2(0, 0), 1);
                for (const Core::FridaProcess &process: work.Processes) {
                    if (!needle.empty() && ToLowerCopy(process.Name).find(needle) == std::string::npos) {
                        continue;
                    }
                    ImGui::Text("%6d  %s", process.Pid, process.Name.c_str());
                }
                ImGui::EndChild();
            }
        }
        ImGui::End();
    }
}
