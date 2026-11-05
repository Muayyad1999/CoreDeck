//
// Created by CoreDeck RE toolbench on 05/11/2026.
//

#include <string>
#include <vector>

#include "imgui.h"

#include "frida_hook.h"
#include "../widgets.h"
#include "../theme.h"
#include "gui/context.h"
#include "core/frida.h"
#include "app/file_dialog.h"
#include "platform/paths.h"
#include "platform/process.h"
#include "platform/i18n.h"

namespace CoreDeck::Gui {
    namespace {
        const std::vector<Core::FridaScript> &Scripts() {
            static const std::vector<Core::FridaScript> scripts = Core::BundledFridaScripts();
            return scripts;
        }

        std::vector<std::string> SelectedScriptPaths(Context &context, std::string &error) {
            auto &work = context.FridaHookWork;
            std::vector<std::string> paths;
            const std::string dir = Platform::JoinPaths({Platform::GetConfigDirectory(), "frida-scripts"});
            const auto &scripts = Scripts();
            for (std::size_t i = 0; i < scripts.size(); ++i) {
                if (i < work.ScriptSelected.size() && work.ScriptSelected[i]) {
                    if (!Core::SaveFridaScript(dir, scripts[i].Filename, scripts[i].Content, error)) {
                        return {};
                    }
                    paths.push_back(Platform::JoinPaths({dir, scripts[i].Filename}));
                }
            }
            for (const std::string &user: work.UserScripts) {
                paths.push_back(user);
            }
            return paths;
        }

        void StartHook(Context &context, const std::string &serial) {
            auto &work = context.FridaHookWork;
            work.Error.clear();
            std::string error;
            const auto paths = SelectedScriptPaths(context, error);
            if (!error.empty()) {
                work.Error = error;
                return;
            }
            if (!Core::StartFridaHook(serial, work.Package, paths, work.Attach, work.Session, error)) {
                work.Error = error;
            }
        }
    }

    void BuildFridaHookWindow(Context &context) {
        auto &work = context.FridaHookWork;

        // Reap a session whose frida process has exited on its own.
        if (work.Session.Running.load() && !Platform::IsProcessRunning(work.Session.Pid)) {
            Core::StopFridaHook(work.Session);
        }

        if (!context.UI.ShowFridaHookDialog) {
            return;
        }

        const auto &scripts = Scripts();
        if (!work.ScriptsInit) {
            work.ScriptSelected.assign(scripts.size(), false);
            if (!work.ScriptSelected.empty()) {
                work.ScriptSelected[0] = true;
            }
            work.ScriptsInit = true;
        }

        const std::string title = Platform::TrWindow("Frida Hook", "FridaHookDialog");
        ImGui::SetNextWindowSize(EmV(34.0F, 34.0F), ImGuiCond_FirstUseEver);
        if (ImGui::Begin(title.c_str(), &context.UI.ShowFridaHookDialog)) {
            if (!context.Host.Sdk.IsFound) {
                ImGui::TextDisabled("%s", Platform::Tr("No Android SDK detected. Set the SDK path in Preferences."));
                ImGui::End();
                return;
            }

            const std::string &serial = context.Target.Serial;
            ImGui::TextDisabled(
                "%s",
                Platform::Tr("Attach frida scripts to an app on a device running frida-server.")
            );
            ImGui::Spacing();

            if (serial.empty()) {
                ImGui::TextDisabled("%s", Platform::Tr("Select a device in the Devices window."));
                ImGui::End();
                return;
            }
            PropertyText(Platform::Tr("Device"), serial.c_str());

            ImGui::TextDisabled("%s", Platform::Tr("Target package"));
            ImGui::SetNextItemWidth(Em(16.0F));
            ImGui::InputTextWithHint("##frida_pkg", "com.example.app", work.Package, sizeof(work.Package));
            ImGui::SameLine();
            ImGui::Checkbox(Platform::Tr("Attach (don't spawn)"), &work.Attach);

            ImGui::Separator();
            const auto scriptCheckbox = [&](std::size_t i) {
                bool selected = i < work.ScriptSelected.size() && work.ScriptSelected[i];
                if (ImGui::Checkbox(scripts[i].Name.c_str(), &selected)) {
                    work.ScriptSelected[i] = selected;
                }
            };

            ImGui::TextDisabled("%s", Platform::Tr("Scripts"));
            for (std::size_t i = 0; i < scripts.size(); ++i) {
                if (scripts[i].Category == "dev") {
                    scriptCheckbox(i);
                }
            }

            bool hasSensitive = false;
            for (const auto &script: scripts) {
                if (script.Category == "sensitive") {
                    hasSensitive = true;
                    break;
                }
            }
            if (hasSensitive) {
                ImGui::Spacing();
                ImGui::TextColored(
                    HexColor(Colors::WARNING),
                    "%s",
                    Platform::Tr("Bypass scripts (authorized testing only)")
                );
                for (std::size_t i = 0; i < scripts.size(); ++i) {
                    if (scripts[i].Category == "sensitive") {
                        scriptCheckbox(i);
                    }
                }
            }

            ImGui::SetNextItemWidth(Em(16.0F));
            ImGui::InputTextWithHint(
                "##frida_user_script",
                Platform::Tr("Path to your own .js"),
                work.UserScriptPath,
                sizeof(work.UserScriptPath)
            );
            ImGui::SameLine();
            if (PickerButton(Platform::Tr("Add"))) {
                if (work.UserScriptPath[0] != '\0') {
                    work.UserScripts.emplace_back(work.UserScriptPath);
                    work.UserScriptPath[0] = '\0';
                } else if (const auto picked = App::FileDialog::PickFile(
                               Platform::Tr("Open frida script"),
                               Platform::Tr("Scripts"),
                               {"*.js"}
                           )) {
                    work.UserScripts.push_back(*picked);
                }
            }
            for (std::size_t i = 0; i < work.UserScripts.size(); ++i) {
                ImGui::BulletText("%s", work.UserScripts[i].c_str());
            }

            if (PickerButton(Platform::Tr("Save scripts to folder..."))) {
                if (const auto dir = App::FileDialog::PickDirectory(Platform::Tr("Choose a folder"))) {
                    std::string error;
                    for (std::size_t i = 0; i < scripts.size(); ++i) {
                        if (i < work.ScriptSelected.size() && work.ScriptSelected[i]) {
                            Core::SaveFridaScript(*dir, scripts[i].Filename, scripts[i].Content, error);
                        }
                    }
                    work.Error = error.empty() ? std::string(Platform::Tr("Saved.")) : error;
                }
            }

            ImGui::Separator();
            const bool running = work.Session.Running.load();
            if (PositiveButton(Platform::Tr("Run"), !running, ImVec2(0, 0), running)) {
                StartHook(context, serial);
            }
            ImGui::SameLine();
            if (NegativeButton(Platform::Tr("Stop"), running, ImVec2(0, 0), false)) {
                Core::StopFridaHook(work.Session);
            }
            ImGui::SameLine();
            ImGui::TextDisabled(
                "%s",
                running ? Platform::Tr("running") : Platform::Tr("Requires frida-server + host frida tools.")
            );

            if (!work.Error.empty()) {
                ImGui::TextColored(HexColor(Colors::NEGATIVE), "%s", work.Error.c_str());
            }

            if (work.Session.Log) {
                ImGui::BeginChild("##frida_hook_log", ImVec2(0, 0), 1);
                for (const std::string &line: work.Session.Log->GetLines()) {
                    ImGui::TextUnformatted(line.c_str());
                }
                if (running) {
                    ImGui::SetScrollHereY(1.0F);
                }
                ImGui::EndChild();
            }
        }
        ImGui::End();
    }
}
