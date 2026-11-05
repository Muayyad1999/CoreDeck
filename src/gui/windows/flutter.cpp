//
// Created by CoreDeck RE toolbench on 05/11/2026.
//

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <future>
#include <string>

#include "imgui.h"

#include "flutter.h"
#include "../widgets.h"
#include "../theme.h"
#include "gui/context.h"
#include "core/flutter.h"
#include "app/file_dialog.h"
#include "platform/paths.h"
#include "platform/i18n.h"

namespace CoreDeck::Gui {
    namespace {
        void StartBlutter(Context &context) {
            auto &work = context.FlutterWork;
            if (work.Busy.load() || work.ApkPath[0] == '\0') {
                return;
            }
            work.Busy = true;
            work.HasResult = false;
            const std::string apk = work.ApkPath;
            const std::string blutter = work.BlutterPath;
            const bool noAnalysis = work.NoAnalysis;
            const std::string base = std::filesystem::path(apk).stem().string();
            const std::string workDir =
                Platform::JoinPaths({Platform::GetConfigDirectory(), "flutter", base.empty() ? "out" : base});
            work.Future = std::async(std::launch::async, [apk, blutter, workDir, noAnalysis] {
                return Core::RunBlutter(apk, blutter, workDir, noAnalysis);
            });
        }

        void PollWork(Context &context) {
            auto &work = context.FlutterWork;
            if (work.Busy.load() && work.Future.valid() &&
                work.Future.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                work.Result = work.Future.get();
                work.HasResult = true;
                work.Busy = false;
            }
        }
    }

    void BuildFlutterWindow(Context &context) {
        PollWork(context);

        if (!context.UI.ShowFlutterDialog) {
            return;
        }

        auto &work = context.FlutterWork;
        if (!work.BlutterInit) {
            const std::string resolved = Core::ResolveBlutter("");
            std::snprintf(work.BlutterPath, sizeof(work.BlutterPath), "%s", resolved.c_str());
            work.BlutterInit = true;
        }

        const std::string title = Platform::TrWindow("Flutter", "FlutterDialog");
        ImGui::SetNextWindowSize(EmV(32.0F, 26.0F), ImGuiCond_FirstUseEver);
        if (ImGui::Begin(title.c_str(), &context.UI.ShowFlutterDialog)) {
            ImGui::TextDisabled(
                "%s",
                Platform::Tr("Dump a Flutter app's Dart names and disassembly with Blutter (arm64). For apps you "
                             "are authorized to analyse.")
            );
            ImGui::Spacing();

            ImGui::TextDisabled("%s", Platform::Tr("APK"));
            ImGui::SetNextItemWidth(Em(20.0F));
            ImGui::InputTextWithHint("##flutter_apk", Platform::Tr("Path to a Flutter .apk"), work.ApkPath, sizeof(work.ApkPath));
            ImGui::SameLine();
            if (PickerButton(Platform::Tr("Browse..."))) {
                if (const auto picked = App::FileDialog::PickFile(
                        Platform::Tr("Open APK"),
                        Platform::Tr("Android packages"),
                        {"*.apk", "*.APK"}
                    )) {
                    std::snprintf(work.ApkPath, sizeof(work.ApkPath), "%s", picked->c_str());
                }
            }

            ImGui::TextDisabled("%s", Platform::Tr("Blutter (blutter.py)"));
            ImGui::SetNextItemWidth(Em(20.0F));
            ImGui::InputTextWithHint(
                "##flutter_blutter",
                Platform::Tr("Path to blutter.py"),
                work.BlutterPath,
                sizeof(work.BlutterPath)
            );
            ImGui::SameLine();
            if (PickerButton((std::string(Platform::Tr("Browse...")) + "##blutter").c_str())) {
                if (const auto picked = App::FileDialog::PickFile(
                        Platform::Tr("Open blutter.py"),
                        Platform::Tr("Python"),
                        {"*.py"}
                    )) {
                    std::snprintf(work.BlutterPath, sizeof(work.BlutterPath), "%s", picked->c_str());
                }
            }

            ImGui::Checkbox(Platform::Tr("--no-analysis (faster, avoids some crashes)"), &work.NoAnalysis);

            const bool busy = work.Busy.load();
            if (PositiveButton(busy ? Platform::Tr("Running...") : Platform::Tr("Run Blutter"), !busy, ImVec2(0, 0), busy)) {
                StartBlutter(context);
            }
            ImGui::TextColored(
                HexColor(Colors::WARNING),
                "%s",
                Platform::Tr("The first run can take minutes (it may build a matching Dart VM).")
            );

            if (work.HasResult) {
                const Core::BlutterRun &result = work.Result;
                ImGui::Separator();
                ImGui::TextColored(
                    HexColor(result.Ok ? Colors::POSITIVE : Colors::NEGATIVE),
                    "%s",
                    result.Message.c_str()
                );
                if (!result.OutDir.empty()) {
                    PropertyText(Platform::Tr("Output"), result.OutDir.c_str());
                }
                for (const std::string &artifact: result.Outputs) {
                    ImGui::BulletText("%s", artifact.c_str());
                }
            }
        }
        ImGui::End();
    }
}
