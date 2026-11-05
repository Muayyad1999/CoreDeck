//
// Created by CoreDeck RE toolbench on 05/11/2026.
//

#include <chrono>
#include <cstdio>
#include <future>
#include <memory>
#include <mutex>
#include <string>

#include "imgui.h"

#include "repackage.h"
#include "../widgets.h"
#include "../theme.h"
#include "gui/context.h"
#include "core/repackage.h"
#include "app/file_dialog.h"
#include "platform/i18n.h"

namespace CoreDeck::Gui {
    namespace {
        Core::PinningMethod MethodFromIndex(const int index) {
            switch (index) {
                case 1:
                    return Core::PinningMethod::FlutterStatic;
                case 2:
                    return Core::PinningMethod::ApkMitm;
                case 3:
                    return Core::PinningMethod::None;
                default:
                    return Core::PinningMethod::Auto;
            }
        }

        void StartRun(Context &context) {
            auto &work = context.RepackageWork;
            if (work.Busy.load()) {
                return;
            }

            Core::RepackageOptions opts;
            opts.Method = MethodFromIndex(work.Method);
            opts.Sign = work.Sign;
            opts.Install = work.Install;
            opts.Grant = work.Grant;
            opts.ApkEditorJar = work.ApkEditorJar;
            opts.Serial = context.Target.Serial;
            opts.Package = work.Package;

            if (work.SourceMode == 0) {
                opts.Source = Core::RepackageSource::Device;
                if (context.Target.Serial.empty()) {
                    work.ValidationError = Platform::Tr("Select a device in the Devices window.");
                    return;
                }
                if (work.Package[0] == '\0') {
                    work.ValidationError = Platform::Tr("Enter a package to pull.");
                    return;
                }
            } else {
                opts.Source = work.SourceMode == 1 ? Core::RepackageSource::Directory : Core::RepackageSource::SingleApk;
                if (work.InputPath[0] == '\0') {
                    work.ValidationError = Platform::Tr("Choose an input folder or APK.");
                    return;
                }
                opts.InputPath = work.InputPath;
            }

            if (work.Install && context.Target.Serial.empty()) {
                work.ValidationError = Platform::Tr("Install needs a device selected in the Devices window.");
                return;
            }

            work.ValidationError.clear();
            work.Busy = true;
            work.HasResult = false;
            work.Progress = std::make_shared<Core::RepackageProgress>();

            const Core::SdkInfo sdk = context.Host.Sdk;
            const Core::JdkInfo jdk = context.Host.Jdk;
            const std::shared_ptr<Core::RepackageProgress> progress = work.Progress;
            work.Future = std::async(std::launch::async, [sdk, jdk, opts, progress] {
                return Core::RunRepackage(sdk, jdk, opts, progress);
            });
        }

        void PollWork(Context &context) {
            auto &work = context.RepackageWork;
            if (work.Busy.load() && work.Future.valid() &&
                work.Future.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                work.Result = work.Future.get();
                work.HasResult = true;
                work.Busy = false;
            }
        }
    }

    void BuildRepackageWindow(Context &context) {
        PollWork(context);

        if (!context.UI.ShowRepackageDialog) {
            return;
        }

        auto &work = context.RepackageWork;
        const std::string title = Platform::TrWindow("Repackage", "RepackageDialog");
        ImGui::SetNextWindowSize(EmV(40.0F, 40.0F), ImGuiCond_FirstUseEver);
        if (ImGui::Begin(title.c_str(), &context.UI.ShowRepackageDialog)) {
            if (!context.Host.Sdk.IsFound) {
                ImGui::TextDisabled("%s", Platform::Tr("No Android SDK detected. Set the SDK path in Preferences."));
                ImGui::End();
                return;
            }

            ImGui::TextDisabled(
                "%s",
                Platform::Tr("Pull an app, merge its splits, strip certificate pinning statically, sign, and "
                             "optionally install. For an app you own or are authorized to test.")
            );
            ImGui::Spacing();

            // ---- source ---------------------------------------------------- //
            ImGui::TextDisabled("%s", Platform::Tr("Source"));
            ImGui::RadioButton(Platform::Tr("Device (by package)"), &work.SourceMode, 0);
            ImGui::SameLine();
            ImGui::RadioButton(Platform::Tr("Folder of splits"), &work.SourceMode, 1);
            ImGui::SameLine();
            ImGui::RadioButton(Platform::Tr("Single APK"), &work.SourceMode, 2);

            if (work.SourceMode == 0) {
                if (context.Target.Serial.empty()) {
                    ImGui::TextColored(HexColor(Colors::WARNING), "%s", Platform::Tr("No device selected (Devices window)."));
                } else {
                    PropertyText(Platform::Tr("Device"), context.Target.Serial.c_str());
                }
                ImGui::SetNextItemWidth(Em(22.0F));
                ImGui::InputTextWithHint(
                    "##repack_pkg",
                    Platform::Tr("e.g. com.example.app"),
                    work.Package,
                    sizeof(work.Package)
                );
            } else {
                ImGui::SetNextItemWidth(Em(22.0F));
                ImGui::InputTextWithHint(
                    "##repack_input",
                    work.SourceMode == 1 ? Platform::Tr("Folder with base.apk + split_*.apk")
                                         : Platform::Tr("Path to an .apk"),
                    work.InputPath,
                    sizeof(work.InputPath)
                );
                ImGui::SameLine();
                if (PickerButton(Platform::Tr("Browse..."))) {
                    if (work.SourceMode == 1) {
                        if (const auto picked = App::FileDialog::PickDirectory(Platform::Tr("Choose splits folder"))) {
                            std::snprintf(work.InputPath, sizeof(work.InputPath), "%s", picked->c_str());
                        }
                    } else if (const auto picked = App::FileDialog::PickFile(
                                   Platform::Tr("Open APK"),
                                   Platform::Tr("Android packages"),
                                   {"*.apk", "*.APK"}
                               )) {
                        std::snprintf(work.InputPath, sizeof(work.InputPath), "%s", picked->c_str());
                    }
                }
            }

            ImGui::Spacing();

            // ---- method ---------------------------------------------------- //
            ImGui::TextDisabled("%s", Platform::Tr("Pinning bypass"));
            const char *methods[] = {
                Platform::Tr("Auto (Flutter -> libflutter patch, native -> apk-mitm)"),
                Platform::Tr("Flutter: static libflutter TLS patch"),
                Platform::Tr("Native: apk-mitm (strip pinning + trust user CAs)"),
                Platform::Tr("None (merge + sign only)"),
            };
            ImGui::SetNextItemWidth(Em(30.0F));
            ImGui::Combo("##repack_method", &work.Method, methods, IM_ARRAYSIZE(methods));

            ImGui::Checkbox(Platform::Tr("Sign the result (managed debug keystore)"), &work.Sign);
            ImGui::Checkbox(Platform::Tr("Install onto the selected device when done"), &work.Install);
            if (work.Install) {
                ImGui::SameLine();
                ImGui::Checkbox(Platform::Tr("Grant permissions (-g)"), &work.Grant);
            }

            // ---- APKEditor path -------------------------------------------- //
            ImGui::TextDisabled("%s", Platform::Tr("APKEditor.jar (merges splits)"));
            ImGui::SetNextItemWidth(Em(22.0F));
            ImGui::InputTextWithHint(
                "##repack_apkeditor",
                Platform::Tr("Path to APKEditor.jar (or set $APKEDITOR_JAR)"),
                work.ApkEditorJar,
                sizeof(work.ApkEditorJar)
            );
            ImGui::SameLine();
            if (PickerButton(Platform::Tr("Browse..."))) {
                if (const auto picked = App::FileDialog::PickFile(
                        Platform::Tr("Open APKEditor.jar"),
                        Platform::Tr("JAR files"),
                        {"*.jar", "*.JAR"}
                    )) {
                    std::snprintf(work.ApkEditorJar, sizeof(work.ApkEditorJar), "%s", picked->c_str());
                }
            }

            ImGui::Spacing();
            ImGui::TextColored(
                HexColor(Colors::WARNING),
                "%s",
                Platform::Tr("Needs APKEditor.jar + a JDK; apk-mitm (Node) for native apps. See RE Tools.")
            );

            const bool busy = work.Busy.load();
            if (PositiveButton(busy ? Platform::Tr("Working...") : Platform::Tr("Run"), !busy, ImVec2(0, 0), busy)) {
                StartRun(context);
            }

            if (!work.ValidationError.empty()) {
                ImGui::TextColored(HexColor(Colors::NEGATIVE), "%s", work.ValidationError.c_str());
            }

            // ---- live log -------------------------------------------------- //
            if (work.Progress) {
                ImGui::Separator();
                ImGui::BeginChild("##repack_log", ImVec2(0, Eh(8.0F)), 1);
                {
                    std::lock_guard<std::mutex> lock(work.Progress->Mutex);
                    for (const std::string &line: work.Progress->Lines) {
                        ImGui::TextUnformatted(line.c_str());
                    }
                }
                if (busy) {
                    ImGui::SetScrollHereY(1.0F);
                }
                ImGui::EndChild();
            }

            // ---- result ---------------------------------------------------- //
            if (work.HasResult) {
                const Core::RepackageResult &r = work.Result;
                ImGui::TextColored(
                    HexColor(r.AllOk() ? Colors::POSITIVE : Colors::NEGATIVE),
                    "%s",
                    r.AllOk() ? Platform::Tr("Done.") : Platform::Tr("Stopped at a failing step.")
                );
                ImGui::TextDisabled(
                    "%s",
                    Platform::TrFormat(
                        "app: {0}   method: {1}",
                        r.IsFlutter ? "Flutter" : "native",
                        r.MethodUsed
                    )
                        .c_str()
                );
                for (const auto &step: r.Steps) {
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
                if (r.AllOk() && !r.FinalApk.empty()) {
                    PropertyText(Platform::Tr("Final APK"), r.FinalApk.c_str());
                }
            }
        }
        ImGui::End();
    }
}
