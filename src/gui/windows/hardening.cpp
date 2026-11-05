//
// Created by CoreDeck RE toolbench on 05/11/2026.
//

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <future>
#include <string>
#include <unordered_map>

#include "imgui.h"

#include "hardening.h"
#include "../widgets.h"
#include "../theme.h"
#include "gui/context.h"
#include "core/checks.h"
#include "app/file_dialog.h"
#include "platform/paths.h"
#include "platform/i18n.h"

namespace CoreDeck::Gui {
    namespace {
        std::string DecodedDir(const std::string &apk) {
            const std::string base = std::filesystem::path(apk).stem().string();
            return Platform::JoinPaths({Platform::GetConfigDirectory(), "checks", base.empty() ? "decoded" : base});
        }

        void StartScan(Context &context) {
            auto &work = context.HardeningWork;
            if (work.ScanBusy.load() || work.ApkPath[0] == '\0') {
                return;
            }
            work.ScanBusy = true;
            work.HasScan = false;
            const std::string apktool = Core::ResolveApktool(work.ApktoolPath);
            const std::string apk = work.ApkPath;
            const std::string decoded = DecodedDir(apk);
            work.ScanFuture = std::async(std::launch::async, [apktool, apk, decoded] {
                return Core::DecodeAndScan(apktool, apk, decoded);
            });
        }

        void StartNeutralize(Context &context) {
            auto &work = context.HardeningWork;
            if (work.NeutBusy.load() || !work.HasScan || !work.Scan.Ok) {
                return;
            }
            work.NeutBusy = true;
            work.HasNeut = false;
            const std::string apktool = Core::ResolveApktool(work.ApktoolPath);
            const std::string decoded = work.Scan.DecodedDir;
            const std::filesystem::path apkPath(work.ApkPath);
            const std::string outApk =
                (apkPath.parent_path() / (apkPath.stem().string() + "-neutralized.apk")).string();
            work.NeutFuture = std::async(std::launch::async, [apktool, decoded, outApk] {
                return Core::NeutralizeAndBuild(apktool, decoded, outApk);
            });
        }

        void PollWork(Context &context) {
            auto &work = context.HardeningWork;
            if (work.ScanBusy.load() && work.ScanFuture.valid() &&
                work.ScanFuture.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                work.Scan = work.ScanFuture.get();
                work.HasScan = true;
                work.ScanBusy = false;
            }
            if (work.NeutBusy.load() && work.NeutFuture.valid() &&
                work.NeutFuture.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                work.Neut = work.NeutFuture.get();
                work.HasNeut = true;
                work.NeutBusy = false;
            }
        }
    }

    void BuildHardeningWindow(Context &context) {
        PollWork(context);

        if (!context.UI.ShowHardeningDialog) {
            return;
        }

        auto &work = context.HardeningWork;
        if (!work.ApktoolInit) {
            std::snprintf(work.ApktoolPath, sizeof(work.ApktoolPath), "%s", Core::ResolveApktool("").c_str());
            work.ApktoolInit = true;
        }

        const std::string title = Platform::TrWindow("Hardening", "HardeningDialog");
        ImGui::SetNextWindowSize(EmV(34.0F, 32.0F), ImGuiCond_FirstUseEver);
        if (ImGui::Begin(title.c_str(), &context.UI.ShowHardeningDialog)) {
            ImGui::TextDisabled(
                "%s",
                Platform::Tr("Scan an app's smali for root/emulator/tamper/integrity/frida/debugger checks. For "
                             "apps you are authorized to test.")
            );
            ImGui::Spacing();

            ImGui::TextDisabled("%s", Platform::Tr("APK"));
            ImGui::SetNextItemWidth(Em(20.0F));
            ImGui::InputTextWithHint("##hard_apk", Platform::Tr("Path to an .apk"), work.ApkPath, sizeof(work.ApkPath));
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
            ImGui::SetNextItemWidth(Em(20.0F));
            ImGui::InputTextWithHint(
                "##hard_apktool",
                Platform::Tr("apktool (on PATH, or a path)"),
                work.ApktoolPath,
                sizeof(work.ApktoolPath)
            );

            const bool scanBusy = work.ScanBusy.load();
            if (PositiveButton(scanBusy ? Platform::Tr("Scanning...") : Platform::Tr("Scan"), !scanBusy, ImVec2(0, 0), scanBusy)) {
                StartScan(context);
            }

            if (work.HasScan) {
                const Core::ScanResult &scan = work.Scan;
                ImGui::TextColored(HexColor(scan.Ok ? Colors::TEXT_MUTED : Colors::NEGATIVE), "%s", scan.Message.c_str());
                if (scan.Ok) {
                    std::unordered_map<std::string, int> counts;
                    for (const auto &f: scan.Findings) {
                        counts[f.Label]++;
                    }
                    for (const auto &[label, count]: counts) {
                        ImGui::BulletText("%s: %d", label.c_str(), count);
                    }

                    ImGui::BeginChild("##hard_findings", ImVec2(0, Eh(8.0F)), 1);
                    for (const auto &f: scan.Findings) {
                        ImGui::TextDisabled("[%s] %s", f.Label.c_str(), f.Text.c_str());
                    }
                    ImGui::EndChild();

                    ImGui::Separator();
                    ImGui::TextColored(
                        HexColor(Colors::WARNING),
                        "%s",
                        Platform::Tr("Neutralize (authorized testing only): comments out self-kill invokes "
                                     "(System.exit / killProcess / halt / finishAffinity) and rebuilds.")
                    );
                    const bool neutBusy = work.NeutBusy.load();
                    if (NegativeButton(
                            neutBusy ? Platform::Tr("Rebuilding...") : Platform::Tr("Neutralize self-kill + rebuild"),
                            !neutBusy,
                            ImVec2(0, 0),
                            neutBusy
                        )) {
                        StartNeutralize(context);
                    }
                    if (work.HasNeut) {
                        const Core::NeutralizeResult &neut = work.Neut;
                        ImGui::TextColored(
                            HexColor(neut.Ok ? Colors::POSITIVE : Colors::NEGATIVE),
                            "%s",
                            neut.Message.c_str()
                        );
                        if (neut.Ok && !neut.OutApk.empty()) {
                            PropertyText(Platform::Tr("Rebuilt APK"), neut.OutApk.c_str());
                        }
                    }
                }
            }
        }
        ImGui::End();
    }
}
