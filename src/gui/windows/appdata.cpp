//
// Created by CoreDeck RE toolbench on 05/11/2026.
//

#include <chrono>
#include <filesystem>
#include <future>
#include <string>
#include <utility>
#include <vector>

#include "imgui.h"

#include "appdata.h"
#include "../widgets.h"
#include "../theme.h"
#include "gui/context.h"
#include "core/appdata.h"
#include "app/file_dialog.h"
#include "platform/i18n.h"

namespace CoreDeck::Gui {
    namespace {
        void StartList(Context &context, const std::string &serial, const std::string &subPath) {
            auto &work = context.AppDataWork;
            if (work.ListBusy.load() || serial.empty() || work.Package[0] == '\0') {
                return;
            }
            work.ListBusy = true;
            work.HasListing = false;
            work.ListError.clear();
            work.PendingSubPath = subPath;
            const Core::SdkInfo sdk = context.Host.Sdk;
            const std::string package = work.Package;
            work.ListFuture = std::async(std::launch::async, [sdk, serial, package, subPath] {
                return Core::ListAppData(sdk, serial, package, subPath);
            });
        }

        void StartGrep(Context &context, const std::string &serial) {
            auto &work = context.AppDataWork;
            if (work.GrepBusy.load() || serial.empty() || work.Package[0] == '\0' || work.GrepPattern[0] == '\0') {
                return;
            }
            work.GrepBusy = true;
            work.HasGrep = false;
            const Core::SdkInfo sdk = context.Host.Sdk;
            const std::string package = work.Package;
            const std::string pattern = work.GrepPattern;
            work.GrepFuture = std::async(std::launch::async, [sdk, serial, package, pattern] {
                return Core::GrepAppData(sdk, serial, package, pattern);
            });
        }

        void StartPull(Context &context, const std::string &serial, const std::string &subPath, const std::string &localPath) {
            auto &work = context.AppDataWork;
            if (work.PullBusy.load() || serial.empty()) {
                return;
            }
            work.PullBusy = true;
            work.PullOutcome.clear();
            const Core::SdkInfo sdk = context.Host.Sdk;
            const std::string package = work.Package;
            work.PullFuture = std::async(std::launch::async, [sdk, serial, package, subPath, localPath] {
                std::string error;
                const bool ok = Core::PullAppFile(sdk, serial, package, subPath, localPath, error);
                return std::make_pair(ok, error);
            });
        }

        void PollWork(Context &context) {
            auto &work = context.AppDataWork;
            if (work.ListBusy.load() && work.ListFuture.valid() &&
                work.ListFuture.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                work.Entries = work.ListFuture.get();
                work.SubPath = work.PendingSubPath;
                work.LoadedPackage = work.Package;
                work.HasListing = true;
                work.ListBusy = false;
                if (work.Entries.empty()) {
                    work.ListError = Platform::Tr(
                        "Nothing listed. Needs a rooted AVD (su), and the app's data dir must exist."
                    );
                }
            }
            if (work.GrepBusy.load() && work.GrepFuture.valid() &&
                work.GrepFuture.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                work.GrepHits = work.GrepFuture.get();
                work.HasGrep = true;
                work.GrepBusy = false;
            }
            if (work.PullBusy.load() && work.PullFuture.valid() &&
                work.PullFuture.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                auto [ok, error] = work.PullFuture.get();
                work.PullOk = ok;
                work.PullOutcome = ok ? std::string(Platform::Tr("Pulled.")) : error;
                work.PullBusy = false;
            }
        }

        // Join the current SubPath with a child entry name.
        std::string ChildPath(const std::string &subPath, const std::string &name) {
            if (subPath.empty()) {
                return name;
            }
            return subPath + "/" + name;
        }

        // Drop the last path component.
        std::string ParentPath(const std::string &subPath) {
            const std::size_t slash = subPath.find_last_of('/');
            if (slash == std::string::npos) {
                return "";
            }
            return subPath.substr(0, slash);
        }
    }

    void BuildAppDataWindow(Context &context) {
        PollWork(context);

        if (!context.UI.ShowAppDataDialog) {
            return;
        }

        auto &work = context.AppDataWork;
        const std::string title = Platform::TrWindow("App Data", "AppDataDialog");
        ImGui::SetNextWindowSize(EmV(36.0F, 32.0F), ImGuiCond_FirstUseEver);
        if (ImGui::Begin(title.c_str(), &context.UI.ShowAppDataDialog)) {
            if (!context.Host.Sdk.IsFound) {
                ImGui::TextDisabled("%s", Platform::Tr("No Android SDK detected. Set the SDK path in Preferences."));
                ImGui::End();
                return;
            }

            const std::string &serial = context.Target.Serial;
            ImGui::TextDisabled(
                "%s",
                Platform::Tr("Browse a package's private /data/data on your rooted AVD - for an app you installed "
                             "to test. Needs su.")
            );
            ImGui::Spacing();

            if (serial.empty()) {
                ImGui::TextDisabled("%s", Platform::Tr("Select a device in the Devices window."));
                ImGui::End();
                return;
            }
            PropertyText(Platform::Tr("Device"), serial.c_str());

            ImGui::TextDisabled("%s", Platform::Tr("Package"));
            ImGui::SetNextItemWidth(Em(22.0F));
            const bool submit = ImGui::InputTextWithHint(
                "##appdata_pkg",
                Platform::Tr("e.g. com.example.app"),
                work.Package,
                sizeof(work.Package),
                ImGuiInputTextFlags_EnterReturnsTrue
            );
            ImGui::SameLine();
            const bool listBusy = work.ListBusy.load();
            const bool open =
                PositiveButton(listBusy ? Platform::Tr("Listing...") : Platform::Tr("Open"), !listBusy, ImVec2(0, 0), listBusy);
            if ((submit || open) && work.Package[0] != '\0') {
                StartList(context, serial, "");
            }

            if (work.HasListing || work.ListBusy.load()) {
                ImGui::Separator();

                // Breadcrumb: /data/data/<pkg>/<subPath>
                ImGui::TextDisabled("/data/data/%s/%s", work.LoadedPackage.c_str(), work.SubPath.c_str());

                if (!work.SubPath.empty()) {
                    if (ImGui::SmallButton(Platform::Tr(".. (up)"))) {
                        StartList(context, serial, ParentPath(work.SubPath));
                    }
                }

                ImGui::BeginChild("##appdata_entries", ImVec2(0, Eh(11.0F)), 1);
                for (const auto &entry: work.Entries) {
                    if (entry.IsDir) {
                        if (ImGui::SmallButton((std::string("[") + entry.Name + "]").c_str())) {
                            StartList(context, serial, ChildPath(work.SubPath, entry.Name));
                        }
                    } else {
                        ImGui::PushID(entry.Name.c_str());
                        ImGui::TextUnformatted(entry.Name.c_str());
                        ImGui::SameLine();
                        ImGui::TextDisabled("  %s", entry.Size.c_str());
                        ImGui::SameLine();
                        const bool pullBusy = work.PullBusy.load();
                        if (ImGui::SmallButton(Platform::Tr("pull")) && !pullBusy) {
                            const std::string remoteSub = ChildPath(work.SubPath, entry.Name);
                            if (const auto picked = App::FileDialog::SaveFile(
                                    Platform::Tr("Save file"),
                                    entry.Name,
                                    Platform::Tr("All files"),
                                    {"*.*"}
                                )) {
                                StartPull(context, serial, remoteSub, *picked);
                            }
                        }
                        ImGui::PopID();
                    }
                }
                ImGui::EndChild();

                if (!work.ListError.empty() && !work.ListBusy.load()) {
                    ImGui::TextColored(HexColor(Colors::TEXT_MUTED), "%s", work.ListError.c_str());
                }
                if (!work.PullOutcome.empty()) {
                    ImGui::TextColored(
                        HexColor(work.PullOk ? Colors::POSITIVE : Colors::NEGATIVE),
                        "%s",
                        work.PullOutcome.c_str()
                    );
                }

                ImGui::Separator();
                ImGui::TextDisabled("%s", Platform::Tr("Search (your own pattern, extended regex, case-insensitive)"));
                ImGui::SetNextItemWidth(Em(22.0F));
                const bool grepSubmit = ImGui::InputTextWithHint(
                    "##appdata_grep",
                    Platform::Tr("grep -E pattern"),
                    work.GrepPattern,
                    sizeof(work.GrepPattern),
                    ImGuiInputTextFlags_EnterReturnsTrue
                );
                ImGui::SameLine();
                const bool grepBusy = work.GrepBusy.load();
                const bool grepGo =
                    PositiveButton(grepBusy ? Platform::Tr("Searching...") : Platform::Tr("Search"), !grepBusy, ImVec2(0, 0), grepBusy);
                if ((grepSubmit || grepGo) && work.GrepPattern[0] != '\0') {
                    StartGrep(context, serial);
                }

                if (work.HasGrep) {
                    if (work.GrepHits.empty()) {
                        ImGui::TextDisabled("%s", Platform::Tr("No matches."));
                    } else {
                        ImGui::BeginChild("##appdata_grep_hits", ImVec2(0, Eh(8.0F)), 1);
                        for (const auto &hit: work.GrepHits) {
                            ImGui::TextUnformatted(hit.c_str());
                        }
                        ImGui::EndChild();
                    }
                }
            }
        }
        ImGui::End();
    }
}
