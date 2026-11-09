//
// Created by CoreDeck RE toolbench on 05/11/2026.
//

#include <chrono>
#include <future>

#include "imgui.h"

#include "retools.h"
#include "../widgets/widgets.h"
#include "../theme.h"
#include "gui/context/context.h"
#include "core/tools.h"
#include "platform/i18n.h"

namespace CoreDeck::Gui {
    namespace {
        void StartDetect(Context &context) {
            auto &work = context.ReToolsWork;
            if (work.Busy.load()) {
                return;
            }
            work.Busy = true;
            work.Loaded = false;
            const Core::SdkInfo sdk = context.Host.Sdk;
            work.Future = std::async(std::launch::async, [sdk] { return Core::DetectReTools(sdk); });
        }

        void PollWork(Context &context) {
            auto &work = context.ReToolsWork;
            if (work.Busy.load() && work.Future.valid() &&
                work.Future.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                work.Statuses = work.Future.get();
                work.Loaded = true;
                work.Busy = false;
            }
        }
    }

    void BuildReToolsWindow(Context &context) {
        PollWork(context);

        if (!context.UI.ShowReToolsDialog) {
            return;
        }

        auto &work = context.ReToolsWork;
        if (!work.Requested) {
            work.Requested = true;
            StartDetect(context);
        }

        const std::string title = Platform::TrWindow("RE Tools", "ReToolsDialog");
        ImGui::SetNextWindowSize(EmV(40.0F, 34.0F), ImGuiCond_FirstUseEver);
        if (ImGui::Begin(title.c_str(), &context.UI.ShowReToolsDialog)) {
            ImGui::TextDisabled(
                "%s",
                Platform::Tr("External tools the Research features can use, and how to get the missing ones. "
                             "Nothing is installed for you.")
            );
            ImGui::Spacing();

            const bool busy = work.Busy.load();
            if (PositiveButton(busy ? Platform::Tr("Checking...") : Platform::Tr("Re-check"), !busy, ImVec2(0, 0), busy)) {
                StartDetect(context);
            }

            if (work.Loaded) {
                int found = 0;
                for (const auto &status: work.Statuses) {
                    if (status.Found) {
                        ++found;
                    }
                }
                ImGui::SameLine();
                ImGui::TextDisabled(
                    "%s",
                    Platform::TrFormat(
                        "{0} of {1} found",
                        std::to_string(found),
                        std::to_string(work.Statuses.size())
                    )
                        .c_str()
                );

                ImGui::Separator();
                ImGui::BeginChild("##retools_list", ImVec2(0, 0), 0);
                for (const auto &status: work.Statuses) {
                    const Core::ReToolSpec &spec = status.Spec;
                    ImGui::PushID(spec.Key.c_str());

                    ImGui::TextColored(
                        HexColor(status.Found ? Colors::POSITIVE : (spec.Optional ? Colors::WARNING : Colors::NEGATIVE)),
                        "%s",
                        status.Found ? "[found]" : "[missing]"
                    );
                    ImGui::SameLine();
                    ImGui::TextUnformatted(spec.Name.c_str());
                    if (!spec.Optional && !status.Found) {
                        ImGui::SameLine();
                        ImGui::TextColored(HexColor(Colors::NEGATIVE), "%s", Platform::Tr("(required)"));
                    }

                    ImGui::Indent();
                    ImGui::TextDisabled("%s", spec.UsedFor.c_str());
                    if (status.Found) {
                        PropertyText(Platform::Tr("Path"), status.ResolvedPath.c_str());
                    } else {
                        if (ImGui::TreeNode(Platform::Tr("How to install"))) {
                            for (const std::string &line: spec.InstallHint) {
                                ImGui::TextWrapped("%s", line.c_str());
                            }
                            ImGui::TreePop();
                        }
                    }
                    ImGui::Unindent();
                    ImGui::Spacing();
                    ImGui::PopID();
                }
                ImGui::EndChild();
            } else if (busy) {
                ImGui::TextDisabled("%s", Platform::Tr("Checking..."));
            }
        }
        ImGui::End();
    }
}
