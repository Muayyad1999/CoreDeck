#include <string>

#include <catch2/catch_test_macros.hpp>

#include "core/checks.h"

using namespace CoreDeck::Core;
using namespace CoreDeck;

TEST_CASE("ScanSmaliText flags known anti-analysis patterns", "[checks]") {
    const std::string smali =
        "    const-string v0, \"/system/xbin/su\"\n"
        "    invoke-static {}, Lcom/x/Root;->isDeviceRooted()Z\n"
        "    const-string v1, \"goldfish\"\n"
        "    invoke-static {v2}, Landroid/os/Debug;->isDebuggerConnected()Z\n"
        "    invoke-static {}, Lcom/google/android/gms/safetynet/SafetyNet;->getClient()V\n"
        "    nop\n";
    const auto findings = ScanSmaliText(smali);
    bool root = false;
    bool emulator = false;
    bool debugger = false;
    bool integrity = false;
    for (const auto &f: findings) {
        if (f.Label == "root") root = true;
        if (f.Label == "emulator") emulator = true;
        if (f.Label == "debugger") debugger = true;
        if (f.Label == "integrity") integrity = true;
    }
    REQUIRE(root);
    REQUIRE(emulator);
    REQUIRE(debugger);
    REQUIRE(integrity);
}

TEST_CASE("IsSelfKillLine matches only void self-kill invokes", "[checks]") {
    REQUIRE(IsSelfKillLine("    invoke-static {v0}, Ljava/lang/System;->exit(I)V"));
    REQUIRE(IsSelfKillLine("    invoke-virtual {p0}, Landroid/app/Activity;->finishAffinity()V"));
    REQUIRE(IsSelfKillLine("    invoke-static {v1}, Landroid/os/Process;->killProcess(I)V"));
    REQUIRE_FALSE(IsSelfKillLine("    invoke-virtual {p0}, Landroid/app/Activity;->finish()V"));
    REQUIRE_FALSE(IsSelfKillLine("    const-string v0, \"System.exit\""));
}

TEST_CASE("NeutralizeSmaliText comments out self-kill lines only", "[checks]") {
    const std::string smali =
        "    invoke-static {}, Lx;->check()Z\n"
        "    invoke-static {v0}, Ljava/lang/System;->exit(I)V\n"
        "    return-void\n";
    auto [out, count] = NeutralizeSmaliText(smali);
    REQUIRE(count == 1);
    REQUIRE(out.find("# [coredeck neutralized]     invoke-static {v0}, Ljava/lang/System;->exit(I)V") != std::string::npos);
    REQUIRE(out.find("\n    return-void") != std::string::npos);
    REQUIRE(out.find("# [coredeck neutralized]     invoke-static {}, Lx;->check()Z") == std::string::npos);
}
