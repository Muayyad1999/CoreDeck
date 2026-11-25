#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "core/fastboot.h"

using namespace CoreDeck::Core::Re;
using namespace CoreDeck;

TEST_CASE("ParseFastbootDevices reads serial/state rows", "[fastboot]") {
    const std::string output =
        "1A2B3C4D5E6F\tfastboot\n"
        "emulatortest        fastboot\n"
        "* daemon started successfully *\n"
        "\n";
    const auto devices = ParseFastbootDevices(output);
    REQUIRE(devices.size() == 2);
    REQUIRE(devices.at(0).Serial == "1A2B3C4D5E6F");
    REQUIRE(devices.at(0).State == "fastboot");
    REQUIRE(devices.at(0).Online());
    REQUIRE(devices.at(1).Serial == "emulatortest");
    REQUIRE(devices.at(1).State == "fastboot");
}

TEST_CASE("ParseGetVarValue tolerates the (bootloader) prefix", "[fastboot]") {
    const std::string plain = "unlocked: yes\nFinished. Total time: 0.001s\n";
    REQUIRE(ParseGetVarValue(plain, "unlocked") == "yes");

    const std::string prefixed =
        "(bootloader) unlocked: no\n"
        "(bootloader) product: shiba\n"
        "OKAY [  0.001s]\n"
        "Finished. Total time: 0.002s\n";
    REQUIRE(ParseGetVarValue(prefixed, "unlocked") == "no");
    REQUIRE(ParseGetVarValue(prefixed, "product") == "shiba");
    REQUIRE(ParseGetVarValue(prefixed, "missing").empty());
}

TEST_CASE("ParseUnlockedValue classifies the lock state", "[fastboot]") {
    REQUIRE(ParseUnlockedValue("yes") == LockState::Unlocked);
    REQUIRE(ParseUnlockedValue(" no ") == LockState::Locked);
    REQUIRE(ParseUnlockedValue("maybe") == LockState::Unknown);
    REQUIRE(ParseUnlockedValue("") == LockState::Unknown);
}

TEST_CASE("ParseBootloaderVars pulls the fields out of getvar all", "[fastboot]") {
    const std::string output =
        "(bootloader) version-bootloader: shiba-1.0\n"
        "(bootloader) product: shiba\n"
        "(bootloader) current-slot: b\n"
        "(bootloader) unlocked: yes\n"
        "(bootloader) serialno: 1A2B3C4D5E6F\n"
        "all: Done!\n"
        "Finished. Total time: 0.050s\n";
    const BootloaderVars vars = ParseBootloaderVars(output);
    REQUIRE(vars.Unlocked == LockState::Unlocked);
    REQUIRE(vars.Product == "shiba");
    REQUIRE(vars.CurrentSlot == "b");
    REQUIRE(vars.SerialNo == "1A2B3C4D5E6F");
}

TEST_CASE("fastboot argv builders produce the expected commands", "[fastboot]") {
    REQUIRE(BuildGetVarArgs("unlocked") == std::vector<std::string>{"getvar", "unlocked"});
    REQUIRE(BuildFlashArgs("init_boot", "/tmp/new-boot.img") ==
            std::vector<std::string>{"flash", "init_boot", "/tmp/new-boot.img"});
    REQUIRE(BuildFlashingUnlockArgs() == std::vector<std::string>{"flashing", "unlock"});
    REQUIRE(BuildFlashingLockArgs() == std::vector<std::string>{"flashing", "lock"});
    REQUIRE(BuildRebootArgs("") == std::vector<std::string>{"reboot"});
    REQUIRE(BuildRebootArgs("system") == std::vector<std::string>{"reboot"});
    REQUIRE(BuildRebootArgs("bootloader") == std::vector<std::string>{"reboot", "bootloader"});
}

TEST_CASE("LockStateName names the states", "[fastboot]") {
    REQUIRE(std::string(LockStateName(LockState::Unlocked)) == "unlocked");
    REQUIRE(std::string(LockStateName(LockState::Locked)) == "locked");
    REQUIRE(std::string(LockStateName(LockState::Unknown)) == "unknown");
}
