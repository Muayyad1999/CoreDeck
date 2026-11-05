#include <string>

#include <catch2/catch_test_macros.hpp>

#include "core/appdata.h"

using namespace CoreDeck::Core;
using namespace CoreDeck;

TEST_CASE("ParseLsOutput reads toybox ls -la rows", "[appdata]") {
    const std::string output =
        "total 32\n"
        "drwx------ 6 u0_a123 u0_a123 4096 2026-01-01 00:00 .\n"
        "drwxrwx--x 4 system  system  4096 2026-01-01 00:00 ..\n"
        "drwxrwx--x 2 u0_a123 u0_a123 4096 2026-01-02 09:15 databases\n"
        "drwxrwx--x 2 u0_a123 u0_a123 4096 2026-01-02 09:15 shared_prefs\n"
        "-rw------- 1 u0_a123 u0_a123  220 2026-01-02 09:15 app_prefs.xml\n"
        "lrwxrwxrwx 1 u0_a123 u0_a123   11 2026-01-02 09:15 link -> target.txt\n";

    const auto entries = ParseLsOutput(output);
    REQUIRE(entries.size() == 4); // "." and ".." dropped

    // Directories sort first, then files, each alphabetical.
    REQUIRE(entries[0].Name == "databases");
    REQUIRE(entries[0].IsDir);
    REQUIRE(entries[1].Name == "shared_prefs");
    REQUIRE(entries[1].IsDir);

    REQUIRE(entries[2].Name == "app_prefs.xml");
    REQUIRE_FALSE(entries[2].IsDir);
    REQUIRE(entries[2].Size == "220");

    REQUIRE(entries[3].Name == "link");
    REQUIRE(entries[3].IsLink);
}

TEST_CASE("ParseLsOutput ignores su notices and blanks", "[appdata]") {
    const std::string output =
        "su: setexeccon failed\n"
        "\n"
        "-rw-rw-rw- 1 root root 5 2026-01-01 00:00 note.txt\n";
    const auto entries = ParseLsOutput(output);
    REQUIRE(entries.size() == 1);
    REQUIRE(entries[0].Name == "note.txt");
}

TEST_CASE("ParseLsOutput keeps names containing spaces", "[appdata]") {
    const std::string output =
        "-rw------- 1 u0_a1 u0_a1 10 2026-01-01 00:00 my file.db\n";
    const auto entries = ParseLsOutput(output);
    REQUIRE(entries.size() == 1);
    REQUIRE(entries[0].Name == "my file.db");
}

TEST_CASE("DataPath joins within the package and rejects traversal", "[appdata]") {
    REQUIRE(DataPath("com.example.app", "") == "/data/data/com.example.app");
    REQUIRE(DataPath("com.example.app", "shared_prefs") == "/data/data/com.example.app/shared_prefs");
    REQUIRE(DataPath("com.example.app", "/databases/x.db") == "/data/data/com.example.app/databases/x.db");

    // Traversal is refused - falls back to the package root.
    REQUIRE(DataPath("com.example.app", "../other") == "/data/data/com.example.app");
    REQUIRE(DataPath("com.example.app", "a/../../b") == "/data/data/com.example.app");
}
