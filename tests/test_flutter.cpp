#include <cstdint>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <miniz.h>

#include "core/flutter.h"

using namespace CoreDeck::Core;
using namespace CoreDeck;

TEST_CASE("IsFlutterLib recognises the Flutter native libs", "[flutter]") {
    REQUIRE(IsFlutterLib("lib/arm64-v8a/libapp.so"));
    REQUIRE(IsFlutterLib("libflutter.so"));
    REQUIRE_FALSE(IsFlutterLib("lib/arm64-v8a/libnative.so"));
}

TEST_CASE("BuildBlutterArgs assembles the python argv", "[flutter]") {
    REQUIRE(BuildBlutterArgs("/t/blutter.py", "/libs", "/out", false, false) == std::vector<std::string>{"/t/blutter.py", "/libs", "/out"});
    REQUIRE(BuildBlutterArgs("b.py", "l", "o", true, true) == std::vector<std::string>{"b.py", "l", "o", "--rebuild", "--no-analysis"});
}

TEST_CASE("ApkIsFlutter detects a Flutter apk", "[flutter]") {
    auto makeZip = [](const char *entry) {
        mz_zip_archive zip = {};
        REQUIRE(mz_zip_writer_init_heap(&zip, 0, 0) == MZ_TRUE);
        REQUIRE(mz_zip_writer_add_mem(&zip, entry, "x", 1, MZ_NO_COMPRESSION) == MZ_TRUE);
        void *buf = nullptr;
        std::size_t n = 0;
        REQUIRE(mz_zip_writer_finalize_heap_archive(&zip, &buf, &n) == MZ_TRUE);
        std::vector<std::uint8_t> out(static_cast<std::uint8_t *>(buf), static_cast<std::uint8_t *>(buf) + n);
        mz_zip_writer_end(&zip);
        mz_free(buf);
        return out;
    };
    REQUIRE(ApkIsFlutter(makeZip("lib/arm64-v8a/libapp.so")));
    REQUIRE_FALSE(ApkIsFlutter(makeZip("classes.dex")));
}
