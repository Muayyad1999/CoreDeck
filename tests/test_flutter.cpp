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

TEST_CASE("ParseMaskedPattern handles nibble masks", "[flutter]") {
    const auto p = ParseMaskedPattern("F? 43 ?? D1");
    REQUIRE(p.Values.size() == 4);
    REQUIRE(p.Values[0] == 0xF0);
    REQUIRE(p.Masks[0] == 0xF0);
    REQUIRE(p.Values[1] == 0x43);
    REQUIRE(p.Masks[1] == 0xFF);
    REQUIRE(p.Masks[2] == 0x00); // ??
    REQUIRE(p.Values[3] == 0xD1);
}

TEST_CASE("MaskedSearch finds a masked match", "[flutter]") {
    std::vector<std::uint8_t> data = {0x11, 0x22, 0xFA, 0x43, 0x99, 0xD1, 0x00};
    const auto p = ParseMaskedPattern("F? 43 ?? D1");
    REQUIRE(MaskedSearch(data, p, 0, data.size()) == 2);
    REQUIRE_FALSE(MaskedSearch(data, p, 3, data.size()).has_value());
}

TEST_CASE("FindFlutterSslOffset locates an NVISO signature", "[flutter]") {
    // Concrete bytes satisfying pattern #2 (prefix F0 for 'F?').
    const std::vector<std::uint8_t> sig = {0xF0, 0x43, 0x01, 0xD1, 0xFE, 0x67, 0x01, 0xA9, 0xF8, 0x5F, 0x02, 0xA9, 0xF6, 0x57, 0x03, 0xA9, 0xF4, 0x4F, 0x04, 0xA9, 0x13, 0x00, 0x40, 0xF9, 0xF4, 0x03, 0x00, 0xAA, 0x68, 0x1A, 0x40, 0xF9};
    std::vector<std::uint8_t> lib(100, 0x00); // non-ELF -> whole buffer scanned
    const std::size_t at = 48;
    std::copy(sig.begin(), sig.end(), lib.begin() + at);
    const auto off = FindFlutterSslOffset(lib);
    REQUIRE(off.has_value());
    REQUIRE(*off == at);

    const auto patched = PatchFlutterSsl(lib, *off);
    REQUIRE(patched[*off] == 0x00);
    REQUIRE(patched[*off + 3] == 0x52);
    REQUIRE(patched[*off + 7] == 0xD6);
}

TEST_CASE("ReplaceApkEntry swaps one entry and keeps the rest", "[flutter]") {
    mz_zip_archive zip = {};
    REQUIRE(mz_zip_writer_init_heap(&zip, 0, 0) == MZ_TRUE);
    REQUIRE(mz_zip_writer_add_mem(&zip, "lib/arm64-v8a/libflutter.so", "OLD", 3, MZ_DEFAULT_COMPRESSION) == MZ_TRUE);
    REQUIRE(mz_zip_writer_add_mem(&zip, "classes.dex", "DEX", 3, MZ_DEFAULT_COMPRESSION) == MZ_TRUE);
    void *buf = nullptr;
    std::size_t n = 0;
    REQUIRE(mz_zip_writer_finalize_heap_archive(&zip, &buf, &n) == MZ_TRUE);
    std::vector<std::uint8_t> apk(static_cast<std::uint8_t *>(buf), static_cast<std::uint8_t *>(buf) + n);
    mz_zip_writer_end(&zip);
    mz_free(buf);

    const std::vector<std::uint8_t> newContent = {'N', 'E', 'W', '!'};
    const auto rebuilt = ReplaceApkEntry(apk, "lib/arm64-v8a/libflutter.so", newContent);
    REQUIRE(rebuilt.has_value());

    const auto lib = ExtractApkEntry(*rebuilt, "lib/arm64-v8a/libflutter.so");
    REQUIRE(lib.has_value());
    REQUIRE(*lib == newContent);
    const auto dex = ExtractApkEntry(*rebuilt, "classes.dex");
    REQUIRE(dex.has_value());
    REQUIRE(std::string(dex->begin(), dex->end()) == "DEX");

    REQUIRE_FALSE(ReplaceApkEntry(apk, "does/not/exist", newContent).has_value());
}
