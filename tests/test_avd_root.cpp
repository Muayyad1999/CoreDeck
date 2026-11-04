#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <miniz.h>

#include "core/avd_root.h"

using namespace CoreDeck::Core;
using namespace CoreDeck;

namespace {
    std::vector<std::uint8_t> Bytes(std::initializer_list<int> values) {
        std::vector<std::uint8_t> out;
        out.reserve(values.size());
        for (const int v: values) {
            out.push_back(static_cast<std::uint8_t>(v));
        }
        return out;
    }

    std::vector<std::uint8_t> FromString(const std::string &s) {
        return std::vector<std::uint8_t>(s.begin(), s.end());
    }

    std::vector<std::uint8_t> Repeat(const std::string &unit, const int times) {
        std::string s;
        for (int i = 0; i < times; ++i) {
            s += unit;
        }
        return FromString(s);
    }
}

TEST_CASE("DetectRamdiskFormat recognises the ramdisk container magics", "[avdroot]") {
    REQUIRE(DetectRamdiskFormat(Bytes({0x1F, 0x8B, 0x08, 0x00})) == RamdiskFormat::Gzip);
    REQUIRE(DetectRamdiskFormat(Bytes({0x02, 0x21, 0x4C, 0x18})) == RamdiskFormat::Lz4Legacy);
    REQUIRE(DetectRamdiskFormat(Bytes({0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00})) == RamdiskFormat::Xz);
    REQUIRE(DetectRamdiskFormat(FromString("070701abc")) == RamdiskFormat::Raw);
    REQUIRE(DetectRamdiskFormat(Bytes({0x00, 0x01, 0x02})) == RamdiskFormat::Unknown);
}

TEST_CASE("gzip round-trips through miniz", "[avdroot]") {
    for (const auto &sample: {std::vector<std::uint8_t>{}, FromString("hello"), Repeat("the quick brown fox ", 500), Repeat("\x00\x01\x02\x03", 1000)}) {
        const auto deflated = GzipDeflate(sample);
        REQUIRE(deflated.size() >= 18); // header + footer
        REQUIRE(DetectRamdiskFormat(deflated) == RamdiskFormat::Gzip);
        const auto inflated = GzipInflate(deflated);
        REQUIRE(inflated.has_value());
        REQUIRE(*inflated == sample);
    }
}

TEST_CASE("lz4-legacy round-trips (literals and matches)", "[avdroot]") {
    for (const auto &sample: {std::vector<std::uint8_t>{}, FromString("A"), FromString("hello world"), Repeat("ABCABCABC", 2000), Repeat("x", 100000)}) {
        const auto compressed = Lz4LegacyCompress(sample);
        REQUIRE(DetectRamdiskFormat(compressed) == RamdiskFormat::Lz4Legacy);
        const auto back = Lz4LegacyDecompress(compressed);
        REQUIRE(back.has_value());
        REQUIRE(*back == sample);
    }
}

TEST_CASE("lz4-legacy decodes a known stream", "[avdroot]") {
    // frame magic + block size(6) + [token 0x32][a b c][offset 3] => "abcabcabc"
    const auto stream = Bytes({0x02, 0x21, 0x4C, 0x18, 0x06, 0x00, 0x00, 0x00, 0x32, 0x61, 0x62, 0x63, 0x03, 0x00});
    const auto out = Lz4LegacyDecompress(stream);
    REQUIRE(out.has_value());
    REQUIRE(std::string(out->begin(), out->end()) == "abcabcabc");
}

TEST_CASE("cpio newc round-trips byte-for-byte", "[avdroot]") {
    CpioArchive archive;
    CpioEntry dir;
    dir.Name = ".";
    dir.Ino = 300000;
    dir.Mode = 0040755;
    dir.Nlink = 2;
    archive.push_back(dir);

    CpioEntry init;
    init.Name = "init";
    init.Ino = 300001;
    init.Mode = 0100750;
    init.Nlink = 1;
    init.Data = FromString("#!/system/bin/init\npayload");
    archive.push_back(init);

    CpioEntry link;
    link.Name = "sbin/sh";
    link.Ino = 300002;
    link.Mode = 0120777;
    link.Nlink = 1;
    link.Data = FromString("/system/bin/sh");
    archive.push_back(link);

    const auto serialized = SerializeCpioNewc(archive);
    const auto parsed = ParseCpioNewc(serialized);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->size() == 3);
    REQUIRE(parsed->at(1).Name == "init");
    REQUIRE(parsed->at(1).Mode == 0100750U);
    REQUIRE(parsed->at(1).Ino == 300001U);
    REQUIRE(parsed->at(1).Data == init.Data);
    REQUIRE(parsed->at(2).IsSymlink());

    // Re-serializing the parsed archive reproduces the exact bytes.
    REQUIRE(SerializeCpioNewc(*parsed) == serialized);
}

TEST_CASE("MergeCpio lets the later archive win on a name collision", "[avdroot]") {
    CpioEntry a;
    a.Name = "init";
    a.Data = FromString("old");
    CpioEntry b;
    b.Name = "init";
    b.Data = FromString("new");
    CpioEntry c;
    c.Name = "fstab";
    c.Data = FromString("x");

    const auto merged = MergeCpio({{a}, {b, c}});
    REQUIRE(merged.size() == 2);
    REQUIRE(merged.at(0).Name == "init");
    REQUIRE(std::string(merged.at(0).Data.begin(), merged.at(0).Data.end()) == "new");
    REQUIRE(merged.at(1).Name == "fstab");
}

TEST_CASE("ParseMagiskReleases honours the stable / prerelease channel", "[avdroot]") {
    const std::string json = R"([
      {"tag_name":"canary-27001","prerelease":true,"draft":false,
       "assets":[{"name":"app-release.apk","browser_download_url":"https://x/canary.apk","size":12345}]},
      {"tag_name":"v27.0","prerelease":false,"draft":false,
       "assets":[{"name":"Magisk-v27.0.apk","browser_download_url":"https://x/v27.apk","size":11111}]}
    ])";

    const auto stable = ParseMagiskReleases(json, false);
    REQUIRE(stable.has_value());
    REQUIRE(stable->Tag == "v27.0");
    REQUIRE(stable->Channel == MagiskChannel::Stable);
    REQUIRE(stable->FileName == "Magisk-v27.0.apk");
    REQUIRE(stable->Size == 11111);

    const auto withPre = ParseMagiskReleases(json, true);
    REQUIRE(withPre.has_value());
    REQUIRE(withPre->Tag == "canary-27001");
    REQUIRE(withPre->Channel == MagiskChannel::Prerelease);
}

TEST_CASE("ParseMagiskApk lists the ABIs under lib/", "[avdroot]") {
    // Build a tiny in-memory zip that looks like a Magisk apk.
    mz_zip_archive zip = {};
    REQUIRE(mz_zip_writer_init_heap(&zip, 0, 0) == MZ_TRUE);
    const char *payload = "ELF";
    for (const char *name: {"lib/x86_64/libmagiskinit.so", "lib/arm64-v8a/libmagiskinit.so", "lib/x86_64/libmagisk.so", "AndroidManifest.xml", "classes.dex"}) {
        REQUIRE(mz_zip_writer_add_mem(&zip, name, payload, 3, MZ_NO_COMPRESSION) == MZ_TRUE);
    }
    void *buf = nullptr;
    std::size_t bufSize = 0;
    REQUIRE(mz_zip_writer_finalize_heap_archive(&zip, &buf, &bufSize) == MZ_TRUE);
    std::vector<std::uint8_t> apk(static_cast<std::uint8_t *>(buf), static_cast<std::uint8_t *>(buf) + bufSize);
    mz_zip_writer_end(&zip);
    mz_free(buf);

    const auto info = ParseMagiskApk(apk);
    REQUIRE(info.has_value());
    REQUIRE(info->Abis.size() == 2);
    REQUIRE(info->Abis.at(0) == "arm64-v8a");
    REQUIRE(info->Abis.at(1) == "x86_64");
}

TEST_CASE("ParseMagiskApk rejects non-zip input", "[avdroot]") {
    REQUIRE_FALSE(ParseMagiskApk(FromString("not a zip")).has_value());
}

TEST_CASE("ParseRootId detects uid=0", "[avdroot]") {
    REQUIRE(ParseRootId("uid=0(root) gid=0(root) groups=0(root) context=u:r:su:s0"));
    REQUIRE(ParseRootId("uid=0"));
    REQUIRE_FALSE(ParseRootId("uid=2000(shell) gid=2000(shell)"));
    REQUIRE_FALSE(ParseRootId("/system/bin/sh: su: not found"));
    REQUIRE_FALSE(ParseRootId(""));
}
