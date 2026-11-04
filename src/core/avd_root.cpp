//
// Created by CoreDeck RE toolbench on 04/11/2026.
//

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include <miniz.h>
#include <rfl/json.hpp>

#include "core/avd_root.h"
#include "core/adb.h"
#include "platform/http_download.h"
#include "platform/paths.h"
#include "platform/sha256.h"

namespace CoreDeck::Core {
    namespace {
        constexpr const char *MAGISK_RELEASES_URL =
            "https://api.github.com/repos/topjohnwu/Magisk/releases?per_page=30";
        constexpr const char *MAGISK_USER_AGENT = "CoreDeck";

        std::uint32_t Align4(const std::uint32_t value) {
            return (value + 3U) & ~3U;
        }

        std::uint32_t Read32LE(const std::vector<std::uint8_t> &d, const std::size_t off) {
            return static_cast<std::uint32_t>(d[off]) | (static_cast<std::uint32_t>(d[off + 1]) << 8) |
                   (static_cast<std::uint32_t>(d[off + 2]) << 16) | (static_cast<std::uint32_t>(d[off + 3]) << 24);
        }

        void Put32LE(std::vector<std::uint8_t> &out, const std::uint32_t value) {
            out.push_back(static_cast<std::uint8_t>(value & 0xFFU));
            out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFU));
            out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFFU));
            out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFFU));
        }

        constexpr std::uint32_t LZ4_BLOCK_MAX = 8U * 1024U * 1024U; // legacy 8 MiB blocks
        constexpr int LZ4_MINMATCH = 4;
        constexpr int LZ4_MFLIMIT = 12;
        constexpr int LZ4_LASTLITERALS = 5;
        constexpr int LZ4_HASH_BITS = 16;

        std::optional<std::vector<std::uint8_t>> ReadFileBytes(const std::string &path) {
            std::ifstream file(path, std::ios::binary);
            if (!file) {
                return std::nullopt;
            }
            return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        }
    }

    const char *RamdiskFormatName(const RamdiskFormat format) {
        switch (format) {
            case RamdiskFormat::Raw:
                return "cpio";
            case RamdiskFormat::Gzip:
                return "gzip";
            case RamdiskFormat::Lz4Legacy:
                return "lz4 (legacy)";
            case RamdiskFormat::Xz:
                return "xz";
            case RamdiskFormat::Unknown:
            default:
                return "unknown";
        }
    }

    RamdiskFormat DetectRamdiskFormat(const std::vector<std::uint8_t> &data) {
        if (data.size() >= 2 && data[0] == 0x1F && data[1] == 0x8B) {
            return RamdiskFormat::Gzip;
        }
        if (data.size() >= 4 && data[0] == 0x02 && data[1] == 0x21 && data[2] == 0x4C && data[3] == 0x18) {
            return RamdiskFormat::Lz4Legacy;
        }
        if (data.size() >= 6 && data[0] == 0xFD && data[1] == 0x37 && data[2] == 0x7A && data[3] == 0x58 &&
            data[4] == 0x5A && data[5] == 0x00) {
            return RamdiskFormat::Xz;
        }
        if (data.size() >= 6 && std::memcmp(data.data(), "070701", 6) == 0) {
            return RamdiskFormat::Raw;
        }
        return RamdiskFormat::Unknown;
    }

    // ------------------------------------------------------------------ gzip //

    std::optional<std::vector<std::uint8_t>> GzipInflate(const std::vector<std::uint8_t> &data) {
        if (data.size() < 18 || data[0] != 0x1F || data[1] != 0x8B || data[2] != 0x08) {
            return std::nullopt;
        }
        const std::uint8_t flags = data[3];
        std::size_t off = 10;
        if ((flags & 0x04U) != 0) { // FEXTRA
            if (off + 2 > data.size()) {
                return std::nullopt;
            }
            const std::size_t xlen = static_cast<std::size_t>(data[off]) | (static_cast<std::size_t>(data[off + 1]) << 8);
            off += 2 + xlen;
        }
        if ((flags & 0x08U) != 0) { // FNAME
            while (off < data.size() && data[off] != 0) {
                ++off;
            }
            ++off;
        }
        if ((flags & 0x10U) != 0) { // FCOMMENT
            while (off < data.size() && data[off] != 0) {
                ++off;
            }
            ++off;
        }
        if ((flags & 0x02U) != 0) { // FHCRC
            off += 2;
        }
        if (off + 8 > data.size()) {
            return std::nullopt;
        }
        const std::size_t deflateLen = data.size() - off - 8;
        std::size_t outLen = 0;
        void *out = tinfl_decompress_mem_to_heap(data.data() + off, deflateLen, &outLen, 0);
        if (out == nullptr) {
            // A valid stream for empty data carries ISIZE=0; tinfl returns null for 0 output.
            if (Read32LE(data, data.size() - 4) == 0) {
                return std::vector<std::uint8_t>{};
            }
            return std::nullopt;
        }
        std::vector<std::uint8_t> result(static_cast<std::uint8_t *>(out), static_cast<std::uint8_t *>(out) + outLen);
        mz_free(out);
        return result;
    }

    std::vector<std::uint8_t> GzipDeflate(const std::vector<std::uint8_t> &data, const int level) {
        std::vector<std::uint8_t> out;
        // Header: magic, CM=deflate, no flags, mtime=0, XFL=0, OS=255 (unknown).
        const std::array<std::uint8_t, 10> header = {0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0, 0xFF};
        out.insert(out.end(), header.begin(), header.end());

        const int clamped = std::clamp(level, 0, 10);
        const mz_uint flags = tdefl_create_comp_flags_from_zip_params(clamped, -15, MZ_DEFAULT_STRATEGY);
        std::size_t deflateLen = 0;
        void *deflated = tdefl_compress_mem_to_heap(data.data(), data.size(), &deflateLen, flags);
        if (deflated != nullptr) {
            out.insert(out.end(), static_cast<std::uint8_t *>(deflated), static_cast<std::uint8_t *>(deflated) + deflateLen);
            mz_free(deflated);
        }

        const mz_ulong crc = mz_crc32(MZ_CRC32_INIT, data.data(), data.size());
        Put32LE(out, static_cast<std::uint32_t>(crc));
        Put32LE(out, static_cast<std::uint32_t>(data.size() & 0xFFFFFFFFULL));
        return out;
    }

    // --------------------------------------------------------------- lz4 legacy //

    std::optional<std::vector<std::uint8_t>> Lz4LegacyDecompress(const std::vector<std::uint8_t> &data) {
        if (data.size() < 4 || data[0] != 0x02 || data[1] != 0x21 || data[2] != 0x4C || data[3] != 0x18) {
            return std::nullopt;
        }
        std::vector<std::uint8_t> out;
        std::size_t pos = 4;
        while (pos + 4 <= data.size()) {
            const std::uint32_t blockSize = Read32LE(data, pos);
            // A new frame magic marks the end of this frame's blocks.
            if (blockSize == 0x184C2102U) {
                pos += 4;
                continue;
            }
            pos += 4;
            if (blockSize == 0 || pos + blockSize > data.size()) {
                break;
            }
            // Decode one LZ4 block.
            const std::size_t end = pos + blockSize;
            std::size_t ip = pos;
            while (ip < end) {
                const std::uint8_t token = data[ip++];
                std::size_t literalLen = token >> 4;
                if (literalLen == 15) {
                    while (ip < end) {
                        const std::uint8_t add = data[ip++];
                        literalLen += add;
                        if (add != 255) {
                            break;
                        }
                    }
                }
                if (ip + literalLen > end) {
                    return std::nullopt;
                }
                out.insert(out.end(), data.begin() + static_cast<std::ptrdiff_t>(ip), data.begin() + static_cast<std::ptrdiff_t>(ip + literalLen));
                ip += literalLen;
                if (ip >= end) {
                    break; // last sequence: literals only
                }
                if (ip + 2 > end) {
                    return std::nullopt;
                }
                const std::size_t offset = static_cast<std::size_t>(data[ip]) | (static_cast<std::size_t>(data[ip + 1]) << 8);
                ip += 2;
                if (offset == 0 || offset > out.size()) {
                    return std::nullopt;
                }
                std::size_t matchLen = token & 0x0FU;
                if (matchLen == 15) {
                    while (ip < end) {
                        const std::uint8_t add = data[ip++];
                        matchLen += add;
                        if (add != 255) {
                            break;
                        }
                    }
                }
                matchLen += 4; // MINMATCH
                std::size_t src = out.size() - offset;
                for (std::size_t i = 0; i < matchLen; ++i) {
                    out.push_back(out[src + i]);
                }
            }
            pos = end;
        }
        return out;
    }

    std::vector<std::uint8_t> Lz4LegacyCompress(const std::vector<std::uint8_t> &data) {
        std::vector<std::uint8_t> out = {0x02, 0x21, 0x4C, 0x18};

        auto compressBlock = [&](const std::uint8_t *in, const std::size_t len) -> std::vector<std::uint8_t> {
            std::vector<std::uint8_t> block;
            std::vector<int> hashTable(static_cast<std::size_t>(1) << LZ4_HASH_BITS, -1);
            const auto hash4 = [](const std::uint8_t *p) {
                std::uint32_t v = 0;
                std::memcpy(&v, p, 4);
                return (v * 2654435761U) >> (32 - LZ4_HASH_BITS);
            };
            const auto emitLiterals = [&](std::size_t anchor, std::size_t ip, const int matchField) {
                const std::size_t litLen = ip - anchor;
                std::uint8_t token = static_cast<std::uint8_t>(matchField & 0x0F);
                if (litLen >= 15) {
                    token |= 0xF0;
                    block.push_back(token);
                    std::size_t remaining = litLen - 15;
                    while (remaining >= 255) {
                        block.push_back(255);
                        remaining -= 255;
                    }
                    block.push_back(static_cast<std::uint8_t>(remaining));
                } else {
                    token |= static_cast<std::uint8_t>(litLen << 4);
                    block.push_back(token);
                }
                block.insert(block.end(), in + anchor, in + ip);
            };

            std::size_t ip = 0;
            std::size_t anchor = 0;
            if (len >= static_cast<std::size_t>(LZ4_MFLIMIT)) {
                const std::size_t matchLimit = len - LZ4_LASTLITERALS;
                const std::size_t mfLimit = len - LZ4_MFLIMIT;
                while (ip < mfLimit) {
                    const std::uint32_t h = hash4(in + ip);
                    const int ref = hashTable[h];
                    hashTable[h] = static_cast<int>(ip);
                    if (ref >= 0 && (ip - static_cast<std::size_t>(ref)) <= 65535 &&
                        std::memcmp(in + ref, in + ip, LZ4_MINMATCH) == 0) {
                        std::size_t matchLen = LZ4_MINMATCH;
                        while (ip + matchLen < matchLimit &&
                               in[static_cast<std::size_t>(ref) + matchLen] == in[ip + matchLen]) {
                            ++matchLen;
                        }
                        const std::size_t offset = ip - static_cast<std::size_t>(ref);
                        const std::size_t extra = matchLen - LZ4_MINMATCH;
                        emitLiterals(anchor, ip, extra >= 15 ? 15 : static_cast<int>(extra));
                        block.push_back(static_cast<std::uint8_t>(offset & 0xFF));
                        block.push_back(static_cast<std::uint8_t>((offset >> 8) & 0xFF));
                        if (extra >= 15) {
                            std::size_t remaining = extra - 15;
                            while (remaining >= 255) {
                                block.push_back(255);
                                remaining -= 255;
                            }
                            block.push_back(static_cast<std::uint8_t>(remaining));
                        }
                        ip += matchLen;
                        anchor = ip;
                    } else {
                        ++ip;
                    }
                }
            }
            // Final sequence: remaining literals only.
            emitLiterals(anchor, len, 0);
            return block;
        };

        std::size_t pos = 0;
        if (data.empty()) {
            const std::vector<std::uint8_t> block = compressBlock(data.data(), 0);
            Put32LE(out, static_cast<std::uint32_t>(block.size()));
            out.insert(out.end(), block.begin(), block.end());
            return out;
        }
        while (pos < data.size()) {
            const std::size_t chunk = std::min<std::size_t>(LZ4_BLOCK_MAX, data.size() - pos);
            const std::vector<std::uint8_t> block = compressBlock(data.data() + pos, chunk);
            Put32LE(out, static_cast<std::uint32_t>(block.size()));
            out.insert(out.end(), block.begin(), block.end());
            pos += chunk;
        }
        return out;
    }

    // ------------------------------------------------------------------ cpio //

    namespace {
        bool ReadHex8(const std::vector<std::uint8_t> &d, const std::size_t off, std::uint32_t &out) {
            std::uint32_t value = 0;
            for (std::size_t i = 0; i < 8; ++i) {
                const std::uint8_t c = d[off + i];
                value <<= 4;
                if (c >= '0' && c <= '9') {
                    value |= static_cast<std::uint32_t>(c - '0');
                } else if (c >= 'a' && c <= 'f') {
                    value |= static_cast<std::uint32_t>(c - 'a' + 10);
                } else if (c >= 'A' && c <= 'F') {
                    value |= static_cast<std::uint32_t>(c - 'A' + 10);
                } else {
                    return false;
                }
            }
            out = value;
            return true;
        }

        void WriteHex8(std::vector<std::uint8_t> &out, const std::uint32_t value) {
            char buffer[9];
            std::snprintf(buffer, sizeof(buffer), "%08x", value);
            out.insert(out.end(), buffer, buffer + 8);
        }

        void PadTo4(std::vector<std::uint8_t> &out) {
            while ((out.size() & 3U) != 0) {
                out.push_back(0);
            }
        }
    }

    std::optional<CpioArchive> ParseCpioNewc(const std::vector<std::uint8_t> &data) {
        CpioArchive archive;
        std::size_t pos = 0;
        while (pos + 110 <= data.size()) {
            if (std::memcmp(data.data() + pos, "070701", 6) != 0) {
                return std::nullopt;
            }
            std::uint32_t ino = 0;
            std::uint32_t mode = 0;
            std::uint32_t uid = 0;
            std::uint32_t gid = 0;
            std::uint32_t nlink = 0;
            std::uint32_t mtime = 0;
            std::uint32_t filesize = 0;
            std::uint32_t devmajor = 0;
            std::uint32_t devminor = 0;
            std::uint32_t rdevmajor = 0;
            std::uint32_t rdevminor = 0;
            std::uint32_t namesize = 0;
            if (!ReadHex8(data, pos + 6, ino) || !ReadHex8(data, pos + 14, mode) || !ReadHex8(data, pos + 22, uid) ||
                !ReadHex8(data, pos + 30, gid) || !ReadHex8(data, pos + 38, nlink) ||
                !ReadHex8(data, pos + 46, mtime) || !ReadHex8(data, pos + 54, filesize) ||
                !ReadHex8(data, pos + 62, devmajor) || !ReadHex8(data, pos + 70, devminor) ||
                !ReadHex8(data, pos + 78, rdevmajor) || !ReadHex8(data, pos + 86, rdevminor) ||
                !ReadHex8(data, pos + 94, namesize)) {
                return std::nullopt;
            }
            if (namesize == 0 || pos + 110 + namesize > data.size()) {
                return std::nullopt;
            }
            const char *namePtr = reinterpret_cast<const char *>(data.data() + pos + 110);
            std::string name(namePtr, namePtr + namesize - 1); // drop trailing NUL

            const std::size_t dataStart = pos + Align4(110U + namesize);
            if (name == "TRAILER!!!") {
                break;
            }
            if (dataStart + filesize > data.size()) {
                return std::nullopt;
            }

            CpioEntry entry;
            entry.Name = std::move(name);
            entry.Ino = ino;
            entry.Mode = mode;
            entry.Nlink = nlink;
            entry.Uid = uid;
            entry.Gid = gid;
            entry.Mtime = mtime;
            entry.DevMajor = devmajor;
            entry.DevMinor = devminor;
            entry.RdevMajor = rdevmajor;
            entry.RdevMinor = rdevminor;
            entry.Data.assign(data.begin() + static_cast<std::ptrdiff_t>(dataStart), data.begin() + static_cast<std::ptrdiff_t>(dataStart + filesize));
            archive.push_back(std::move(entry));

            pos = dataStart + Align4(filesize);
        }
        return archive;
    }

    std::vector<std::uint8_t> SerializeCpioNewc(const CpioArchive &archive) {
        std::vector<std::uint8_t> out;
        const auto writeRecord = [&out](const CpioEntry &e) {
            const std::uint32_t namesize = static_cast<std::uint32_t>(e.Name.size()) + 1;
            out.insert(out.end(), {'0', '7', '0', '7', '0', '1'});
            WriteHex8(out, e.Ino);
            WriteHex8(out, e.Mode);
            WriteHex8(out, e.Uid);
            WriteHex8(out, e.Gid);
            WriteHex8(out, e.Nlink);
            WriteHex8(out, e.Mtime);
            WriteHex8(out, static_cast<std::uint32_t>(e.Data.size()));
            WriteHex8(out, e.DevMajor);
            WriteHex8(out, e.DevMinor);
            WriteHex8(out, e.RdevMajor);
            WriteHex8(out, e.RdevMinor);
            WriteHex8(out, namesize);
            WriteHex8(out, 0); // check (newc = 0)
            out.insert(out.end(), e.Name.begin(), e.Name.end());
            out.push_back(0);
            PadTo4(out);
            out.insert(out.end(), e.Data.begin(), e.Data.end());
            PadTo4(out);
        };

        for (const CpioEntry &entry: archive) {
            writeRecord(entry);
        }

        CpioEntry trailer;
        trailer.Name = "TRAILER!!!";
        trailer.Ino = 0;
        trailer.Mode = 0;
        trailer.Nlink = 1;
        writeRecord(trailer);
        return out;
    }

    CpioArchive MergeCpio(const std::vector<CpioArchive> &archives) {
        CpioArchive merged;
        for (const CpioArchive &archive: archives) {
            for (const CpioEntry &entry: archive) {
                const auto it = std::find_if(merged.begin(), merged.end(), [&entry](const CpioEntry &existing) {
                    return existing.Name == entry.Name;
                });
                if (it != merged.end()) {
                    *it = entry; // later wins
                } else {
                    merged.push_back(entry);
                }
            }
        }
        return merged;
    }

    // --------------------------------------------------------------- Magisk //

    namespace {
        struct GhAsset {
            std::string name; // NOLINT(readability-identifier-naming)
            std::string browser_download_url; // NOLINT(readability-identifier-naming)
            std::uint64_t size = 0; // NOLINT(readability-identifier-naming)
        };

        struct GhRelease {
            std::string tag_name; // NOLINT(readability-identifier-naming)
            bool prerelease = false; // NOLINT(readability-identifier-naming)
            bool draft = false; // NOLINT(readability-identifier-naming)
            std::vector<GhAsset> assets; // NOLINT(readability-identifier-naming)
        };

        bool EndsWithApk(const std::string &name) {
            return name.size() >= 4 && name.compare(name.size() - 4, 4, ".apk") == 0;
        }
    }

    std::optional<MagiskRelease> ParseMagiskReleases(const std::string &json, const bool includePrerelease) {
        try {
            const auto parsed = rfl::json::read<std::vector<GhRelease>, rfl::DefaultIfMissing>(json);
            if (!parsed) {
                return std::nullopt;
            }
            // GitHub returns releases newest-first; take the first match.
            for (const GhRelease &release: parsed.value()) {
                if (release.draft || release.tag_name.empty()) {
                    continue;
                }
                if (release.prerelease && !includePrerelease) {
                    continue;
                }
                for (const GhAsset &asset: release.assets) {
                    if (!EndsWithApk(asset.name)) {
                        continue;
                    }
                    MagiskRelease result;
                    result.Tag = release.tag_name;
                    result.Channel = release.prerelease ? MagiskChannel::Prerelease : MagiskChannel::Stable;
                    result.Url = asset.browser_download_url;
                    result.FileName = asset.name;
                    result.Size = asset.size;
                    return result;
                }
            }
            return std::nullopt;
        } catch (...) {
            return std::nullopt;
        }
    }

    std::optional<MagiskApkInfo> ParseMagiskApk(const std::vector<std::uint8_t> &apkBytes) {
        mz_zip_archive zip = {};
        if (mz_zip_reader_init_mem(&zip, apkBytes.data(), apkBytes.size(), 0) == MZ_FALSE) {
            return std::nullopt;
        }
        std::vector<std::string> abis;
        const mz_uint count = mz_zip_reader_get_num_files(&zip);
        for (mz_uint i = 0; i < count; ++i) {
            char nameBuf[512];
            const mz_uint len = mz_zip_reader_get_filename(&zip, i, nameBuf, sizeof(nameBuf));
            if (len == 0) {
                continue;
            }
            const std::string name(nameBuf, len > 0 ? len - 1 : 0); // len includes NUL
            constexpr std::string_view LIB = "lib/";
            if (name.size() <= LIB.size() || name.compare(0, LIB.size(), LIB) != 0) {
                continue;
            }
            const std::size_t slash = name.find('/', LIB.size());
            if (slash == std::string::npos) {
                continue;
            }
            const std::string abi = name.substr(LIB.size(), slash - LIB.size());
            if (!abi.empty() && std::find(abis.begin(), abis.end(), abi) == abis.end()) {
                abis.push_back(abi);
            }
        }
        mz_zip_reader_end(&zip);
        std::sort(abis.begin(), abis.end());
        return MagiskApkInfo{abis};
    }

    MagiskResolveDeps DefaultMagiskResolveDeps() {
        MagiskResolveDeps deps;
        deps.HttpGet = [](const std::string &url) {
            return Platform::HttpGetString(url, MAGISK_USER_AGENT, "application/vnd.github+json");
        };
        deps.Download = [](const std::string &url, const std::string &destPath, std::string &error) {
            return Platform::HttpDownloadToFile(
                url,
                destPath,
                MAGISK_USER_AGENT,
                [](std::uint64_t, std::uint64_t) { return true; },
                error
            );
        };
        deps.FileSha256 = [](const std::string &path) { return Platform::Sha256File(path); };
        deps.CacheDir = Platform::JoinPaths({Platform::GetConfigDirectory(), "magisk"});
        return deps;
    }

    std::optional<ResolvedMagisk> ResolveMagisk(
        const MagiskResolveDeps &deps,
        const bool includePrerelease,
        const bool allowDownload,
        const std::string &overridePath,
        std::string &error
    ) {
        namespace fs = std::filesystem;
        MagiskRelease release;
        std::string localPath;

        if (!overridePath.empty()) {
            if (!fs::exists(overridePath)) {
                error = "Magisk file not found: " + overridePath;
                return std::nullopt;
            }
            localPath = overridePath;
            release.Tag = "(local)";
            release.FileName = fs::path(overridePath).filename().string();
        } else {
            if (!deps.HttpGet) {
                error = "No network access is configured.";
                return std::nullopt;
            }
            const auto body = deps.HttpGet(MAGISK_RELEASES_URL);
            if (!body) {
                error = "Could not reach the Magisk releases API.";
                return std::nullopt;
            }
            const auto picked = ParseMagiskReleases(*body, includePrerelease);
            if (!picked) {
                error = "No suitable Magisk release was found.";
                return std::nullopt;
            }
            release = *picked;
            if (deps.CacheDir.empty()) {
                error = "No cache directory is configured.";
                return std::nullopt;
            }
            std::error_code ec;
            fs::create_directories(deps.CacheDir, ec);
            localPath = Platform::JoinPaths({deps.CacheDir, release.FileName});
            if (!fs::exists(localPath)) {
                if (!allowDownload) {
                    error = "Magisk is not cached and downloads are disabled.";
                    return std::nullopt;
                }
                if (!deps.Download) {
                    error = "No downloader is configured.";
                    return std::nullopt;
                }
                std::string downloadError;
                if (!deps.Download(release.Url, localPath, downloadError)) {
                    error = "Download failed: " + downloadError;
                    return std::nullopt;
                }
            }
        }

        ResolvedMagisk resolved;
        resolved.Release = release;
        resolved.LocalPath = localPath;
        if (deps.FileSha256) {
            resolved.Sha256 = deps.FileSha256(localPath);
        }
        if (const auto bytes = ReadFileBytes(localPath)) {
            if (const auto info = ParseMagiskApk(*bytes)) {
                resolved.Info = *info;
            }
        }
        return resolved;
    }

    // ------------------------------------------------------------ root check //

    const char *RootStatusName(const RootStatus status) {
        switch (status) {
            case RootStatus::Rooted:
                return "rooted";
            case RootStatus::NotRooted:
                return "not rooted";
            case RootStatus::Unknown:
            default:
                return "unknown";
        }
    }

    bool ParseRootId(const std::string &idOutput) {
        if (idOutput.find("uid=0(root)") != std::string::npos) {
            return true;
        }
        // Fall back to a bare "uid=0" at the start of a line.
        if (idOutput.compare(0, 6, "uid=0 ") == 0 || idOutput == "uid=0" ||
            idOutput.compare(0, 6, "uid=0\t") == 0) {
            return true;
        }
        return false;
    }

    RootStatus CheckRoot(const SdkInfo &sdk, const std::string &serial) {
        if (ResolveAdbPath(sdk).empty() || serial.empty()) {
            return RootStatus::Unknown;
        }
        const AdbResult result = ShellSu(sdk, serial, "id");
        if (!result.Started) {
            return RootStatus::Unknown;
        }
        return ParseRootId(result.Output) ? RootStatus::Rooted : RootStatus::NotRooted;
    }

    // ------------------------------------------------------------ stage labels //

    const char *RootStageLabel(const RootStage stage) {
        switch (stage) {
            case RootStage::ResolveMagisk:
                return "Resolve Magisk";
            case RootStage::StartEmulator:
                return "Start emulator";
            case RootStage::ReadPreinit:
                return "Read preinit device";
            case RootStage::WriteMagiskEnv:
                return "Write Magisk environment";
            case RootStage::PatchRamdisk:
                return "Patch ramdisk";
            case RootStage::ColdReboot:
                return "Cold reboot";
            case RootStage::GrantSu:
                return "Grant su";
            case RootStage::Verify:
                return "Verify root";
            case RootStage::Done:
                return "Done";
            case RootStage::Failed:
                return "Failed";
            case RootStage::Idle:
            default:
                return "Idle";
        }
    }
}
