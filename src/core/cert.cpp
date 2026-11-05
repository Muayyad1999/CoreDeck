//
// Created by CoreDeck RE toolbench on 05/11/2026.
//

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include "core/cert.h"
#include "core/adb.h"
#include "platform/paths.h"

namespace CoreDeck::Core {
    namespace {
        // ------------------------------------------------------------------ MD5 //
        struct Md5 {
            std::uint32_t a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
            std::uint64_t total = 0;
            std::array<std::uint8_t, 64> buffer{};
            std::size_t bufLen = 0;

            static std::uint32_t Rol(std::uint32_t x, int c) {
                return (x << c) | (x >> (32 - c));
            }

            void Block(const std::uint8_t *p) {
                static const std::array<std::uint32_t, 64> K = {
                    0xd76aa478,
                    0xe8c7b756,
                    0x242070db,
                    0xc1bdceee,
                    0xf57c0faf,
                    0x4787c62a,
                    0xa8304613,
                    0xfd469501,
                    0x698098d8,
                    0x8b44f7af,
                    0xffff5bb1,
                    0x895cd7be,
                    0x6b901122,
                    0xfd987193,
                    0xa679438e,
                    0x49b40821,
                    0xf61e2562,
                    0xc040b340,
                    0x265e5a51,
                    0xe9b6c7aa,
                    0xd62f105d,
                    0x02441453,
                    0xd8a1e681,
                    0xe7d3fbc8,
                    0x21e1cde6,
                    0xc33707d6,
                    0xf4d50d87,
                    0x455a14ed,
                    0xa9e3e905,
                    0xfcefa3f8,
                    0x676f02d9,
                    0x8d2a4c8a,
                    0xfffa3942,
                    0x8771f681,
                    0x6d9d6122,
                    0xfde5380c,
                    0xa4beea44,
                    0x4bdecfa9,
                    0xf6bb4b60,
                    0xbebfbc70,
                    0x289b7ec6,
                    0xeaa127fa,
                    0xd4ef3085,
                    0x04881d05,
                    0xd9d4d039,
                    0xe6db99e5,
                    0x1fa27cf8,
                    0xc4ac5665,
                    0xf4292244,
                    0x432aff97,
                    0xab9423a7,
                    0xfc93a039,
                    0x655b59c3,
                    0x8f0ccc92,
                    0xffeff47d,
                    0x85845dd1,
                    0x6fa87e4f,
                    0xfe2ce6e0,
                    0xa3014314,
                    0x4e0811a1,
                    0xf7537e82,
                    0xbd3af235,
                    0x2ad7d2bb,
                    0xeb86d391
                };
                static const std::array<int, 64> S = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
                std::array<std::uint32_t, 16> M{};
                for (int i = 0; i < 16; ++i) {
                    M[i] = static_cast<std::uint32_t>(p[i * 4]) | (static_cast<std::uint32_t>(p[i * 4 + 1]) << 8) |
                           (static_cast<std::uint32_t>(p[i * 4 + 2]) << 16) |
                           (static_cast<std::uint32_t>(p[i * 4 + 3]) << 24);
                }
                std::uint32_t a = a0, b = b0, c = c0, d = d0;
                for (int i = 0; i < 64; ++i) {
                    std::uint32_t f = 0;
                    int g = 0;
                    if (i < 16) {
                        f = (b & c) | (~b & d);
                        g = i;
                    } else if (i < 32) {
                        f = (d & b) | (~d & c);
                        g = (5 * i + 1) % 16;
                    } else if (i < 48) {
                        f = b ^ c ^ d;
                        g = (3 * i + 5) % 16;
                    } else {
                        f = c ^ (b | ~d);
                        g = (7 * i) % 16;
                    }
                    f = f + a + K[i] + M[g];
                    a = d;
                    d = c;
                    c = b;
                    b = b + Rol(f, S[i]);
                }
                a0 += a;
                b0 += b;
                c0 += c;
                d0 += d;
            }

            void Update(const std::uint8_t *data, std::size_t len) {
                total += len;
                while (len > 0) {
                    const std::size_t take = std::min<std::size_t>(64 - bufLen, len);
                    std::memcpy(buffer.data() + bufLen, data, take);
                    bufLen += take;
                    data += take;
                    len -= take;
                    if (bufLen == 64) {
                        Block(buffer.data());
                        bufLen = 0;
                    }
                }
            }

            std::array<std::uint8_t, 16> Finish() {
                const std::uint64_t bits = total * 8;
                std::uint8_t pad = 0x80;
                Update(&pad, 1);
                pad = 0;
                while (bufLen != 56) {
                    Update(&pad, 1);
                }
                std::array<std::uint8_t, 8> lenBytes{};
                for (int i = 0; i < 8; ++i) {
                    lenBytes[i] = static_cast<std::uint8_t>((bits >> (8 * i)) & 0xFF);
                }
                Update(lenBytes.data(), 8);
                std::array<std::uint8_t, 16> out{};
                const std::array<std::uint32_t, 4> v = {a0, b0, c0, d0};
                for (int i = 0; i < 4; ++i) {
                    out[i * 4] = static_cast<std::uint8_t>(v[i] & 0xFF);
                    out[i * 4 + 1] = static_cast<std::uint8_t>((v[i] >> 8) & 0xFF);
                    out[i * 4 + 2] = static_cast<std::uint8_t>((v[i] >> 16) & 0xFF);
                    out[i * 4 + 3] = static_cast<std::uint8_t>((v[i] >> 24) & 0xFF);
                }
                return out;
            }
        };

        std::array<std::uint8_t, 16> Md5Digest(const std::vector<std::uint8_t> &data) {
            Md5 md5;
            md5.Update(data.data(), data.size());
            return md5.Finish();
        }

        // --------------------------------------------------------------- base64 //
        int Base64Value(const char c) {
            if (c >= 'A' && c <= 'Z') {
                return c - 'A';
            }
            if (c >= 'a' && c <= 'z') {
                return c - 'a' + 26;
            }
            if (c >= '0' && c <= '9') {
                return c - '0' + 52;
            }
            if (c == '+') {
                return 62;
            }
            if (c == '/') {
                return 63;
            }
            return -1;
        }

        std::vector<std::uint8_t> Base64Decode(const std::string &input) {
            std::vector<std::uint8_t> out;
            int buffer = 0;
            int bits = 0;
            for (const char c: input) {
                if (c == '=') {
                    break;
                }
                const int value = Base64Value(c);
                if (value < 0) {
                    continue; // skip whitespace / newlines
                }
                buffer = (buffer << 6) | value;
                bits += 6;
                if (bits >= 8) {
                    bits -= 8;
                    out.push_back(static_cast<std::uint8_t>((buffer >> bits) & 0xFF));
                }
            }
            return out;
        }

        std::string Base64Encode(const std::vector<std::uint8_t> &data) {
            static const char *T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string out;
            std::size_t i = 0;
            while (i + 3 <= data.size()) {
                const std::uint32_t n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
                out.push_back(T[(n >> 18) & 63]);
                out.push_back(T[(n >> 12) & 63]);
                out.push_back(T[(n >> 6) & 63]);
                out.push_back(T[n & 63]);
                i += 3;
            }
            if (data.size() - i == 1) {
                const std::uint32_t n = data[i] << 16;
                out.push_back(T[(n >> 18) & 63]);
                out.push_back(T[(n >> 12) & 63]);
                out.append("==");
            } else if (data.size() - i == 2) {
                const std::uint32_t n = (data[i] << 16) | (data[i + 1] << 8);
                out.push_back(T[(n >> 18) & 63]);
                out.push_back(T[(n >> 12) & 63]);
                out.push_back(T[(n >> 6) & 63]);
                out.push_back('=');
            }
            return out;
        }

        // ---------------------------------------------------------------- DER walk //
        // Return {valueStart, contentLen} for the TLV beginning at index i.
        std::optional<std::pair<std::size_t, std::size_t>> ReadTlv(
            const std::vector<std::uint8_t> &b, const std::size_t i
        ) {
            if (i + 2 > b.size()) {
                return std::nullopt;
            }
            std::size_t j = i + 1;
            std::size_t len = b[j];
            ++j;
            if ((len & 0x80U) != 0) {
                const std::size_t n = len & 0x7FU;
                if (n == 0 || n > 4 || j + n > b.size()) {
                    return std::nullopt;
                }
                len = 0;
                for (std::size_t k = 0; k < n; ++k) {
                    len = (len << 8) | b[j + k];
                }
                j += n;
            }
            if (j + len > b.size()) {
                return std::nullopt;
            }
            return std::make_pair(j, len);
        }

        std::string DerToPem(const std::vector<std::uint8_t> &der) {
            const std::string b64 = Base64Encode(der);
            std::string pem = "-----BEGIN CERTIFICATE-----\n";
            for (std::size_t i = 0; i < b64.size(); i += 64) {
                pem += b64.substr(i, 64);
                pem += '\n';
            }
            pem += "-----END CERTIFICATE-----\n";
            return pem;
        }

        std::optional<std::vector<std::uint8_t>> ReadFileBytes(const std::string &path) {
            std::ifstream file(path, std::ios::binary);
            if (!file) {
                return std::nullopt;
            }
            return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        }

        int DeviceApi(const SdkInfo &sdk, const std::string &serial) {
            const std::string value = GetDeviceProp(sdk, serial, "ro.build.version.sdk");
            try {
                return value.empty() ? 0 : std::stoi(value);
            } catch (...) {
                return 0;
            }
        }
    }

    std::string Md5Hex(const std::vector<std::uint8_t> &data) {
        const auto digest = Md5Digest(data);
        std::string hex;
        hex.reserve(32);
        char buf[3];
        for (const std::uint8_t byte: digest) {
            std::snprintf(buf, sizeof(buf), "%02x", byte);
            hex += buf;
        }
        return hex;
    }

    std::optional<std::vector<std::uint8_t>> CertToDer(const std::vector<std::uint8_t> &certBytes) {
        const std::string text(certBytes.begin(), certBytes.end());
        const std::string begin = "-----BEGIN CERTIFICATE-----";
        const std::size_t start = text.find(begin);
        if (start != std::string::npos) {
            const std::size_t bodyStart = start + begin.size();
            const std::size_t end = text.find("-----END CERTIFICATE-----", bodyStart);
            if (end == std::string::npos) {
                return std::nullopt;
            }
            const auto der = Base64Decode(text.substr(bodyStart, end - bodyStart));
            if (der.empty()) {
                return std::nullopt;
            }
            return der;
        }
        if (!certBytes.empty() && certBytes[0] == 0x30) {
            return certBytes; // already DER
        }
        return std::nullopt;
    }

    std::optional<std::vector<std::uint8_t>> ExtractSubjectDer(const std::vector<std::uint8_t> &derCert) {
        const auto cert = ReadTlv(derCert, 0); // Certificate SEQUENCE
        if (!cert) {
            return std::nullopt;
        }
        const auto tbs = ReadTlv(derCert, cert->first); // tbsCertificate SEQUENCE
        if (!tbs) {
            return std::nullopt;
        }
        std::size_t i = tbs->first;
        if (i < derCert.size() && derCert[i] == 0xA0) { // optional [0] version
            const auto v = ReadTlv(derCert, i);
            if (!v) {
                return std::nullopt;
            }
            i = v->first + v->second;
        }
        for (int field = 0; field < 4; ++field) { // serialNumber, signature, issuer, validity
            const auto v = ReadTlv(derCert, i);
            if (!v) {
                return std::nullopt;
            }
            i = v->first + v->second;
        }
        const std::size_t start = i; // subject Name SEQUENCE (full TLV)
        const auto subject = ReadTlv(derCert, i);
        if (!subject) {
            return std::nullopt;
        }
        const std::size_t end = subject->first + subject->second;
        if (end > derCert.size()) {
            return std::nullopt;
        }
        return std::vector<std::uint8_t>(derCert.begin() + static_cast<std::ptrdiff_t>(start), derCert.begin() + static_cast<std::ptrdiff_t>(end));
    }

    std::optional<std::string> SubjectHashOld(const std::vector<std::uint8_t> &certBytes) {
        const auto der = CertToDer(certBytes);
        if (!der) {
            return std::nullopt;
        }
        const auto subject = ExtractSubjectDer(*der);
        if (!subject) {
            return std::nullopt;
        }
        const auto digest = Md5Digest(*subject);
        const std::uint32_t value = static_cast<std::uint32_t>(digest[0]) |
                                    (static_cast<std::uint32_t>(digest[1]) << 8) |
                                    (static_cast<std::uint32_t>(digest[2]) << 16) |
                                    (static_cast<std::uint32_t>(digest[3]) << 24);
        char buf[9];
        std::snprintf(buf, sizeof(buf), "%08x", value);
        return std::string(buf);
    }

    std::optional<CaCertInfo> InspectCaCert(const std::vector<std::uint8_t> &certBytes) {
        const auto hash = SubjectHashOld(certBytes);
        if (!hash) {
            return std::nullopt;
        }
        return CaCertInfo{*hash, *hash + ".0"};
    }

    std::optional<CaCertInfo> InspectCaCertFile(const std::string &path) {
        const auto bytes = ReadFileBytes(path);
        if (!bytes) {
            return std::nullopt;
        }
        return InspectCaCert(*bytes);
    }

    std::optional<std::string> InstallCaCert(
        const SdkInfo &sdk, const std::string &serial, const std::string &certPath, std::string &error
    ) {
        const auto bytes = ReadFileBytes(certPath);
        if (!bytes) {
            error = "Cannot read the certificate file: " + certPath;
            return std::nullopt;
        }
        const auto der = CertToDer(*bytes);
        if (!der) {
            error = "The file is not a PEM or DER certificate.";
            return std::nullopt;
        }
        const auto hash = SubjectHashOld(*bytes);
        if (!hash) {
            error = "Could not compute the certificate subject hash.";
            return std::nullopt;
        }
        const std::string name = *hash + ".0";

        const std::string cacheDir = Platform::JoinPaths({Platform::GetConfigDirectory(), "cacerts"});
        std::error_code ec;
        std::filesystem::create_directories(cacheDir, ec);
        const std::string localPem = Platform::JoinPaths({cacheDir, name});
        {
            std::ofstream out(localPem, std::ios::binary | std::ios::trunc);
            if (!out) {
                error = "Cannot write the certificate to the cache directory.";
                return std::nullopt;
            }
            const std::string pem = DerToPem(*der);
            out.write(pem.data(), static_cast<std::streamsize>(pem.size()));
        }

        const std::string devTmp = "/data/local/tmp/" + name;
        const AdbResult push = Push(sdk, serial, localPem, devTmp);
        if (!push.Ok()) {
            error = "adb push failed: " + push.Output;
            return std::nullopt;
        }

        const int api = DeviceApi(sdk, serial);
        const std::string store = "/system/etc/security/cacerts";
        std::string script;
        if (api >= 34) {
            script = "set -e; d=" + store +
                     "; mkdir -p -m 700 /data/local/tmp/cacopy; "
                     "cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/cacopy/ 2>/dev/null || true; "
                     "mount -t tmpfs tmpfs $d; "
                     "cp /data/local/tmp/cacopy/* $d/ 2>/dev/null || true; "
                     "cp " +
                     devTmp + " $d/" + name +
                     "; chown 0:0 $d/*; chmod 644 $d/*; "
                     "chcon u:object_r:system_security_cacerts_file:s0 $d/* 2>/dev/null || true; echo OK";
        } else {
            script = "set -e; mount -o rw,remount / 2>/dev/null || mount -o rw,remount /system; cp " + devTmp + " " +
                     store + "/" + name + "; chown 0:0 " + store + "/" + name + "; chmod 644 " + store + "/" + name +
                     "; chcon u:object_r:system_security_cacerts_file:s0 " + store + "/" + name +
                     " 2>/dev/null || true; echo OK";
        }

        const AdbResult result = ShellSu(sdk, serial, script);
        if (!result.Ok() || result.Output.find("OK") == std::string::npos) {
            error = "System install failed (device not rooted, or su denied). " + result.Output;
            return std::nullopt;
        }
        return name;
    }

    bool RemoveCaCert(const SdkInfo &sdk, const std::string &serial, const std::string &name, std::string &error) {
        const std::string store = "/system/etc/security/cacerts";
        const std::string script = "mount -o rw,remount / 2>/dev/null || mount -o rw,remount /system; rm -f " + store +
                                   "/" + name + "; echo OK";
        const AdbResult result = ShellSu(sdk, serial, script);
        if (!result.Ok() || result.Output.find("OK") == std::string::npos) {
            error = "Removal failed (device not rooted, or su denied). " + result.Output;
            return false;
        }
        return true;
    }
}
