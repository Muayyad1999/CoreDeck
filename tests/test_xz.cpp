#include <cstdint>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "core/avd_root.h" // XzStoreCompress
#include "core/xz.h" // XzDecompress

using namespace CoreDeck::Core;
using namespace CoreDeck;

namespace {
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

    std::vector<std::uint8_t> Base64Decode(const std::string &input) {
        auto value = [](char c) -> int {
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
        };
        std::vector<std::uint8_t> out;
        int buffer = 0;
        int bits = 0;
        for (const char c: input) {
            if (c == '=') {
                break;
            }
            const int v = value(c);
            if (v < 0) {
                continue;
            }
            buffer = (buffer << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.push_back(static_cast<std::uint8_t>((buffer >> bits) & 0xFF));
            }
        }
        return out;
    }

    // "CoreDeck xz decode test. The quick brown fox jumps over the lazy dog. " x40,
    // compressed with: xz -9  (genuine LZMA2, not store mode).
    const char *REAL_XZ_B64 =
        "/Td6WFoAAATm1rRGAgAhARwAAAAQz1jM4ArvAFZdACGbykZlz0ozkPMHysrcgIQ1smzFESlX6AV93j0mj3Si/"
        "ghtPy9DVm6qW0gRXlcJaEvMpfHbZro+qHepiEp5/glV8prrhPS0QqzgjBMSBH5xa93rjbq4AAAAebrkcVf7G1AAAXLwFQAAAOePTKqxxGf7Ag"
        "AAAAAEWVo=";
}

TEST_CASE("XzDecompress round-trips our store-mode encoder", "[xz]") {
    for (const auto &sample: {FromString("x"), FromString("hello world"), Repeat("ABCABC", 3000), Repeat("\x00\x01\x02\x03", 5000)}) {
        const auto compressed = XzStoreCompress(sample);
        const auto back = XzDecompress(compressed);
        REQUIRE(back.has_value());
        REQUIRE(*back == sample);
    }
}

TEST_CASE("XzDecompress decodes a genuine xz -9 (LZMA2) stream", "[xz]") {
    const auto xz = Base64Decode(REAL_XZ_B64);
    const auto decoded = XzDecompress(xz);
    REQUIRE(decoded.has_value());

    const std::string expected = [] {
        std::string s;
        for (int i = 0; i < 40; ++i) {
            s += "CoreDeck xz decode test. The quick brown fox jumps over the lazy dog. ";
        }
        return s;
    }();
    REQUIRE(std::string(decoded->begin(), decoded->end()) == expected);
}

TEST_CASE("XzDecompress rejects non-xz input", "[xz]") {
    REQUIRE_FALSE(XzDecompress(FromString("not an xz stream")).has_value());
    REQUIRE_FALSE(XzDecompress({}).has_value());
}
