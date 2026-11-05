//
// Created by CoreDeck RE toolbench on 05/11/2026.
//

#ifndef COREDECK_XZ_H
#define COREDECK_XZ_H

#include <cstdint>
#include <optional>
#include <vector>

namespace CoreDeck::Core {
    // Decompress a .xz stream (LZMA2) using the vendored XZ Embedded decoder.
    // Returns nullopt on malformed/truncated input.
    std::optional<std::vector<std::uint8_t>> XzDecompress(const std::vector<std::uint8_t> &data);
}

#endif // COREDECK_XZ_H
