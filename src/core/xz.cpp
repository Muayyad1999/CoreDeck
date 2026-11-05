//
// Created by CoreDeck RE toolbench on 05/11/2026.
//

#include <cstdint>
#include <optional>
#include <vector>

#include "core/xz.h"

extern "C" {
#include <xz.h> // vendored XZ Embedded (extern/xz_embedded)
}

namespace CoreDeck::Core {
    std::optional<std::vector<std::uint8_t>> XzDecompress(const std::vector<std::uint8_t> &data) {
        if (data.empty()) {
            return std::nullopt;
        }

        xz_crc32_init();
        xz_crc64_init();

        // DYNALLOC grows the dictionary as needed, up to this cap.
        xz_dec *dec = xz_dec_init(XZ_DYNALLOC, 1U << 27); // 128 MiB
        if (dec == nullptr) {
            return std::nullopt;
        }

        std::vector<std::uint8_t> out;
        std::vector<std::uint8_t> chunk(1U << 20); // 1 MiB output window

        xz_buf buf;
        buf.in = data.data();
        buf.in_pos = 0;
        buf.in_size = data.size();

        bool ok = true;
        bool done = false;
        while (!done) {
            buf.out = chunk.data();
            buf.out_pos = 0;
            buf.out_size = chunk.size();

            const xz_ret ret = xz_dec_run(dec, &buf);
            out.insert(out.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(buf.out_pos));

            if (ret == XZ_STREAM_END) {
                done = true;
            } else if (ret == XZ_OK || ret == XZ_UNSUPPORTED_CHECK) {
                // XZ_OK means it needs more input or more output space. If the
                // output window was not filled and the input is exhausted, the
                // stream is truncated.
                if (buf.in_pos == buf.in_size && buf.out_pos < chunk.size()) {
                    ok = false;
                    done = true;
                }
            } else {
                ok = false;
                done = true;
            }
        }

        xz_dec_end(dec);
        if (!ok) {
            return std::nullopt;
        }
        return out;
    }
}
