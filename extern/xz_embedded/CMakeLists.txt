# XZ Embedded (0BSD) - decode-only. Vendored from tukaani-project/xz-embedded.
# Used to decompress .xz payloads (frida-server, xz-compressed ramdisks).
add_library(xz_embedded STATIC
    xz_crc32.c
    xz_crc64.c
    xz_dec_stream.c
    xz_dec_lzma2.c
)

target_include_directories(xz_embedded PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# CRC32 is always built. Enable CRC64 (xz's default check), tolerate any check
# type, and support concatenated streams.
target_compile_definitions(xz_embedded PUBLIC
    XZ_USE_CRC64
    XZ_DEC_ANY_CHECK
    XZ_DEC_CONCATENATED
)
