//
// Created by CoreDeck RE toolbench on 05/11/2026.
//
// CA-certificate trust: compute the OpenSSL subject_hash_old filename and install
// a CA into a rooted AVD's system trust store so the emulator's apps trust your
// proxy (Burp/Fiddler). The hashing/parsing is pure and unit-tested; the install
// drives adb/su and is API-aware (classic remount vs Android 14+ tmpfs overlay).
//

#ifndef COREDECK_CERT_H
#define COREDECK_CERT_H

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/sdk.h"

namespace CoreDeck::Core {
    // Lowercase hex MD5 of the input (exposed for testing).
    std::string Md5Hex(const std::vector<std::uint8_t> &data);

    // Normalize a certificate to DER: PEM is base64-decoded, DER is returned as-is.
    std::optional<std::vector<std::uint8_t>> CertToDer(const std::vector<std::uint8_t> &certBytes);

    // Extract the DER-encoded subject Name (full TLV) from a DER X.509 certificate.
    std::optional<std::vector<std::uint8_t>> ExtractSubjectDer(const std::vector<std::uint8_t> &derCert);

    // OpenSSL X509_NAME_hash_old of the subject: first 4 bytes of MD5(subject DER),
    // little-endian, as 8 hex chars. The Android system-store filename is "<hash>.0".
    std::optional<std::string> SubjectHashOld(const std::vector<std::uint8_t> &certBytes);

    struct CaCertInfo {
        std::string Hash; // 8 hex chars
        std::string FileName; // "<hash>.0"
    };

    // Parse a cert (PEM or DER) and return its hash + store filename.
    std::optional<CaCertInfo> InspectCaCert(const std::vector<std::uint8_t> &certBytes);
    std::optional<CaCertInfo> InspectCaCertFile(const std::string &path);

    // Install a CA file (PEM/DER) into the device's SYSTEM trust store on a rooted
    // AVD. API-aware (classic remount < 34, tmpfs overlay for 34+). Returns the
    // installed "<hash>.0" name, or nullopt with error set. Requires su.
    std::optional<std::string> InstallCaCert(
        const SdkInfo &sdk, const std::string &serial, const std::string &certPath, std::string &error
    );

    // Remove a previously installed system CA by its "<hash>.0" name.
    bool RemoveCaCert(const SdkInfo &sdk, const std::string &serial, const std::string &name, std::string &error);
}

#endif // COREDECK_CERT_H
