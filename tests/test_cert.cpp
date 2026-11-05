#include <cstdint>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "core/cert.h"

using namespace CoreDeck::Core;
using namespace CoreDeck;

namespace {
    std::vector<std::uint8_t> Bytes(const std::string &s) {
        return std::vector<std::uint8_t>(s.begin(), s.end());
    }

    // A real X.509 CA generated with openssl; openssl reports:
    //   openssl x509 -subject_hash_old -> 85f766e2
    const char *TEST_CA_PEM =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIDYzCCAkugAwIBAgIUL86rJlKrPmQFlqd+CsgZyxM3KbcwDQYJKoZIhvcNAQEL\n"
        "BQAwQTELMAkGA1UEBhMCVVMxGTAXBgNVBAoMEENvcmVEZWNrIFRlc3QgQ0ExFzAV\n"
        "BgNVBAMMDkNvcmVEZWNrIFByb3h5MB4XDTI2MTEwNTAxMjUyN1oXDTI3MTEwNTAx\n"
        "MjUyN1owQTELMAkGA1UEBhMCVVMxGTAXBgNVBAoMEENvcmVEZWNrIFRlc3QgQ0Ex\n"
        "FzAVBgNVBAMMDkNvcmVEZWNrIFByb3h5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n"
        "MIIBCgKCAQEAqVj8ezInBiwOtEnAOSFg/gN/gQEBMaz344box/ItIkvvL6sZ0GMJ\n"
        "ZIybzSrxhdQ2enN3JHl13zLkowDJcfP7DOiyNwS+BtoTao/Lv/3qYBHG9clps7RX\n"
        "3FqvfQDKpceQtrbWpKLCqPAVx+eot/ktNZIEvBm0TJAZ6TIkWs8kcRnr1LZUXjJc\n"
        "tE7Tc6gSNTvvDJUfavONVxSHUEc4suoqdumxz40DyjdeAPaWjtJCROVHPoJU7HJL\n"
        "XYhBd0P8VN5qiyT4JMC6if7vhP7BUq547LyaghFY7IiSyHbbVMnyC2GkmIbzbesE\n"
        "xLvDq7BnSgcEd5KJhd3GkqjNKqRDXtBjQQIDAQABo1MwUTAdBgNVHQ4EFgQU5x8z\n"
        "8BkFlMUrYbkZvCf95udgVFUwHwYDVR0jBBgwFoAU5x8z8BkFlMUrYbkZvCf95udg\n"
        "VFUwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAd5Rxl6J66bAC\n"
        "Oc4Y/9PRvcaLWb6U0kLBbqFIfnD3LeA5UbW64ST4WcaRsefjmvDijn+HZMK8b8vo\n"
        "vzJ4EbruAt1VztdN741elBvXvjTbnnHtUcuMgj1Bgfgoc+/UwjFsk0S2LWpFDixr\n"
        "mv/H7JttcQgCvSr7Wah+s8oI7jSGAAcAo5Z3SpDIlpNm8rhixdSNw77GOSFu6oHG\n"
        "Mys0LA6VNtkNvfa8XrNgQoGMmrSrF5tPO5Exi3CvZ8/04qlcPRh8kqizT9dC2TCV\n"
        "3l+PszYewM6aONI+ZXtjN9Dm2HrD6oK9sqLWcMEvkWZmAbTFWfQ9kZSy63LLqHrE\n"
        "saz/BEf2jw==\n"
        "-----END CERTIFICATE-----\n";
}

TEST_CASE("Md5Hex matches the RFC 1321 vectors", "[cert]") {
    REQUIRE(Md5Hex(Bytes("")) == "d41d8cd98f00b204e9800998ecf8427e");
    REQUIRE(Md5Hex(Bytes("abc")) == "900150983cd24fb0d6963f7d28e17f72");
    REQUIRE(Md5Hex(Bytes("message digest")) == "f96b697d7cb7938d525a2f31aaf161d0");
    REQUIRE(Md5Hex(Bytes("abcdefghijklmnopqrstuvwxyz")) == "c3fcd3d76192e4007dfb496cca67e13b");
}

TEST_CASE("CertToDer decodes PEM and passes DER through", "[cert]") {
    const auto der = CertToDer(Bytes(TEST_CA_PEM));
    REQUIRE(der.has_value());
    REQUIRE_FALSE(der->empty());
    REQUIRE(der->front() == 0x30); // SEQUENCE

    // Feeding the DER back in returns it unchanged.
    const auto again = CertToDer(*der);
    REQUIRE(again.has_value());
    REQUIRE(*again == *der);

    REQUIRE_FALSE(CertToDer(Bytes("not a certificate")).has_value());
}

TEST_CASE("SubjectHashOld matches openssl's X509_NAME_hash_old", "[cert]") {
    const auto hash = SubjectHashOld(Bytes(TEST_CA_PEM));
    REQUIRE(hash.has_value());
    REQUIRE(*hash == "85f766e2");

    // Same answer from the DER form.
    const auto der = CertToDer(Bytes(TEST_CA_PEM));
    REQUIRE(der.has_value());
    REQUIRE(SubjectHashOld(*der) == "85f766e2");
}

TEST_CASE("InspectCaCert returns the store filename", "[cert]") {
    const auto info = InspectCaCert(Bytes(TEST_CA_PEM));
    REQUIRE(info.has_value());
    REQUIRE(info->Hash == "85f766e2");
    REQUIRE(info->FileName == "85f766e2.0");
}

TEST_CASE("Certificate parsing rejects garbage", "[cert]") {
    REQUIRE_FALSE(SubjectHashOld(Bytes("garbage")).has_value());
    REQUIRE_FALSE(ExtractSubjectDer(Bytes("\x30\x03garbage")).has_value());
}
