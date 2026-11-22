#!/usr/bin/env bash
# Import the Developer ID certificate into a temporary keychain.
# Without signing secrets (a fork, for example), fall back to ad-hoc signing.

set -euo pipefail

if [[ -z "${APPLE_CERTIFICATE_BASE64:-}" || -z "${APPLE_CERTIFICATE_PASSWORD:-}" ]]; then
  echo "::warning::No Apple Developer ID certificate configured; the macOS build will be ad-hoc signed and not notarized."
  echo "CERTIFICATE_NAME=-" >> "$GITHUB_ENV"
  exit 0
fi

: "${APPLE_CERTIFICATE_BASE64:?}"
: "${APPLE_CERTIFICATE_PASSWORD:?}"

security create-keychain -p "${APPLE_CERTIFICATE_PASSWORD}" build.keychain
security default-keychain -s build.keychain
security unlock-keychain -p "${APPLE_CERTIFICATE_PASSWORD}" build.keychain
echo "${APPLE_CERTIFICATE_BASE64}" | base64 -d > certificate.p12
security import certificate.p12 -k build.keychain -P "${APPLE_CERTIFICATE_PASSWORD}" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "${APPLE_CERTIFICATE_PASSWORD}" build.keychain
echo "CERTIFICATE_NAME=$(security find-identity -v -p codesigning build.keychain | grep 'Developer ID Application' | head -1 | sed 's/.*"\(.*\)"/\1/')" >> "$GITHUB_ENV"
