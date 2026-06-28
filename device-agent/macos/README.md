# ZeroTrustHR macOS Device Agent

This agent generates the enrollment material using a non-exportable Secure Enclave
private key:

- CSR PEM
- device public key PEM
- challenge signature in Base64

## Build

```bash
CLANG_MODULE_CACHE_PATH=/tmp/zerotrusthr-swift-module-cache swiftc \
  /Users/pietrosalvatore/zeroTrustHR/device-agent/macos/SecureEnclaveIdentity.swift \
  /Users/pietrosalvatore/zeroTrustHR/device-agent/macos/EnrollmentOutput.swift \
  /Users/pietrosalvatore/zeroTrustHR/device-agent/macos/main.swift \
  -o /tmp/ZeroTrustHRDeviceAgent
```

## Sign for the real persistent-key flow

Use an Apple Development certificate from Xcode. Replace the identity with the
exact value printed by `security find-identity -v -p codesigning`.

```bash
codesign --force --options runtime \
  --entitlements /Users/pietrosalvatore/zeroTrustHR/device-agent/macos/ZeroTrustHRDeviceAgent.entitlements \
  --sign "Apple Development: YOUR NAME (TEAMID)" \
  /tmp/ZeroTrustHRDeviceAgent
```

Ad-hoc signing with `--sign -` is enough for simple binaries, but it is not a
real app identity for a persistent Secure Enclave key in the Keychain.

## Build as a macOS app bundle

If the raw CLI still fails with `-34018`, build the app bundle instead. The
bundle gives the Keychain a stable app identity:

```bash
chmod +x /Users/pietrosalvatore/zeroTrustHR/device-agent/macos/build-app.sh

/Users/pietrosalvatore/zeroTrustHR/device-agent/macos/build-app.sh \
  "Apple Development: salvatorepietro883@gmail.com (AU2TYW86WK)"
```

Run the executable inside the signed app bundle:

```bash
/tmp/ZeroTrustHRDeviceAgent.app/Contents/MacOS/ZeroTrustHRDeviceAgent \
  "DEVICE_ID_FROM_FRONTEND" \
  "CERTIFICATE_SAN_URI_FROM_FRONTEND" \
  "CHALLENGE_FROM_FRONTEND"
```

## Run

```bash
/tmp/ZeroTrustHRDeviceAgent \
  "DEVICE_ID_FROM_FRONTEND" \
  "CERTIFICATE_SAN_URI_FROM_FRONTEND" \
  "CHALLENGE_FROM_FRONTEND"
```

The output JSON fields must be copied into the frontend enrollment form.
