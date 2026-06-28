import Foundation

enum AgentError: Error, CustomStringConvertible {
    case invalidArguments
    case emptyChallenge

    var description: String {
        switch self {
        case .invalidArguments:
            return """
            Uso:
              ZeroTrustHRDeviceAgent <device_id> <certificate_san_uri> <challenge>

            Esempio:
              ZeroTrustHRDeviceAgent "abc-device-id" "urn:zerotrusthr:device:abc-device-id" "challenge-dal-frontend"
            """
        case .emptyChallenge:
            return "La challenge non puo essere vuota."
        }
    }
}

func run() throws {
    guard CommandLine.arguments.count == 4 else {
        throw AgentError.invalidArguments
    }

    let deviceId = CommandLine.arguments[1].trimmingCharacters(in: .whitespacesAndNewlines)
    let certificateSanUri = CommandLine.arguments[2].trimmingCharacters(in: .whitespacesAndNewlines)
    let challenge = CommandLine.arguments[3]

    guard !deviceId.isEmpty, certificateSanUri == "urn:zerotrusthr:device:\(deviceId)" else {
        throw AgentError.invalidArguments
    }

    guard let challengeData = challenge.data(using: .utf8), !challengeData.isEmpty else {
        throw AgentError.emptyChallenge
    }

    let identity = SecureEnclaveIdentity()
    let privateKey = try identity.createOrLoadNonExportableKey()

    let output = EnrollmentOutput(
        csrPem: try identity.createCertificateSigningRequestPem(
            privateKey: privateKey,
            deviceId: deviceId
        ),
        publicKeyPem: try identity.publicKeyPem(from: privateKey),
        challengeSignature: try identity.signChallenge(
            challengeData,
            with: privateKey
        ).base64EncodedString()
    )

    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let json = try encoder.encode(output)
    FileHandle.standardOutput.write(json)
    FileHandle.standardOutput.write(Data("\n".utf8))
}

do {
    try run()
} catch {
    FileHandle.standardError.write(Data("\(error)\n".utf8))
    exit(1)
}
