import SwiftUI

@main
struct ZeroTrustHRDeviceAgentApp: App {
    var body: some Scene {
        WindowGroup {
            EnrollmentView()
        }
    }
}

struct EnrollmentView: View {
    @State private var deviceId = ""
    @State private var certificateSanUri = ""
    @State private var challenge = ""
    @State private var output = ""
    @State private var errorMessage = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("ZeroTrustHR Device Agent")
                .font(.title2)
                .bold()

            TextField("Device ID", text: $deviceId)
                .textFieldStyle(.roundedBorder)

            TextField("Certificate SAN URI", text: $certificateSanUri)
                .textFieldStyle(.roundedBorder)

            TextField("Challenge", text: $challenge)
                .textFieldStyle(.roundedBorder)

            Button("Genera dati enrollment") {
                generateEnrollmentData()
            }
            .buttonStyle(.borderedProminent)

            if !errorMessage.isEmpty {
                Text(errorMessage)
                    .foregroundStyle(.red)
            }

            TextEditor(text: $output)
                .font(.system(.body, design: .monospaced))
                .frame(minHeight: 260)
                .border(Color.gray.opacity(0.4))

            Button("Copia JSON") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(output, forType: .string)
            }
            .disabled(output.isEmpty)
        }
        .padding()
        .frame(width: 760, height: 560)
    }

    private func generateEnrollmentData() {
        errorMessage = ""
        output = ""

        let trimmedDeviceId = deviceId.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedSanUri = certificateSanUri.trimmingCharacters(in: .whitespacesAndNewlines)

        guard !trimmedDeviceId.isEmpty else {
            errorMessage = "Device ID mancante."
            return
        }

        guard trimmedSanUri == "urn:zerotrusthr:device:\(trimmedDeviceId)" else {
            errorMessage = "Certificate SAN URI non coerente con il Device ID."
            return
        }

        guard let challengeData = challenge.data(using: .utf8), !challengeData.isEmpty else {
            errorMessage = "Challenge mancante."
            return
        }

        do {
            let identity = SecureEnclaveIdentity()
            let privateKey = try identity.createOrLoadNonExportableKey()
            let result = EnrollmentOutput(
                csrPem: try identity.createCertificateSigningRequestPem(
                    privateKey: privateKey,
                    deviceId: trimmedDeviceId
                ),
                publicKeyPem: try identity.publicKeyPem(from: privateKey),
                challengeSignature: try identity.signChallenge(
                    challengeData,
                    with: privateKey
                ).base64EncodedString()
            )

            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            output = String(data: try encoder.encode(result), encoding: .utf8) ?? ""
        } catch {
            errorMessage = String(describing: error)
        }
    }
}
