import Foundation
import Security

final class SecureEnclaveIdentity {
    private let tag = "it.zerotrusthr.device.identity".data(using: .utf8)!

    func createOrLoadNonExportableKey() throws -> SecKey {
        if let key = try? loadPrivateKey() {
            return key
        }

        return try createNonExportableKey()
    }

    private func createNonExportableKey() throws -> SecKey {
        var error: Unmanaged<CFError>?

        // Specifica del controllo di accessi
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            &error
        )
        else {
            throw error!.takeRetainedValue() as Error
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access,
                kSecAttrIsExtractable as String: false
            ]
        ]

        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }

        return privateKey
    }

    private func loadPrivateKey() throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }

        return item as! SecKey
    }

    func publicKeyPem(from privateKey: SecKey) throws -> String {
        let spki = try publicKeySubjectPublicKeyInfoDer(from: privateKey)
        return pem(label: "PUBLIC KEY", der: spki)
    }

    func createCertificateSigningRequestPem(
        privateKey: SecKey,
        deviceId: String
    ) throws -> String {
        let spki = try publicKeySubjectPublicKeyInfoDer(from: privateKey)
        let subject = Der.sequence([
            Der.set([
                Der.sequence([
                    Der.objectIdentifier([2, 5, 4, 3]),
                    Der.utf8String("zerotrusthr-device")
                ])
            ]),
            Der.set([
                Der.sequence([
                    Der.objectIdentifier([2, 5, 4, 10]),
                    Der.utf8String("ZeroTrustHR")
                ])
            ]),
            Der.set([
                Der.sequence([
                    Der.objectIdentifier([2, 5, 4, 11]),
                    Der.utf8String("secure_enclave")
                ])
            ]),
            Der.set([
                Der.sequence([
                    Der.objectIdentifier([2, 5, 4, 5]),
                    Der.utf8String(deviceId)
                ])
            ])
        ])

        let certificationRequestInfo = Der.sequence([
            Der.integer(0),
            subject,
            spki,
            Der.contextSpecificConstructed(tag: 0, value: Data())
        ])

        let signature = try signData(certificationRequestInfo, with: privateKey)
        let ecdsaWithSha256 = Der.sequence([
            Der.objectIdentifier([1, 2, 840, 10045, 4, 3, 2])
        ])

        let csr = Der.sequence([
            certificationRequestInfo,
            ecdsaWithSha256,
            Der.bitString(signature)
        ])

        return pem(label: "CERTIFICATE REQUEST", der: csr)
    }

    func signChallenge(_ challenge: Data, with privateKey: SecKey) throws -> Data {
        try signData(challenge, with: privateKey)
    }

    private func publicKeySubjectPublicKeyInfoDer(from privateKey: SecKey) throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw NSError(domain: "ZeroTrustHR", code: 1)
        }

        var error: Unmanaged<CFError>?
        guard let x963PublicKey = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }

        let algorithmIdentifier = Der.sequence([
            Der.objectIdentifier([1, 2, 840, 10045, 2, 1]),
            Der.objectIdentifier([1, 2, 840, 10045, 3, 1, 7])
        ])

        return Der.sequence([
            algorithmIdentifier,
            Der.bitString(x963PublicKey)
        ])
    }

    private func signData(_ data: Data, with privateKey: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?

        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        ) as Data? else {
            throw error!.takeRetainedValue() as Error
        }

        return signature
    }

    private func pem(label: String, der: Data) -> String {
        let base64 = der.base64EncodedString()
        let lines = stride(from: 0, to: base64.count, by: 64).map { index -> String in
            let start = base64.index(base64.startIndex, offsetBy: index)
            let end = base64.index(start, offsetBy: min(64, base64.distance(from: start, to: base64.endIndex)))
            return String(base64[start..<end])
        }

        return """
        -----BEGIN \(label)-----
        \(lines.joined(separator: "\n"))
        -----END \(label)-----

        """
    }
}

private enum Der {
    static func sequence(_ values: [Data]) -> Data {
        tlv(tag: 0x30, value: values.reduce(Data(), +))
    }

    static func set(_ values: [Data]) -> Data {
        tlv(tag: 0x31, value: values.reduce(Data(), +))
    }

    static func integer(_ value: Int) -> Data {
        if value == 0 {
            return tlv(tag: 0x02, value: Data([0x00]))
        }

        var bytes = Data()
        var number = value
        while number > 0 {
            bytes.insert(UInt8(number & 0xff), at: 0)
            number >>= 8
        }

        if let first = bytes.first, first & 0x80 != 0 {
            bytes.insert(0x00, at: 0)
        }

        return tlv(tag: 0x02, value: bytes)
    }

    static func objectIdentifier(_ oid: [UInt64]) -> Data {
        precondition(oid.count >= 2)

        var body = Data([UInt8(oid[0] * 40 + oid[1])])
        for component in oid.dropFirst(2) {
            body.append(contentsOf: base128(component))
        }

        return tlv(tag: 0x06, value: body)
    }

    static func utf8String(_ value: String) -> Data {
        tlv(tag: 0x0c, value: Data(value.utf8))
    }

    static func bitString(_ value: Data) -> Data {
        var body = Data([0x00])
        body.append(value)
        return tlv(tag: 0x03, value: body)
    }

    static func contextSpecificConstructed(tag: UInt8, value: Data) -> Data {
        tlv(tag: 0xa0 + tag, value: value)
    }

    private static func tlv(tag: UInt8, value: Data) -> Data {
        var data = Data([tag])
        data.append(length(value.count))
        data.append(value)
        return data
    }

    private static func length(_ length: Int) -> Data {
        if length < 128 {
            return Data([UInt8(length)])
        }

        var bytes = Data()
        var remaining = length
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0xff), at: 0)
            remaining >>= 8
        }

        var result = Data([0x80 | UInt8(bytes.count)])
        result.append(bytes)
        return result
    }

    private static func base128(_ value: UInt64) -> [UInt8] {
        var bytes = [UInt8(value & 0x7f)]
        var remaining = value >> 7

        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0x7f) | 0x80, at: 0)
            remaining >>= 7
        }

        return bytes
    }
}
