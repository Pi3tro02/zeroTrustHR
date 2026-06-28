import Foundation

struct EnrollmentOutput: Encodable {
    let csrPem: String
    let publicKeyPem: String
    let challengeSignature: String
}
