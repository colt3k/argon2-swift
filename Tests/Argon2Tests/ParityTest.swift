import XCTest
import Argon2

/// Keyless argon2id vectors captured from the Go library (t=3, m=64 MiB,
/// p=4, keyLen=32). These guard that the ported engine still matches the
/// reference for the common password-hashing configuration.
final class ParityTest: XCTestCase {
    private let params = Argon2Params(
        variant: .id, timeCost: 3, memoryCostKilobytes: 65536, parallelism: 4,
        outputLength: 32
    )

    private let vectors: [(token: String, salt: Data, expectedHex: String)] = [
        ("D2YZUNMIUD43GE4K7EADYFCYPY",
         Data((0..<16).map { UInt8($0) }),
         "90177c0a7e53373be8c62fc9a99625aae40616439c338bbdb86ebb142484d486"),
        ("ABC123XYZ789",
         Data([UInt8](repeating: 0, count: 16)),
         "618afcb1dc5ebbafe975eeb829af5b738b487398ffc053fe0166a5328b2c915b"),
        (String(repeating: "Z", count: 32),
         Data([UInt8](repeating: 0xFF, count: 16)),
         "bf0d3ccecd6e41abbb4dc07bbe9ca154cb70c391ee714775d71ed79c140415d9"),
    ]

    func testArgon2IdMatchesGoLibrary() throws {
        for v in vectors {
            let tag = try Argon2.deriveKey(
                password: Data(v.token.utf8), salt: v.salt, params: params
            )
            let hex = tag.map { String(format: "%02x", $0) }.joined()
            XCTAssertEqual(hex, v.expectedHex, "token \(v.token)")
        }
    }
}