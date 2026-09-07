import XCTest
@testable import Argon2

/// Objective accreditation gate: the RFC 9106 Section 5.2 test vectors.
///
/// Inputs (identical for all three variants):
///   password = 0x01 x 32, salt = 0x02 x 16, secret = 0x03 x 8, ad = 0x04 x 12
///   t = 3, m = 32, p = 4, taglen = 32, v = 19
final class RFC9106Test: XCTestCase {
    private let password = Data(repeating: 0x01, count: 32)
    private let salt = Data(repeating: 0x02, count: 16)
    private let secret = Data(repeating: 0x03, count: 8)
    private let ad = Data(repeating: 0x04, count: 12)

    private func params(_ variant: Argon2Variant) -> Argon2Params {
        Argon2Params(variant: variant, timeCost: 3, memoryCostKilobytes: 32,
                     parallelism: 4, outputLength: 32, version: 19)
    }

    func testArgon2dTag() throws {
        let tag = try Argon2.deriveKey(password: password, salt: salt, secret: secret,
                                       associatedData: ad, params: params(.d))
        XCTAssertEqual(hex(tag),
                       "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb")
    }

    func testArgon2iTag() throws {
        let tag = try Argon2.deriveKey(password: password, salt: salt, secret: secret,
                                       associatedData: ad, params: params(.i))
        XCTAssertEqual(hex(tag),
                       "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8")
    }

    func testArgon2idTag() throws {
        let tag = try Argon2.deriveKey(password: password, salt: salt, secret: secret,
                                       associatedData: ad, params: params(.id))
        XCTAssertEqual(hex(tag),
                       "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
    }

    func testArgon2dH0() throws {
        let h0 = Argon2Engine.h0Digest(password: Array(password), salt: Array(salt), secret: Array(secret), ad: Array(ad),
                                       time: 3, memory: 32, threads: 4, keyLen: 32,
                                       mode: Argon2Engine.argon2d)
        XCTAssertEqual(hex(Data(h0)),
                       "b8819791a0359660bb7709c85fa48f04d5d82c05c5f215ccdb885491717cf757082c28b951be381410b5fc2eb7274033b9fdc7ae672bcaac5d179097a4af3109")
    }

    func testArgon2iH0() throws {
        let h0 = Argon2Engine.h0Digest(password: Array(password), salt: Array(salt), secret: Array(secret), ad: Array(ad),
                                       time: 3, memory: 32, threads: 4, keyLen: 32,
                                       mode: Argon2Engine.argon2i)
        XCTAssertEqual(hex(Data(h0)),
                       "c46065815276a0b3e731731c902f1fd80cf776907fbb7b6a5ca72e7b56011feeca446c86dd75b9469a5e6879dec4b72d0863fb939b982e5f397cc7d164fddaa9")
    }

    func testArgon2idH0() throws {
        let h0 = Argon2Engine.h0Digest(password: Array(password), salt: Array(salt), secret: Array(secret), ad: Array(ad),
                                       time: 3, memory: 32, threads: 4, keyLen: 32,
                                       mode: Argon2Engine.argon2id)
        XCTAssertEqual(hex(Data(h0)),
                       "2889de487eb42ae500c0007ed9252f1069eadec40d5765b485de6dc2437a67b8546a2f0acc1a0882db8fcf74714b472e94df421a5da1112ffa11434370a1e997")
    }

    private func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}