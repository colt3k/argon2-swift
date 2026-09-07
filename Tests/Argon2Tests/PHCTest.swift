import XCTest
import Argon2

final class PHCTest: XCTestCase {
    func testEncodeDecodeRoundTrip() throws {
        let params = Argon2Params(
            variant: .id, timeCost: 2, memoryCostKilobytes: 19456, parallelism: 1,
            outputLength: 32
        )
        let password = Data("correct horse battery staple".utf8)
        let salt = Argon2.randomSalt(length: 16)
        let tag = try Argon2.deriveKey(password: password, salt: salt, params: params)

        let phc = Argon2PHC(params: params, salt: salt, tag: tag)
        let string = phc.encode()
        XCTAssertTrue(string.hasPrefix("$argon2id$v=19$m=19456,t=2,p=1$"), string)

        let decoded = try Argon2PHC.decode(string)
        XCTAssertEqual(decoded, phc)
        XCTAssertEqual(decoded.params, params)
        XCTAssertEqual(decoded.salt, salt)
        XCTAssertEqual(decoded.tag, tag)

        // Re-deriving with the decoded params/salt must reproduce the tag.
        let rederived = try Argon2.deriveKey(
            password: password, salt: decoded.salt, params: decoded.params
        )
        XCTAssertEqual(rederived, decoded.tag)
    }

    func testKnownVectorEncoding() {
        // Fixed inputs so the encoded string is deterministic.
        let params = Argon2Params(
            variant: .i, timeCost: 1, memoryCostKilobytes: 8, parallelism: 1,
            outputLength: 4
        )
        let salt = Data([0x01, 0x02, 0x03, 0x04])
        let tag = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let string = Argon2PHC(params: params, salt: salt, tag: tag).encode()
        XCTAssertEqual(string, "$argon2i$v=19$m=8,t=1,p=1$AQIDBA$3q2+7w")
    }

    func testDecodeRejectsMalformed() {
        XCTAssertThrowsError(try Argon2PHC.decode("not-a-phc-string"))
        XCTAssertThrowsError(try Argon2PHC.decode("$argon2xyz$v=19$m=8,t=1,p=1$AQIDBA$3q2+7w"))
        XCTAssertThrowsError(try Argon2PHC.decode("$argon2id$v=18$m=8,t=1,p=1$AQIDBA$3q2+7w"))
        XCTAssertThrowsError(try Argon2PHC.decode("$argon2id$v=19$m=8,t=1$AQIDBA$3q2+7w"))
    }
}