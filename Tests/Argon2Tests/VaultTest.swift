import XCTest
import Argon2

final class VaultTest: XCTestCase {
    // Light params keep the suite fast while exercising the full path.
    private let vault = PasswordVault(params: Argon2Params(
        variant: .id, timeCost: 2, memoryCostKilobytes: 10240, parallelism: 1,
        outputLength: 32
    ))

    func testEncryptDecryptRoundTrip() throws {
        let password = Data("correct horse battery staple".utf8)
        let plaintext = Data("the vault secret".utf8)
        let record = try vault.encrypt(plaintext: plaintext, password: password)
        let decrypted = try vault.decrypt(record, password: password)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testRecordIsSelfDescribing() throws {
        let password = Data("pw".utf8)
        let plaintext = Data("payload".utf8)
        let record = try vault.encrypt(plaintext: plaintext, password: password)

        // A freshly constructed vault (different params) can still open the
        // record, because the cost parameters and salt are embedded in it.
        let other = PasswordVault(params: Argon2Params(
            variant: .id, timeCost: 1, memoryCostKilobytes: 8192, parallelism: 1,
            outputLength: 32
        ))
        let decrypted = try other.decrypt(record, password: password)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testWrongPasswordFailsAuthentication() throws {
        let record = try vault.encrypt(
            plaintext: Data("x".utf8), password: Data("right".utf8)
        )
        XCTAssertThrowsError(try vault.decrypt(record, password: Data("wrong".utf8))) { error in
            XCTAssertEqual(error as? Argon2Error, .authenticationFailed)
        }
    }

    func testTamperedCiphertextFailsAuthentication() throws {
        var record = [UInt8](try vault.encrypt(
            plaintext: Data("hello".utf8), password: Data("pw".utf8)
        ))
        record[record.count - 1] ^= 0xFF
        XCTAssertThrowsError(try vault.decrypt(Data(record), password: Data("pw".utf8))) { error in
            XCTAssertEqual(error as? Argon2Error, .authenticationFailed)
        }
    }

    func testTruncatedRecordRejected() {
        let short = Data([0x00, 0x01, 0x02])
        XCTAssertThrowsError(try vault.decrypt(short, password: Data("pw".utf8))) { error in
            XCTAssertEqual(error as? Argon2Error, .malformedCiphertext)
        }
    }
}