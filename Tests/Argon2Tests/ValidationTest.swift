import XCTest
import Argon2

final class ValidationTest: XCTestCase {
    func testRejectsMemoryBelowMinimum() {
        // memory must be >= 8 * parallelism
        let params = Argon2Params(timeCost: 1, memoryCostKilobytes: 4, parallelism: 1)
        XCTAssertThrowsError(try params.validate())
    }

    func testRejectsUnsupportedVersion() {
        let params = Argon2Params(timeCost: 1, memoryCostKilobytes: 8, parallelism: 1, version: 18)
        XCTAssertThrowsError(try params.validate())
    }

    func testRejectsOutputShorterThan4Bytes() {
        let params = Argon2Params(timeCost: 1, memoryCostKilobytes: 8, parallelism: 1, outputLength: 2)
        XCTAssertThrowsError(try params.validate())
    }

    func testRejectsZeroTime() {
        let params = Argon2Params(timeCost: 0, memoryCostKilobytes: 8, parallelism: 1)
        XCTAssertThrowsError(try params.validate())
    }

    func testRejectsZeroParallelism() {
        let params = Argon2Params(timeCost: 1, memoryCostKilobytes: 8, parallelism: 0)
        XCTAssertThrowsError(try params.validate())
    }

    func testAcceptsMinimalValid() throws {
        try Argon2Params(timeCost: 1, memoryCostKilobytes: 8, parallelism: 1, outputLength: 4)
            .validate()
    }

    func testDeriveKeyValidatesParams() {
        let bad = Argon2Params(timeCost: 1, memoryCostKilobytes: 4, parallelism: 1)
        XCTAssertThrowsError(try Argon2.deriveKey(
            password: Data("pw".utf8), salt: Data([0, 1, 2, 3]), params: bad
        ))
    }
}