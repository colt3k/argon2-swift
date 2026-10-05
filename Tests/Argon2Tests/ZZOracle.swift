import XCTest
@testable import Argon2

final class ZZOracle: XCTestCase {
    func testOracle() {
        let password = [UInt8](repeating: 0x01, count: 32)
        let salt = [UInt8](repeating: 0x02, count: 16)
        let secret = [UInt8](repeating: 0x03, count: 8)
        let ad = [UInt8](repeating: 0x04, count: 12)
        var h0 = Argon2Engine.initHash(password: password, salt: salt, secret: secret, ad: ad,
            time: 3, memory: 32, threads: 4, keyLen: 32, mode: Argon2Engine.argon2d)
        var mem = 32
        mem = (mem / (4*4)) * (4*4)
        if mem < 2*4*4 { mem = 2*4*4 }
        func hexBytes(_ a: ArraySlice<UInt8>) -> String { a.map{String(format:"%02x",$0)}.joined() }
        func hexWords(_ a: ArraySlice<UInt64>) -> String {
            var s = ""
            for w in a { for i in 0..<8 { s += String(format:"%02x", (w >> (i*8)) & 0xFF) } }
            return s
        }
        print("ORACLE h0full = " + hexBytes(h0[0..<72]))
        var B = Argon2Engine.initBlocks(&h0, memory: UInt32(mem), threads: 4)
        print("ORACLE block0 = " + hexWords(B[0..<128]))
        Argon2Engine.processBlocks(&B, time: 3, memory: UInt32(mem), threads: 4, mode: Argon2Engine.argon2d)
        let finalBlock = (mem - 1) * 128
        for lane in 0..<(4-1) {
            let lastOfLane = (lane*(mem/4) + (mem/4) - 1) * 128
            for i in 0..<128 { B[finalBlock+i] ^= B[lastOfLane+i] }
        }
        print("ORACLE finalblock = " + hexWords(B[finalBlock..<finalBlock+128]))
    }
}
