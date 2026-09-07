import Foundation
import CryptoKit

/// A password vault that derives an AES-256 key from a low-entropy password
/// using Argon2id, then encrypts records with AES-256-GCM.
///
/// The key is never stored. Each record is self-describing: it embeds the
/// Argon2 cost parameters, the salt, the GCM nonce, the auth tag and the
/// ciphertext, so `decrypt` only needs the password.
///
/// Record layout (little-endian):
///
/// ```
/// [4] variant      [4] version      [4] timeCost
/// [4] memoryKiB    [4] parallelism  [2] saltLen
/// [saltLen] salt   [12] nonce       [16] tag
/// [rest]  ciphertext
/// ```
public struct PasswordVault {
    /// Argon2id, 3 passes, 64 MiB, 4 lanes, 32-byte (AES-256) key.
    public static let defaultParams = Argon2Params(
        variant: .id, timeCost: 3, memoryCostKilobytes: 65536, parallelism: 4, outputLength: 32
    )

    private static let nonceLength = 12
    private static let tagLength = 16
    private static let headerLength = 5 * 4 + 2

    public let params: Argon2Params

    /// - Precondition: `params` must use argon2id with a 32-byte output
    ///   (an AES-256 key).
    public init(params: Argon2Params = PasswordVault.defaultParams) {
        precondition(params.variant == .id, "PasswordVault requires argon2id")
        precondition(params.outputLength == 32, "PasswordVault requires a 32-byte (AES-256) key")
        self.params = params
    }

    /// Encrypts `plaintext` under `password`, producing a self-describing record.
    public func encrypt(
        plaintext: Data,
        password: Data,
        salt: Data = Argon2.randomSalt(length: 16)
    ) throws -> Data {
        try params.validate()
        let key = try deriveKey(password: password, salt: salt, params: params)
        let symKey = SymmetricKey(data: Data(key))
        let nonceData = Argon2.randomSalt(length: Self.nonceLength)
        let nonce = try AES.GCM.Nonce(data: nonceData)
        let box = try AES.GCM.seal(plaintext, using: symKey, nonce: nonce)

        var record = Data()
        record.appendLE32(params.variant.rawValue)
        record.appendLE32(params.version)
        record.appendLE32(params.timeCost)
        record.appendLE32(params.memoryCostKilobytes)
        record.appendLE32(params.parallelism)
        record.appendLE16(UInt16(salt.count))
        record.append(salt)
        record.append(nonceData)
        record.append(box.tag)
        record.append(box.ciphertext)
        return record
    }

    /// Decrypts a record produced by `encrypt`, authenticating with GCM.
    ///
    /// Throws `Argon2Error.authenticationFailed` if the password is wrong or
    /// the record was tampered with.
    public func decrypt(_ record: Data, password: Data) throws -> Data {
        let bytes = [UInt8](record)
        guard bytes.count >= Self.headerLength + Self.nonceLength + Self.tagLength else {
            throw Argon2Error.malformedCiphertext
        }
        var offset = 0
        let variant = leUint32(bytes, &offset)
        let version = leUint32(bytes, &offset)
        let timeCost = leUint32(bytes, &offset)
        let memory = leUint32(bytes, &offset)
        let parallelism = leUint32(bytes, &offset)
        let saltLen = Int(leUint16(bytes, &offset))

        guard bytes.count >= offset + saltLen + Self.nonceLength + Self.tagLength else {
            throw Argon2Error.malformedCiphertext
        }
        let salt = Data(bytes[offset..<(offset + saltLen)]); offset += saltLen
        let nonceData = Data(bytes[offset..<(offset + Self.nonceLength)]); offset += Self.nonceLength
        let tag = Data(bytes[offset..<(offset + Self.tagLength)]); offset += Self.tagLength
        let ciphertext = Data(bytes[offset..<bytes.count])

        // Trust the record's own cost parameters (they are not secret).
        let recordParams = Argon2Params(
            variant: Argon2Variant(rawValue: variant) ?? .id,
            timeCost: timeCost,
            memoryCostKilobytes: memory,
            parallelism: parallelism,
            outputLength: 32,
            version: version
        )
        try recordParams.validate()

        let key = try deriveKey(password: password, salt: salt, params: recordParams)
        let symKey = SymmetricKey(data: Data(key))
        let nonce = try AES.GCM.Nonce(data: nonceData)
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        do {
            return try AES.GCM.open(box, using: symKey)
        } catch {
            throw Argon2Error.authenticationFailed
        }
    }

    private func deriveKey(password: Data, salt: Data, params: Argon2Params) throws -> [UInt8] {
        var key = Argon2Engine.derive(
            password: Array(password),
            salt: Array(salt),
            secret: [],
            ad: [],
            time: params.timeCost,
            memory: params.memoryCostKilobytes,
            threads: params.parallelism,
            keyLen: UInt32(params.outputLength),
            mode: Int(params.variant.rawValue)
        )
        defer { wipe(&key) }
        return key
    }
}

// MARK: - Little-endian helpers

private extension Data {
    mutating func appendLE32(_ v: UInt32) {
        append(UInt8(v & 0xFF))
        append(UInt8((v >> 8) & 0xFF))
        append(UInt8((v >> 16) & 0xFF))
        append(UInt8((v >> 24) & 0xFF))
    }

    mutating func appendLE16(_ v: UInt16) {
        append(UInt8(v & 0xFF))
        append(UInt8((v >> 8) & 0xFF))
    }
}

private func leUint32(_ b: [UInt8], _ offset: inout Int) -> UInt32 {
    let v = UInt32(b[offset]) | (UInt32(b[offset + 1]) << 8)
        | (UInt32(b[offset + 2]) << 16) | (UInt32(b[offset + 3]) << 24)
    offset += 4
    return v
}

private func leUint16(_ b: [UInt8], _ offset: inout Int) -> UInt16 {
    let v = UInt16(b[offset]) | (UInt16(b[offset + 1]) << 8)
    offset += 2
    return v
}