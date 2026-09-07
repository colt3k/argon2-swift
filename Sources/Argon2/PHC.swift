import Foundation

/// A decoded PHC-format Argon2 string.
///
/// The PHC string layout is:
///
/// ```
/// $argon2id$v=19$m=65536,t=3,p=4$<salt-b64>$<tag-b64>
/// ```
///
/// where the salt and tag are standard base64 **without** padding.
public struct Argon2PHC: Equatable, Sendable {
    public let params: Argon2Params
    public let salt: Data
    public let tag: Data

    public init(params: Argon2Params, salt: Data, tag: Data) {
        self.params = params
        self.salt = salt
        self.tag = tag
    }

    /// Encodes this record as a PHC string.
    public func encode() -> String {
        let variantName: String
        switch params.variant {
        case .d: variantName = "argon2d"
        case .i: variantName = "argon2i"
        case .id: variantName = "argon2id"
        }
        let saltB64 = PHCBase64.encodeNoPad(salt)
        let tagB64 = PHCBase64.encodeNoPad(tag)
        return "$\(variantName)$v=\(params.version)$m=\(params.memoryCostKilobytes),t=\(params.timeCost),p=\(params.parallelism)$\(saltB64)$\(tagB64)"
    }

    /// Parses a PHC string. The tag length (and therefore `outputLength`) is
    /// recovered from the decoded tag.
    public static func decode(_ string: String) throws -> Argon2PHC {
        let parts = string.components(separatedBy: "$")
        guard parts.count == 6, parts[0].isEmpty else {
            throw Argon2Error.malformedPHC("expected 6 '$'-separated fields")
        }

        let variant: Argon2Variant
        switch parts[1] {
        case "argon2d": variant = .d
        case "argon2i": variant = .i
        case "argon2id": variant = .id
        default: throw Argon2Error.malformedPHC("unknown variant '\(parts[1])'")
        }

        guard parts[2].hasPrefix("v="), let version = UInt32(parts[2].dropFirst(2)) else {
            throw Argon2Error.malformedPHC("bad version field '\(parts[2])'")
        }

        var memory: UInt32?
        var time: UInt32?
        var parallelism: UInt32?
        for field in parts[3].components(separatedBy: ",") {
            let kv = field.components(separatedBy: "=")
            guard kv.count == 2 else {
                throw Argon2Error.malformedPHC("bad cost field '\(field)'")
            }
            switch kv[0] {
            case "m": memory = UInt32(kv[1])
            case "t": time = UInt32(kv[1])
            case "p": parallelism = UInt32(kv[1])
            default: throw Argon2Error.malformedPHC("unknown cost field '\(kv[0])'")
            }
        }
        guard let m = memory, let t = time, let p = parallelism else {
            throw Argon2Error.malformedPHC("missing m/t/p cost fields")
        }

        let salt = try PHCBase64.decodeNoPad(parts[4])
        let tag = try PHCBase64.decodeNoPad(parts[5])
        let params = Argon2Params(
            variant: variant, timeCost: t, memoryCostKilobytes: m,
            parallelism: p, outputLength: tag.count, version: version
        )
        try params.validate()
        return Argon2PHC(params: params, salt: salt, tag: tag)
    }
}

/// Standard base64 without padding, as used by the PHC string format.
enum PHCBase64 {
    static func encodeNoPad(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "=", with: "")
    }

    static func decodeNoPad(_ s: String) throws -> Data {
        var padded = s
        switch padded.count % 4 {
        case 0: break
        case 2: padded += "=="
        case 3: padded += "="
        default: throw Argon2Error.malformedPHC("invalid base64 length")
        }
        guard let data = Data(base64Encoded: padded) else {
            throw Argon2Error.malformedPHC("invalid base64")
        }
        return data
    }
}