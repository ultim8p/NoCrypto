public struct NoCrypto {
    public private(set) var text = "Hello, World!"

    public init() {
    }
}

public enum Default {
    static let rsaKeySize: RSAKeySize = .key1024
    static let otpInterval: Int = 30
    static let otpRangeValidation: Int = 1
    static let otpKeySize: OTPKeySize = .key40
    static let apiKeySize: Int = 40
}

public extension String {
    
    static func createCredentials(tag: String) throws -> (privateKey: String, publicKey: String, otpKey: String, apiKey: String) {
        let rsaKeys = try String.generateRSAKeyPair(sizeInBits: Default.rsaKeySize, tag: tag)
        let otpKey = try String.generateOTPKey(size: Default.otpKeySize)
        let apiKey = String.randomString(length: Default.apiKeySize)
        return (rsaKeys.privateKey, rsaKeys.publicKey, otpKey, apiKey)
    }
}
