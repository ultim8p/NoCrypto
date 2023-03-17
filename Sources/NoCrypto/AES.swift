//
//  File.swift
//  
//
//  Created by Guerson Perez on 3/17/23.
//

import Foundation
import CommonCrypto

public enum AESError: Error {
    case keyGenerationError
    case encryptionError
    case decryptionError
}


public extension String {
    
    static func aesGenerateEncryptionKey(length: Int = kCCKeySizeAES256) throws -> String {
        return try AES.aesGenerateEncryptionKey().aesKeyString
    }
    
    func aesEncrypt(data: Data) throws -> Data {
        let key = try aesKeyData
        return try AES.encrypt(data: data, key: key)
    }
    
    func aesDecrypt(data: Data) throws -> Data {
        let key = try aesKeyData
        return try AES.decrypt(data: data, key: key)
    }
    
    func aesEncrypt(object: Encodable, using encoder: JSONEncoder? = nil) throws -> Data {
        let encoder = encoder ?? JSONEncoder()
        let objectData = try encoder.encode(object)
        return try aesEncrypt(data: objectData)
    }
    
    func aesDecrypt<T: Decodable>(data: Data, using decoder: JSONDecoder? = nil) throws -> T {
        let objectData = try aesDecrypt(data: data)
        let decoder = decoder ?? JSONDecoder()
        let object = try decoder.decode(T.self, from: objectData)
        return object
    }
}

private extension String {
    
    var aesKeyData: Data {
        get throws {
            guard let data = Data(base64Encoded: self)
            else { throw AESError.keyGenerationError }
            return data
        }
    }
}

private extension Data {
    
    var aesKeyString: String {
        get throws {
            return base64EncodedString()
        }
    }
}

public class AES {
    
    public static func aesGenerateEncryptionKey(length: Int = kCCKeySizeAES256) throws -> Data {
        var keyData = Data(count: length)
        let result = keyData.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, length, $0.baseAddress!)
        }
        
        if result == errSecSuccess {
            return keyData
        } else {
            throw AESError.keyGenerationError
        }
    }

    public static func encrypt(data: Data, key: Data) throws -> Data {
        try crypt(data: data, key: key, operation: CCOperation(kCCEncrypt))
    }

    public static func decrypt(data: Data, key: Data) throws -> Data {
        try crypt(data: data, key: key, operation: CCOperation(kCCDecrypt))
    }

    private static func crypt(data: Data, key: Data, operation: CCOperation) throws -> Data {
        let cryptLength = size_t(data.count + kCCBlockSizeAES128)
        var cryptData = Data(count: cryptLength)
        
        var numBytesEncrypted: size_t = 0
        let options = CCOptions(kCCOptionPKCS7Padding)
        
        let cryptStatus = cryptData.withUnsafeMutableBytes { cryptBytes in
            data.withUnsafeBytes { dataBytes in
                key.withUnsafeBytes { keyBytes in
                    CCCrypt(operation, CCAlgorithm(kCCAlgorithmAES), options,
                            keyBytes.baseAddress, key.count,
                            nil,
                            dataBytes.baseAddress, data.count,
                            cryptBytes.baseAddress, cryptLength,
                            &numBytesEncrypted)
                }
            }
        }
        
        if cryptStatus == CCCryptorStatus(kCCSuccess) {
            cryptData.removeSubrange(numBytesEncrypted..<cryptData.count)
            return cryptData
        } else {
            throw operation == CCOperation(kCCEncrypt) ? AESError.encryptionError : AESError.decryptionError
        }
    }
}
