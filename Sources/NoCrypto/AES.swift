//
//  File.swift
//  
//
//  Created by Guerson Perez on 3/17/23.
//

import Foundation
import Crypto

public enum AESError: Error {
    
    case keyGenerationError
    
    case encryptionError
    
    case decryptionError
}

public extension String {
    
    static func aesGenerateEncryptionKey() throws -> String {
        return try AESCrypt.aesGenerateEncryptionKey().aesKeyString
    }
    
    func aesEncrypt(data: Data) throws -> Data {
        let key = try aesKeyData
        return try AESCrypt.encrypt(data: data, key: key)
    }
    
    func aesDecrypt(data: Data) throws -> Data {
        let key = try aesKeyData
        return try AESCrypt.decrypt(data: data, key: key)
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

public class AESCrypt {
    
    public static func aesGenerateEncryptionKey() throws -> Data {
        let keyData = SymmetricKey(size: .bits256)
        return keyData.withUnsafeBytes {
            Data(Array($0.bindMemory(to: UInt8.self)))
        }
    }

    public static func encrypt(data: Data, key: Data) throws -> Data {
        try crypt(data: data, key: key, encrypt: true)
    }

    public static func decrypt(data: Data, key: Data) throws -> Data {
        try crypt(data: data, key: key, encrypt: false)
    }

    private static func crypt(data: Data, key: Data, encrypt: Bool) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        if encrypt {
            let sealedBox = try AES.GCM.seal(data, using: symmetricKey)
            return sealedBox.combined!
        } else {
            guard let sealedBox = try? AES.GCM.SealedBox(combined: data) else {
                throw AESError.decryptionError
            }
            return try AES.GCM.open(sealedBox, using: symmetricKey)
        }
    }
}
