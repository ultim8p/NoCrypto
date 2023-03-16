//
//  File.swift
//  
//
//  Created by Guerson Perez on 3/15/23.
//

import Foundation
import Security

public enum RSAKeySize: Int {
   case key1024 = 1024
   case key2048 = 2048
}

enum RSAError: Error {
   case rsaDecryption(_ error: Unmanaged<CFError>?)
   case rsaEncryprion(_ error: Unmanaged<CFError>?)
   case rsaKeyPairGeneration(_ error: Unmanaged<CFError>?)
   case creatingReferenceKey(_ error: Unmanaged<CFError>?)
   case invalidReferenceKey
}

public extension String {
   
   static func generateRSAKeyPair(sizeInBits size: RSAKeySize, tag: String) throws -> (privateKey: String, publicKey: String) {
       let pair = try SecKey.generateRSAKeyPair(sizeInBits: size.rawValue, tag: tag)
       let privateKey = try pair.privateKey.keyString
       let publicKey = try pair.publicKey.keyString
       return (privateKey, publicKey)
   }
   
   func rsaKey(size: RSAKeySize, encrypt data: Data) throws -> Data {
       return try secKey(isPublic: true, size: size.rawValue)
           .encrypt(data: data, algorithm: .rsaEncryptionPKCS1)
   }
   
   func rsaKey(size: RSAKeySize, decrypt data: Data) throws -> Data {
       return try secKey(isPublic: false, size: size.rawValue)
           .decryp(data: data, algorithm: .rsaEncryptionPKCS1)
   }
   
   func rsaKey(size: RSAKeySize, encrypt object: Encodable, using encoder: JSONEncoder? = nil) throws -> Data {
       let encoder = encoder ?? JSONEncoder()
       let objectData = try encoder.encode(object)
       return try rsaKey(size: size, encrypt: objectData)
   }
   
   func rsaKey<Object: Decodable>(size: RSAKeySize, decrypt data: Data, using decoder: JSONDecoder? = nil) throws -> Object {
       let objectData = try rsaKey(size: size, decrypt: data)
       let decoder = decoder ?? JSONDecoder()
       let object = try decoder.decode(Object.self, from: objectData)
       return object
   }
}

private extension SecKey {
   
   var keyData: Data {
       get throws {
           var error: Unmanaged<CFError>?
           let data = SecKeyCopyExternalRepresentation(self, &error)
           guard let unwrappedData = data as Data? else {
               throw RSAError.creatingReferenceKey(error)
           }
           return unwrappedData
       }
   }
   
   var keyString: String {
       get throws {
           return try keyData.base64EncodedString()
       }
   }
}

private extension String {
   
   func secKey(isPublic: Bool, size: Int) throws -> SecKey {
       guard let pubKeyData = Data(base64Encoded: self) else {
           throw RSAError.invalidReferenceKey
       }
       
       let query: [String: Any] = [
         kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
         kSecAttrKeyClass as String: isPublic ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate,
         kSecAttrKeySizeInBits as String: size
       ]
       
       var error: Unmanaged<CFError>?
       guard let pubKeyRef = SecKeyCreateWithData(pubKeyData as CFData, query as CFDictionary, &error)
       else {
           throw RSAError.creatingReferenceKey(error)
       }
       return pubKeyRef
   }
}

private extension SecKey {
   
   static func generateRSAKeyPair(sizeInBits size: Int, tag: String) throws -> (privateKey: SecKey, publicKey: SecKey) {
       let attributes: [CFString: Any] = [
           kSecAttrKeyType: kSecAttrKeyTypeRSA,
           kSecAttrKeySizeInBits: size,
           kSecPrivateKeyAttrs: [
               kSecAttrIsPermanent: false,
               kSecAttrApplicationTag: tag
           ]
       ]
       
       var error: Unmanaged<CFError>?
       guard let privKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
             let pubKey = SecKeyCopyPublicKey(privKey) else {
           throw RSAError.rsaKeyPairGeneration(error)
       }
       return (privateKey: privKey, publicKey: pubKey)
   }
   
   func encrypt(data: Data, algorithm: SecKeyAlgorithm) throws -> Data {
       let payloadData = data as CFData
       var error: Unmanaged<CFError>?
       let encryptedData = SecKeyCreateEncryptedData(self, algorithm, payloadData, &error)
       guard let result = encryptedData as Data?
       else {
           throw RSAError.rsaEncryprion(error)
       }
       return result
   }
   
   func decryp(data: Data, algorithm: SecKeyAlgorithm) throws -> Data {
       let payloadData = data as CFData
       var error: Unmanaged<CFError>?
       let decryptedData = SecKeyCreateDecryptedData(self, algorithm, payloadData, &error)
       guard let result = decryptedData as Data?
       else {
           throw RSAError.rsaDecryption(error)
       }
       return result
   }
}
