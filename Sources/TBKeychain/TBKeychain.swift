//
//  TBKeychain.swift
//
//  Created by Todd Bowden on 10/14/21.
//


import Foundation
import CryptoKit

public class TBKeychain {

    public let accessGroup: String
    
    public init(accessGroup: String) {
        self.accessGroup = accessGroup
    }
    

    // MARK: Getting KeyPairs from the keychain
 
    public func keyPair(publicKey: Data) throws -> KeyPair {
        return try keyPair(publicKey: PublicKey(publicKey))
    }
    
    public func keyPair(publicKey: PublicKey) throws -> KeyPair {
        do {
            return try keyPair(applicationLabel: publicKey.sha1)
        } catch (let error as Error) {
            throw error.replace(.keyNotFound(""), with: .keyNotFound(publicKey.uncompressed.hex))
        }
    }
    
    public func keyPair(applicationLabel: Data? = nil, tag: String? = nil) throws -> KeyPair {
        try KeyPair(attributes: keyAttributes(applicationLabel: applicationLabel, tag: tag))
    }
    
    public func keyPairs(applicationLabel: Data? = nil, tag: String? = nil) throws -> [KeyPair] {
        try keysAttributes(applicationLabel: applicationLabel, tag: tag).map { try KeyPair(attributes: $0) }
    }

    public func keyAttributes(applicationLabel: Data? = nil, tag: String? = nil) throws -> [String: Any] {
        let query = lookupKeyAttributesQuery(applicationLabel: applicationLabel, tag: tag, matchAll: false)
        var item: CFTypeRef?
        let result = SecItemCopyMatching(query as CFDictionary, &item)
        if result == errSecItemNotFound {
            throw Error.keyNotFound("")
        }
        guard result == errSecSuccess else {
            throw Error.keysQueryError(result)
        }
        guard let attributes = item as? [String: Any] else {
            throw Error.keysAttributesError
        }
        return attributes
    }
    
    public func keysAttributes(applicationLabel: Data? = nil, tag: String? = nil) throws -> [[String: Any]] {
        let query = lookupKeyAttributesQuery(applicationLabel: applicationLabel, tag: tag, matchAll: true)
        var items: CFTypeRef?
        let result = SecItemCopyMatching(query as CFDictionary, &items)
        if result == errSecItemNotFound {
            return [[String: Any]]()
        }
        guard result == errSecSuccess else {
            throw Error.keysQueryError(result)
        }
        guard let array = items as? [[String: Any]] else {
            throw Error.keysAttributesError
        }
        return array
    }
    
    
    private func lookupKeyAttributesQuery(applicationLabel: Data? = nil, tag: String? = nil, matchAll: Bool = true) -> [String:Any] {
        var query: [String: Any] =  [
            kSecClass as String: kSecClassKey,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnAttributes as String: true,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: matchAll ? kSecMatchLimitAll : kSecMatchLimitOne
        ]
        if let tag = tag {
            query[kSecAttrApplicationTag as String] = tag
        }
        if let applicationLabel = applicationLabel {
            query[kSecAttrApplicationLabel as String] = applicationLabel
        }
        return query
    }
    
    
    // MARK: Encryption and Decryption
    
    /// Encrypt message with publicKey using provided algorithm.  default = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
    public func encrypt(message: Data, publicKey: Data, algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM) throws -> Data {
        try encrypt(message: message, publicKey: PublicKey(publicKey), algorithm: algorithm)
    }

    /// Encrypt message with publicKey using provided algorithm.  default = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
    public func encrypt(message: Data, publicKey: PublicKey, algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let encryptedData = SecKeyCreateEncryptedData(publicKey.secKey, algorithm, message as CFData, &error) else {
            throw Error.encryptionError(error.debugDescription)
        }
        return encryptedData as Data
    }
    
    public func decrypt(message: Data, publicKey: Data, algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM) throws -> Data {
        let keyPair = try keyPair(publicKey: publicKey)
        return try decrypt(message: message, privateKey: keyPair.privateKey, algorithm: algorithm)
    }
    
    public func decrypt(message: Data, privateKey: PrivateKey, algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let decryptedData = SecKeyCreateDecryptedData(privateKey.secKey, algorithm, message as CFData, &error) else {
            throw Error.decryptionError(error.debugDescription)
        }
        return decryptedData as Data
    }
    

}


