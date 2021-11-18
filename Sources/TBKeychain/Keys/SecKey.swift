//
//  SecKey.swift
//
//  Created by Todd Bowden on 10/23/21.
//

import Foundation

public extension SecKey {
    
    static func publicKey(_ data: Data) throws -> SecKey {
        let attributes: [String:Any] = [
            kSecAttrKeyType as String:              kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String:             kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String:        256,
            kSecAttrIsPermanent as String:          false,
        ]
        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error) else {
            throw Error.unableToCreatePublicSecKey(error.debugDescription)
        }
        return secKey
    }
    
    static func privateKey(_ data: Data, isPermanent: Bool) throws -> SecKey {
        let attributes: [String:Any] = [
            kSecAttrKeyType as String:              kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String:             kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String:        256,
            kSecAttrIsPermanent as String:          isPermanent,
        ]
        return try privateKey(data, attributes: attributes)
    }
    
    static func privateKey(_ data: Data, attributes: [String:Any]) throws -> SecKey {
        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error) else {
            throw Error.unableToCreatePrivateSecKey(error.debugDescription)
        }
        return secKey
    }
    
    static func generatePrivateKey() throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String:              kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String:             kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String:        256,
            kSecAttrIsPermanent as String:          false,
        ]
        return try generatePrivateKey(attributes: attributes)
    }
    
    static func generatePrivateKey(attributes: [String:Any]) throws -> SecKey {
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw Error.unableToCreatePrivateSecKey(error.debugDescription)
        }
        return privateKey
    }
    
    func externalRepresentation() throws -> Data {
        var error: Unmanaged<CFError>?
        if let cfdata = SecKeyCopyExternalRepresentation(self, &error) {
            return cfdata as Data
        } else {
            throw Error.secKeyUnableToGetExternalRepresentation(error.debugDescription)
        }
    }

    var publicSecKey: SecKey? {
        return SecKeyCopyPublicKey(self)
    }
}
