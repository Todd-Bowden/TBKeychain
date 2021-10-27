//
//  File.swift
//  
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
        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error) else {
            throw Error.unableToCreatePrivateSecKey(error.debugDescription)
        }
        return secKey
    }
    
    static func generatePrivateKey() -> SecKey? {

        let attributes: [String: Any] = [
            kSecAttrKeyType as String:              kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String:             kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String:        256,
            kSecAttrIsPermanent as String:          false,
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            return nil
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
