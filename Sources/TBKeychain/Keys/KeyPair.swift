//
//  TBKeychain+KeyPair.swift
//  
//
//  Created by Todd Bowden on 10/19/21.
//

import Foundation
    
public struct KeyPair {
        
    public let label: String?
    public let applicationLabel: String?
    public let tag: String?
    public let description: String?
    public let accessGroup: String
    public let tokenID: String
    public let isSecureEnclave: Bool
    public let privateKey: PrivateKey
    public let publicKey: PublicKey

    public init(attributes: [String: Any]) throws {
        label = attributes[kSecAttrLabel as String] as? String
        applicationLabel = attributes[kSecAttrApplicationLabel as String] as? String
        tag = attributes[kSecAttrApplicationTag as String] as? String
        description = attributes[kSecAttrDescription as String] as? String
        accessGroup = attributes[kSecAttrAccessGroup as String] as? String ?? ""
        tokenID = attributes[kSecAttrTokenID as String] as? String ?? ""
        isSecureEnclave = tokenID == kSecAttrTokenIDSecureEnclave as String
        guard let privateSecKey = attributes[kSecValueRef as String] else {
            throw Error.cannotGetPrivateSecKey
        }
        privateKey = PrivateKey(secKey: privateSecKey as! SecKey)
        guard let pubKey = privateKey.publicKey else {
            throw Error.unableToCreatePublicKey
        }
        publicKey = pubKey
    }
}

 
 
