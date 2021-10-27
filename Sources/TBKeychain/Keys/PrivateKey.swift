//
//  PrivateKey.swift
//  
//
//  Created by Todd Bowden on 10/25/21.
//

import Foundation
import CryptoKit

public struct PrivateKey {
    
    // MARK: Stored values

    public let secKey: SecKey
    
    // MARK: Computed values
    
    public var publicKey: PublicKey? {
        guard let publicSecKey = secKey.publicSecKey else { return nil }
        return try? PublicKey(secKey: publicSecKey)
    }
    
    public var x963: Data? {
        return try? secKey.externalRepresentation()
    }
    public var der: Data? {
        ckPrivateKey?.derRepresentation
    }
    public var raw: Data? {
        ckPrivateKey?.rawRepresentation
    }
    public var pem: String? {
        ckPrivateKey?.pemRepresentation
    }
    
    private var ckPrivateKey: P256.Signing.PrivateKey? {
        guard let key = x963 else { return nil }
        return try? P256.Signing.PrivateKey.init(x963Representation: key)
    }
        
    // MARK: Initializers
        
    public init(secKey: SecKey) {
        self.secKey = secKey
    }
    
    public init(_ data: Data, isPermanent: Bool, curve: KeyCurve = .secp256r1) throws {
        if data.isX963Full256PublicPrivateKey {
            self.secKey = try SecKey.privateKey(data, isPermanent: isPermanent)
        } else if data.count == 33 && curve == .secp256r1 {
            let ckKey = try P256.Signing.PrivateKey(rawRepresentation: data)
            self.secKey = try SecKey.privateKey(ckKey.x963Representation, isPermanent: isPermanent)
        } else {
            throw Error.unsupportedKeyFormat
        }
    }
    
}
