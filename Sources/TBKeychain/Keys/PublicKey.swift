//
//  PublicKey.swift
//
//  Created by Todd Bowden on 10/20/21.
//

import Foundation
import CryptoKit
import BigInt


public struct PublicKey {
    
    // MARK: Stored values
   
    public let x963Uncompressed: Data
    public let secKey: SecKey
    
    // MARK: Computed values
    
    public var curve: KeyCurve {
        PublicKey.detectCurve(key: x963Uncompressed)
    }
    public var uncompressed: Data {
        x963Uncompressed
    }
    public var x963Compressed: Data {
        (try? PublicKey.compress(key: x963Uncompressed)) ?? Data()
    }
    public var compressed: Data {
        x963Compressed
    }
    public var pem: String {
        ckPublicKey?.pemRepresentation ?? ""
    }
    public var der: Data {
        ckPublicKey?.derRepresentation ?? Data()
    }
    public var raw: Data {
        guard x963Uncompressed.count == 65 else { return Data() }
        return x963Uncompressed[1...64]
    }
    public var x: Data {
        guard x963Uncompressed.count == 65 else { return Data() }
        return x963Uncompressed[1...32]
    }
    public var y: Data {
        guard x963Uncompressed.count == 65 else { return Data() }
        return x963Uncompressed[33...64]
    }
    public var sha1: Data {
        Data(Insecure.SHA1.hash(data: x963Uncompressed))
    }
    public var sha256: Data {
        Data(SHA256.hash(data: x963Uncompressed))
    }
    
    private var ckPublicKey: P256.Signing.PublicKey? {
        return try? P256.Signing.PublicKey.init(x963Representation: x963Uncompressed)
    }
        
    // MARK: Initializers
    
    private init(x963Uncompressed: Data, secKey: SecKey? = nil) throws {
        guard x963Uncompressed.isX963Uncompressed256PublicKey else {
            throw Error.unsupportedKeyFormat
        }
        self.x963Uncompressed = x963Uncompressed
        self.secKey = try secKey ?? SecKey.publicKey(x963Uncompressed)
    }
        
    public init(secKey: SecKey) throws {
        let key = try secKey.externalRepresentation()
        guard key.isX963Uncompressed256PublicKey else {
            throw Error.secKeyIsNotAValidPublicKey
        }
        try self.init(x963Uncompressed: key, secKey: secKey)
    }
    
    public init(_ data: Data, curve: KeyCurve = .secp256r1) throws {
        if data.isX963Uncompressed256PublicKey {
            try self.init(x963Uncompressed: data)
        } else if data.isX963Compressed256PublicKey {
            try self.init(x963Uncompressed: data.toX963Uncompressed256PublicKey(curve: curve))
        } else if data.count == 64 {
            try self.init(x963Uncompressed: [0x04] + data)
        } else if let key = try? P256.Signing.PublicKey.init(derRepresentation: data).x963Representation {
            try self.init(x963Uncompressed: key)
        } else {
            throw Error.unsupportedKeyFormat
        }
    }
    
    public init(pem: String) throws {
        try self.init(x963Uncompressed: P256.Signing.PublicKey.init(pemRepresentation: pem).x963Representation)
    }
    
    // MARK: Static Functions
    
    static func compress(key: Data) throws -> Data {
        if key.isX963Compressed256PublicKey { return key }
        guard key.isX963Uncompressed256PublicKey else { throw Error.unsupportedKeyFormat }
        let x = key[1...32]
        let flag: UInt8 = 2 + (key[64] % 2)
        return Data([flag]) + x
    }
    
    static func uncompress(key: Data, curve: KeyCurve) throws -> Data {
        if key.isX963Uncompressed256PublicKey { return key }
        guard key.isX963Compressed256PublicKey else { throw Error.unsupportedKeyFormat }
        guard key.count == 33 else { throw Error.unsupportedKeyFormat }
        guard let p = curve.p, let a = curve.a, let b = curve.b else { throw Error.unsupportedKeyCurve }
        let xData = key[1...32]
        let x = BigInt(BigUInt(xData))
        let y = calculateY(x: x, a: BigInt(a), b: BigInt(BigUInt(b)), p: BigInt(BigUInt(p)), isOdd: key[0] == 3)
        var yData = y.serialize()
        while yData.count < 32 { yData = [0x00] + yData }
        return [0x04] + xData + yData
    }
    
    static func calculateY(x: BigInt, a: BigInt, b: BigInt, p: BigInt, isOdd: Bool) -> BigUInt {
        let y2 = (x.power(3, modulus: p) + (a * x) + b).modulus(p)
        var y = y2.power((p+1)/4, modulus: p)
        let yMod2 = y.modulus(2)
        if isOdd && yMod2 != 1 || !isOdd && yMod2 != 0  {
            y = p - y
        }
        return BigUInt(y)
    }
    
    static func detectCurve(key: Data) -> KeyCurve {
        if isCurve(.secp256r1, key: key) { return .secp256r1 }
        return .unknown
    }
    
    static func isCurve(_ curve: KeyCurve, key: Data) -> Bool {
        guard key.isX963Uncompressed256PublicKey else { return false }
        guard let cKey = try? compress(key: key) else { return false }
        guard let uKey = try? uncompress(key: cKey, curve: curve) else { return false }
        return key == uKey
    }
    
}



    

