//
//  PublicKeyTests.swift
//  
//
//  Created by Todd Bowden on 10/21/21.
//

import Foundation
import XCTest
import CryptoKit
@testable import TBKeychain

final class PublicKeyTests: XCTestCase {
    
    func generateX963Secp256r1PublicKey() -> Data? {
        try? SecKey.generatePrivateKey()?.publicSecKey?.externalRepresentation()
    }
    
    func generateX963RandomDataPublicKey() -> Data? {
        guard let bytes = randomBytes(64) else { return nil }
        return [0x04] + bytes
    }
    
    func randomBytes(_ count: Int) -> Data? {
          var bytes = [UInt8](repeating: 0, count: count)
          let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
          guard status == errSecSuccess else { return nil }
          return Data(bytes)
      }
    
    func test_CompressUncompressSecp256r1() {
        for i in 0...500 {
            if i % 100 == 0 { print(i) }
            guard let key = generateX963Secp256r1PublicKey() else { return XCTFail() }
            guard let compressedKey = try? PublicKey.compress(key: key) else { return XCTFail() }
            guard let uncompressedKey = try? PublicKey.uncompress(key: compressedKey, curve: .secp256r1) else { return XCTFail() }
            XCTAssertEqual(key, uncompressedKey)
        }
    }
    
    func test_DectectCurveSecp256r1() {
        for i in 0...100 {
            if i % 10 == 0 { print(i) }
            guard let key = generateX963Secp256r1PublicKey() else { return XCTFail() }
            let curve = PublicKey.detectCurve(key: key)
            XCTAssertEqual(curve,.secp256r1)
        }
    }
    
    func test_DectectCurveUnknown() {
        for i in 0...100 {
            if i % 10 == 0 { print(i) }
            guard let key = generateX963RandomDataPublicKey() else { return XCTFail() }
            let curve = PublicKey.detectCurve(key: key)
            XCTAssertEqual(curve,.unknown)
        }
    }
    
    
    
}
