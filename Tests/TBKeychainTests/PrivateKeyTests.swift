//
//  PrivateKeyTests.swift
//
//  Created by Todd Bowden on 10/25/21.
//

import Foundation
import XCTest
import CryptoKit
@testable import TBKeychain

final class PrivateKeyTests: XCTestCase {
    
    func generateX963Secp256r1PrivateKey() -> Data? {
        try? SecKey.generatePrivateKey().externalRepresentation()
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
   
    func testPrivKey() {
        let key = generateX963Secp256r1PrivateKey()!
        print(key)
        print(key.hex)
        let privKey = key.suffix(key.count - 65)
        print(privKey)
        print(privKey.hex)
        let ckKey = try! P256.Signing.PrivateKey(x963Representation: key)
        print(ckKey)
        print(ckKey.pemRepresentation)
        print("^^^^^^^^^^^^^^^^^^^^^^^^")
        let ckPrivKey = try! P256.Signing.PrivateKey(rawRepresentation: privKey)
        print(ckPrivKey)
        print(ckPrivKey.rawRepresentation.hex)
        print(ckPrivKey.x963Representation.hex)
    }
    
    
    
}
