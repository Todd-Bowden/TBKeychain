//
//  File.swift
//  
//
//  Created by Todd Bowden on 10/19/21.
//

import Foundation


public extension Data {
    
    var isX963Compressed256PublicKey: Bool {
        return self.count == 33 && (self.first == 2 || self.first == 3)
    }
    
    var isX963Uncompressed256PublicKey: Bool {
        return self.count == 65 && self.first == 4
    }
    
    var isX963Full256PublicPrivateKey: Bool {
        return self.count == 97 && self.first == 4
    }
 
    func toX963Compressed256PublicKey() throws -> Data {
        try PublicKey.compress(key: self)
    }
    
    func toX963Uncompressed256PublicKey(curve: KeyCurve) throws -> Data {
        try PublicKey.uncompress(key: self, curve: curve)
    }
 
}

