//
//  KeyCurve.swift
//  
//  Created by Todd Bowden on 10/23/21.
//

import Foundation


public enum KeyCurve {
    case secp256r1
    case unknown
    
    var p: Data? {
        switch self {
        case .secp256r1:
            return Data([
                0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
            ])
        default:
            return nil
        }
    }
    
    var a: Int? {
        switch self {
        case .secp256r1:
            return -3
        default:
            return nil
        }
    }
    
    var b: Data? {
        switch self {
        case .secp256r1:
            return Data([
                0x5a,0xc6,0x35,0xd8,0xaa,0x3a,0x93,0xe7,0xb3,0xeb,0xbd,0x55,0x76,0x98,0x86,0xbc,
                0x65,0x1d,0x06,0xb0,0xcc,0x53,0xb0,0xf6,0x3b,0xce,0x3c,0x3e,0x27,0xd2,0x60,0x4b
            ])
        default:
            return nil
        }
    }
    
}
