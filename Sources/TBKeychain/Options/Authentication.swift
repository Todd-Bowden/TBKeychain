//
//  Authentication.swift
//  
//
//  Created by Todd Bowden on 11/7/21.
//

// authentication

import Foundation

public struct Authentication {
    
    public let accessFlags: SecAccessControlCreateFlags
    
    public init(_ flags: [SecAccessControlCreateFlags]) {
        accessFlags = SecAccessControlCreateFlags(flags)
    }
    
    public static var none: Authentication {
        return Authentication([])
    }
    
    public static var presence: Authentication {
        return Authentication([.userPresence])
    }
    
    public static var biometric: Authentication {
        return Authentication([.biometryAny])
    }
    
    public static var biometricCurrent: Authentication {
        return Authentication([.biometryCurrentSet])
    }
    
}
