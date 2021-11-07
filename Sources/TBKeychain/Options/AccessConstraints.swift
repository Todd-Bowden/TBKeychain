//
//  File.swift
//  
//
//  Created by Todd Bowden on 11/7/21.
//

import Foundation

public struct AccessConstraints {
    
    public let accessFlags: SecAccessControlCreateFlags
    
    public init(_ flags: [SecAccessControlCreateFlags]) {
        accessFlags = SecAccessControlCreateFlags(flags)
    }
    
    public static var none: AccessConstraints {
        return AccessConstraints([])
    }
    
    public static var presence: AccessConstraints {
        return AccessConstraints([.userPresence])
    }
    
    public static var biometric: AccessConstraints {
        return AccessConstraints([.biometryAny])
    }
    
    public static var biometricCurrent: AccessConstraints {
        return AccessConstraints([.biometryCurrentSet])
    }
    
}
