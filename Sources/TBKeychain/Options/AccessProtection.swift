//
//  AccessabilityProtection.swift
//  
//
//  Created by Todd Bowden on 11/6/21.
//

import Foundation

public enum AccessProtection {
    /// The data in the keychain can only be accessed when the device is unlocked. Only available if a passcode is set on the device.
    case whenPasscodeSetThisDeviceOnly
    /// The data in the keychain item can be accessed only while the device is unlocked by the user.
    case whenUnlockedThisDeviceOnly
    /// The data in the keychain item can be accessed only while the device is unlocked by the user.
    case whenUnlocked
    /// The data in the keychain item cannot be accessed after a restart until the device has been unlocked once by the user.
    case afterFirstUnlockThisDeviceOnly
    /// The data in the keychain item cannot be accessed after a restart until the device has been unlocked once by the user.
    case afterFirstUnlock
    
    
    public var string: CFString {
        switch self {
        case .whenPasscodeSetThisDeviceOnly:
            return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        case .whenUnlockedThisDeviceOnly:
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .whenUnlocked:
            return kSecAttrAccessibleWhenUnlocked
        case .afterFirstUnlockThisDeviceOnly:
            return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .afterFirstUnlock:
            return kSecAttrAccessibleAfterFirstUnlock
        }
        
    }
}


