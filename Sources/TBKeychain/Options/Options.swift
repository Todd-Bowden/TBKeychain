//
//  Options.swift
//  
//
//  Created by Todd Bowden on 11/6/21.
//

import Foundation

public struct Options {
    public var protection: AccessProtection
    public var authentication: Authentication
    public var synchronizable: Bool
    public var invisible: Bool
    public var encryptItems: Bool
    
    public init(protection: AccessProtection, authentication: Authentication, synchronizable: Bool, invisible: Bool, encryptItems: Bool) {
        self.protection = protection
        self.authentication = authentication
        self.synchronizable = synchronizable
        self.invisible = invisible
        self.encryptItems = encryptItems
    }
    
    public func accessControl(isPrivateKey: Bool = false) throws -> SecAccessControl {
        var flags = authentication.accessFlags
        if isPrivateKey {
            flags = flags.union(.privateKeyUsage)
        } else {
            flags = flags.subtracting(.privateKeyUsage)
        }
        
        var error: Unmanaged<CFError>?
        if let accessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault,protection.string,flags,&error) {
            return accessControl
        } else {
            throw Error.unableToCreateAccessControl(error.debugDescription)
        }
    }
}

public extension Options {
    static var `default`: Options {
        return Options(
            protection: .afterFirstUnlockThisDeviceOnly,
            authentication: Authentication.none,
            synchronizable: false,
            invisible: true,
            encryptItems: false
        )
    }
    
    static var `defaultEncryptItems`: Options {
        return Options(
            protection: .afterFirstUnlockThisDeviceOnly,
            authentication: Authentication.none,
            synchronizable: false,
            invisible: true,
            encryptItems: true
        )
    }
}
