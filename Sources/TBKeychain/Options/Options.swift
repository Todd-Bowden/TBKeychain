//
//  Options.swift
//  
//
//  Created by Todd Bowden on 11/6/21.
//

import Foundation

public struct Options {
    public var protection: AccessProtection
    public var constraints: AccessConstraints
    public var synchronizable: Bool
    public var invisible: Bool
    public var encryptItems: Bool
    
    public init(protection: AccessProtection, constraints: AccessConstraints, synchronizable: Bool, invisible: Bool, encryptItems: Bool) {
        self.protection = protection
        self.constraints = constraints
        self.synchronizable = synchronizable
        self.invisible = invisible
        self.encryptItems = encryptItems
    }
    
    public func accessControl(isPrivateKey: Bool = false) throws -> SecAccessControl {
        var flags = constraints.accessFlags
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
            constraints: AccessConstraints.none,
            synchronizable: false,
            invisible: true,
            encryptItems: false
        )
    }
    
    static var `defaultEncryptItems`: Options {
        return Options(
            protection: .afterFirstUnlockThisDeviceOnly,
            constraints: AccessConstraints.none,
            synchronizable: false,
            invisible: true,
            encryptItems: true
        )
    }
}
