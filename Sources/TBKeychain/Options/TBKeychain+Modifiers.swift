//
//  TBKeychain+Modifiers.swift
//  
//
//  Created by Todd Bowden on 11/17/21.
//

import Foundation

public extension TBKeychain {
    
    func accessGroup(_ accessGroup: String) -> TBKeychain {
        TBKeychain(accessGroup: accessGroup, service: service, options: options)
    }
    
    func service(_ service: String) -> TBKeychain {
        TBKeychain(accessGroup: accessGroup, service: service, options: options)
    }
    
    var encryptItems: TBKeychain {
        var options = self.options
        options.encryptItems = true
        return TBKeychain(accessGroup: accessGroup, service: service, options: options)
    }
    
    func authentication(_ auth: Authentication) -> TBKeychain {
        var options = self.options
        options.authentication = auth
        return TBKeychain(accessGroup: accessGroup, service: service, options: options)
    }
    
    func accessProtection(_ accessProtection: AccessProtection) -> TBKeychain {
        var options = self.options
        options.protection = accessProtection
        return TBKeychain(accessGroup: accessGroup, service: service, options: options)
    }
    
}
