//
//  TBKeychain.swift
//
//  Created by Todd Bowden on 10/14/21.
//

import Foundation

public class TBKeychain {

    public let accessGroup: String?
    public let service: String
    public let options: Options
    
    public init(accessGroup: String? = nil, service: String = "", options: Options? = nil) {
        self.accessGroup = accessGroup
        self.service = service
        self.options = options ?? Options.default
    }
    
}


