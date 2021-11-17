//
//  File.swift
//  
//
//  Created by Todd Bowden on 11/13/21.
//

import Foundation

extension Data {
    
    func utf8String() throws -> String {
        guard let string = String(data: self, encoding: .utf8) else {
            throw Error.unableToEncodeDataAsUtf8String
        }
        return string
    }
}
