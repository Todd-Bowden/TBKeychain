//
//  File.swift
//  
//
//  Created by Todd Bowden on 11/13/21.
//

import Foundation

extension String {
    
    func utf8Data() throws -> Data {
        guard let data = self.data(using: .utf8) else {
            throw Error.unableToEncodeStringAsUtf8(self)
        }
        return data
    }
}
