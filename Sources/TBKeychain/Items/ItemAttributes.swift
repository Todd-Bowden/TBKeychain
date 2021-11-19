//
//  ItemAttributes.swift
//  
//
//  Created by Todd Bowden on 11/13/21.
//

import Foundation

public struct ItemAttributes {
    
    public enum ItemType: String, Codable {
        case string = "String"
        case data = "Data"
        case codable = "Codable"
        case password = "Password"
    }
    
    public struct ItemMetadata: Codable {
        let type: ItemType
        let encryption: Data?
    }
    
    public let name: String
    public let service: String
    public let vData: Data
    public let label: String?
    public let accessGroup: String?
    public let synchronizable: Bool
    public let invisible: Bool
    public let creationDate: Date
    public let modificationData: Date
    public let `class`: String
    public let uuid: String
    
    public let type: ItemType
    public let encryptionKey: Data?
    public var isEncrypted: Bool { return encryptionKey != nil }
    
    public func data() throws -> Data {
        if let encryptionKey = encryptionKey {
            let keychain = TBKeychain(accessGroup: accessGroup, service: service)
            return try keychain.decrypt(message: vData, publicKey: encryptionKey)
        } else {
            return vData
        }
    }
    
    public func string() throws -> String {
        try data().utf8String()
    }
    
    public func object<T:Codable>() throws -> T {
        let decoder = JSONDecoder()
        return try decoder.decode(T.self, from: data())
    }
    
    public func item() throws -> Data {
        try data()
    }
    
    public func item() throws -> String {
        try string()
    }
    
    public func item<T:Codable>() throws -> T {
        try object()
    }
    
    init(_ attributes: [String:Any]) {
        name = attributes[kSecAttrAccount as String] as? String ?? ""
        service = attributes[kSecAttrService as String] as? String ?? ""
        vData = attributes["v_Data"] as? Data ?? Data()
        label = attributes[kSecAttrLabel as String] as? String
        accessGroup = attributes[kSecAttrAccessGroup as String] as? String ?? ""
        synchronizable = attributes[kSecAttrSynchronizable as String] as? Bool ?? false
        invisible = attributes[kSecAttrIsInvisible as String] as? Bool ?? false
        `class` = attributes["class"] as? String ?? ""
        uuid = attributes["UUID"] as? String ?? ""
        creationDate = attributes[kSecAttrCreationDate as String] as? Date ?? Date(timeIntervalSince1970: 0)
        modificationData = attributes[kSecAttrModificationDate as String] as? Date ?? Date(timeIntervalSince1970: 0)
        
        let decoder = JSONDecoder()
        if let labelData = label?.data(using: .utf8), let metadata = try? decoder.decode(ItemMetadata.self, from: labelData) {
            type = metadata.type
            encryptionKey = metadata.encryption
        } else {
            type = .password
            encryptionKey = nil
        }
    }
    
}
