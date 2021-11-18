//
//  TBKeychain+Items.swift
//  
//
//  Created by Todd Bowden on 11/13/21.
//

import Foundation

public extension TBKeychain {
    
    typealias ItemType = ItemAttributes.ItemType
    typealias ItemMetadata = ItemAttributes.ItemMetadata
    
    
    // MARK: Get items from the keychain
    
    func itemAttributes(name: String, service: String) throws -> ItemAttributes {
        try ItemAttributes(itemAttributesDictionary(name: name, service: service))
    }
    
    func itemAttributesDictionary(name: String, service: String) throws -> [String:Any] {
        let query = makeItemsAttributesLookupQuery(name: name, service: service)
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            throw Error.itemQueryError(status)
        }
        guard let attributes = item as? [String: Any] else {
            throw Error.unableToGetItemAttributes
        }
        return attributes
    }
    
    private func makeItemsAttributesLookupQuery(name: String?, service: String) -> [String:Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecReturnRef as String: true
        ]
        if let name = name {
            query[kSecAttrAccount as String] = name
            query[kSecMatchLimit as String] = kSecMatchLimitOne
        } else {
            query[kSecMatchLimit as String] = kSecMatchLimitAll
        }
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }
    
    func string(name: String, service: String) throws -> String {
        try itemAttributes(name: name, service: service).string()
    }
    
    func object<T:Codable>(name: String, service: String) throws -> T {
        try itemAttributes(name: name, service: service).object()
    }
    
    func data(name: String, service: String) throws -> Data {
        try itemAttributes(name: name, service: service).data()
    }
    
    
    // MARK: Save items to the keychain
    
    func save(string: String, name: String, service: String? = nil, options: Options? = nil) throws {
        guard let data = string.data(using: .utf8) else {
            throw Error.unableToEncodeStringAsUtf8(string)
        }
        try save(data: data, name: name, service: service, label: nil, options: options, type: .string)
    }
    
    func save<T:Codable>(object: T, name: String, service: String? = nil, options: Options? = nil) throws {
        let encoder = JSONEncoder()
        let data = try encoder.encode(object)
        try save(data: data, name: name, service: service, label: nil, options: options, type: .codable)
    }
    
    func save(data: Data, name: String, service: String? = nil, options: Options? = nil) throws {
        try save(data: data, name: name, service: service, label: nil, options: options, type: .data)
    }
    
    func save(password: Data, name: String, service: String? = nil, label: String, options: Options? = nil) throws {
        try save(data: password, name: name, service: service, label: nil, options: options, type: .password)
    }
    
    private func save(data: Data, name: String, service: String?, label: String?, options: Options?, type: ItemType) throws {
        var data = data
        var label = label
        let service = service ?? self.service
        let options = options ?? self.options
        let access = try options.accessControl()
        var encrypt = options.encryptItems
        var synchronizable = options.synchronizable
        var invisible = options.invisible
        
        switch type {
        case .string, .data, .codable:
            var encryptionKey: Data?
            if encrypt {
                let keyPair = try itemEncryptionKeyPair()
                data = try self.encrypt(message: data, publicKey: keyPair.publicKey)
                encryptionKey = keyPair.publicKey.uncompressed
                synchronizable = false
                invisible = true
            }
            let metadata = ItemMetadata(type: type, encryption: encryptionKey)
            let jsonEncoder = JSONEncoder()
            label = try jsonEncoder.encode(metadata).utf8String()
        case .password:
            encrypt = false
        }
        
        var status = add(data: data, name: name, service: service, label: label, access: access, synchronizable: synchronizable, invisible: invisible)
        guard status == errSecSuccess else {
            status = update(data: data, name: name, service: service, label: label, access: access, synchronizable: synchronizable, invisible: invisible)
            guard status == errSecSuccess else {
                throw Error.unableToSaveItem(status)
            }
            return
        }
    }
        
    private func add(data: Data, name: String, service: String, label: String?, access: SecAccessControl, synchronizable: Bool, invisible: Bool) -> OSStatus {
        var attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: name,
            kSecAttrService as String: service,
            kSecValueData as String: data,
            kSecAttrAccessControl as String: access,
            kSecAttrSynchronizable as String: synchronizable,
            kSecAttrIsInvisible as String: invisible
        ]
        if let accessGroup = accessGroup {
            attributes[kSecAttrAccessGroup as String] = accessGroup
        }
        if let label = label {
            attributes[kSecAttrLabel as String] = label
        }
        return SecItemAdd(attributes as CFDictionary, nil)
    }
    
    private func update(data: Data, name: String, service: String, label: String?, access: SecAccessControl, synchronizable: Bool, invisible: Bool) -> OSStatus {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: name,
            kSecAttrService as String: service
        ]
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        var attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessControl as String: access,
            kSecAttrSynchronizable as String: synchronizable,
            kSecAttrIsInvisible as String: invisible
        ]
        if let label = label {
            attributes[kSecAttrLabel as String] = label
        }
        return SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    }
    
    
    // MARK: Delete items in the keychain
    
    func delete(name: String, service: String) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: name,
            kSecAttrService as String: service
        ]
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        let result = SecItemDelete(query as CFDictionary)
        guard result == errSecSuccess else {
            throw Error.unableToDeleteItem(result)
        }
    }
    
}
