//
//  Error.swift
//
//  Created by Todd Bowden on 10/25/21.
//

import Foundation

public enum Error: Swift.Error, Equatable {
    case cannotGetPrivateSecKey
    case decryptionError(String)
    case encryptionError(String)
    case encryptionErrorInvalidPublicKey
    case itemQueryError(Int32)
    case keyNotFound(String)
    case keysAttributesError
    case keysQueryError(Int32)
    case reservedKeyTag(String)
    case secKeyIsNotAValidPublicKey
    case secKeyUnableToGetExternalRepresentation(String)
    case unableToEncodeDataAsUtf8String
    case unableToEncodeStringAsUtf8(String)
    case unableToCreateAccessControl(String)
    case unableToCreatePrivateSecKey(String)
    case unableToCreatePublicKey
    case unableToCreatePublicSecKey(String)
    case unableToCreatePublicKeyFromData(Data)
    case unableToDeleteKey(Int32)
    case unableToGetItemAttributes
    case unableToSaveItem(Int32)
    case unsupportedKeyCurve
    case unsupportedKeyFormat
    

    func replace(_ error: Error, with replacement: Error) -> Error {
        return self == error ? replacement : error
    }
}
