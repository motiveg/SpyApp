import Foundation

protocol Cipher {
    func encode(_ message: String, secret: String) -> String
    func decrypt(_ encodedMessage: String, secret: String) -> String
}

struct CipherMessage {
    // error messages
    static let invisibleCharError = "Error: invisible ascii characters cannot be used.\n"
    static let invalidSecret = "Error: an invalid secret was passed. Only unsigned integers are allowed.\n"
    static let secretTooLarge = "Error: secret is too large for decryption.\n"
    static let alphanumericOnly = "Error: only alphanumeric characters are accepted for this cipher.\n"
    static let nilError = "Error: nil input was detected.\n"
    static let invalidConversion = "Error: one or more characters could not be converted correctly; try a different secret.\n"
    
    static let noMessage = "No message entered.\n"
    static let noSecret = "No secret entered.\n"
    
    static let noCipherSelected = "Error: no cipher selected.\n"
}

// This function encodes and decrypts strings by shifting characters by
// a specified amount. All visible characters can be used but the shift
// amount for decrypting can't result in unseeable ascii characters.
// The decrypt function will return an error string if this happens.
struct CesarCipher: Cipher {
    
    func encode(_ message: String, secret: String) -> String {
        
        if (message == "" && secret == "") {
            return CipherMessage.noMessage + CipherMessage.noSecret
        }
        if (message == "") {
            return CipherMessage.noMessage
        }
        if (secret == "") {
            return CipherMessage.noSecret
        }
        
        var encoded = ""
        
        if let shiftBy = UInt32(secret) {
            
            for character in message {
                
                let unicode = character.unicodeScalars.first!.value
                
                // valid character
                if (unicode > 32) {
                    let shiftedUnicode = unicode + shiftBy
                    let shiftedCharacter = String(UnicodeScalar(UInt32(shiftedUnicode))!)
                    encoded = encoded + shiftedCharacter
                    
                // leave space as is
                } else if (unicode == 32) {
                    encoded = encoded + " "
                    
                // invisible ascii character encountered
                } else {
                    return CipherMessage.invisibleCharError
                } // end inner if
            } // end for
        } else {
            return CipherMessage.invalidSecret
        } // end outer if
        
        // validate conversion
        if (message.count == encoded.count) {
            return encoded
        } else {
            return CipherMessage.invalidConversion
        }
    }
    
    func decrypt(_ encodedMessage: String, secret: String) -> String {
        
        if (encodedMessage == "" && secret == "") {
            return CipherMessage.noMessage + CipherMessage.noSecret
        }
        if (encodedMessage == "") {
            return CipherMessage.noMessage
        }
        if (secret == "") {
            return CipherMessage.noSecret
        }
        
        var decrypted = ""
        if let shiftBy = UInt32(secret) {
            
            for character in encodedMessage {
                
                let unicode = character.unicodeScalars.first!.value
                
                // ascii value less than 32
                if (unicode < 32) {
                    return CipherMessage.invisibleCharError
                }
                
                // valid character
                if (unicode > shiftBy + 32) {
                    let shiftedUnicode = unicode - shiftBy
                    let shiftedCharacter = String(UnicodeScalar(UInt32(shiftedUnicode))!)
                    decrypted = decrypted + shiftedCharacter
                    
                // leave space as is
                } else if (unicode == 32) {
                    decrypted = decrypted + " "
                    
                // invisible ascii character encountered
                } else {
                    return CipherMessage.secretTooLarge
                } // end inner if
                
            } // end for
        } else {
            return CipherMessage.invalidSecret
        } // end outer if
        
        // validate conversion
        if (encodedMessage.count == decrypted.count) {
            return decrypted
        } else {
            return CipherMessage.invalidConversion
        }
    }
}

// Only take alphanumeric input (characters A-Z, a-z and numbers 0-9,
// with the exception of spaces).
// The output should only include characters A-Z or 0-9. Lower-case
// characters should be converted to upper-case before they are encrypted
// The mapping should be cyclical in either direction
struct AlphanumericCesarCipher: Cipher {
    
    // 0-9: 48-57
    // A-Z: 65-90
    // a-z: 97-122
    
    // if 97-122, convert by subtracting 32
    // i.e. for a to A => a.value - 32 = 65
    let numMin: UInt32 = 48,
    numMax: UInt32 = 57,
    alphaMin: UInt32 = 97,
    alphaMax: UInt32 = 122,
    alphaUpperMin: UInt32 = 65,
    alphaUpperMax: UInt32 = 90,
    space: UInt32 = 32
    
    func encode(_ message: String, secret: String) -> String {
        
        if (message == "" && secret == "") {
            return CipherMessage.noMessage + CipherMessage.noSecret
        }
        if (message == "") {
            return CipherMessage.noMessage
        }
        if (secret == "") {
            return CipherMessage.noSecret
        }
        
        var encoded = ""
        if let shiftBy = UInt32(secret) {
            
            for character in message {
                
                var remainingShift = shiftBy
                let unicode = character.unicodeScalars.first!.value
                var shiftedUnicode = unicode
                
                // if uppercase, convert to lowercase
                if (unicode >= alphaMin && unicode <= alphaMax) {
                    shiftedUnicode -= 32
                }
                
                while remainingShift > 0 {
                    
                    // character should either be within 48-57 or 97-122
                    // if unicode + remainingShift > topOfRange
                    // make unicode topOfRange and get remainingShift = remainingShift - ( topOfRange - currentValue )
                    
                    // check if shiftedUnicode is number
                    if (shiftedUnicode >= numMin && shiftedUnicode <= numMax) {
                        
                        // remaining shift amount too big
                        if (shiftedUnicode + remainingShift > numMax) {
                            remainingShift = remainingShift - ( numMax - shiftedUnicode ) - 1
                            shiftedUnicode = alphaUpperMin
                        }
                            
                        // remaining shift amount is used
                        else {
                            shiftedUnicode += remainingShift
                            remainingShift = 0
                        }
                    }
                        
                    // check if shiftedUnicode is lower alpha
                    else if (shiftedUnicode >= alphaUpperMin && shiftedUnicode <= alphaUpperMax) {
                        
                        // remaining shift amount too big
                        if (shiftedUnicode + remainingShift > alphaUpperMax) {
                            remainingShift = remainingShift - ( alphaUpperMax - shiftedUnicode ) - 1
                            shiftedUnicode = numMin
                        }
                            
                        // remaining shift amount is used
                        else {
                            shiftedUnicode += remainingShift
                            remainingShift = 0
                        }
                    }
                        
                    // check if shiftedUnicode is a space
                    else if (shiftedUnicode == space){
                        remainingShift = 0
                    }
                        
                    // shiftedUnicode is an invalid character
                    else {
                        return CipherMessage.alphanumericOnly
                    }
                }
                
                let shiftedCharacter = String(UnicodeScalar(UInt8(shiftedUnicode)))
                encoded = encoded + shiftedCharacter
                
            }
        } else {
            return CipherMessage.invalidSecret
        }
        
        // validate conversion
        if (message.count == encoded.count) {
            return encoded
        } else {
            return CipherMessage.invalidConversion
        }
    }
    
    func decrypt(_ encodedMessage: String, secret: String) -> String {
        
        if (encodedMessage == "" && secret == "") {
            return CipherMessage.noMessage + CipherMessage.noSecret
        }
        if (encodedMessage == "") {
            return CipherMessage.noMessage
        }
        if (secret == "") {
            return CipherMessage.noSecret
        }
        
        var decrypted = ""
        if let shiftBy = UInt32(secret) {
            
            for character in encodedMessage {
                
                var remainingShift = shiftBy
                let unicode = character.unicodeScalars.first!.value
                var shiftedUnicode = unicode
                
                // if uppercase, convert to lowercase
                if (unicode >= alphaMin && unicode <= alphaMax) {
                    shiftedUnicode -= 32
                }
                
                while remainingShift > 0 {
                    
                    // character should either be within 48-57 or 97-122
                    // if unicode + remainingShift > topOfRange
                    // make unicode topOfRange and get remainingShift = remainingShift - ( topOfRange - currentValue )
                    
                    // check if shiftedUnicode is number
                    if (shiftedUnicode >= numMin && shiftedUnicode <= numMax) {
                        
                        // remaining shift amount too big
                        if (shiftedUnicode < numMin + remainingShift) {
                            remainingShift = remainingShift - ( shiftedUnicode - numMin ) - 1
                            shiftedUnicode = alphaUpperMax
                        }
                            
                        // remaining shift amount is used
                        else {
                            shiftedUnicode -= remainingShift
                            remainingShift = 0
                        }
                    }
                        
                    // check if shiftedUnicode is lower alpha
                    else if (shiftedUnicode >= alphaUpperMin && shiftedUnicode <= alphaUpperMax) {
                        
                        // remaining shift amount too big
                        if (shiftedUnicode < alphaUpperMin + remainingShift) {
                            remainingShift = remainingShift - ( shiftedUnicode - alphaUpperMin ) - 1
                            shiftedUnicode = numMax
                        }
                            
                        // remaining shift amount is used
                        else {
                            shiftedUnicode -= remainingShift
                            remainingShift = 0
                        }
                    
                    // check if shiftedUnicode is a space
                    } else if (shiftedUnicode == space){
                        remainingShift = 0
                        
                    // shiftedUnicode is an invalid character
                    } else {
                        return CipherMessage.alphanumericOnly
                    }
                }
                
                let shiftedCharacter = String(UnicodeScalar(UInt8(shiftedUnicode)))
                decrypted = decrypted + shiftedCharacter
                
            }
        } else {
            return CipherMessage.invalidSecret
        }
        
        // validate conversion
        if (encodedMessage.count == decrypted.count) {
            return decrypted
        } else {
            return CipherMessage.invalidConversion
        }
    }
}

// This function encodes and decrypts strings by shifting characters by
// a function amount. All visible characters can be used but the shift
// amount for decrypting can't result in unseeable ascii characters.
// The decrypt function will return an error string if this happens.
struct FtnCipher: Cipher {
    
    func encode(_ message: String, secret: String) -> String {
        
        if (message == "" && secret == "") {
            return CipherMessage.noMessage + CipherMessage.noSecret
        }
        if (message == "") {
            return CipherMessage.noMessage
        }
        if (secret == "") {
            return CipherMessage.noSecret
        }
        
        var encoded = ""
        if let shiftFactor = UInt32(secret) {
            
            for character in message {
                
                let unicode = character.unicodeScalars.first!.value
                
                // valid character
                if (unicode > 32) {
                    let shiftedUnicode = unicode + (shiftFactor*shiftFactor) + (2 * shiftFactor)
                    let shiftedCharacter = String(UnicodeScalar(UInt32(shiftedUnicode))!)
                    encoded = encoded + shiftedCharacter
                    
                // leave space as is
                } else if (unicode == 32) {
                    encoded = encoded + " "
                    
                // invisible ascii character encountered
                } else {
                    return CipherMessage.invisibleCharError
                }
            }
        } else {
            return CipherMessage.invalidSecret
        }
        
        // validate conversion
        if (message.count == encoded.count) {
            return encoded
        } else {
            return CipherMessage.invalidConversion
        }
    }
    
    func decrypt(_ encodedMessage: String, secret: String) -> String {
        
        if (encodedMessage == "" && secret == "") {
            return CipherMessage.noMessage + CipherMessage.noSecret
        }
        if (encodedMessage == "") {
            return CipherMessage.noMessage
        }
        if (secret == "") {
            return CipherMessage.noSecret
        }
        
        var decrypted = ""
        if let shiftFactor = UInt32(secret) {
            
            for character in encodedMessage {
                
                let unicode = character.unicodeScalars.first!.value
                
                // ascii value less than 32
                if (unicode < 32) {
                    return CipherMessage.invisibleCharError
                }
                
                // valid character
                if ( unicode > (shiftFactor * shiftFactor) + (2 * shiftFactor) + 32 ) {
                    let shiftedUnicode = unicode - (shiftFactor*shiftFactor) - (2 * shiftFactor)
                    let shiftedCharacter = String(UnicodeScalar(UInt32(shiftedUnicode))!)
                    decrypted = decrypted + shiftedCharacter
                    
                // leave space as is
                } else if (unicode == 32) {
                    decrypted = decrypted + " "
                    
                // shiftedUnicode is an invalid character
                } else {
                    return CipherMessage.secretTooLarge
                }
                
            }
        } else {
            return CipherMessage.invalidSecret
        }
        
        // validate conversion
        if (encodedMessage.count == decrypted.count) {
            return decrypted
        } else {
            return CipherMessage.invalidConversion
        }
    }
}

// This function encodes and decrypts strings by shifting characters by
// a function amount. All visible characters can be used but the shift
// amount for decrypting can't result in unseeable ascii characters.
// The decrypt function will return an error string if this happens.
struct Ftn2Cipher: Cipher {
    
    func encode(_ message: String, secret: String) -> String {
        
        if (message == "" && secret == "") {
            return CipherMessage.noMessage + CipherMessage.noSecret
        }
        if (message == "") {
            return CipherMessage.noMessage
        }
        if (secret == "") {
            return CipherMessage.noSecret
        }
        
        var encoded = ""
        if let shiftFactor = UInt32(secret) {
            
            for character in message {
                
                let unicode = character.unicodeScalars.first!.value
                
                // valid character
                if (unicode > 32) {
                    let shiftedUnicode = (unicode * 2) + shiftFactor
                    let shiftedCharacter = String(UnicodeScalar(UInt32(shiftedUnicode))!)
                    encoded = encoded + shiftedCharacter
                    
                // leave space as is
                } else if (unicode == 32) {
                    encoded = encoded + " "
                    
                // invisible ascii character encountered
                } else {
                    return CipherMessage.invisibleCharError
                }
                
            }
        } else {
            return CipherMessage.invalidSecret
        }
        
        // validate conversion
        if (message.count == encoded.count) {
            return encoded
        } else {
            return CipherMessage.invalidConversion
        }
    }
    
    func decrypt(_ encodedMessage: String, secret: String) -> String {
        
        if (encodedMessage == "" && secret == "") {
            return CipherMessage.noMessage + CipherMessage.noSecret
        }
        if (encodedMessage == "") {
            return CipherMessage.noMessage
        }
        if (secret == "") {
            return CipherMessage.noSecret
        }
        
        var decrypted = ""
        if let shiftFactor = UInt32(secret) {
            
            for character in encodedMessage {
                
                let unicode = character.unicodeScalars.first!.value
                
                // ascii value less than 32
                if (unicode < 32) {
                    return CipherMessage.invisibleCharError
                }
                
                // valid character
                if (unicode > (32 * 2) + shiftFactor) {
                    let shiftedUnicode = (unicode - shiftFactor) / 2
                    let shiftedCharacter = String(UnicodeScalar(UInt8(shiftedUnicode)))
                    decrypted = decrypted + shiftedCharacter
                    
                // leave space as is
                } else if (unicode == 32) {
                    decrypted = decrypted + " "
                    
                // invisible ascii character encountered
                } else {
                    return CipherMessage.secretTooLarge
                }
                
            }
        } else {
            return CipherMessage.invalidSecret
        }
        
        // validate conversion
        if (encodedMessage.count == decrypted.count) {
            return decrypted
        } else {
            return CipherMessage.invalidConversion
        }
    }
}
