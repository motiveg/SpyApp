import Foundation

protocol Cipher {
    func encode(_ plaintext: String, secret: String) -> String
    func decrypt(_ encryptedString: String, secret: String) -> String
}

// This function encodes and decrypts strings by shifting characters by
// a specified amount. All visible characters can be used but the shift
// amount for decrypting can't result in unseeable ascii characters.
// The decrypt function will return an error string if this happens.
struct CeaserCipher: Cipher {
    
    func encode(_ plaintext: String, secret: String) -> String {
        
        var encoded = ""
        if let shiftBy = UInt32(secret) {
            
            for character in plaintext {
                
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
                    encoded = "Error: invisible ascii characters cannot be used"
                } // end inner if
            } // end for
        } else {
            encoded = "Error: an invalid secret was passed. Only unsigned integers are allowed."
        } // end outer if
        
        return encoded
    }
    
    func decrypt(_ encryptedString: String, secret: String) -> String {
        
        var decrypted = ""
        if let shiftBy = UInt32(secret) {
            
            for character in encryptedString {
                
                let unicode = character.unicodeScalars.first!.value
                
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
                    decrypted = "Error: secret is too large for decryption"
                    return decrypted
                } // end inner if
                
            } // end for
        } else {
            decrypted = "Error: an invalid secret was passed. Only unsigned integers are allowed."
        } // end outer if
        
        return decrypted
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
    
    func encode(_ plaintext: String, secret: String) -> String {
        
        var encoded = ""
        if let shiftBy = UInt32(secret) {
            
            for character in plaintext {
                
                var remainingShift = shiftBy
                let unicode = character.unicodeScalars.first!.value
                var shiftedUnicode = unicode
                
                // if uppercase, convert to lowercase
                if (unicode >= alphaUpperMin && unicode <= alphaUpperMax) {
                    shiftedUnicode += 32
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
                            shiftedUnicode = alphaMin
                        }
                            
                        // remaining shift amount is used
                        else {
                            shiftedUnicode += remainingShift
                            remainingShift = 0
                        }
                    }
                        
                    // check if shiftedUnicode is lower alpha
                    else if (shiftedUnicode >= alphaMin && shiftedUnicode <= alphaMax) {
                        
                        // remaining shift amount too big
                        if (shiftedUnicode + remainingShift > alphaMax) {
                            remainingShift = remainingShift - ( alphaMax - shiftedUnicode ) - 1
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
                        let message = "Error: only alphanumeric characters are accepted for this cipher."
                        return message
                    }
                }
                
                let shiftedCharacter = String(UnicodeScalar(UInt8(shiftedUnicode)))
                encoded = encoded + shiftedCharacter
                
            }
        } else {
            encoded = "Error: an invalid secret was passed. Only unsigned integers are allowed."
        }
        return encoded
    }
    
    func decrypt(_ encryptedString: String, secret: String) -> String {
        
        var decrypted = ""
        if let shiftBy = UInt32(secret) {
            
            for character in encryptedString {
                
                var remainingShift = shiftBy
                let unicode = character.unicodeScalars.first!.value
                var shiftedUnicode = unicode
                
                // if uppercase, convert to lowercase
                if (unicode >= alphaUpperMin && unicode <= alphaUpperMax) {
                    shiftedUnicode += 32
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
                            shiftedUnicode = alphaMax
                        }
                            
                        // remaining shift amount is used
                        else {
                            shiftedUnicode -= remainingShift
                            remainingShift = 0
                        }
                    }
                        
                    // check if shiftedUnicode is lower alpha
                    else if (shiftedUnicode >= alphaMin && shiftedUnicode <= alphaMax) {
                        
                        // remaining shift amount too big
                        if (shiftedUnicode < alphaMin + remainingShift) {
                            remainingShift = remainingShift - ( shiftedUnicode - alphaMin ) - 1
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
                        let message = "Error: only alphanumeric characters are accepted for this cipher."
                        return message
                    }
                }
                
                let shiftedCharacter = String(UnicodeScalar(UInt8(shiftedUnicode)))
                decrypted = decrypted + shiftedCharacter
                
            }
        } else {
            decrypted = "Error: an invalid secret was passed. Only unsigned integers are allowed."
        }
        return decrypted
    }
}

// This function encodes and decrypts strings by shifting characters by
// a function amount. All visible characters can be used but the shift
// amount for decrypting can't result in unseeable ascii characters.
// The decrypt function will return an error string if this happens.
struct FtnCipher: Cipher {
    
    func encode(_ plaintext: String, secret: String) -> String {
        
        var encoded = ""
        if let shiftFactor = UInt32(secret) {
            
            for character in plaintext {
                
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
                    encoded = "Error: invisible ascii characters cannot be used"
                }
            }
        } else {
            encoded = "Error: an invalid secret was passed. Only unsigned integers are allowed."
        }
        
        return encoded
    }
    
    func decrypt(_ encryptedString: String, secret: String) -> String {
        
        var decrypted = ""
        if let shiftFactor = UInt32(secret) {
            
            for character in encryptedString {
                
                let unicode = character.unicodeScalars.first!.value
                
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
                    decrypted = "Error: secret is too large for decryption"
                    return decrypted
                }
                
            }
        } else {
            decrypted = "Error: an invalid secret was passed. Only unsigned integers are allowed."
        }
        
        return decrypted
    }
}

// This function encodes and decrypts strings by shifting characters by
// a function amount. All visible characters can be used but the shift
// amount for decrypting can't result in unseeable ascii characters.
// The decrypt function will return an error string if this happens.
struct Ftn2Cipher: Cipher {
    
    func encode(_ plaintext: String, secret: String) -> String {
        
        var encoded = ""
        if let shiftFactor = UInt32(secret) {
            
            for character in plaintext {
                
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
                    encoded = "Error: invisible ascii characters cannot be used"
                }
                
            }
        } else {
            encoded = "Error: an invalid secret was passed. Only unsigned integers are allowed."
        }
        
        return encoded
    }
    
    func decrypt(_ encryptedString: String, secret: String) -> String {
        
        var decrypted = ""
        if let shiftFactor = UInt32(secret) {
            
            for character in encryptedString {
                
                let unicode = character.unicodeScalars.first!.value
                
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
                    decrypted = "Error: secret is too large for decryption"
                    return decrypted
                }
                
            }
        } else {
            decrypted = "Error: an invalid secret was passed. Only unsigned integers are allowed."
        }
        
        return decrypted
    }
}
