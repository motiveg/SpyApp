//
//  FtnCipherTests.swift
//  SpyAppTests
//
//  Created by Brian Casipit on 9/19/18.
//  Copyright © 2018 Axel Ancona Esselmann. All rights reserved.
//

import XCTest
@testable import SpyApp

class FtnCipherTests: XCTestCase {

    var cipher: Cipher!
    
    override func setUp() {
        super.setUp()
        
        cipher = FtnCipher()
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
    }

    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }
    
    // MESSAGE TEXT FIELD TESTS
    func test_blankMessageTextField() {
        let testMessage = ""
        let testSecret = "5"
        let assertMessage = "Error: Expected output message doesn't match for blank message text field.\n"
        
        let encodeResult = cipher.encode(testMessage, secret: testSecret)
        XCTAssertEqual(encodeResult, CipherMessage.noMessage, assertMessage)
        
        let decryptResult = cipher.decrypt(testMessage, secret: testSecret)
        XCTAssertEqual(decryptResult, CipherMessage.noMessage, assertMessage)
    }
    func test_resultingASCIICharLessThan32() {
        //String(UnicodeScalar(UInt32(shiftedUnicode))!)
        let testASCIIValue = 28
        let testMessage = String(UnicodeScalar(UInt32(testASCIIValue))!)
        let testSecret = "5"
        let assertMessage = "Error: Expected output message doesn't match for unseeable ascii characters.\n"
        
        let encodeResult = cipher.encode(testMessage, secret: testSecret)
        XCTAssertEqual(encodeResult, CipherMessage.invisibleCharError, assertMessage)
        
        let decryptResult = cipher.decrypt(testMessage, secret: testSecret)
        XCTAssertEqual(decryptResult, CipherMessage.invisibleCharError, assertMessage)
    }
    
    // SECRET TEXT FIELD TESTS
    func test_blankSecretTextField() {
        let testMessage = "Hello"
        let testSecret = ""
        let assertMessage = "Error: Expected output message doesn't match for blank secret text field.\n"
        
        let encodeResult = cipher.encode(testMessage, secret: testSecret)
        XCTAssertEqual(encodeResult, CipherMessage.noSecret, assertMessage)
        
        let decryptResult = cipher.decrypt(testMessage, secret: testSecret)
        XCTAssertEqual(decryptResult, CipherMessage.noSecret, assertMessage)
    }
    func test_largeSecretValue() {
        let testMessage = "Hello"
        let testSecret = "1000"
        let assertMessage = "Error: Expected output message doesn't match for large secret in text field.\n"
        
        let decryptResult = cipher.decrypt(testMessage, secret: testSecret)
        XCTAssertEqual(decryptResult, CipherMessage.secretTooLarge, assertMessage)
    }
    func test_nonNumericInputInSecret() {
        let testMessage = "Hello"
        let testSecret = "world"
        let assertMessage = "Error: Expected output message doesn't match for invalid secret in text field.\n"
        
        let encodeResult = cipher.encode(testMessage, secret: testSecret)
        XCTAssertEqual(encodeResult, CipherMessage.invalidSecret, assertMessage)
        
        let decryptResult = cipher.decrypt(testMessage, secret: testSecret)
        XCTAssertEqual(decryptResult, CipherMessage.invalidSecret, assertMessage)
    }

    // MESSAGE+SECRET TEXT FIELD TESTS
    func test_blankMessageAndSecretTextField() {
        let testMessage = ""
        let testSecret = ""
        let assertMessage = "Error: Expected output message doesn't match for blank message and secret text fields.\n"
        
        let encodeResult = cipher.encode(testMessage, secret: testSecret)
        XCTAssertEqual(encodeResult, CipherMessage.noMessage + CipherMessage.noSecret, assertMessage)
        
        let decryptResult = cipher.decrypt(testMessage, secret: testSecret)
        XCTAssertEqual(decryptResult, CipherMessage.noMessage + CipherMessage.noSecret, assertMessage)
    }
    
}
