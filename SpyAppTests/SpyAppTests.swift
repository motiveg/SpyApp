//
//  SpyAppTests.swift
//  SpyAppTests
//
//  Created by Axel Ancona Esselmann on 8/30/18.
//  Copyright © 2018 Axel Ancona Esselmann. All rights reserved.
//

import XCTest
@testable import SpyApp

class SpyAppTests: XCTestCase {
    
    var cipher: Cipher!
    
    override func setUp() {
        super.setUp()
        
        cipher = CeaserCipher()
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
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
    
    func text_oneCharacterStringGetsMappedToSelfWith_0_secret() {
        let plaintext = "a"
        let result = cipher.encode(plaintext, secret: "0")
        
        XCTAssertEqual(plaintext, result)
    }
    
    func test_nonNumericInputInSecret() {
        let plaintext = "a"
        let result = cipher.encode(plaintext, secret: "secret")
        
        XCTAssertNil(result)
    }
    
}
