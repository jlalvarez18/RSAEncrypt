//
//  PPEncryptTests.m
//  PPEncryptTests
//
//  Created by Juan on 3/3/14.
//  Copyright (c) 2014 Alvarez Productions. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "PPEncrypt.h"

static NSString *RealIdentifier = @"com.alvarezproductions.real";
static NSString *FakeIdentifier = @"com.alvarezproductions.fake";

@interface PPEncryptTests : XCTestCase

@property (nonatomic, assign) PPKeyPair *fakePair;
@property (nonatomic, assign) PPKeyPair *realPair;

@end

@implementation PPEncryptTests

- (void)setUp
{
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
    
    self.fakePair = [self getPairWithIdentifier:FakeIdentifier];
    self.realPair = [self getPairWithIdentifier:RealIdentifier];
}

- (void)tearDown
{
    self.fakePair = nil;
    self.realPair = nil;
    
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (PPKeyPair *)getPairWithIdentifier:(NSString *)identifier
{
    PPKeyPair *pair = [PPEncrypt keyPairWithIdentifier:identifier];
    
    if (pair == nil) {
        pair = [PPEncrypt generateKeyPairWithSize:PPEncryptRSASize1024 identifier:identifier];
    }
    
    return pair;
}

- (void)testPairGeneration
{
    PPKeyPair *pair = [PPEncrypt generateKeyPairWithSize:PPEncryptRSASize1024 identifier:nil];
    
    XCTAssertNotNil(pair, @"Should not be nil");
}

- (void)testEncryptDecrypt
{
    NSString *testString = @"Put setup code here. This method is called before the invocation of each test method in the class.";
    
    NSString *encryptedString = [PPEncrypt encryptString:testString withPair:self.realPair];
    
    XCTAssertNotNil(encryptedString, @"Encrypted string should not be nil");
    
    NSString *decryptedString = [PPEncrypt decryptString:encryptedString withPair:self.realPair];
    
    XCTAssertNotNil(decryptedString, @"Decrypted string should not be nil");
    XCTAssertEqualObjects(testString, decryptedString, @"The test string and decrypted string should be equal");
}

- (void)testPairAuthenticity
{
    NSString *testString = @"Put setup code here. This method is called before the invocation of each test method in the class.";
    
    NSString *encryptedString = [PPEncrypt encryptString:testString withPair:self.realPair];
    NSString *fakeDecryptedString = [PPEncrypt decryptString:encryptedString withPair:self.fakePair];
    
    XCTAssertNil(fakeDecryptedString, @"fakeDecryptedString should be nil");
}

- (void)testSigning
{
    NSString *testString = @"jlalvarez18@gmail.com";
    
    NSData *signedData = [PPEncrypt signString:testString withPair:self.realPair];
    
    XCTAssertNotNil(signedData, @"signedString should not be nil");
    
    BOOL verified = [PPEncrypt verifyString:testString withSignature:signedData andPair:self.realPair];
    
    XCTAssertEqual(verified, YES, @"verification should succeed");
    
    BOOL shouldFail = [PPEncrypt verifyString:testString withSignature:signedData andPair:self.fakePair];
    
    XCTAssertEqual(shouldFail, NO, @"verification should failed");
}

@end
