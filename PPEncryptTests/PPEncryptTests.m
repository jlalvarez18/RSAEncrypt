//
//  PPEncryptTests.m
//  PPEncryptTests
//
//  Created by Juan on 3/3/14.
//  Copyright (c) 2014 Alvarez Productions. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "PPEncrypt.h"

static NSString *PublicTagName = @"com.alvarezproductions.public";
static NSString *PrivateTagName = @"com.alvarezproductions.private";

static NSString *FakePrivateTagName = @"com.alvarezproductions.private.fake";

@interface PPEncryptTests : XCTestCase

@property (nonatomic, assign) SecKeyRef fakePrivateKey;

@end

@implementation PPEncryptTests

- (void)setUp
{
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
    
    SecKeyRef publicKey = NULL;
    SecKeyRef privateKey = NULL;
    
    [PPEncrypt generateKeyPairWithPublicTag:PublicTagName
                                 privateTag:PrivateTagName
                                  publicKey:&publicKey
                                 privateKey:&privateKey];
    
    self.fakePrivateKey = privateKey;
}

- (void)tearDown
{
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testEncryptDecrypt
{
    SecKeyRef publicKey = NULL;
    SecKeyRef privateKey = NULL;
    
    [PPEncrypt generateKeyPairWithPublicTag:PublicTagName
                                 privateTag:PrivateTagName
                                  publicKey:&publicKey
                                 privateKey:&privateKey];
    
    NSString *testingString = @"Put setup code here. This method is called before the invocation of each test method in the class.";
    
    NSString *encryptedString = [PPEncrypt encryptRSA:testingString key:publicKey];
    
    NSString *decryptedString = [PPEncrypt decryptRSA:encryptedString key:privateKey];
    
    XCTAssertEqualObjects(testingString, decryptedString, @"These strings must be equal.");
}

- (void)testKeysRetrival
{
    SecKeyRef publicKey = NULL;
    SecKeyRef privateKey = NULL;
    
    publicKey = [PPEncrypt getKeyWithTag:PublicTagName];
    privateKey = [PPEncrypt getKeyWithTag:PrivateTagName];
    
    XCTAssertNotNil((__bridge id)publicKey, @"This must not be nil");
    XCTAssertNotNil((__bridge id)privateKey, @"This must not be nil");
    
    NSString *testingString = @"This is so fucking cool!";
    
    NSString *encryptedString = [PPEncrypt encryptRSA:testingString key:publicKey];
    
    NSString *decryptedString = [PPEncrypt decryptRSA:encryptedString key:privateKey];
    
    XCTAssertEqualObjects(testingString, decryptedString, @"These strings must be equal.");
    
    NSString *fakeDecryptedString = [PPEncrypt decryptRSA:encryptedString key:self.fakePrivateKey];
    
    XCTAssertNil(fakeDecryptedString, @"This must be nil");
}

@end
