//
//  PPEncrypt.h
//  PPEncrypt
//
//  Created by Juan on 3/3/14.
//  Copyright (c) 2014 Alvarez Productions. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "PPKeyPair.h"

typedef NS_ENUM(NSInteger, PPEncryptRSASize) {
    PPEncryptRSASize512 = 512,
    PPEncryptRSASize768 = 768,
    PPEncryptRSASize1024 = 1024,
    PPEncryptRSASize2048 = 2048
};

@interface PPEncrypt : NSObject

+ (PPKeyPair *)generateKeyPairWithSize:(PPEncryptRSASize)size identifier:(NSString *)identifier;
+ (PPKeyPair *)keyPairWithIdentifier:(NSString *)identifier;

+ (NSString *)encryptString:(NSString *)string withPair:(PPKeyPair *)pair;
+ (NSString *)decryptString:(NSString *)string withPair:(PPKeyPair *)pair;

+ (NSData *)signString:(NSString *)string withPair:(PPKeyPair *)pair;
+ (BOOL)verifyString:(NSString *)stringToVerify withSignature:(NSData *)signature andPair:(PPKeyPair *)pair;

@end
