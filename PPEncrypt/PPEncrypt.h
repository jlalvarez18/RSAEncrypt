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

typedef NS_ENUM(NSInteger, PPEncryptHashType) {
    PPEncryptHashTypeSHA1,
    PPEncryptHashTypeSHA224,
    PPEncryptHashTypeSHA256,
    PPEncryptHashTypeSHA384,
    PPEncryptHashTypeSHA512
};

typedef NS_ENUM(NSInteger, PPEncryptPaddingType) {
    PPEncryptPaddingTypeNone  = kSecPaddingNone,
    PPEncryptPaddingTypePKCS1 = kSecPaddingPKCS1,
    PPEncryptPaddingTypeOAEP  = kSecPaddingOAEP
};

@interface PPEncrypt : NSObject

+ (PPKeyPair *)generateKeyPairWithSize:(PPEncryptRSASize)size identifier:(NSString *)identifier;
+ (PPKeyPair *)keyPairWithIdentifier:(NSString *)identifier;

+ (NSString *)encryptString:(NSString *)string withPadding:(PPEncryptPaddingType)padding andPair:(PPKeyPair *)pair;
+ (NSString *)decryptString:(NSString *)string withPadding:(PPEncryptPaddingType)padding andPair:(PPKeyPair *)pair;

+ (NSData *)signData:(NSData *)data hashType:(PPEncryptHashType)hashType withPair:(PPKeyPair *)pair;
+ (BOOL)verifyData:(NSData *)data againstSignature:(NSData *)signature hashType:(PPEncryptHashType)hashType andPair:(PPKeyPair *)pair;

@end
