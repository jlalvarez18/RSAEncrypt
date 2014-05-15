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

@interface PPEncryptSettings : NSObject

@property (nonatomic, assign) PPEncryptRSASize rsaSize;
@property (nonatomic, assign) SecPadding padding;

@end

@interface PPEncrypt : NSObject

@property (nonatomic, strong, readonly) PPEncryptSettings *settings;
@property (nonatomic, strong, readonly) PPKeyPair *keyPair;

- (instancetype)initWithSettings:(PPEncryptSettings *)settings keyPair:(PPKeyPair *)pair;

+ (PPKeyPair *)generateKeyPairWithSize:(PPEncryptRSASize)size identifier:(NSString *)identifier;
+ (PPKeyPair *)keyPairWithIdentifier:(NSString *)identifier;

+ (NSData *)encryptString:(NSString *)string withPadding:(SecPadding)padding andPair:(PPKeyPair *)pair;
+ (NSString *)decryptData:(NSData *)data withPadding:(SecPadding)padding andPair:(PPKeyPair *)pair;

+ (NSData *)signData:(NSData *)data withPadding:(SecPadding)padding andPair:(PPKeyPair *)pair;
+ (BOOL)verifyData:(NSData *)data againstSignature:(NSData *)signature withPadding:(SecPadding)padding andPair:(PPKeyPair *)pair;

@end
