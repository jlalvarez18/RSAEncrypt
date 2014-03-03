//
//  PPEncrypt.h
//  PPEncrypt
//
//  Created by Juan on 3/3/14.
//  Copyright (c) 2014 Alvarez Productions. All rights reserved.
//

#import <Foundation/Foundation.h>

extern NSString *const kPublicKeyPairKey;
extern NSString *const kPrivateKeyPairKey;

@interface PPEncrypt : NSObject

+(void)generateKeyPairWithPublicTag:(NSString *)publicTagString
                         privateTag:(NSString *)privateTagString
                          publicKey:(SecKeyRef *)publicKey
                         privateKey:(SecKeyRef *)privateKey;

+(NSString *)encryptRSA:(NSString *)plainTextString key:(SecKeyRef)publicKey;
+(NSString *)decryptRSA:(NSString *)cipherString key:(SecKeyRef) privateKey;

+ (SecKeyRef)getKeyWithTag:(NSString *)tagString;
@end
