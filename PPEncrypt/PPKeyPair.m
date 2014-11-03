//
//  PPKeyPair.m
//  PPEncrypt
//
//  Created by Juan Alvarez on 5/8/14.
//  Copyright (c) 2014 Alvarez Productions. All rights reserved.
//

#import "PPKeyPair.h"

#import <CommonCrypto/CommonCrypto.h>

// Inspiration from https://github.com/kuapay/iOS-Certificate--Key--and-Trust-Sample-Project

static unsigned char oidSequence [] = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };

@interface PPKeyPair ()

@end

@implementation PPKeyPair

- (instancetype)initWithIdentifier:(NSString *)identifier
                         publicKey:(SecKeyRef)publicKey
                        privateKey:(SecKeyRef)privateKey
{
    NSParameterAssert(identifier != nil);
    NSParameterAssert(publicKey != nil);
    NSParameterAssert(privateKey != nil);
    
    self = [super init];
    
    _identifier = identifier;
    _publicKeyRef = publicKey;
    _privateKeyRef = privateKey;
    
    return self;
}

- (NSString *)X509FormattedPublicKeyString
{
    return [PPKeyPair X509FormattedPublicKey:self.publicKeyRef error:nil];
}

- (NSString *)PEMFormattedPrivateKeyString
{
    return [PPKeyPair PEMFormattedPrivateKey:self.privateKeyRef error:nil];
}

#pragma mark - Private

+ (NSString *)X509FormattedPublicKey:(SecKeyRef)key error:(NSError **)error
{
    NSError *keyDataError;
    NSData *publicKeyData = [self dataFromKey:key error:&keyDataError];
    
    if (keyDataError)
    {
        *error = keyDataError;
        
        return nil;
    }
    
    unsigned char builder[15];
    unsigned long bitstringEncLength;
    if  ([publicKeyData length] + 1  < 128 )
    {
        bitstringEncLength = 1 ;
    }
    else
    {
        bitstringEncLength = (([publicKeyData length ] + 1)/256) + 2;
    }
    
    builder[0] = 0x30;
    
    size_t i = sizeof(oidSequence) + 2 + bitstringEncLength + [publicKeyData length];
    size_t j = [self encode:&builder[1]
                     length:i];
    
    NSMutableData *encodedKey = [[NSMutableData alloc] init];
    
    [encodedKey appendBytes:builder
                     length:j + 1];
    
    [encodedKey appendBytes:oidSequence
                     length:sizeof(oidSequence)];
    
    builder[0] = 0x03;
    j = [self encode:&builder[1]
              length:[publicKeyData length] + 1];
    
    builder[j+1] = 0x00;
    [encodedKey appendBytes:builder
                     length:j + 2];
    
    [encodedKey appendData:publicKeyData];
    
    NSString *returnString = [NSString stringWithFormat:@"%@\n%@\n%@",
                              [self X509PublicHeader],
                              [encodedKey base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength],
                              [self X509PublicFooter]];
    
    return returnString;
}

+ (NSString *)PEMFormattedPrivateKey:(SecKeyRef)key error:(NSError **)error
{
    NSError *keyDataError;
    NSData *privateKeyData = [self dataFromKey:key error:&keyDataError];
    
    if (keyDataError) {
        *error = keyDataError;
        
        return nil;
    }
    
    NSString *result = [NSString stringWithFormat:@"%@\n%@\n%@",
                        [self PEMPrivateHeader],
                        [privateKeyData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength],
                        [self PEMPrivateFooter]];
    
    return result;
}

+ (NSData *)dataFromKey:(SecKeyRef)key error:(NSError **)error
{
    NSDictionary *query = @{
                            (__bridge id)kSecReturnData: @YES,
//                            (__bridge id)kSecClass: (__bridge id)kSecClassKey,
//                            (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
                            (__bridge id)kSecMatchItemList: @[(__bridge id)key]
                            };
    
    SecKeyRef result = NULL;
    OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
    
    if (err != noErr || result == nil) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:@"" code:0 userInfo:nil];
        }
        
        return nil;
    }
    
    return (__bridge NSData *)result;
}

#pragma mark - RSA Key Anatomy

+ (NSString *)X509PublicHeader
{
    return @"-----BEGIN PUBLIC KEY-----";
}

+ (NSString *)X509PublicFooter
{
    return @"-----END PUBLIC KEY-----";
}

+ (NSString *)PKCS1PublicHeader
{
    return  @"-----BEGIN RSA PUBLIC KEY-----";
}

+ (NSString *)PKCS1PublicFooter
{
    return @"-----END RSA PUBLIC KEY-----";
}

+ (NSString *)PEMPrivateHeader
{
    return @"-----BEGIN RSA PRIVATE KEY-----";
}

+ (NSString *)PEMPrivateFooter
{
    return @"-----END RSA PRIVATE KEY-----";
}

#pragma mark - Helper

+ (size_t)encode:(unsigned char *)buffer length:(size_t)length
{
    if (length < 128)
    {
        buffer[0] = length;
        return 1;
    }
    
    size_t i = (length / 256) + 1;
    buffer[0] = i + 0x80;
    for (size_t j = 0 ; j < i; ++j)
    {
        buffer[i - j] = length & 0xFF;
        length = length >> 8;
    }
    
    return i + 1;
}

@end
