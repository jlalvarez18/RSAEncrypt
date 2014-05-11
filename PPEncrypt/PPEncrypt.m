//
//  PPEncrypt.m
//  PPEncrypt
//
//  Created by Juan on 3/3/14.
//  Copyright (c) 2014 Alvarez Productions. All rights reserved.
//

#import "PPEncrypt.h"

#import <CommonCrypto/CommonCrypto.h>

#import "NSString+SHADigest.h"
#import "NSData+SHADigest.h"

// Inspiration from https://github.com/kuapay/iOS-Certificate--Key--and-Trust-Sample-Project

static unsigned char oidSequence [] = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };

@import Security;

@implementation PPEncrypt

+ (PPKeyPair *)generateKeyPairWithSize:(PPEncryptRSASize)size identifier:(NSString *)identifier
{
    NSString *publicKeyIdentifier = [self publicKeyIdentifierWithTag:identifier];
    NSString *privateKeyIdentifier = [self privateKeyIdentifierWithTag:identifier];
    
    [self removeKey:publicKeyIdentifier error:nil];
    [self removeKey:privateKeyIdentifier error:nil];
    
    NSMutableDictionary *publicKeyAttributes = [[NSMutableDictionary alloc] init];
	[publicKeyAttributes setObject:@YES forKey:(__bridge id)kSecAttrIsPermanent];
    [publicKeyAttributes setObject:[publicKeyIdentifier dataUsingEncoding:NSUTF8StringEncoding] forKey:(__bridge id)kSecAttrApplicationTag];
    
    NSMutableDictionary *privateKeyAttributes = [[NSMutableDictionary alloc] init];
	[privateKeyAttributes setObject:@YES forKey:(__bridge id)kSecAttrIsPermanent];
    [privateKeyAttributes setObject:[privateKeyIdentifier dataUsingEncoding:NSUTF8StringEncoding] forKey:(__bridge id)kSecAttrApplicationTag];
    
    NSMutableDictionary *keyPairAttributes = [NSMutableDictionary dictionary];
    [keyPairAttributes setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyPairAttributes setObject:@(size) forKey:(__bridge id)kSecAttrKeySizeInBits];
    [keyPairAttributes setObject:privateKeyAttributes forKey:(__bridge id)kSecPrivateKeyAttrs];
    [keyPairAttributes setObject:publicKeyAttributes forKey:(__bridge id)kSecPublicKeyAttrs];
	
    SecKeyRef publicKey = NULL;
	SecKeyRef privateKey = NULL;
    
	OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttributes, &publicKey, &privateKey);
    
    PPKeyPair *pair;
    
    if (status == errSecSuccess) {
        pair = [self keyPairWithIdentifier:identifier];
        
        if (pair.publicKey == nil || pair.privateKey == nil) {
            pair = nil;
        }
    }
    
    return pair;
}

+ (PPKeyPair *)keyPairWithIdentifier:(NSString *)identifier
{
    NSString *publicKeyIdentifier = [self publicKeyIdentifierWithTag:identifier];
    NSString *privateKeyIdentifier = [self privateKeyIdentifierWithTag:identifier];
    
    SecKeyRef publicKey = [self keyRefWithTag:publicKeyIdentifier error:nil];
    SecKeyRef privateKey = [self keyRefWithTag:privateKeyIdentifier error:nil];
    
    PPKeyPair *pair;
    
    if (publicKey && privateKey) {
        pair = [[PPKeyPair alloc] init];
        
        [pair setValue:identifier forKey:@"identifier"];
        [pair setValue:[self X509FormattedPublicKey:publicKeyIdentifier error:nil] forKey:@"publicKey"];
        [pair setValue:[self PEMFormattedPrivateKey:privateKeyIdentifier error:nil] forKey:@"privateKey"];
    }
    
    return pair;
}

+ (NSString *)encryptString:(NSString *)string withPadding:(PPEncryptPaddingType)padding andPair:(PPKeyPair *)pair
{
    if (!string) {
        return nil;
    }
    
    SecKeyRef publicKey = [self keyRefWithTag:[self publicKeyIdentifierWithTag:pair.identifier] error:nil];
    
    if (publicKey) {
        size_t cipherBufferSize = SecKeyGetBlockSize(publicKey);
        uint8_t *cipherBuffer = malloc(cipherBufferSize);
        uint8_t *nonce = (uint8_t *)[string UTF8String];
        
        OSStatus status = SecKeyEncrypt(publicKey,
                                        padding,
                                        nonce,
                                        strlen( (char*)nonce ),
                                        &cipherBuffer[0],
                                        &cipherBufferSize);
        
        if (status == errSecSuccess) {
            NSData *encryptedData = [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];
            NSString *encryptedString = [encryptedData base64EncodedStringWithOptions:0];
            
            return encryptedString;
        }
    }
    
    return nil;
}

+ (NSString *)decryptString:(NSString *)string withPadding:(PPEncryptPaddingType)padding andPair:(PPKeyPair *)pair
{
    if (!pair) {
        return nil;
    }
    
    SecKeyRef privateKey = [self keyRefWithTag:[self privateKeyIdentifierWithTag:pair.identifier] error:nil];
    
    if (privateKey) {
        size_t plainBufferSize = SecKeyGetBlockSize(privateKey);
        uint8_t *plainBuffer = malloc(plainBufferSize);
        NSData *incomingData = [[NSData alloc] initWithBase64EncodedString:string options:0];
        uint8_t *cipherBuffer = (uint8_t*)[incomingData bytes];
        size_t cipherBufferSize = SecKeyGetBlockSize(privateKey);
        
        SecKeyDecrypt(privateKey,
                      padding,
                      cipherBuffer,
                      cipherBufferSize,
                      plainBuffer,
                      &plainBufferSize);
        
        NSData *decryptedData = [NSData dataWithBytes:plainBuffer length:plainBufferSize];
        NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
        
        return decryptedString;
    }
    
    return nil;
}

+ (NSData *)signData:(NSData *)data hashType:(PPEncryptHashType)hashType withPair:(PPKeyPair *)pair
{
    if (!data) {
        return nil;
    }
    
    SecKeyRef privateKey = [self keyRefWithTag:[self privateKeyIdentifierWithTag:pair.identifier] error:nil];
    
    if (privateKey) {
        NSData *digest = [self digestForData:data withType:hashType];
        
        size_t maxLength = SecKeyGetBlockSize(privateKey) - 11;
        
        if ([digest length] > maxLength) {
            NSString *reason = [NSString stringWithFormat:@"Digest is too long to sign with this key, max length is %ld and actual length is %ld", maxLength, (unsigned long)data.length];
            NSException *ex = [NSException exceptionWithName:@"PPInvalidArgumentException" reason:reason userInfo:nil];
            @throw ex;
        }
        
        uint8_t *plainBuffer = (uint8_t *)[digest bytes];
        size_t plainBufferSize = [digest length];
        size_t cipherBufferSize = SecKeyGetBlockSize(privateKey);
        uint8_t *cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
        
        OSStatus status = SecKeyRawSign(privateKey,
                                        [self secPaddingForHashType:hashType],
                                        plainBuffer,
                                        plainBufferSize,
                                        &cipherBuffer[0],
                                        &cipherBufferSize);
        
        if (status == errSecSuccess) {
            NSData *signedData = [NSData dataWithBytesNoCopy:cipherBuffer length:cipherBufferSize freeWhenDone:YES];
            
            return signedData;
        }
    }
    
    return nil;
}

+ (BOOL)verifyData:(NSData *)data againstSignature:(NSData *)signature hashType:(PPEncryptHashType)hashType andPair:(PPKeyPair *)pair
{
    if (!signature) {
        return NO;
    }
    
    SecKeyRef publicKey = [self keyRefWithTag:[self publicKeyIdentifierWithTag:pair.identifier] error:nil];
    
    if (publicKey) {
        NSData *dataToVerify = [self digestForData:data withType:hashType];
        
        OSStatus status = SecKeyRawVerify(publicKey,
                                          [self secPaddingForHashType:hashType],
                                          dataToVerify.bytes,
                                          dataToVerify.length,
                                          signature.bytes,
                                          signature.length);
        
        return (status == errSecSuccess);
    }
    
    return NO;
}

#pragma mark - Private Methods

+ (SecPadding)secPaddingForHashType:(PPEncryptHashType)hashType
{
    switch (hashType) {
        case PPEncryptHashTypeSHA1:
            return kSecPaddingPKCS1SHA1;
            break;
        case PPEncryptHashTypeSHA224:
            return kSecPaddingPKCS1SHA224;
            break;
        case PPEncryptHashTypeSHA256:
            return kSecPaddingPKCS1SHA256;
            break;
        case PPEncryptHashTypeSHA384:
            return kSecPaddingPKCS1SHA384;
            break;
        case PPEncryptHashTypeSHA512:
            return kSecPaddingPKCS1SHA512;
            break;
            
        default:
            break;
    }
    
    return kSecPaddingNone;
}

+ (NSData *)digestForData:(NSData *)data withType:(PPEncryptHashType)hashType
{
    switch (hashType) {
        case PPEncryptHashTypeSHA1:
            return [data SHA1Digest];
            break;
        case PPEncryptHashTypeSHA224:
            return [data SHA224Digest];
            break;
        case PPEncryptHashTypeSHA256:
            return [data SHA256Digest];
            break;
        case PPEncryptHashTypeSHA384:
            return [data SHA384Digest];
            break;
        case PPEncryptHashTypeSHA512:
            return [data SHA512Digest];
            break;
            
        default:
            break;
    }
    
    return nil;
}

+ (NSString *)PEMFormattedPrivateKey:(NSString *)tag error:(NSError *)error
{
    NSData *privateKeyData = [self keyDataWithTag:tag error:error];
    
    if (error) {
        return nil;
    }
    
    NSString *result = [NSString stringWithFormat:@"%@\n%@\n%@",
                        [self PEMPrivateHeader],
                        [privateKeyData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength],
                        [self PEMPrivateFooter]];
    
    return result;
}


+ (NSString *)X509FormattedPublicKey:(NSString *)tag error:(NSError *)error
{
    NSData *publicKeyData = [self keyDataWithTag:tag error:error];
    
    if (error)
    {
        return nil;
    }
    
    unsigned char builder[15];
    int bitstringEncLength;
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

#pragma mark - Keychain Methods

+ (NSData *)keyDataWithTag:(NSString *)tag error:(NSError *)error
{
    NSMutableDictionary *queryKey = [self keyQueryDictionary:tag];
    [queryKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    
    SecKeyRef key = NULL;
    OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)queryKey, (CFTypeRef *)&key);
    
    if (err != noErr || !key)
    {
        error = [NSError errorWithDomain:@"" code:0 userInfo:nil];
        
        return nil;
    }
    
    return (__bridge NSData *)key;
}


+ (SecKeyRef)keyRefWithTag:(NSString *)tag error:(NSError *)error
{
    NSMutableDictionary *queryKey = [self keyQueryDictionary:tag];
    [queryKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    SecKeyRef key = NULL;
    OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)queryKey, (CFTypeRef *)&key);
    
    if (err != noErr) {
        error = [NSError errorWithDomain:@"" code:0 userInfo:nil];
        
        return nil;
    }
    
    return key;
}

+ (void)removeKey:(NSString *)tag error:(NSError *)error
{
    NSDictionary *queryKey = [self keyQueryDictionary:tag];
    OSStatus secStatus = SecItemDelete((__bridge CFDictionaryRef)queryKey);
    
    if ((secStatus != noErr) && (secStatus != errSecDuplicateItem))
    {
        error = [NSError errorWithDomain:@"" code:0 userInfo:nil];
    }
}


+ (NSMutableDictionary *)keyQueryDictionary:(NSString *)tag
{
    NSData *keyTag = [tag dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableDictionary *result = [[NSMutableDictionary alloc] init];
    [result setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [result setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [result setObject:keyTag forKey:(__bridge id)kSecAttrApplicationTag];
    [result setObject:(__bridge id)kSecAttrAccessibleWhenUnlocked forKey:(__bridge id)kSecAttrAccessible];
    
    return result;
}

#pragma mark - Identifier Methods

+ (NSString *)publicKeyIdentifier
{
    return [self publicKeyIdentifierWithTag:nil];
}

+ (NSString *)privateKeyIdentifier
{
    return [self privateKeyIdentifierWithTag:nil];
}

+ (NSString *)publicKeyIdentifierWithTag:(NSString *)additionalTag
{
    NSString *identifier = [NSString stringWithFormat:@"%@.publicKey", [[NSBundle mainBundle] bundleIdentifier]];
    
    if (additionalTag) {
        identifier = [identifier stringByAppendingFormat:@".%@", additionalTag];
    }
    
    return identifier;
}

+ (NSString *)privateKeyIdentifierWithTag:(NSString *)additionalTag
{
    NSString *identifier = [NSString stringWithFormat:@"%@.privateKey", [[NSBundle mainBundle] bundleIdentifier]];
    
    if (additionalTag) {
        identifier = [identifier stringByAppendingFormat:@".%@", additionalTag];
    }
    
    return identifier;
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

@end
