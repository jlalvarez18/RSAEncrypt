//
//  PPEncrypt.m
//  PPEncrypt
//
//  Created by Juan on 3/3/14.
//  Copyright (c) 2014 Alvarez Productions. All rights reserved.
//

#import "PPEncrypt.h"

#import <CommonCrypto/CommonCrypto.h>

#import "NSData+Digest.h"

@import Security;

@interface PPEncrypt ()

@end

@implementation PPEncrypt

+ (PPKeyPair *)generateKeyPairWithSize:(PPEncryptRSASize)size identifier:(NSString *)identifier
{
    NSString *publicKeyIdentifier = [self publicKeyIdentifierWithTag:identifier];
    NSString *privateKeyIdentifier = [self privateKeyIdentifierWithTag:identifier];
    
    [self removeKey:publicKeyIdentifier error:nil];
    [self removeKey:privateKeyIdentifier error:nil];
    
    NSData *publicKeyIdentifierData = [publicKeyIdentifier dataUsingEncoding:NSUTF8StringEncoding];
    NSData *privateKeyIdentifierData = [privateKeyIdentifier dataUsingEncoding:NSUTF8StringEncoding];
    
    NSDictionary *publicKeyAttributes = @{
                                          (__bridge id)kSecAttrIsPermanent: @YES,
                                          (__bridge id)kSecAttrApplicationTag: publicKeyIdentifierData
                                          };
    
    NSDictionary *privateKeyAttributes = @{
                                           (__bridge id)kSecAttrIsPermanent: @YES,
                                           (__bridge id)kSecAttrApplicationTag: privateKeyIdentifierData
                                           };
    
    NSDictionary *keypairAttributes = @{
                                        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
                                        (__bridge id)kSecAttrKeySizeInBits: @(size),
                                        (__bridge id)kSecPrivateKeyAttrs: privateKeyAttributes,
                                        (__bridge id)kSecPublicKeyAttrs: publicKeyAttributes
                                        };
	
    SecKeyRef publicKey = NULL;
	SecKeyRef privateKey = NULL;
    
	OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)keypairAttributes, &publicKey, &privateKey);
    
    PPKeyPair *pair;
    
    if (status == errSecSuccess) {
        pair = [self keyPairWithIdentifier:identifier];
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
        pair = [[PPKeyPair alloc] initWithIdentifier:identifier
                                           publicKey:publicKey
                                          privateKey:privateKey];
    }
    
    return pair;
}

#pragma mark - Encryption Methods

+ (NSString *)encrypt:(NSString *)string withPair:(PPKeyPair *)pair
{
    if (string == nil || pair == nil) {
        return nil;
    }
    
    SecKeyRef publicKey = pair.publicKeyRef;
    
    uint8_t *nonce = (uint8_t *)[string UTF8String];
    size_t cipherBufferSize = SecKeyGetBlockSize(publicKey);
    uint8_t *cipherBuffer = malloc(cipherBufferSize);
    
//    Length of plainText in bytes, this must be less than
//    or equal to the value returned by SecKeyGetBlockSize().
    if (cipherBufferSize < sizeof(nonce)) {
        NSString *reason = [NSString stringWithFormat:@"String length is too long to sign with this key, max length is %ld and actual length is %ld", cipherBufferSize, strlen((char *)nonce)];
        NSLog(@"%@", reason);
        
        return nil;
    }
    
    NSData *encryptedData;
    
    OSStatus status = SecKeyEncrypt(publicKey,
                                    kSecPaddingPKCS1,
                                    nonce,
                                    strlen((char *)nonce),
                                    &cipherBuffer[0],
                                    &cipherBufferSize);
    
    if (status == errSecSuccess) {
        encryptedData = [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];
    }
    
    free(cipherBuffer);
    
    return [encryptedData base64EncodedStringWithOptions:0];
}

#pragma mark - Decryption Methods

+ (NSString *)decrypt:(NSString *)cipherText withPair:(PPKeyPair *)pair
{
    if (cipherText == nil || pair == nil) {
        return nil;
    }
    
    SecKeyRef privateKey = pair.privateKeyRef;
    
    size_t plainBufferSize = SecKeyGetBlockSize(privateKey);
    uint8_t *plainBuffer = malloc(plainBufferSize);
    
    NSData *data = [[NSData alloc] initWithBase64EncodedString:cipherText options:0];
    
    uint8_t *cipherBuffer = (uint8_t*)[data bytes];
    size_t cipherBufferSize = SecKeyGetBlockSize(privateKey);
    
    if (plainBufferSize < cipherBufferSize) {
        NSString *reason = [NSString stringWithFormat:@"Cipher size is too long to sign with this key, max length is %ld and actual length is %ld", plainBufferSize, (unsigned long)cipherText.length];
        
        NSLog(@"%@", reason);
        
        return nil;
    }
    
    OSStatus status = SecKeyDecrypt(privateKey,
                                    kSecPaddingPKCS1,
                                    cipherBuffer,
                                    cipherBufferSize,
                                    plainBuffer,
                                    &plainBufferSize);
    
    NSString *decryptedString;
    
    if (status == errSecSuccess) {
        NSData *bufferData = [NSData dataWithBytesNoCopy:plainBuffer length:plainBufferSize freeWhenDone:YES];
        
        decryptedString = [[NSString alloc] initWithData:bufferData encoding:NSUTF8StringEncoding];
    }
    
    return decryptedString;
}

#pragma mark - Signing Methods

+ (NSData *)signData:(NSData *)data withPadding:(SecPadding)padding andPair:(PPKeyPair *)pair
{
    if (data == nil || pair == nil) {
        return nil;
    }
    
    NSString *identifier = [self privateKeyIdentifierWithTag:pair.identifier];
    
    SecKeyRef privateKey = [self keyRefWithTag:identifier error:nil];
    
    NSData *signedData;
    
    if (privateKey) {
        NSData *digest = [self digestForData:data withPadding:padding];
        
//        When PKCS1 padding is performed, the maximum length of data that can
//        be signed is the value returned by SecKeyGetBlockSize() - 11.
        size_t maxLength = SecKeyGetBlockSize(privateKey);
        
        // if hash type is not none, then PKCS1 padding will be done
        if ([self isPaddingPKCS1:padding]) {
            maxLength -= 11;
        }
        
        if ([digest length] > maxLength) {
            NSString *reason = [NSString stringWithFormat:@"Digest is too long to sign with this key, max length is %ld and actual length is %ld", maxLength, (unsigned long)data.length];
            
            NSLog(@"%@", reason);
            
            return nil;
        }
        
        uint8_t *plainBuffer = (uint8_t *)[digest bytes];
        size_t plainBufferSize = [digest length];
        size_t cipherBufferSize = SecKeyGetBlockSize(privateKey);
        uint8_t *cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
        
        OSStatus status = SecKeyRawSign(privateKey,
                                        padding,
                                        plainBuffer,
                                        plainBufferSize,
                                        &cipherBuffer[0],
                                        &cipherBufferSize);
        
        if (status == errSecSuccess) {
            signedData = [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];
        }
        
        free(cipherBuffer);
    }
    
    return signedData;
}

+ (BOOL)verifyData:(NSData *)data againstSignature:(NSData *)signature withPadding:(SecPadding)padding andPair:(PPKeyPair *)pair
{
    if (!signature) {
        return NO;
    }
    
    NSString *identifier = [self publicKeyIdentifierWithTag:pair.identifier];
    
    SecKeyRef publicKey = [self keyRefWithTag:identifier error:nil];
    
    if (publicKey) {
        NSData *dataToVerify = [self digestForData:data withPadding:padding];
        
        OSStatus status = SecKeyRawVerify(publicKey,
                                          padding,
                                          dataToVerify.bytes,
                                          dataToVerify.length,
                                          signature.bytes,
                                          signature.length);
        
        return (status == errSecSuccess);
    }
    
    return NO;
}

#pragma mark - Private Methods

+ (BOOL)isPaddingPKCS1:(SecPadding)padding
{
    return (padding == kSecPaddingPKCS1SHA1 ||
            padding == kSecPaddingPKCS1SHA224 ||
            padding == kSecPaddingPKCS1SHA256 ||
            padding == kSecPaddingPKCS1SHA384 ||
            padding == kSecPaddingPKCS1SHA512);
}

+ (NSData *)digestForData:(NSData *)data withPadding:(SecPadding)padding
{
    switch (padding) {
        case kSecPaddingPKCS1SHA1:
            return [data SHA1Digest];
            break;
            
        case kSecPaddingPKCS1SHA224:
            return [data SHA224Digest];
            break;
            
        case kSecPaddingPKCS1SHA256:
            return [data SHA256Digest];
            break;
            
        case kSecPaddingPKCS1SHA384:
            return [data SHA384Digest];
            break;
            
        case kSecPaddingPKCS1SHA512:
            return [data SHA512Digest];
            break;
            
        default:
            return data;
            break;
    }
    
    return nil;
}


#pragma mark - Keychain Methods

+ (NSData *)keyDataWithTag:(NSString *)tag error:(NSError **)error
{
    NSMutableDictionary *queryKey = [self keyQueryDictionary:tag];
    [queryKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    
    SecKeyRef key = NULL;
    OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)queryKey, (CFTypeRef *)&key);
    
    if (err != noErr || !key) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:@"" code:0 userInfo:nil];
        }
        
        return nil;
    }
    
    return (__bridge NSData *)key;
}


+ (SecKeyRef)keyRefWithTag:(NSString *)tag error:(NSError **)error
{
    NSMutableDictionary *queryKey = [self keyQueryDictionary:tag];
    [queryKey setObject:@YES forKey:(__bridge id)kSecReturnRef];
    
    SecKeyRef key = NULL;
    OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)queryKey, (CFTypeRef *)&key);
    
    if (err != noErr) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:@"" code:0 userInfo:nil];
        }
        
        return nil;
    }
    
    return key;
}

+ (BOOL)removeKey:(NSString *)tag error:(NSError **)error
{
    NSDictionary *queryKey = [self keyQueryDictionary:tag];
    OSStatus secStatus = SecItemDelete((__bridge CFDictionaryRef)queryKey);
    
    if ((secStatus != noErr) && (secStatus != errSecDuplicateItem))
    {
        if (error != NULL) {
            *error = [NSError errorWithDomain:@"" code:0 userInfo:nil];
        }
        
        return NO;
    }
    
    return YES;
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

+ (NSString *)publicKeyIdentifierWithTag:(NSString *)tag
{
    NSString *identifier = [NSString stringWithFormat:@"%@.publicKey", tag];
    
    return identifier;
}

+ (NSString *)privateKeyIdentifierWithTag:(NSString *)tag
{
    NSString *identifier = [NSString stringWithFormat:@"%@.privateKey", tag];
    
    return identifier;
}

@end
