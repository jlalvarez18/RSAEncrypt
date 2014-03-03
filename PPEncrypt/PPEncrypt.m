//
//  PPEncrypt.m
//  PPEncrypt
//
//  Created by Juan on 3/3/14.
//  Copyright (c) 2014 Alvarez Productions. All rights reserved.
//

#import "PPEncrypt.h"

#import <CommonCrypto/CommonCrypto.h>

NSString *const kPublicKeyPairKey = @"PublicKeyPairKey";
NSString *const kPrivateKeyPairKey = @"PrivateKeyPairKey";

@import Security;

@implementation PPEncrypt

+(NSString *)encryptRSA:(NSString *)plainTextString key:(SecKeyRef)publicKey {
	size_t cipherBufferSize = SecKeyGetBlockSize(publicKey);
	uint8_t *cipherBuffer = malloc(cipherBufferSize);
	uint8_t *nonce = (uint8_t *)[plainTextString UTF8String];
	SecKeyEncrypt(publicKey,
                  kSecPaddingOAEP,
                  nonce,
                  strlen( (char*)nonce ),
                  &cipherBuffer[0],
                  &cipherBufferSize);
	NSData *encryptedData = [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];
    NSString *encryptedString = [encryptedData base64EncodedStringWithOptions:0];
    
	return encryptedString;
}

+(NSString *)decryptRSA:(NSString *)cipherString key:(SecKeyRef)privateKey {
	size_t plainBufferSize = SecKeyGetBlockSize(privateKey);
	uint8_t *plainBuffer = malloc(plainBufferSize);
    NSData *incomingData = [[NSData alloc] initWithBase64EncodedString:cipherString options:0];
	uint8_t *cipherBuffer = (uint8_t*)[incomingData bytes];
	size_t cipherBufferSize = SecKeyGetBlockSize(privateKey);
	SecKeyDecrypt(privateKey,
                  kSecPaddingOAEP,
                  cipherBuffer,
                  cipherBufferSize,
                  plainBuffer,
                  &plainBufferSize);
	NSData *decryptedData = [NSData dataWithBytes:plainBuffer length:plainBufferSize];
	NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
    
    return decryptedString;
}

+(void)generateKeyPairWithPublicTag:(NSString *)publicTagString
                         privateTag:(NSString *)privateTagString
                          publicKey:(SecKeyRef *)publicKey
                         privateKey:(SecKeyRef *)privateKey
{
	NSData *publicTag = [publicTagString dataUsingEncoding:NSUTF8StringEncoding];
	NSData *privateTag = [privateTagString dataUsingEncoding:NSUTF8StringEncoding];
	
    NSMutableDictionary *privateKeyAttr = [[NSMutableDictionary alloc] init];
	[privateKeyAttr setObject:@YES forKey:(__bridge id)kSecAttrIsPermanent];
	[privateKeyAttr setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
	
    NSMutableDictionary *publicKeyAttr = [[NSMutableDictionary alloc] init];
	[publicKeyAttr setObject:@YES forKey:(__bridge id)kSecAttrIsPermanent];
	[publicKeyAttr setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
	
    NSMutableDictionary *keyPairAttr = [[NSMutableDictionary alloc] init];
	[keyPairAttr setObject:privateKeyAttr forKey:(__bridge id)kSecPrivateKeyAttrs];
	[keyPairAttr setObject:publicKeyAttr forKey:(__bridge id)kSecPublicKeyAttrs];
    [keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
	[keyPairAttr setObject:@2048 forKey:(__bridge id)kSecAttrKeySizeInBits];
	
    SecKeyRef _publicKey = NULL;
	SecKeyRef _privateKey = NULL;
    
	OSStatus err = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &_publicKey, &_privateKey);
	
	if (err == 0) {
        [self _saveKey:_publicKey withTag:publicTagString];
        [self _saveKey:_privateKey withTag:privateTagString];
        
        if (publicKey != NULL) {
            *publicKey = _publicKey;
        }
        
        if (privateKey != NULL) {
            *privateKey = _privateKey;
        }
    }
}

+ (BOOL)savePublicKey:(SecKeyRef)publicKey
        andPrivateKey:(SecKeyRef)privateKey
        withPublicTag:(NSString *)publicTag
        andPrivateTag:(NSString *)privateTag
{
    return [self _saveKey:publicKey withTag:publicTag] && [self _saveKey:privateKey withTag:privateTag];
}

+ (BOOL)_saveKey:(SecKeyRef)key withTag:(NSString *)tagString
{
    NSData *tag = [tagString dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableDictionary *queryAttr = [[NSMutableDictionary alloc] init];
    [queryAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryAttr setObject:tag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    NSMutableDictionary *privateSaveAttr = [queryAttr mutableCopy];
    [privateSaveAttr setObject:(__bridge id)key forKey:(__bridge id)kSecValueRef];
    [privateSaveAttr setObject:@YES forKey:(__bridge id)kSecReturnData];
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)privateSaveAttr, &result);
    
    if (status == errSecSuccess || status == errSecDuplicateItem)
        return YES;
    
    return NO;
}

- (BOOL)deleteKeyWithTag:(NSString *)tagString
{
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    query[(__bridge id)kSecAttrApplicationTag] = tagString;
    
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    
    if (status == errSecSuccess || status == errSecItemNotFound) {
        return YES;
    }
    
    return NO;
}

+ (SecKeyRef)getKeyWithTag:(NSString *)tagString
{
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    query[(__bridge id)kSecAttrApplicationTag] = tagString;
    query[(__bridge id)kSecClass] = (__bridge id)kSecClassKey;
    query[(__bridge id)kSecAttrKeyType] = (__bridge id)kSecAttrKeyTypeRSA;
    query[(__bridge id)kSecReturnRef] = @YES;
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)(query), &result);
    
    if (status == errSecSuccess) {
        return (SecKeyRef)result;
    }
    
    return nil;
}

@end
