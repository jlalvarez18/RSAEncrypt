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

// Inspiration from https://github.com/kuapay/iOS-Certificate--Key--and-Trust-Sample-Project

static unsigned char oidSequence [] = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };

@import Security;

@interface PPEncrypt ()

@property (nonatomic, strong) PPEncryptSettings *settings;
@property (nonatomic, strong) PPKeyPair *keyPair;

@end

@implementation PPEncrypt

- (instancetype)initWithSettings:(PPEncryptSettings *)settings keyPair:(PPKeyPair *)pair
{
    self = [super init];
    
    self.settings = settings;
    self.keyPair = pair;
    
    return self;
}

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

#pragma mark - Encryption Methods

- (NSData *)encryptString:(NSString *)string
{
    return [PPEncrypt encryptString:string withPadding:self.settings.padding andPair:self.keyPair];
}

+ (NSData *)encryptString:(NSString *)string withPadding:(SecPadding)padding andPair:(PPKeyPair *)pair
{
    if (string == nil || pair == nil) {
        return nil;
    }
    
    NSString *identifier = [PPEncrypt publicKeyIdentifierWithTag:pair.identifier];
    
    SecKeyRef publicKey = [PPEncrypt keyRefWithTag:identifier error:nil];
    
    size_t maxLength = SecKeyGetBlockSize(publicKey);
    
//    When PKCS1 padding is performed, the maximum length of data that can
//    be encrypted is the value returned by SecKeyGetBlockSize() - 11.
    if ([self isPaddingPKCS1:padding]) {
        maxLength -= 11;
    }
    
    uint8_t *nonce = (uint8_t *)[string UTF8String];
    size_t nonceSize = strlen((char *)nonce);
    
//    Length of plainText in bytes, this must be less than
//    or equal to the value returned by SecKeyGetBlockSize().
    if (nonceSize > maxLength) {
        NSString *reason = [NSString stringWithFormat:@"String length is too long to sign with this key, max length is %ld and actual length is %ld", maxLength, nonceSize];
        NSLog(@"%@", reason);
        
        return nil;
    }
    
    NSData *encryptedData;
    
    if (publicKey) {
        size_t cipherBufferSize = SecKeyGetBlockSize(publicKey);
        uint8_t *cipherBuffer = malloc(cipherBufferSize);
        
        OSStatus status = SecKeyEncrypt(publicKey,
                                        padding,
                                        nonce,
                                        nonceSize,
                                        &cipherBuffer[0],
                                        &cipherBufferSize);
        
        if (status == errSecSuccess) {
            encryptedData = [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];
        }
        
        free(cipherBuffer);
    }
    
    return encryptedData;
}

#pragma mark - Decryption Methods

- (NSString *)decryptData:(NSData *)data
{
    return [PPEncrypt decryptData:data withPadding:self.settings.padding andPair:self.keyPair];
}

+ (NSString *)decryptData:(NSData *)data withPadding:(SecPadding)padding andPair:(PPKeyPair *)pair
{
    if (pair == nil || pair == nil) {
        return nil;
    }
    
    NSString *identifier = [self privateKeyIdentifierWithTag:pair.identifier];
    
    SecKeyRef privateKey = [self keyRefWithTag:identifier error:nil];
    
    size_t keySize = SecKeyGetBlockSize(privateKey);
    
    if (data.length > keySize) {
        NSString *reason = [NSString stringWithFormat:@"Cipher size is too long to sign with this key, max length is %ld and actual length is %ld", keySize, (unsigned long)data.length];
        
        NSLog(@"%@", reason);
        
        return nil;
    }
    
    NSString *decryptedString;
    
    if (privateKey) {
        size_t plainBufferSize = SecKeyGetBlockSize(privateKey);
        uint8_t *plainBuffer = malloc(keySize);
        
        uint8_t *cipher = (uint8_t*)[data bytes];
        size_t cipherSize = strlen((char *)cipher);
        
        OSStatus status = SecKeyDecrypt(privateKey,
                                        padding,
                                        cipher,
                                        cipherSize,
                                        plainBuffer,
                                        &plainBufferSize);
        
        if (status == errSecSuccess) {
            NSData *decryptedData = [NSData dataWithBytes:plainBuffer length:plainBufferSize];
            
            decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
        }
        
        free(plainBuffer);
    }
    
    return decryptedString;
}

#pragma mark - Signing Methods

- (NSData *)signData:(NSData *)data
{
    return [PPEncrypt signData:data withPadding:self.settings.padding andPair:self.keyPair];
}

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

+ (NSString *)PEMFormattedPrivateKey:(NSString *)tag error:(NSError **)error
{
    NSError *keyDataError;
    NSData *privateKeyData = [self keyDataWithTag:tag error:&keyDataError];
    
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


+ (NSString *)X509FormattedPublicKey:(NSString *)tag error:(NSError **)error
{
    NSError *keyDataError;
    NSData *publicKeyData = [self keyDataWithTag:tag error:&keyDataError];
    
    if (keyDataError)
    {
        *error = keyDataError;
        
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

+ (NSData *)keyDataWithTag:(NSString *)tag error:(NSError **)error
{
    NSMutableDictionary *queryKey = [self keyQueryDictionary:tag];
    [queryKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    
    SecKeyRef key = NULL;
    OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)queryKey, (CFTypeRef *)&key);
    
    if (err != noErr || !key)
    {
        *error = [NSError errorWithDomain:@"" code:0 userInfo:nil];
        
        return nil;
    }
    
    return (__bridge NSData *)key;
}


+ (SecKeyRef)keyRefWithTag:(NSString *)tag error:(NSError **)error
{
    NSMutableDictionary *queryKey = [self keyQueryDictionary:tag];
    [queryKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    SecKeyRef key = NULL;
    OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)queryKey, (CFTypeRef *)&key);
    
    if (err != noErr) {
        *error = [NSError errorWithDomain:@"" code:0 userInfo:nil];
        
        return nil;
    }
    
    return key;
}

+ (void)removeKey:(NSString *)tag error:(NSError **)error
{
    NSDictionary *queryKey = [self keyQueryDictionary:tag];
    OSStatus secStatus = SecItemDelete((__bridge CFDictionaryRef)queryKey);
    
    if ((secStatus != noErr) && (secStatus != errSecDuplicateItem))
    {
        *error = [NSError errorWithDomain:@"" code:0 userInfo:nil];
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
