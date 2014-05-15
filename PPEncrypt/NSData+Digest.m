//
//  NSData+Digest.m
//  PPEncrypt
//
//  Created by Juan Alvarez on 5/9/14.
//  Copyright (c) 2014 Alvarez Productions. All rights reserved.
//

#import "NSData+Digest.h"

#import <CommonCrypto/CommonDigest.h>

typedef NS_ENUM(NSInteger, DigestType) {
    DigestTypeMD5,
    DigestTypeSHA1,
    DigestTypeSHA224,
    DigestTypeSHA256,
    DigestTypeSHA384,
    DigestTypeSHA512,
};

@implementation NSData (Digest)

#pragma mark - Public Methods

- (NSData *)MD5Digest
{
    return [self _digestWithType:DigestTypeMD5];
}

- (NSData *)SHA1Digest
{
    return [self _digestWithType:DigestTypeSHA1];
}

- (NSData *)SHA224Digest
{
    return [self _digestWithType:DigestTypeSHA224];
}

- (NSData *)SHA256Digest
{
    return [self _digestWithType:DigestTypeSHA256];
}

- (NSData *)SHA384Digest
{
    return [self _digestWithType:DigestTypeSHA384];
}

- (NSData *)SHA512Digest
{
    return [self _digestWithType:DigestTypeSHA512];
}

#pragma mark - Private Methods

- (NSData *)_digestWithType:(DigestType)type
{
    NSInteger digestLength = 0;
    
    if (type == DigestTypeMD5) {
        digestLength = CC_MD5_DIGEST_LENGTH;
    }
    
    else if (type == DigestTypeSHA1) {
        digestLength = CC_SHA1_DIGEST_LENGTH;
    }
    
    else if (type == DigestTypeSHA224) {
        digestLength = CC_SHA224_DIGEST_LENGTH;
    }
    
    else if (type == DigestTypeSHA256) {
        digestLength = CC_SHA256_DIGEST_LENGTH;
    }
    
    else if (type == DigestTypeSHA384) {
        digestLength = CC_SHA384_DIGEST_LENGTH;
    }
    
    else if (type == DigestTypeSHA512) {
        digestLength = CC_SHA512_DIGEST_LENGTH;
    }
    
    if (digestLength != 0) {
        unsigned char result[digestLength];
        
        unsigned char *state;
        CC_LONG dataLength = (CC_LONG)self.length;
        
        switch (type) {
            case DigestTypeMD5:
                state = CC_MD5(self.bytes, dataLength, result);
                break;
            case DigestTypeSHA1:
                state = CC_SHA1(self.bytes, dataLength, result);
                break;
            case DigestTypeSHA224:
                state = CC_SHA224(self.bytes, dataLength, result);
                break;
            case DigestTypeSHA256:
                state = CC_SHA256(self.bytes, dataLength, result);
                break;
            case DigestTypeSHA384:
                state = CC_SHA384(self.bytes, dataLength, result);
                break;
            case DigestTypeSHA512:
                state = CC_SHA512(self.bytes, dataLength, result);
                break;
                
            default:
                break;
        }
        
        if (state) {
            return [[NSData alloc] initWithBytes:result length:digestLength];
        }
    }
    
    return nil;
}

@end
