//
//  NSData+SHADigest.m
//  PPEncrypt
//
//  Created by Juan Alvarez on 5/9/14.
//  Copyright (c) 2014 Alvarez Productions. All rights reserved.
//

#import "NSData+SHADigest.h"

#import <CommonCrypto/CommonDigest.h>

typedef NS_ENUM(NSInteger, SHADigestType) {
    SHADigestTypeSHA1,
    SHADigestTypeSHA224,
    SHADigestTypeSHA256,
    SHADigestTypeSHA384,
    SHADigestTypeSHA512,
};

@implementation NSData (SHADigest)

#pragma mark - Public Methods

- (NSData *)SHA1Digest
{
    return [self _SHADigestWithType:SHADigestTypeSHA1];
}

- (NSData *)SHA224Digest
{
    return [self _SHADigestWithType:SHADigestTypeSHA224];
}

- (NSData *)SHA256Digest
{
    return [self _SHADigestWithType:SHADigestTypeSHA256];
}

- (NSData *)SHA384Digest
{
    return [self _SHADigestWithType:SHADigestTypeSHA384];
}

- (NSData *)SHA512Digest
{
    return [self _SHADigestWithType:SHADigestTypeSHA512];
}

#pragma mark - Private Methods

- (NSData *)_SHADigestWithType:(SHADigestType)type
{
    NSInteger digestLength = 0;
    
    if (type == SHADigestTypeSHA1) {
        digestLength = CC_SHA1_DIGEST_LENGTH;
    }
    
    else if (type == SHADigestTypeSHA224) {
        digestLength = CC_SHA224_DIGEST_LENGTH;
    }
    
    else if (type == SHADigestTypeSHA256) {
        digestLength = CC_SHA256_DIGEST_LENGTH;
    }
    
    else if (type == SHADigestTypeSHA384) {
        digestLength = CC_SHA384_DIGEST_LENGTH;
    }
    
    else if (type == SHADigestTypeSHA512) {
        digestLength = CC_SHA512_DIGEST_LENGTH;
    }
    
    unsigned char result[digestLength];
    
    unsigned char *state;
    CC_LONG dataLength = (CC_LONG)self.length;
    
    switch (type) {
        case SHADigestTypeSHA1:
            state = CC_SHA1(self.bytes, dataLength, result);
            break;
        case SHADigestTypeSHA224:
            state = CC_SHA224(self.bytes, dataLength, result);
            break;
        case SHADigestTypeSHA256:
            state = CC_SHA256(self.bytes, dataLength, result);
            break;
        case SHADigestTypeSHA384:
            state = CC_SHA384(self.bytes, dataLength, result);
            break;
        case SHADigestTypeSHA512:
            state = CC_SHA512(self.bytes, dataLength, result);
            break;
            
        default:
            break;
    }
    
    if (state) {
        return [[NSData alloc] initWithBytes:result length:digestLength];
    }
    
    return nil;
}

@end
