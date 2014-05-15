//
//  NSString+Digest.m
//  PPEncrypt
//
//  Created by Juan Alvarez on 5/9/14.
//  Copyright (c) 2014 Alvarez Productions. All rights reserved.
//

#import "NSString+Digest.h"

#import "NSData+Digest.h"

@implementation NSString (Digest)

- (NSData *)MD5Digest
{
    NSData *data = [self dataUsingEncoding:NSUTF8StringEncoding];
    
    return [data MD5Digest];
}

- (NSData *)SHA1Digest
{
    NSData *data = [self dataUsingEncoding:NSUTF8StringEncoding];
    
    return [data SHA1Digest];
}

- (NSData *)SHA224Digest
{
    NSData *data = [self dataUsingEncoding:NSUTF8StringEncoding];
    
    return [data SHA224Digest];
}

- (NSData *)SHA256Digest
{
    NSData *data = [self dataUsingEncoding:NSUTF8StringEncoding];
    
    return [data SHA256Digest];
}

- (NSData *)SHA384Digest
{
    NSData *data = [self dataUsingEncoding:NSUTF8StringEncoding];
    
    return [data SHA384Digest];
}

- (NSData *)SHA512Digest
{
    NSData *data = [self dataUsingEncoding:NSUTF8StringEncoding];
    
    return [data SHA512Digest];
}

@end
