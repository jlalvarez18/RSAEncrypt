//
//  NSData+SHADigest.h
//  PPEncrypt
//
//  Created by Juan Alvarez on 5/9/14.
//  Copyright (c) 2014 Alvarez Productions. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSData (SHADigest)

- (NSData *)SHA1Digest;
- (NSData *)SHA224Digest;
- (NSData *)SHA256Digest;
- (NSData *)SHA384Digest;
- (NSData *)SHA512Digest;

@end
