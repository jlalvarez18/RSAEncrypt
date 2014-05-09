//
//  PPKeyPair.m
//  PPEncrypt
//
//  Created by Juan Alvarez on 5/8/14.
//  Copyright (c) 2014 Alvarez Productions. All rights reserved.
//

#import "PPKeyPair.h"

#import <CommonCrypto/CommonCrypto.h>

@interface PPKeyPair ()

@property (nonatomic, assign) SecKeyRef privateKeyRef;
@property (nonatomic, assign) SecKeyRef publicKeyRef;

@end

@implementation PPKeyPair

@end
