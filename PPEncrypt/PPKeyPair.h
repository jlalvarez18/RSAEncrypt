//
//  PPKeyPair.h
//  PPEncrypt
//
//  Created by Juan Alvarez on 5/8/14.
//  Copyright (c) 2014 Alvarez Productions. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface PPKeyPair : NSObject

@property (nonatomic, strong, readonly) NSString *identifier;
@property (nonatomic, strong, readonly) NSString *publicKey;
@property (nonatomic, strong, readonly) NSString *privateKey;

@end
