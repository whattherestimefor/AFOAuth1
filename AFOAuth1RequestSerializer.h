//
// AFOAuth1RequestSerializer.h
//
// Copyright (c) 2011 Mattt Thompson (http://mattt.me/)
// Changes and file/class renaming 2013 (c) Shannon Hughes (AFNetworking 2.0 compatibility)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "AFURLRequestSerialization.h"

@class AFOAuth1Token;

typedef enum {
    AFHMACSHA1SignatureMethod = 1,
} AFOAuthSignatureMethod;

static NSString * const kAFOAuth1Version = @"1.0";

@interface AFOAuth1RequestSerializer : AFHTTPRequestSerializer

@property (nonatomic) AFOAuthSignatureMethod signatureMethod;
@property (nonatomic, strong) NSString *secret;
@property (nonatomic, strong) NSString *realm;


@property (nonatomic, strong) AFOAuth1Token *accessToken;


@property (nonatomic, strong) NSString *oauthAccessMethod;

-(NSMutableURLRequest*)requestWithMethod:(NSString *)method
                               URLString:(NSString *)URLString
                              parameters:(NSDictionary *)parameters
                            authenticate:(BOOL)authenticate;

@end

#pragma mark -

/**
 
 */
@interface AFOAuth1Token : NSObject <NSCoding, NSCopying>

/**
 
 */
@property (readonly, nonatomic, copy) NSString *key;

/**
 
 */
@property (readonly, nonatomic, copy) NSString *secret;

/**
 
 */
@property (readonly, nonatomic, copy) NSString *session;

/**
 
 */
@property (nonatomic, copy) NSString *verifier;


/**
 
 */
@property (readonly, nonatomic, assign, getter = canBeRenewed) BOOL renewable;

/**
 
 */
@property (readonly, nonatomic, assign, getter = isExpired) BOOL expired;

/**
 
 */
@property (nonatomic, strong) NSDictionary *userInfo;

/**
 
 */
- (id)initWithQueryString:(NSString *)queryString;

/**
 
 */
- (id)initWithKey:(NSString *)key
           secret:(NSString *)secret
          session:(NSString *)session
       expiration:(NSDate *)expiration
        renewable:(BOOL)canBeRenewed;

+(NSString*)verifierFromQueryString:(NSString*)query;

#ifdef _SECURITY_SECITEM_H_
///---------------------
/// @name Authenticating
///---------------------


/**
 Stores the specified OAuth token for a given web service identifier in the Keychain.
 
 @param token The OAuth credential to be stored.
 @param identifier The service identifier associated with the specified token.
 
 @return Whether or not the credential was stored in the keychain.
 */
+ (BOOL)storeCredential:(AFOAuth1Token *)credential
         withIdentifier:(NSString *)identifier;

/**
 Retrieves the OAuth credential stored with the specified service identifier from the Keychain.
 
 @param identifier The service identifier associated with the specified credential.
 
 @return The retrieved OAuth token.
 */
+ (AFOAuth1Token *)retrieveCredentialWithIdentifier:(NSString *)identifier;

/**
 Deletes the OAuth token stored with the specified service identifier from the Keychain.
 
 @param identifier The service identifier associated with the specified token.
 
 @return Whether or not the token was deleted from the keychain.
 */
+ (BOOL)deleteCredentialWithIdentifier:(NSString *)identifier;
#endif

@end