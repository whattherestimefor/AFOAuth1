// AFOAuth1SessionManager.m
//
// Copyright (c) 2011 Mattt Thompson (http://mattt.me/)
// Updates 2013 (c) Shannon Hughes (AFNetworking 2.0 compatibility)
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

#import "AFHTTPSessionManager.h"
#import "AFOAuth1RequestSerializer.h"



@class AFOAuth1Token;

/**

 */
@interface AFOAuth1SessionManager : AFHTTPSessionManager <NSCoding, NSCopying>

///-----------------------------------
/// @name Managing OAuth Configuration
///-----------------------------------

/**
 
 */
@property (nonatomic, strong) NSString *key;

/**

 
 */
@property (nonatomic, strong) AFOAuth1RequestSerializer <AFURLRequestSerialization> * requestSerializer;
/**
 
 
 */


///---------------------
/// @name Initialization
///---------------------

/**

 */

#pragma mark - Initialization

- (id)initWithBaseURL:(NSURL *)url
                  key:(NSString *)key
               secret:(NSString *)secret;


///---------------------
/// @name Authenticating
///---------------------

/**

 */

#pragma mark - Acquiring Tokens

- (void)authorizeUsingOAuthWithRequestTokenPath:(NSString *)requestTokenPath
                          userAuthorizationPath:(NSString *)userAuthorizationPath
                                    callbackURL:(NSURL *)callbackURL
                                accessTokenPath:(NSString *)accessTokenPath
                                          scope:(NSString *)scope
                                        success:(void (^)(AFOAuth1Token *accessToken, id responseObject))success
                                        failure:(void (^)(NSError *error))failure;

/**

 */
- (void)acquireOAuthRequestTokenWithPath:(NSString *)path
                             callbackURL:(NSURL *)url
                                   scope:(NSString *)scope
                                 success:(void (^)(AFOAuth1Token *requestToken, id responseObject))success
                                 failure:(void (^)(NSError *error))failure;

/**

 */
- (void)acquireOAuthAccessTokenWithPath:(NSString *)path
                           requestToken:(AFOAuth1Token *)requestToken
                                success:(void (^)(AFOAuth1Token *accessToken, id responseObject))success
                                failure:(void (^)(NSError *error))failure;


#pragma mark - Authentication Option on Requests

-(NSURLSessionDataTask *)authenticatedGET:(NSString *)URLString parameters:(NSDictionary *)parameters success:(void (^)(NSURLSessionDataTask *, id))success failure:(void (^)(NSURLSessionDataTask *, NSError *))failure;

-(NSURLSessionDataTask *)authenticatedPOST:(NSString *)URLString parameters:(NSDictionary *)parameters success:(void (^)(NSURLSessionDataTask *, id))success failure:(void (^)(NSURLSessionDataTask *, NSError *))failure;

@end

///----------------
/// @name Constants
///----------------

/**

 */
extern NSString * const kAFApplicationLaunchedWithURLNotification;

/**

 */
extern NSString * const kAFApplicationLaunchOptionsURLKey;


