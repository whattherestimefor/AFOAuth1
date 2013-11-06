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

#import "AFOAuth1SessionManager.h"
#import "AFHTTPRequestOperation.h"
#import "AFURLRequestSerialization.h"
#import "AFOAuth1RequestSerializer.h"


#import <CommonCrypto/CommonHMAC.h>


NSString * const kAFApplicationLaunchedWithURLNotification = @"kAFApplicationLaunchedWithURLNotification";
#if __IPHONE_OS_VERSION_MIN_REQUIRED
NSString * const kAFApplicationLaunchOptionsURLKey = @"UIApplicationLaunchOptionsURLKey";
#else
NSString * const kAFApplicationLaunchOptionsURLKey = @"NSApplicationLaunchOptionsURLKey";
#endif


#pragma mark -

@interface AFOAuth1SessionManager ()

@property (readwrite, nonatomic, strong) id applicationLaunchNotificationObserver;

@end

@implementation AFOAuth1SessionManager

- (id)initWithBaseURL:(NSURL *)url
                  key:(NSString *)clientID
               secret:(NSString *)secret
{
    NSParameterAssert(clientID);
    NSParameterAssert(secret);

   
    self = [super initWithBaseURL:url];
    if (!self) {
        return nil;
    }

     self.requestSerializer = [AFOAuth1RequestSerializer serializer];
    self.key = clientID;
    self.requestSerializer.secret = secret;
    self.requestSerializer.signatureMethod = AFHMACSHA1SignatureMethod;

    return self;
}

- (void)dealloc {
    self.applicationLaunchNotificationObserver = nil;
}

- (void)setApplicationLaunchNotificationObserver:(id)applicationLaunchNotificationObserver {
    if (_applicationLaunchNotificationObserver) {
        [[NSNotificationCenter defaultCenter] removeObserver:_applicationLaunchNotificationObserver];
    }

    [self willChangeValueForKey:@"applicationLaunchNotificationObserver"];
    _applicationLaunchNotificationObserver = applicationLaunchNotificationObserver;
    [self didChangeValueForKey:@"applicationLaunchNotificationObserver"];
}


-(void)clearHTTPHeaderDefaults{
    for (NSString *key in self.requestSerializer.HTTPRequestHeaders) {
        [self.requestSerializer setValue:nil forHTTPHeaderField:key];
    }
}


#pragma mark -

- (void)authorizeUsingOAuthWithRequestTokenPath:(NSString *)requestTokenPath
                          userAuthorizationPath:(NSString *)userAuthorizationPath
                                    callbackURL:(NSURL *)callbackURL
                                accessTokenPath:(NSString *)accessTokenPath
                                          scope:(NSString *)scope
                                        success:(void (^)(AFOAuth1Token *accessToken, id responseObject))success
                                        failure:(void (^)(NSError *error))failure
{
    self.responseSerializer = [AFHTTPResponseSerializer serializer];
    
    [self acquireOAuthRequestTokenWithPath:requestTokenPath
                               callbackURL:callbackURL
                                     scope:scope
                                   success:^(AFOAuth1Token *requestToken, id responseObject) {
        __block AFOAuth1Token *currentRequestToken = requestToken;

        self.applicationLaunchNotificationObserver = [[NSNotificationCenter defaultCenter] addObserverForName:kAFApplicationLaunchedWithURLNotification object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(NSNotification *notification) {
            NSURL *url = [[notification userInfo] valueForKey:kAFApplicationLaunchOptionsURLKey];

            currentRequestToken.verifier = [AFOAuth1Token verifierFromQueryString:[url query]];

            [self acquireOAuthAccessTokenWithPath:accessTokenPath
                                     requestToken:currentRequestToken
                                          success:^(AFOAuth1Token * accessToken, id responseObject) {
                self.applicationLaunchNotificationObserver = nil;
                if (accessToken) {
                    self.requestSerializer.accessToken = accessToken;
                    
                    if (success) {
                        success(accessToken, responseObject);
                    }
                } else {
                    if (failure) {
                        failure(nil);
                    }
                }
            } failure:^(NSError *error) {
                self.applicationLaunchNotificationObserver = nil;
                if (failure) {
                    failure(error);
                }
            }];
        }];

        NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
        parameters[@"oauth_token"] = requestToken.key;
        NSMutableURLRequest *request = [self.requestSerializer requestWithMethod:@"GET" URLString:[[NSURL URLWithString:userAuthorizationPath relativeToURL:self.baseURL] absoluteString] parameters:parameters];
        [request setHTTPShouldHandleCookies:NO];
#if __IPHONE_OS_VERSION_MIN_REQUIRED
        [[UIApplication sharedApplication] openURL:[request URL]];
#else
        [[NSWorkspace sharedWorkspace] openURL:[request URL]];
#endif
    } failure:^(NSError *error) {
        if (failure) {
            failure(error);
        }
    }];
}

- (void)acquireOAuthRequestTokenWithPath:(NSString *)path
                             callbackURL:(NSURL *)callbackURL
                                   scope:(NSString *)scope
                                 success:(void (^)(AFOAuth1Token *requestToken, id responseObject))success
                                 failure:(void (^)(NSError *error))failure
{
    NSMutableDictionary *parameters = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                       [callbackURL absoluteString], @"oauth_callback",
                                       self.key, @"oauth_consumer_key",
                                       nil];
    if (scope && !self.requestSerializer.accessToken) {
        parameters[@"scope"] = scope;
    }

    [self authenticatedPOST:path
                 parameters:parameters
                    success:^(NSURLSessionDataTask *task, id responseObject) {
                        NSString *tokenQueryString = [[NSString alloc] initWithData:responseObject encoding:self.responseSerializer.stringEncoding];
                        AFOAuth1Token *requestToken = [[AFOAuth1Token alloc] initWithQueryString:tokenQueryString];
                        if (success) {
                            success(requestToken, responseObject);
                        }
                    } failure:^(NSURLSessionDataTask *task, NSError *error) {
                        NSLog(@"%@", error);
                    }];
}

- (void)acquireOAuthAccessTokenWithPath:(NSString *)path
                           requestToken:(AFOAuth1Token *)requestToken
                                success:(void (^)(AFOAuth1Token *accessToken, id responseObject))success
                                failure:(void (^)(NSError *error))failure
{
    self.requestSerializer.accessToken = requestToken;

    NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
    parameters[@"oauth_token"] = requestToken.key;
    [self authenticatedPOST:path
                 parameters:parameters
                    success:^(NSURLSessionDataTask *task, id responseObject) {
                        if (success) {
                            NSString *responseString = [[NSString alloc] initWithData:responseObject encoding:self.responseSerializer.stringEncoding];
                            if (responseString) {
                                AFOAuth1Token *accessToken = [[AFOAuth1Token alloc] initWithQueryString:responseString];
                                success(accessToken, responseObject);
                            }
                        }
                    } failure:^(NSURLSessionDataTask *task, NSError *error) {
                        if (failure) {
                            failure(error);
                        }
                    }];
}

#pragma mark - Authenticated Options

-(NSURLSessionDataTask *)authenticatedGET:(NSString *)URLString
                  parameters:(NSDictionary *)parameters
                     success:(void (^)(NSURLSessionDataTask *, id))success
                     failure:(void (^)(NSURLSessionDataTask *, NSError *))failure{
    
    // essentially copied from AFHTTPSessionManager
    NSMutableURLRequest *request = [self.requestSerializer requestWithMethod:@"GET" URLString:[[NSURL URLWithString:URLString relativeToURL:self.baseURL] absoluteString] parameters:parameters authenticate:YES];
    
    __block NSURLSessionDataTask *task = [self dataTaskWithRequest:request completionHandler:^(NSURLResponse * __unused response, id responseObject, NSError *error) {
        if (error) {
            if (failure) {
                failure(task, error);
            }
        } else {
            if (success) {
                success(task, responseObject);
            }
        }
    }];
    
    [task resume];
    
    return task;
}

-(NSURLSessionDataTask *)authenticatedPOST:(NSString *)URLString parameters:(NSDictionary *)parameters success:(void (^)(NSURLSessionDataTask *, id))success failure:(void (^)(NSURLSessionDataTask *, NSError *))failure{
    NSMutableURLRequest *request = [self.requestSerializer requestWithMethod:@"POST" URLString:[[NSURL URLWithString:URLString relativeToURL:self.baseURL] absoluteString] parameters:parameters authenticate:YES];
    
    __block NSURLSessionDataTask *task = [self dataTaskWithRequest:request completionHandler:^(NSURLResponse * __unused response, id responseObject, NSError *error) {
        if (error) {
            if (failure) {
                failure(task, error);
            }
        } else {
            if (success) {
                success(task, responseObject);
            }
        }
    }];
    
    [task resume];
    
    return task;
}

#pragma mark - NSCoding (incomplete method implementations!)

- (id)initWithCoder:(NSCoder *)decoder {
    // incomplete
    self = [super initWithCoder:decoder];
    if (!self) {
        return nil;
    }

    self.requestSerializer = [decoder decodeObjectForKey:@"requestSerializer"];
    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    // incomplete
    [super encodeWithCoder:coder];
    
    [coder encodeObject:self.requestSerializer forKey:@"requestSerializer"];
}

#pragma mark - NSCopying

- (id)copyWithZone:(NSZone *)zone {
    // incomplete
    AFOAuth1SessionManager *copy = [[[self class] allocWithZone:zone] initWithBaseURL:self.baseURL
                                                                          key:self.key
                                                                       secret:self.requestSerializer.secret];
    copy.requestSerializer = [self.requestSerializer copy];
    copy.responseSerializer = [self.responseSerializer copy];
    return copy;
}

@end

#pragma mark -

@interface AFOAuth1Token ()
@property (readwrite, nonatomic, copy) NSString *key;
@property (readwrite, nonatomic, copy) NSString *secret;
@property (readwrite, nonatomic, copy) NSString *session;
@property (readwrite, nonatomic, strong) NSDate *expiration;
@property (readwrite, nonatomic, assign, getter = canBeRenewed) BOOL renewable;
@end

