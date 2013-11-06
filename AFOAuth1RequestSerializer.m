//
// AFOAuth1RequestSerializer.m
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

#import "AFOAuth1RequestSerializer.h"
#import <CommonCrypto/CommonHMAC.h>

static NSString * const kAFCharactersToBeEscapedInQueryString = @":/?&=;+!@#$()',*";

static NSString * AFPercentEscapedQueryStringKeyFromStringWithEncoding(NSString *string, NSStringEncoding encoding) {
    static NSString * const kAFCharactersToLeaveUnescapedInQueryStringPairKey = @"[].";
    
	return (__bridge_transfer  NSString *)CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, (__bridge CFStringRef)string, (__bridge CFStringRef)kAFCharactersToLeaveUnescapedInQueryStringPairKey, (__bridge CFStringRef)kAFCharactersToBeEscapedInQueryString, CFStringConvertNSStringEncodingToEncoding(encoding));
}

static NSString * AFPercentEscapedQueryStringValueFromStringWithEncoding(NSString *string, NSStringEncoding encoding) {
	return (__bridge_transfer  NSString *)CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, (__bridge CFStringRef)string, NULL, (__bridge CFStringRef)kAFCharactersToBeEscapedInQueryString, CFStringConvertNSStringEncodingToEncoding(encoding));
}

static NSString * AFEncodeBase64WithData(NSData *data) {
    NSUInteger length = [data length];
    NSMutableData *mutableData = [NSMutableData dataWithLength:((length + 2) / 3) * 4];
    
    uint8_t *input = (uint8_t *)[data bytes];
    uint8_t *output = (uint8_t *)[mutableData mutableBytes];
    
    for (NSUInteger i = 0; i < length; i += 3) {
        NSUInteger value = 0;
        for (NSUInteger j = i; j < (i + 3); j++) {
            value <<= 8;
            if (j < length) {
                value |= (0xFF & input[j]);
            }
        }
        
        static uint8_t const kAFBase64EncodingTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        NSUInteger idx = (i / 3) * 4;
        output[idx + 0] = kAFBase64EncodingTable[(value >> 18) & 0x3F];
        output[idx + 1] = kAFBase64EncodingTable[(value >> 12) & 0x3F];
        output[idx + 2] = (i + 1) < length ? kAFBase64EncodingTable[(value >> 6)  & 0x3F] : '=';
        output[idx + 3] = (i + 2) < length ? kAFBase64EncodingTable[(value >> 0)  & 0x3F] : '=';
    }
    
    return [[NSString alloc] initWithData:mutableData encoding:NSASCIIStringEncoding];
}

static NSString * AFPercentEscapedQueryStringPairMemberFromStringWithEncoding(NSString *string, NSStringEncoding encoding) {
    static NSString * const kAFCharactersToBeEscaped = @":/?&=;+!@#$()',*";
    static NSString * const kAFCharactersToLeaveUnescaped = @"[].";
    
	return (__bridge_transfer NSString *)CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, (__bridge CFStringRef)string, (__bridge CFStringRef)kAFCharactersToLeaveUnescaped, (__bridge CFStringRef)kAFCharactersToBeEscaped, CFStringConvertNSStringEncodingToEncoding(encoding));
}

static NSDictionary * AFParametersFromQueryString(NSString *queryString) {
    NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
    if (queryString) {
        NSScanner *parameterScanner = [[NSScanner alloc] initWithString:queryString];
        NSString *name = nil;
        NSString *value = nil;
        
        while (![parameterScanner isAtEnd]) {
            name = nil;
            [parameterScanner scanUpToString:@"=" intoString:&name];
            [parameterScanner scanString:@"=" intoString:NULL];
            
            value = nil;
            [parameterScanner scanUpToString:@"&" intoString:&value];
            [parameterScanner scanString:@"&" intoString:NULL];
            
            if (name && value) {
                parameters[[name stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding]] = [value stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
            }
        }
    }
    
    return parameters;
}

static inline BOOL AFQueryStringValueIsTrue(NSString *value) {
    return value && [[value lowercaseString] hasPrefix:@"t"];
}





NSString * const kAFOAuth1CredentialServiceName = @"AFOAuthCredentialService";

static NSDictionary * AFKeychainQueryDictionaryWithIdentifier(NSString *identifier) {
    return @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
             (__bridge id)kSecAttrAccount: identifier,
             (__bridge id)kSecAttrService: kAFOAuth1CredentialServiceName
             };
}


@implementation AFOAuth1RequestSerializer

-(NSMutableURLRequest*)requestWithMethod:(NSString *)method
                               URLString:(NSString *)URLString
                              parameters:(NSDictionary *)parameters
                            authenticate:(BOOL)authenticate{
    
    if (!authenticate) {
        return [super requestWithMethod:method URLString:URLString parameters:parameters];
    }
    
    // otherwise, we have work to do
    NSMutableURLRequest *request = nil;
    
    if ([method isEqualToString:@"POST"]) {
        // oauth_ parameters have to go into the Authorization header field in a special format
        NSMutableDictionary *nonOAuthParameters = [parameters mutableCopy];

        for (NSString *key in parameters) {
            if ([key hasPrefix:@"oauth_"]) {
                [nonOAuthParameters removeObjectForKey:key];
            }
        }
    
        request = [super requestWithMethod:method URLString:URLString parameters:nonOAuthParameters];  // oauth_ fields don't go in the actual request for POST
    
        NSString *contentTypeString = [request valueForHTTPHeaderField:@"Content-Type"];
        NSDictionary *authorizationParameters = ([contentTypeString rangeOfString:@"application/x-www-form-urlencoded"].location != NSNotFound ? parameters : nil);  // oauthparameters may be necessary for creating the authorization header
        
        [request setValue:[self authorizationHeaderForMethod:method URLString:URLString parameters:authorizationParameters]
       forHTTPHeaderField:@"Authorization"];
        [request setHTTPShouldHandleCookies:NO];        
    }
    
    else{
        // for any other method, add the proper parameters
        NSMutableDictionary *completeParameters = [self completeParametersToAuthenticateWithHTTPMethod:method URLString:URLString nonOAuthParameters:parameters];
        request =  [super requestWithMethod:method URLString:URLString parameters:completeParameters];
    }
    
    NSLog(@"Created request in my serializer:  %@", request.URL);
    NSLog(@"                         Headers:  %@", request.allHTTPHeaderFields);
    
    return request;
}


-(NSMutableDictionary*)completeParametersToAuthenticateWithHTTPMethod:(NSString*)method URLString:(NSString*)URLString nonOAuthParameters:(NSDictionary*)nonOAuthParameters{
    NSMutableDictionary *oauthParameters = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                       kAFOAuth1Version, @"oauth_version",
                                       NSStringFromAFOAuthSignatureMethod(self.signatureMethod), @"oauth_signature_method",
                                       [@(floor([[NSDate date] timeIntervalSince1970])) stringValue], @"oauth_timestamp",
                                       AFNounce(), @"oauth_nonce",
                                       nil];
    
    if (self.accessToken) {
        if (self.accessToken.key) {
            oauthParameters[@"oauth_token"] = self.accessToken.key;
        }
        if (self.accessToken.verifier) {
            oauthParameters[@"oauth_verifier"] = self.accessToken.verifier;            
        }
    }
    
    NSMutableDictionary *completeParameters = [NSMutableDictionary dictionaryWithDictionary:oauthParameters];
    [completeParameters addEntriesFromDictionary:nonOAuthParameters];
    
    completeParameters[@"oauth_signature"] = [self OAuthSignatureForMethod:method path:URLString
                                                        parameters:completeParameters
                                                             token:self.accessToken];
    
    return completeParameters;
}


-(NSString*)authorizationHeaderForMethod:(NSString*)method  URLString:(NSString*)URLString  parameters:(NSDictionary*)parameters{
    NSString* kOAuth1FormatString = @" %@=\"%@\",";
    
    NSString *authorizationHeaderString = @"OAuth";
    
    NSMutableDictionary *completeParameters = [NSMutableDictionary dictionaryWithDictionary:parameters];

    // try with the plain one, will double write some keys when requesting tokens, but that shouldn't matter
    completeParameters = [self completeParametersToAuthenticateWithHTTPMethod:method URLString:URLString nonOAuthParameters:parameters];
    
    for (NSString *key in [[completeParameters allKeys] sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)]) {
        if ([key isKindOfClass:[NSString class]]) {
            NSString *newPairString = [NSString stringWithFormat:kOAuth1FormatString,
                                       AFPercentEscapedQueryStringKeyFromStringWithEncoding(key, self.stringEncoding),
                                       AFPercentEscapedQueryStringValueFromStringWithEncoding(completeParameters[key], self.stringEncoding)];
            authorizationHeaderString = [authorizationHeaderString stringByAppendingString:newPairString];
        }
    }
    
    authorizationHeaderString = [authorizationHeaderString substringToIndex:authorizationHeaderString.length - 1]; // to cut off the trailing comma
    return authorizationHeaderString;
}

static inline NSString * NSStringFromAFOAuthSignatureMethod(AFOAuthSignatureMethod signatureMethod) {
    switch (signatureMethod) {
        case AFHMACSHA1SignatureMethod:
            return @"HMAC-SHA1";
        default:
            return nil;
    }
}

static inline NSString * AFHMACSHA1Signature(NSURLRequest *request, NSString *consumerSecret, NSString *tokenSecret, NSStringEncoding stringEncoding) {
    NSString *secret = tokenSecret ? tokenSecret : @"";
    NSString *secretString = [NSString stringWithFormat:@"%@&%@", AFPercentEscapedQueryStringPairMemberFromStringWithEncoding(consumerSecret, stringEncoding), AFPercentEscapedQueryStringPairMemberFromStringWithEncoding(secret, stringEncoding)];
    NSData *secretStringData = [secretString dataUsingEncoding:stringEncoding];
    
    NSString *queryString = AFPercentEscapedQueryStringPairMemberFromStringWithEncoding([[[[[request URL] query] componentsSeparatedByString:@"&"] sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@"&"], stringEncoding);
    NSString *requestString = [NSString stringWithFormat:@"%@&%@&%@", [request HTTPMethod],
                               AFPercentEscapedQueryStringPairMemberFromStringWithEncoding([[[request URL] absoluteString] componentsSeparatedByString:@"?"][0], stringEncoding), queryString];
    NSData *requestStringData = [requestString dataUsingEncoding:stringEncoding];
    
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CCHmacContext cx;
    CCHmacInit(&cx, kCCHmacAlgSHA1, [secretStringData bytes], [secretStringData length]);
    CCHmacUpdate(&cx, [requestStringData bytes], [requestStringData length]);
    CCHmacFinal(&cx, digest);
    
    return AFEncodeBase64WithData([NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH]);
}

- (NSString *)OAuthSignatureForMethod:(NSString *)method
                                 path:(NSString *)path
                           parameters:(NSDictionary *)parameters
                                token:(AFOAuth1Token *)token
{
    NSMutableURLRequest *request = [super requestWithMethod:@"GET"
                                                                   URLString:path
                                                                  parameters:parameters];
    [request setHTTPMethod:method];
    
    NSString *tokenSecret = token ? token.secret : nil;
    
    switch (self.signatureMethod) {
        case AFHMACSHA1SignatureMethod:
            return AFHMACSHA1Signature(request, self.secret, tokenSecret, self.stringEncoding);
        default:
            return nil;
    }
}



static inline NSString * AFNounce() {
    CFUUIDRef uuid = CFUUIDCreate(NULL);
    CFStringRef string = CFUUIDCreateString(NULL, uuid);
    CFRelease(uuid);
    
    return (NSString *)CFBridgingRelease(string);
}

@end

@interface AFOAuth1Token ()
@property (readwrite, nonatomic, copy) NSString *key;
@property (readwrite, nonatomic, copy) NSString *secret;
@property (readwrite, nonatomic, copy) NSString *session;
@property (readwrite, nonatomic, strong) NSDate *expiration;
@property (readwrite, nonatomic, assign, getter = canBeRenewed) BOOL renewable;
@end

@implementation AFOAuth1Token

- (id)initWithQueryString:(NSString *)queryString {
    if (!queryString || [queryString length] == 0) {
        return nil;
    }
    
    NSDictionary *attributes = AFParametersFromQueryString(queryString);
    
    if ([attributes count] == 0) {
        return nil;
    }
    
    NSString *key = attributes[@"oauth_token"];
    NSString *secret = attributes[@"oauth_token_secret"];
    NSString *session = attributes[@"oauth_session_handle"];
    
    NSDate *expiration = nil;
    if (attributes[@"oauth_token_duration"]) {
        expiration = [NSDate dateWithTimeIntervalSinceNow:[attributes[@"oauth_token_duration"] doubleValue]];
    }
    
    BOOL canBeRenewed = NO;
    if (attributes[@"oauth_token_renewable"]) {
        canBeRenewed = AFQueryStringValueIsTrue(attributes[@"oauth_token_renewable"]);
    }
    
    self = [self initWithKey:key secret:secret session:session expiration:expiration renewable:canBeRenewed];
    if (!self) {
        return nil;
    }
    
    NSMutableDictionary *mutableUserInfo = [attributes mutableCopy];
    [mutableUserInfo removeObjectsForKeys:@[@"oauth_token", @"oauth_token_secret", @"oauth_session_handle", @"oauth_token_duration", @"oauth_token_renewable"]];
    
    if ([mutableUserInfo count] > 0) {
        self.userInfo = [NSDictionary dictionaryWithDictionary:mutableUserInfo];
    }
    
    return self;
}

- (id)initWithKey:(NSString *)key
           secret:(NSString *)secret
          session:(NSString *)session
       expiration:(NSDate *)expiration
        renewable:(BOOL)canBeRenewed
{
    NSParameterAssert(key);
    NSParameterAssert(secret);
    
    self = [super init];
    if (!self) {
        return nil;
    }
    
    self.key = key;
    self.secret = secret;
    self.session = session;
    self.expiration = expiration;
    self.renewable = canBeRenewed;
    
    return self;
}

- (BOOL)expired{
    return [self.expiration compare:[NSDate date]] == NSOrderedDescending;
}

+(NSString*)verifierFromQueryString:(NSString *)query{
    return [AFParametersFromQueryString(query) valueForKey:@"oauth_verifier"];
}

#pragma mark -

+ (AFOAuth1Token *)retrieveCredentialWithIdentifier:(NSString *)identifier {
    NSMutableDictionary *mutableQueryDictionary = [AFKeychainQueryDictionaryWithIdentifier(identifier) mutableCopy];
    mutableQueryDictionary[(__bridge id)kSecReturnData] = (__bridge id)kCFBooleanTrue;
    mutableQueryDictionary[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    
    CFDataRef result = nil;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)mutableQueryDictionary, (CFTypeRef *)&result);
    
    if (status != errSecSuccess) {
        NSLog(@"Unable to fetch credential with identifier \"%@\" (Error %li)", identifier, (long int)status);
        return nil;
    }
    
    NSData *data = (__bridge_transfer NSData *)result;
    AFOAuth1Token *credential = [NSKeyedUnarchiver unarchiveObjectWithData:data];
    
    return credential;
}

+ (BOOL)deleteCredentialWithIdentifier:(NSString *)identifier {
    NSMutableDictionary *mutableQueryDictionary = [AFKeychainQueryDictionaryWithIdentifier(identifier) mutableCopy];
    
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)mutableQueryDictionary);
    
    if (status != errSecSuccess) {
        NSLog(@"Unable to delete credential with identifier \"%@\" (Error %li)", identifier, (long int)status);
    }
    
    return (status == errSecSuccess);
}

+ (BOOL)storeCredential:(AFOAuth1Token *)credential
         withIdentifier:(NSString *)identifier
{
    NSMutableDictionary *mutableQueryDictionary = [AFKeychainQueryDictionaryWithIdentifier(identifier) mutableCopy];
    
    if (!credential) {
        return [self deleteCredentialWithIdentifier:identifier];
    }
    
    NSMutableDictionary *mutableUpdateDictionary = [NSMutableDictionary dictionary];
    NSData *data = [NSKeyedArchiver archivedDataWithRootObject:credential];
    mutableUpdateDictionary[(__bridge id)kSecValueData] = data;
    
    OSStatus status;
    BOOL exists = !![self retrieveCredentialWithIdentifier:identifier];
    
    if (exists) {
        status = SecItemUpdate((__bridge CFDictionaryRef)mutableQueryDictionary, (__bridge CFDictionaryRef)mutableUpdateDictionary);
    } else {
        [mutableQueryDictionary addEntriesFromDictionary:mutableUpdateDictionary];
        status = SecItemAdd((__bridge CFDictionaryRef)mutableQueryDictionary, NULL);
    }
    
    if (status != errSecSuccess) {
        NSLog(@"Unable to %@ credential with identifier \"%@\" (Error %li)", exists ? @"update" : @"add", identifier, (long int)status);
    }
    
    return (status == errSecSuccess);
}

#pragma mark - NSCoding (possibly incomplete)

- (id)initWithCoder:(NSCoder *)decoder {
    self = [super init];
    if (!self) {
        return nil;
    }
    
    self.key = [decoder decodeObjectForKey:@"key"];
    self.secret = [decoder decodeObjectForKey:@"secret"];
    self.session = [decoder decodeObjectForKey:@"session"];
    self.verifier = [decoder decodeObjectForKey:@"verifier"];
    self.expiration = [decoder decodeObjectForKey:@"expiration"];
    self.renewable = [decoder decodeBoolForKey:@"renewable"];
    self.userInfo = [decoder decodeObjectForKey:@"userInfo"];
    
    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:self.key forKey:@"key"];
    [coder encodeObject:self.secret forKey:@"secret"];
    [coder encodeObject:self.session forKey:@"session"];
    [coder encodeObject:self.verifier forKey:@"verifier"];
    [coder encodeObject:self.expiration forKey:@"expiration"];
    [coder encodeBool:self.renewable forKey:@"renewable"];
    [coder encodeObject:self.userInfo forKey:@"userInfo"];
}

#pragma mark - NSCopying

- (id)copyWithZone:(NSZone *)zone {
    AFOAuth1Token *copy = [[[self class] allocWithZone:zone] init];
    copy.key = self.key;
    copy.secret = self.secret;
    copy.session = self.session;
    copy.verifier = self.verifier;
    copy.expiration = self.expiration;
    copy.renewable = self.renewable;
    copy.userInfo = self.userInfo;
    
    return copy;
}

@end

