//
//  ApplicationDelegate.m
//  PushMeBaby
//
//  Created by Stefan Hafeneger on 07.04.09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import "ApplicationDelegate.h"
#import "ioSock.h"

@interface ApplicationDelegate () {
    NSString *_deviceToken, *_payload, *_certificate;
    otSocket socket;
    SSLContextRef contextRef;
    SecKeychainRef keychainRef;
    SecCertificateRef _certificateRef;
    SecIdentityRef identityRef;
}
#pragma mark Properties
@property(nonatomic, retain) NSString *deviceToken, *payload, *certificate;
#pragma mark Private
- (void)connect;
- (void)disconnect;
@end

@implementation ApplicationDelegate

#pragma mark Allocation

- (id)init {
	self = [super init];
	if(self != nil) {
        self.deviceToken = @"e967259e b9622008 89a9d3fb ab3be0c5 e25ef2ab 569f0ae4 850779b8 187be219";
        // or
        self.deviceToken = @"e967259eb962200889a9d3fbab3be0c5e25ef2ab569f0ae4850779b8187be219";
		self.payload = @"{\"aps\":{\"alert\":\"This is some fancy message.\",\"badge\":1}}";
		self.certificate = [[NSBundle mainBundle] pathForResource:@"apns" ofType:@"cer"];
	}
	return self;
}

- (void)dealloc {
	
	// Release objects.
	self.deviceToken = nil;
	self.payload = nil;
	self.certificate = nil;
	
	// Call super.
	[super dealloc];
	
}


#pragma mark Properties

@synthesize deviceToken = _deviceToken;
@synthesize payload = _payload;
@synthesize certificate = _certificate;

#pragma mark Inherent

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
	
}

- (void)applicationWillTerminate:(NSNotification *)notification {
	
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)application {
	return YES;
}

- (NSString*)stringFromCerificateWithLongwindedDescription:(SecCertificateRef) certificateRef {
    if (certificateRef == NULL)
        return @"";
    
    CFStringRef commonNameRef;
    OSStatus status;
    if ((status=SecCertificateCopyCommonName(certificateRef, &commonNameRef)) != errSecSuccess) {
        NSLog(@"Could not extract name from cert: %@",
              SecCopyErrorMessageString(status, NULL));
        return @"Unreadable cert";
    };
    
    CFStringRef summaryRef = SecCertificateCopySubjectSummary(certificateRef);
    if (summaryRef == NULL)
        summaryRef = CFRetain(commonNameRef);
    
    CFErrorRef error;
    
    const void *keys[] = { kSecOIDX509V1SubjectName, kSecOIDX509V1IssuerName };
    const void *labels[] = { "Subject", "Issuer" };
    CFArrayRef keySelection = CFArrayCreate(NULL, keys , sizeof(keys)/sizeof(keys[0]), &kCFTypeArrayCallBacks);
    
    CFDictionaryRef vals = SecCertificateCopyValues(certificateRef, keySelection,&error);
    NSMutableString *longDesc = [[NSMutableString alloc] init];
    
    for(int i = 0; i < sizeof(keys)/sizeof(keys[0]); i++) {
        CFDictionaryRef dict = CFDictionaryGetValue(vals, keys[i]);
        CFArrayRef values = CFDictionaryGetValue(dict, kSecPropertyKeyValue);
        if (values == NULL)
            continue;
        [longDesc appendFormat:@"%s:%@\n\n", labels[i], [self stringFromDNwithSubjectName:values]];
    }
    
    CFRelease(vals);
    CFRelease(summaryRef);
    CFRelease(commonNameRef);
    
    return longDesc;
}

- (NSString *)stringFromDNwithSubjectName:(CFArrayRef)array {
    NSMutableString * out = [[NSMutableString alloc] init];
    const void *keys[] = { kSecOIDCommonName, kSecOIDEmailAddress, kSecOIDOrganizationalUnitName, kSecOIDOrganizationName, kSecOIDLocalityName, kSecOIDStateProvinceName, kSecOIDCountryName };
    const void *labels[] = { "CN", "E", "OU", "O", "L", "S", "C", "E" };
    
    for(int i = 0; i < sizeof(*keys) - 1;  i++) {
        for (CFIndex n = 0 ; n < CFArrayGetCount(array); n++) {
            CFDictionaryRef dict = CFArrayGetValueAtIndex(array, n);
            if (CFGetTypeID(dict) != CFDictionaryGetTypeID())
                continue;
            CFTypeRef dictkey = CFDictionaryGetValue(dict, kSecPropertyKeyLabel);
            if (!CFEqual(dictkey, keys[i]))
                continue;
            CFStringRef str = (CFStringRef) CFDictionaryGetValue(dict, kSecPropertyKeyValue);
            [out appendFormat:@"%s=%@ ", labels[i], (__bridge NSString*)str];
        }
    }
    return [NSString stringWithString:out];
}

#pragma mark Private

- (void)connect {
	
	if(self.certificate == nil) {
		return;
	}
	
    // Create certificate.
    NSData *certificateData = [NSData dataWithContentsOfFile:self.certificate];
    
    _certificateRef = SecCertificateCreateWithData(kCFAllocatorDefault, (CFDataRef)certificateData);
    BOOL sandbox = [[[self stringFromCerificateWithLongwindedDescription:_certificateRef] lowercaseString] containsString:@"development"];
    const char *hostName = sandbox?"gateway.sandbox.push.apple.com":"gateway.push.apple.com";
    if (_certificateRef == NULL)
        NSLog (@"SecCertificateCreateWithData failled");
    
	// Define result variable.
	OSStatus result;
	
	// Establish connection to server.
	PeerSpec peer;
	result = MakeServerConnection(hostName, 2195, &socket, &peer);// NSLog(@"MakeServerConnection(): %d", result);
	
	// Create new SSL context.
	result = SSLNewContext(false, &contextRef);// NSLog(@"SSLNewContext(): %d", result);
	
	// Set callback functions for SSL context.
	result = SSLSetIOFuncs(contextRef, SocketRead, SocketWrite);// NSLog(@"SSLSetIOFuncs(): %d", result);
	
	// Set SSL context connection.
	result = SSLSetConnection(contextRef, socket);// NSLog(@"SSLSetConnection(): %d", result);
	
	// Set server domain name.
	result = SSLSetPeerDomainName(contextRef, hostName, 30);// NSLog(@"SSLSetPeerDomainName(): %d", result);
	
	// Open keychain.
	result = SecKeychainCopyDefault(&keychainRef);// NSLog(@"SecKeychainOpen(): %d", result);
    
	// Create identity.
	result = SecIdentityCreateWithCertificate(keychainRef, _certificateRef, &identityRef);// NSLog(@"SecIdentityCreateWithCertificate(): %d", result);
	
	// Set client certificate.
	CFArrayRef certificates = CFArrayCreate(NULL, (const void **)&identityRef, 1, NULL);
	result = SSLSetCertificate(contextRef, certificates);// NSLog(@"SSLSetCertificate(): %d", result);
	CFRelease(certificates);
	
	// Perform SSL handshake.
	do {
		result = SSLHandshake(contextRef);// NSLog(@"SSLHandshake(): %d", result);
	} while(result == errSSLWouldBlock);
	
}

- (void)disconnect {
	
	if(self.certificate == nil) {
		return;
	}
	
	// Define result variable.
	OSStatus result;
	
	// Close SSL session.
	result = SSLClose(contextRef);// NSLog(@"SSLClose(): %d", result);
	
	// Release identity.
    if (identityRef != NULL)
        CFRelease(identityRef);
	
	// Release certificate.
    if (_certificateRef != NULL)
        CFRelease(_certificateRef);
	
	// Release keychain.
    if (keychainRef != NULL)
        CFRelease(keychainRef);
	
	// Close connection to server.
	close((int)socket);
	
	// Delete SSL context.
	result = SSLDisposeContext(contextRef);// NSLog(@"SSLDisposeContext(): %d", result);
	
}

#pragma mark IBAction

- (IBAction)push:(id)sender {
	[self disconnect];
    [self connect];
	if(self.certificate == nil) {
        NSLog(@"you need the APNS Certificate for the app to work");
        exit(1);
	}
	
	// Validate input.
	if(self.deviceToken == nil || self.payload == nil) {
		return;
	}
    NSString * deviceTokenHex = [[[self.deviceToken
                                   stringByReplacingOccurrencesOfString: @"<" withString: @""]
                                  stringByReplacingOccurrencesOfString: @">" withString: @""]
                                 stringByReplacingOccurrencesOfString: @" " withString: @""];
    NSData *deviceToken = [self dataFromHexString:deviceTokenHex];
    if (deviceTokenHex.length == 64 && deviceToken) {
        // Create C input variables.
        char *deviceTokenBinary = (char *)[deviceToken bytes];
        char *payloadBinary = (char *)[self.payload UTF8String];
        size_t payloadLength = strlen(payloadBinary);
        
        // Define some variables.
        uint8_t command = 0;
        char message[293];
        char *pointer = message;
        uint16_t networkTokenLength = htons(32);
        uint16_t networkPayloadLength = htons(payloadLength);
        
        // Compose message.
        memcpy(pointer, &command, sizeof(uint8_t));
        pointer += sizeof(uint8_t);
        memcpy(pointer, &networkTokenLength, sizeof(uint16_t));
        pointer += sizeof(uint16_t);
        memcpy(pointer, deviceTokenBinary, 32);
        pointer += 32;
        memcpy(pointer, &networkPayloadLength, sizeof(uint16_t));
        pointer += sizeof(uint16_t);
        memcpy(pointer, payloadBinary, payloadLength);
        pointer += payloadLength;
        
        // Send message over SSL.
        size_t processed = 0;
        OSStatus result = SSLWrite(contextRef, &message, (pointer - message), &processed);
        if (result != noErr)
            NSLog(@"SSLWrite(): %d %zd", result, processed);
    } else {
        NSAlert * alert = [NSAlert alertWithMessageText:@"format error" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"device token"];
        [alert beginSheetModalForWindow:[[NSApplication sharedApplication] keyWindow] completionHandler:NULL];
    }
}

- (NSData*)dataFromHexString:(NSString *)hexString{
    int j = 0;
    hexString = [hexString stringByReplacingOccurrencesOfString:@" " withString:@""];
    if (!(hexString && [hexString length] > 0 && [hexString length]%2 == 0)) {
        return nil;
    }
    Byte bytes[[hexString length]/2];
    for (int i=0 ; i < [hexString length] ; i++) {
        int int_ch;
        
        unichar hex_char1 = [hexString characterAtIndex:i];
        int int_ch1;
        if(hex_char1 >= '0' && hex_char1 <= '9')
            int_ch1 = (hex_char1 - 48) * 16;
        else if(hex_char1 >= 'A' && hex_char1 <= 'F')
            int_ch1 = (hex_char1 - 55) * 16;
        else if(hex_char1 >= 'a' && hex_char1 <= 'f')
            int_ch1 = (hex_char1 - 87) * 16;
        else
            return nil;
        i++;
        
        unichar hex_char2 = [hexString characterAtIndex:i];
        int int_ch2;
        if(hex_char2 >= '0' && hex_char2 <= '9')
            int_ch2 = (hex_char2 - 48);
        else if(hex_char2 >= 'A' && hex_char2 <= 'F')
            int_ch2 = hex_char2 - 55;
        else if(hex_char2 >= 'a' && hex_char2 <= 'f')
            int_ch2 = hex_char2 - 87;
        else
            return nil;
        
        int_ch = int_ch1 + int_ch2;
        bytes[j] = int_ch;
        j++;
    }
    return [[NSData alloc] initWithBytes:bytes length:[hexString length]/2];
}

@end
