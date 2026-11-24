#import <Cocoa/Cocoa.h>
#import <ApplicationServices/ApplicationServices.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/socket.h>
#import <sys/stat.h>
#import <sys/un.h>
#import <unistd.h>

static const NSUInteger HawkMaxBrokerBytes = 256 * 1024;

static NSString *HawkExpandPath(NSString *path) {
    return [[path stringByExpandingTildeInPath] stringByStandardizingPath];
}

static NSString *HawkBase64URL(NSData *data) {
    NSString *value = [data base64EncodedStringWithOptions:0];
    value = [value stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
    value = [value stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    return [value stringByReplacingOccurrencesOfString:@"=" withString:@""];
}

static NSData *HawkBase64URLDecode(NSString *value) {
    if (![value isKindOfClass:NSString.class] || value.length == 0) return nil;
    NSCharacterSet *invalid = [[NSCharacterSet characterSetWithCharactersInString:@"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"] invertedSet];
    if ([value rangeOfCharacterFromSet:invalid].location != NSNotFound) return nil;
    NSString *base64 = [[value stringByReplacingOccurrencesOfString:@"-" withString:@"+"] stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
    while (base64.length % 4) base64 = [base64 stringByAppendingString:@"="];
    return [[NSData alloc] initWithBase64EncodedString:base64 options:0];
}

static NSString *HawkSHA256Hex(NSData *data) {
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *result = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [result appendFormat:@"%02x", digest[i]];
    return result;
}

static NSDictionary *HawkJSONDictionary(NSData *data) {
    if (!data || data.length > HawkMaxBrokerBytes) return nil;
    id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    return [object isKindOfClass:NSDictionary.class] ? object : nil;
}

static NSDictionary *HawkReadJSONFile(NSString *path) {
    return HawkJSONDictionary([NSData dataWithContentsOfFile:HawkExpandPath(path)]);
}

static void HawkSetError(NSError *__autoreleasing *errorOut, NSInteger code, NSString *message) {
    if (errorOut) *errorOut = [NSError errorWithDomain:@"com.hawk.governance-overlay" code:code userInfo:@{NSLocalizedDescriptionKey: message}];
}

static SecKeyRef HawkPublicKeyFromPEM(NSString *pem) {
    if (![pem isKindOfClass:NSString.class]) return NULL;
    NSString *body = [[pem stringByReplacingOccurrencesOfString:@"-----BEGIN PUBLIC KEY-----" withString:@""] stringByReplacingOccurrencesOfString:@"-----END PUBLIC KEY-----" withString:@""];
    body = [[body componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet] componentsJoinedByString:@""];
    NSData *der = [[NSData alloc] initWithBase64EncodedString:body options:0];
    if (der.length < 65) return NULL;
    NSData *x963 = [der subdataWithRange:NSMakeRange(der.length - 65, 65)];
    const unsigned char *bytes = x963.bytes;
    if (!bytes || bytes[0] != 0x04) return NULL;
    NSDictionary *attributes = @{
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
        (__bridge id)kSecAttrKeySizeInBits: @256,
    };
    return SecKeyCreateWithData((__bridge CFDataRef)x963, (__bridge CFDictionaryRef)attributes, NULL);
}

static NSString *HawkThumbprintForKey(SecKeyRef key) {
    if (!key) return nil;
    CFErrorRef error = NULL;
    CFDataRef external = SecKeyCopyExternalRepresentation(key, &error);
    if (error) CFRelease(error);
    if (!external) return nil;
    NSData *data = CFBridgingRelease(external);
    if (data.length != 65 || ((const unsigned char *)data.bytes)[0] != 0x04) return nil;
    NSData *x = [data subdataWithRange:NSMakeRange(1, 32)];
    NSData *y = [data subdataWithRange:NSMakeRange(33, 32)];
    NSString *canonical = [NSString stringWithFormat:@"{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%@\",\"y\":\"%@\"}", HawkBase64URL(x), HawkBase64URL(y)];
    return HawkSHA256Hex([canonical dataUsingEncoding:NSUTF8StringEncoding]);
}

static NSDictionary *HawkVerifiedPayload(NSDictionary *response, NSString *expectedThumbprint, NSError **errorOut) {
    if (![response isKindOfClass:NSDictionary.class]) { HawkSetError(errorOut, 1, @"invalid response"); return nil; }
    NSDictionary *auth = [response[@"broker_auth"] isKindOfClass:NSDictionary.class] ? response[@"broker_auth"] : nil;
    NSString *thumbprint = [auth[@"key_thumbprint"] isKindOfClass:NSString.class] ? [auth[@"key_thumbprint"] lowercaseString] : @"";
    if (!auth || expectedThumbprint.length != 64 || ![thumbprint isEqualToString:expectedThumbprint.lowercaseString]) { HawkSetError(errorOut, 1, @"broker key pin mismatch"); return nil; }
    if (![auth[@"version"] isEqual:@"hawk-local-broker-v1"] || ![auth[@"algorithm"] isEqual:@"ES256"]) { HawkSetError(errorOut, 1, @"unsupported broker authentication"); return nil; }
    NSNumber *issuedNumber = [auth[@"issued_at"] isKindOfClass:NSNumber.class] ? auth[@"issued_at"] : nil;
    NSTimeInterval issuedAt = issuedNumber.doubleValue;
    NSTimeInterval now = NSDate.date.timeIntervalSince1970;
    if (!issuedNumber || issuedAt > now + 30 || now - issuedAt > 120) { HawkSetError(errorOut, 1, @"stale broker response"); return nil; }
    SecKeyRef key = HawkPublicKeyFromPEM(auth[@"public_key_pem"]);
    if (!key) { HawkSetError(errorOut, 1, @"invalid broker public key"); return nil; }
    NSString *actualThumbprint = HawkThumbprintForKey(key);
    if (![actualThumbprint isEqualToString:thumbprint]) { CFRelease(key); HawkSetError(errorOut, 1, @"broker public key mismatch"); return nil; }
    NSString *signedPayload = [auth[@"signed_payload"] isKindOfClass:NSString.class] ? auth[@"signed_payload"] : @"";
    NSData *payloadData = HawkBase64URLDecode(signedPayload);
    NSData *signature = HawkBase64URLDecode(auth[@"signature"]);
    NSString *statement = [NSString stringWithFormat:@"hawk-local-broker-v1\nES256\n%@\n%lld\n%@\n%@", auth[@"endpoint_id"] ?: @"", issuedNumber.longLongValue, thumbprint, signedPayload];
    BOOL valid = payloadData && signature && SecKeyVerifySignature(key, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, (__bridge CFDataRef)[statement dataUsingEncoding:NSUTF8StringEncoding], (__bridge CFDataRef)signature, NULL);
    CFRelease(key);
    if (!valid) { HawkSetError(errorOut, 1, @"invalid broker signature"); return nil; }
    NSDictionary *payload = HawkJSONDictionary(payloadData);
    if (!payload) { HawkSetError(errorOut, 1, @"invalid authenticated payload"); return nil; }
    return payload;
}

static NSDictionary *HawkSocketExchange(NSString *socketPath, NSString *clientApp, NSError **errorOut) {
    NSString *path = HawkExpandPath(socketPath);
    struct stat socketStat = {0}, parentStat = {0};
    if (lstat(path.fileSystemRepresentation, &socketStat) != 0 || !S_ISSOCK(socketStat.st_mode) || socketStat.st_uid != getuid() || (socketStat.st_mode & 0777) != 0600) { HawkSetError(errorOut, 2, @"endpoint broker unavailable"); return nil; }
    if (lstat(path.stringByDeletingLastPathComponent.fileSystemRepresentation, &parentStat) != 0 || !S_ISDIR(parentStat.st_mode) || parentStat.st_uid != getuid() || (parentStat.st_mode & 0022) != 0) { HawkSetError(errorOut, 2, @"endpoint broker unavailable"); return nil; }
    if ([path lengthOfBytesUsingEncoding:NSUTF8StringEncoding] >= sizeof(((struct sockaddr_un *)0)->sun_path)) { HawkSetError(errorOut, 2, @"endpoint broker unavailable"); return nil; }

    int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0) { HawkSetError(errorOut, 2, @"endpoint broker unavailable"); return nil; }
    struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};
    setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    strlcpy(address.sun_path, path.fileSystemRepresentation, sizeof(address.sun_path));
    if (connect(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0) { close(descriptor); HawkSetError(errorOut, 2, @"endpoint broker unavailable"); return nil; }
    NSDictionary *request = @{ @"protocol_version": @1, @"request_id": NSUUID.UUID.UUIDString, @"op": @"governance_status", @"client_app": clientApp ?: @"Unknown client" };
    NSMutableData *encoded = [[NSJSONSerialization dataWithJSONObject:request options:0 error:nil] mutableCopy];
    [encoded appendBytes:"\n" length:1];
    const unsigned char *out = encoded.bytes;
    NSUInteger remaining = encoded.length;
    while (remaining) {
        ssize_t count = write(descriptor, out, remaining);
        if (count <= 0) { close(descriptor); HawkSetError(errorOut, 2, @"endpoint broker unavailable"); return nil; }
        out += count; remaining -= (NSUInteger)count;
    }
    NSMutableData *received = [NSMutableData data];
    unsigned char buffer[4096];
    while (received.length <= HawkMaxBrokerBytes) {
        ssize_t count = read(descriptor, buffer, sizeof(buffer));
        if (count <= 0) break;
        const void *newline = memchr(buffer, '\n', (size_t)count);
        if (newline) {
            NSUInteger prefix = (NSUInteger)((const unsigned char *)newline - buffer);
            [received appendBytes:buffer length:prefix];
            break;
        }
        [received appendBytes:buffer length:(NSUInteger)count];
    }
    close(descriptor);
    if (received.length == 0 || received.length > HawkMaxBrokerBytes) { HawkSetError(errorOut, 2, @"endpoint broker unavailable"); return nil; }
    NSDictionary *response = HawkJSONDictionary(received);
    if (response) return response;
    HawkSetError(errorOut, 2, @"endpoint broker unavailable");
    return nil;
}

static NSRect HawkWindowFrame(pid_t pid) {
    AXUIElementRef app = AXUIElementCreateApplication(pid);
    AXUIElementRef window = NULL;
    CGPoint position = CGPointZero;
    CGSize size = CGSizeZero;
    BOOL found = AXUIElementCopyAttributeValue(app, kAXFocusedWindowAttribute, (CFTypeRef *)&window) == kAXErrorSuccess && window;
    if (found) {
        AXValueRef pos = NULL, dimensions = NULL;
        found = AXUIElementCopyAttributeValue(window, kAXPositionAttribute, (CFTypeRef *)&pos) == kAXErrorSuccess && AXUIElementCopyAttributeValue(window, kAXSizeAttribute, (CFTypeRef *)&dimensions) == kAXErrorSuccess;
        if (found) found = AXValueGetValue(pos, kAXValueCGPointType, &position) && AXValueGetValue(dimensions, kAXValueCGSizeType, &size);
        if (pos) CFRelease(pos); if (dimensions) CFRelease(dimensions); CFRelease(window);
    }
    CFRelease(app);
    if (!found) {
        CFArrayRef rawWindows = CGWindowListCopyWindowInfo(
            kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements,
            kCGNullWindowID
        );
        NSArray *windows = CFBridgingRelease(rawWindows);
        CGFloat largestArea = 0;
        for (NSDictionary *candidate in windows) {
            if ([candidate[(__bridge id)kCGWindowOwnerPID] intValue] != pid) continue;
            if ([candidate[(__bridge id)kCGWindowLayer] intValue] != 0) continue;
            CGRect bounds = CGRectZero;
            if (!CGRectMakeWithDictionaryRepresentation((__bridge CFDictionaryRef)candidate[(__bridge id)kCGWindowBounds], &bounds)) continue;
            CGFloat area = bounds.size.width * bounds.size.height;
            if (area > largestArea) {
                largestArea = area;
                position = bounds.origin;
                size = bounds.size;
                found = YES;
            }
        }
    }
    if (!found) return NSZeroRect;
    for (NSScreen *screen in NSScreen.screens) {
        NSNumber *screenNumber = screen.deviceDescription[@"NSScreenNumber"];
        CGRect cg = CGDisplayBounds(screenNumber.unsignedIntValue);
        CGPoint center = CGPointMake(position.x + size.width / 2, position.y + size.height / 2);
        if (CGRectContainsPoint(cg, center)) {
            return NSMakeRect(screen.frame.origin.x + position.x - cg.origin.x,
                              screen.frame.origin.y + CGRectGetMaxY(cg) - (position.y + size.height),
                              size.width, size.height);
        }
    }
    return NSZeroRect;
}

static NSTextField *HawkLabel(CGFloat size, NSFontWeight weight, NSColor *color) {
    NSTextField *label = [NSTextField labelWithString:@""];
    label.font = [NSFont systemFontOfSize:size weight:weight];
    label.textColor = color;
    label.lineBreakMode = NSLineBreakByTruncatingTail;
    return label;
}

@interface HawkOverlayController : NSObject <NSApplicationDelegate>
@property NSString *socketPath;
@property NSString *trustedThumbprint;
@property NSString *hawkURL;
@property NSPanel *panel;
@property NSTextField *brandLabel;
@property NSTextField *stateLabel;
@property NSTextField *summaryLabel;
@property NSTextField *detailLabel;
@property NSButton *toggleButton;
@property NSButton *openButton;
@property NSTimer *timer;
@property BOOL expanded;
@property NSString *evidenceRef;
@end

@implementation HawkOverlayController
- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    (void)notification;
    [self buildPanel];
    self.timer = [NSTimer scheduledTimerWithTimeInterval:2.0 target:self selector:@selector(tick) userInfo:nil repeats:YES];
    [self tick];
}

- (void)buildPanel {
    self.panel = [[NSPanel alloc] initWithContentRect:NSMakeRect(0, 0, 330, 64) styleMask:NSWindowStyleMaskBorderless | NSWindowStyleMaskNonactivatingPanel backing:NSBackingStoreBuffered defer:NO];
    self.panel.level = NSFloatingWindowLevel;
    self.panel.opaque = NO;
    self.panel.backgroundColor = NSColor.clearColor;
    self.panel.hasShadow = YES;
    self.panel.appearance = [NSAppearance appearanceNamed:NSAppearanceNameDarkAqua];
    self.panel.hidesOnDeactivate = NO;
    self.panel.collectionBehavior = NSWindowCollectionBehaviorCanJoinAllSpaces | NSWindowCollectionBehaviorFullScreenAuxiliary | NSWindowCollectionBehaviorTransient;
    NSVisualEffectView *view = [[NSVisualEffectView alloc] initWithFrame:self.panel.contentView.bounds];
    view.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    view.material = NSVisualEffectMaterialHUDWindow;
    view.blendingMode = NSVisualEffectBlendingModeBehindWindow;
    view.state = NSVisualEffectStateActive;
    view.wantsLayer = YES;
    view.layer.cornerRadius = 14;
    view.layer.masksToBounds = YES;
    view.layer.borderWidth = 1;
    view.layer.borderColor = [NSColor colorWithWhite:1 alpha:.12].CGColor;
    self.panel.contentView = view;

    self.brandLabel = HawkLabel(9, NSFontWeightBold, [NSColor colorWithRed:1 green:.56 blue:.23 alpha:1]);
    self.brandLabel.stringValue = @"HAWK AI · GOVERNED SESSION";
    self.brandLabel.frame = NSMakeRect(14, 40, 210, 14);
    [view addSubview:self.brandLabel];
    self.stateLabel = HawkLabel(14, NSFontWeightSemibold, NSColor.secondaryLabelColor);
    self.stateLabel.stringValue = @"Disconnected";
    self.stateLabel.frame = NSMakeRect(14, 16, 110, 20);
    [view addSubview:self.stateLabel];
    self.summaryLabel = HawkLabel(10, NSFontWeightRegular, NSColor.secondaryLabelColor);
    self.summaryLabel.stringValue = @"Waiting for endpoint broker";
    self.summaryLabel.frame = NSMakeRect(120, 18, 155, 16);
    [view addSubview:self.summaryLabel];
    self.toggleButton = [NSButton buttonWithTitle:@"Details" target:self action:@selector(toggle:)];
    self.toggleButton.bezelStyle = NSBezelStyleRecessed;
    self.toggleButton.font = [NSFont systemFontOfSize:10 weight:NSFontWeightMedium];
    self.toggleButton.frame = NSMakeRect(274, 17, 50, 22);
    [view addSubview:self.toggleButton];
    self.detailLabel = HawkLabel(11, NSFontWeightRegular, NSColor.labelColor);
    self.detailLabel.maximumNumberOfLines = 10;
    self.detailLabel.frame = NSMakeRect(14, 42, 350, 176);
    self.detailLabel.hidden = YES;
    [view addSubview:self.detailLabel];
    self.openButton = [NSButton buttonWithTitle:@"Open evidence in Hawk" target:self action:@selector(openEvidence:)];
    self.openButton.bezelStyle = NSBezelStyleRounded;
    self.openButton.frame = NSMakeRect(214, 12, 150, 28);
    self.openButton.hidden = YES;
    self.openButton.enabled = NO;
    [view addSubview:self.openButton];
}

- (void)toggle:(id)sender {
    (void)sender;
    self.expanded = !self.expanded;
    [self resizePanel];
}

- (void)resizePanel {
    CGFloat height = self.expanded ? 244 : 64;
    NSRect frame = self.panel.frame;
    frame.origin.y += frame.size.height - height;
    frame.size = NSMakeSize(self.expanded ? 380 : 330, height);
    [self.panel setFrame:frame display:YES animate:YES];
    self.detailLabel.hidden = !self.expanded;
    self.openButton.hidden = !self.expanded;
    self.summaryLabel.hidden = self.expanded;
    self.toggleButton.title = self.expanded ? @"Close" : @"Details";
    self.brandLabel.frame = NSMakeRect(14, self.expanded ? 218 : 40, 240, 14);
    self.stateLabel.frame = NSMakeRect(14, self.expanded ? 190 : 16, 150, 22);
    self.toggleButton.frame = NSMakeRect(self.expanded ? 318 : 274, self.expanded ? 189 : 17, 50, 22);
    self.detailLabel.frame = NSMakeRect(14, 48, 350, 134);
}

- (void)openEvidence:(id)sender {
    (void)sender;
    if (!self.evidenceRef.length || !self.hawkURL.length) return;
    NSString *encoded = [self.evidenceRef stringByAddingPercentEncodingWithAllowedCharacters:NSCharacterSet.URLQueryAllowedCharacterSet];
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"%@/prove?evidence_ref=%@", [self.hawkURL stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"/"]], encoded]];
    if (url) [NSWorkspace.sharedWorkspace openURL:url];
}

- (void)tick {
    NSRunningApplication *front = NSWorkspace.sharedWorkspace.frontmostApplication;
    NSString *name = front.localizedName ?: @"";
    NSString *bundle = front.bundleIdentifier ?: @"";
    NSString *client = nil;
    if ([name localizedCaseInsensitiveContainsString:@"Claude"] || [bundle localizedCaseInsensitiveContainsString:@"anthropic"]) client = @"Claude Desktop";
    if ([name localizedCaseInsensitiveContainsString:@"Codex"] || [bundle localizedCaseInsensitiveContainsString:@"codex"]) client = @"Codex";
    if (!client) { [self.panel orderOut:nil]; return; }
    NSRect target = HawkWindowFrame(front.processIdentifier);
    if (NSIsEmptyRect(target)) { [self.panel orderOut:nil]; return; }
    NSRect frame = self.panel.frame;
    frame.origin = NSMakePoint(NSMaxX(target) - frame.size.width - 14, NSMaxY(target) - frame.size.height - 42);
    [self.panel setFrame:frame display:NO];
    [self.panel orderFrontRegardless];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSError *exchangeError = nil;
        NSDictionary *outer = HawkSocketExchange(self.socketPath, client, &exchangeError);
        NSError *verifyError = nil;
        NSDictionary *status = outer ? HawkVerifiedPayload(outer, self.trustedThumbprint, &verifyError) : nil;
        dispatch_async(dispatch_get_main_queue(), ^{ [self renderStatus:status client:client error:exchangeError ?: verifyError]; });
    });
}

- (void)renderStatus:(NSDictionary *)status client:(NSString *)client error:(NSError *)error {
    if (error || ![status[@"ok"] boolValue]) {
        [self setState:@"Disconnected" color:[NSColor colorWithRed:.98 green:.45 blue:.5 alpha:1]];
        self.summaryLabel.stringValue = @"Broker unavailable or unverified";
        self.detailLabel.stringValue = [NSString stringWithFormat:@"Client\t%@\nConnection\tDisconnected\nControl mode\tUnknown\nLatest decision\tUnknown\nTools\tUnknown\nTool calls\tUnknown\nTokens\tUnknown\nSpend\tCost not reported\nEvidence\tUnavailable", client];
        self.evidenceRef = nil; self.openButton.enabled = NO; return;
    }
    NSString *state = [status[@"state"] isKindOfClass:NSString.class] ? [status[@"state"] lowercaseString] : @"unknown";
    NSString *evidence = [status[@"evidence_ref"] isKindOfClass:NSString.class] ? status[@"evidence_ref"] : nil;
    if (!([state isEqual:@"unknown"] || evidence.length)) state = @"unknown";
    NSDictionary *appearance = @{
        @"governed": @[@"Governed", [NSColor colorWithRed:.35 green:.88 blue:.65 alpha:1]],
        @"blocked": @[@"Blocked", [NSColor colorWithRed:.98 green:.45 blue:.5 alpha:1]],
        @"monitor": @[@"Monitor", [NSColor colorWithRed:.98 green:.75 blue:.26 alpha:1]],
        @"unknown": @[@"Unknown", NSColor.secondaryLabelColor],
    };
    NSArray *style = appearance[state] ?: appearance[@"unknown"];
    [self setState:style[0] color:style[1]];
    NSString *(^show)(id) = ^NSString *(id value) { return value && value != NSNull.null ? [value description] : @"Unknown"; };
    NSDictionary *usage = [status[@"token_usage"] isKindOfClass:NSDictionary.class] ? status[@"token_usage"] : @{};
    NSString *tokens = usage[@"total"] && usage[@"total"] != NSNull.null ? [NSString stringWithFormat:@"%@ (%@)", usage[@"total"], usage[@"provenance"] ?: @"unknown"] : @"Unknown";
    NSDictionary *cost = [status[@"cost_usage"] isKindOfClass:NSDictionary.class] ? status[@"cost_usage"] : @{};
    NSString *spend = [cost[@"amount"] isKindOfClass:NSNumber.class] && [cost[@"currency"] isKindOfClass:NSString.class]
        ? [NSString stringWithFormat:@"%@ %.6f (%@ · %@)", cost[@"currency"], [cost[@"amount"] doubleValue], cost[@"provenance"] ?: @"unknown", cost[@"source"] ?: @"unknown"]
        : @"Cost not reported";
    self.summaryLabel.stringValue = [NSString stringWithFormat:@"Connected · %@ · %@ calls", show(status[@"server_id"]), show(status[@"tool_call_count"])];
    self.detailLabel.stringValue = [NSString stringWithFormat:@"Client\t%@\nConnection\tConnected · signature verified\nMCP server\t%@\nSession\t%@\nControl mode\t%@\nLatest decision\t%@\nAvailable tools\t%@\nTool calls\t%@\nTokens\t%@\nSpend\t%@\nEvidence\t%@", client, show(status[@"server_id"]), show(status[@"session_id"]), show(status[@"control_mode"]), show(status[@"latest_decision"]), show(status[@"available_tool_count"]), show(status[@"tool_call_count"]), tokens, spend, evidence ?: @"Unavailable"];
    self.evidenceRef = evidence;
    self.openButton.enabled = evidence.length > 0;
}

- (void)setState:(NSString *)state color:(NSColor *)color {
    self.stateLabel.stringValue = state;
    self.stateLabel.textColor = color;
}
@end

static NSString *HawkArgument(NSArray<NSString *> *arguments, NSString *name) {
    NSUInteger index = [arguments indexOfObject:name];
    return index != NSNotFound && index + 1 < arguments.count ? arguments[index + 1] : nil;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSArray<NSString *> *arguments = NSProcessInfo.processInfo.arguments;
        NSString *expected = HawkArgument(arguments, @"--trusted-thumbprint");
        NSString *verifyPath = HawkArgument(arguments, @"--verify-response");
        if (verifyPath) {
            NSDictionary *verified = HawkVerifiedPayload(HawkReadJSONFile(verifyPath), expected ?: @"", nil);
            if (!verified) return 2;
            NSData *output = [NSJSONSerialization dataWithJSONObject:verified options:NSJSONWritingSortedKeys error:nil];
            fwrite(output.bytes, 1, output.length, stdout); fputc('\n', stdout);
            return 0;
        }
        NSString *configPath = HawkArgument(arguments, @"--endpoint-config") ?: @"~/.config/hawk/endpoint-agent.json";
        NSDictionary *config = HawkReadJSONFile(configPath) ?: @{};
        NSString *socketPath = HawkArgument(arguments, @"--socket") ?: config[@"ipc_socket_path"] ?: @"~/.config/hawk/agent.sock";
        NSString *thumbprint = expected ?: config[@"ipc_trusted_device_thumbprint"] ?: @"";
        NSString *hawkURL = HawkArgument(arguments, @"--hawk-url") ?: @"http://localhost:3001";
        [NSApplication sharedApplication];
        NSApp.activationPolicy = NSApplicationActivationPolicyAccessory;
        HawkOverlayController *controller = [HawkOverlayController new];
        controller.socketPath = socketPath;
        controller.trustedThumbprint = [thumbprint lowercaseString];
        controller.hawkURL = hawkURL;
        NSApp.delegate = controller;
        [NSApp run];
    }
    return 0;
}
