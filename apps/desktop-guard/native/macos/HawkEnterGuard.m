#import <ApplicationServices/ApplicationServices.h>
#import <Cocoa/Cocoa.h>
#import <Foundation/Foundation.h>
#include <signal.h>

@interface HawkEnterGuard : NSObject
@property(nonatomic, copy) NSString *configPath;
@property(nonatomic, copy) NSString *applicationName;
@property(nonatomic, copy) NSString *desktopAppName;
@property(nonatomic, strong) NSArray<NSRegularExpression *> *blockingPatterns;
@property(nonatomic, strong) NSArray<NSString *> *blockingReasons;
@property(nonatomic, strong) NSRegularExpression *accessLogPattern;
@property(nonatomic, strong) NSRegularExpression *privateIpPattern;
@property(nonatomic, strong) NSRegularExpression *sensitiveLogPathPattern;
@property(nonatomic, copy) NSString *lastBlockedHash;
@property(nonatomic, strong) NSDate *lastBlockedAt;
- (BOOL)shouldHandleEvent:(CGEventRef)event;
- (BOOL)blockIfNeeded;
@end

static NSString *ArgumentValue(NSArray<NSString *> *arguments, NSString *name, NSString *defaultValue) {
    NSUInteger index = [arguments indexOfObject:name];
    if (index == NSNotFound || index + 1 >= arguments.count) {
        return defaultValue;
    }
    return arguments[index + 1];
}

static void ShowDialog(NSString *title, NSString *message) {
    NSString *escapedTitle = [title stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""];
    NSString *escapedMessage = [message stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""];
    NSString *script = [NSString stringWithFormat:
        @"display dialog \"%@\" with title \"%@\" buttons {\"OK\"} default button \"OK\" giving up after 8",
        escapedMessage,
        escapedTitle
    ];
    NSTask *task = [[NSTask alloc] init];
    task.executableURL = [NSURL fileURLWithPath:@"/usr/bin/osascript"];
    task.arguments = @[@"-e", script];
    [task launchAndReturnError:nil];
}

static void LogLine(NSString *message) {
    NSString *line = [NSString stringWithFormat:@"HawkEnterGuard: %@\n", message ?: @""];
    fprintf(stderr, "%s", line.UTF8String);
    fflush(stderr);
}

static NSRegularExpression *CompilePattern(NSString *pattern) {
    return [NSRegularExpression regularExpressionWithPattern:pattern
                                                     options:NSRegularExpressionCaseInsensitive
                                                       error:nil];
}

static void AddBlockingPattern(NSMutableArray<NSRegularExpression *> *patterns,
                               NSMutableArray<NSString *> *reasons,
                               NSString *pattern,
                               NSString *reason) {
    NSRegularExpression *compiled = CompilePattern(pattern);
    if (!compiled) {
        return;
    }
    [patterns addObject:compiled];
    [reasons addObject:reason];
}

static void SendKey(CGKeyCode keyCode, CGEventFlags flags) {
    CGEventSourceRef source = CGEventSourceCreate(kCGEventSourceStateCombinedSessionState);
    CGEventRef down = CGEventCreateKeyboardEvent(source, keyCode, true);
    CGEventRef up = CGEventCreateKeyboardEvent(source, keyCode, false);
    CGEventSetFlags(down, flags);
    CGEventSetFlags(up, flags);
    CGEventPost(kCGHIDEventTap, down);
    CGEventPost(kCGHIDEventTap, up);
    if (down) CFRelease(down);
    if (up) CFRelease(up);
    if (source) CFRelease(source);
}

@implementation HawkEnterGuard

- (instancetype)initWithArguments:(NSArray<NSString *> *)arguments {
    self = [super init];
    if (!self) {
        return nil;
    }
    NSString *defaultConfig = [@"~/.hawk/desktop-guard.json" stringByExpandingTildeInPath];
    self.configPath = ArgumentValue(arguments, @"--config", defaultConfig);
    self.applicationName = ArgumentValue(arguments, @"--application", @"Claude Desktop");
    self.desktopAppName = ArgumentValue(arguments, @"--desktop-app", @"Claude");
    NSMutableArray<NSRegularExpression *> *patterns = [NSMutableArray array];
    NSMutableArray<NSString *> *reasons = [NSMutableArray array];
    AddBlockingPattern(patterns, reasons, @"\\b(api\\s*key|ap[io]\\s*key|secret|token|credential)\\b.{0,80}\\b([a-z0-9_-]{8,}|sk-[a-z0-9_-]{8,})\\b", @"local_api_key_pattern");
    AddBlockingPattern(patterns, reasons, @"\\b[A-Z0-9_]*(?:API[_-]?KEY|ACCESS[_-]?TOKEN|SECRET|PRIVATE[_-]?KEY|AUTH[_-]?TOKEN|BEARER[_-]?TOKEN)\\b\\s*[:=]\\s*['\\\"]?[A-Za-z0-9_\\-./+=]{8,}", @"high_confidence_secret_pattern");
    AddBlockingPattern(patterns, reasons, @"\\bAuthorization\\s*:\\s*Bearer\\s+[A-Za-z0-9_\\-./+=]{12,}", @"high_confidence_secret_pattern");
    AddBlockingPattern(patterns, reasons, @"\\b(?:sk|pk|ghp|github_pat|xox[baprs]|AIza)[A-Za-z0-9_\\-]{10,}\\b", @"high_confidence_secret_pattern");
    AddBlockingPattern(patterns, reasons, @"-----BEGIN [A-Z ]*PRIVATE KEY-----", @"high_confidence_secret_pattern");
    AddBlockingPattern(patterns, reasons, @"\\b(?:token|secret|password|passwd|pwd)\\b\\s*[:=]\\s*['\\\"]?[A-Za-z0-9_\\-./+=]{8,}", @"high_confidence_secret_pattern");
    AddBlockingPattern(patterns, reasons, @"\\bignore\\b[^\\n\\r]{0,32}\\binstructions?\\b", @"prompt_injection_pattern");
    AddBlockingPattern(patterns, reasons, @"\\b(?:reveal|show)\\b[^\\n\\r]{0,48}\\b(?:system|hidden)\\s*(?:prompt|instructions?)\\b", @"prompt_injection_pattern");
    AddBlockingPattern(patterns, reasons, @"\\b(?:copy|paste)\\b[^\\n\\r]{0,80}\\b(?:prompt|instructions?|system)\\b", @"prompt_injection_pattern");
    AddBlockingPattern(patterns, reasons, @"\\b(?:decompose|break(?:\\s+down)?|split)\\b[^\\n\\r]{0,80}\\b(?:prompt|request|payload|instructions?)\\b[^\\n\\r]{0,80}\\b(?:into|as)\\b[^\\n\\r]{0,40}\\b(?:steps?|parts?|chunks?)\\b", @"prompt_decomposition_pattern");
    AddBlockingPattern(patterns, reasons, @"\\b(?:step[\\s-]?by[\\s-]?step|one\\s+step\\s+at\\s+a\\s+time)\\b[^\\n\\r]{0,120}\\b(?:bypass|evade|avoid|circumvent|sidestep)\\b[^\\n\\r]{0,48}\\b(?:policy|guard(?:rail)?s?|filter|detection|safety)\\b", @"prompt_decomposition_pattern");
    AddBlockingPattern(patterns, reasons, @"\\b(?:rephrase|rewrite)\\b[^\\n\\r]{0,80}\\b(?:forbidden|blocked|restricted)\\b[^\\n\\r]{0,80}\\b(?:into|as)\\b[^\\n\\r]{0,40}\\b(?:harmless|safe)\\b[^\\n\\r]{0,60}\\b(?:steps?|parts?)\\b", @"prompt_decomposition_pattern");
    AddBlockingPattern(patterns, reasons, @"(?<!\\d)784-?\\d{4}-?\\d{7}-?\\d(?!\\d)", @"uae_sensitive_identifier");
    AddBlockingPattern(patterns, reasons, @"\\b(?:emirates\\s*id|uae\\s*(?:id|national\\s*id)|eid)\\b[^\\n\\r]{0,40}\\b\\d{10,18}\\b", @"uae_sensitive_identifier");
    AddBlockingPattern(patterns, reasons, @"\\b(?:phone|mobile|contact|whatsapp|call|sms|mock\\s*number|number)\\b[^\\n\\r]{0,48}(?:\\+?\\d[\\d\\s().-]{8,}\\d)\\b", @"pii_phone_number");
    AddBlockingPattern(patterns, reasons, @"(?m)^\\s*(?:def\\s+\\w+\\s*\\(|async\\s+def\\s+\\w+\\s*\\(|class\\s+\\w+|from\\s+[\\w.]+\\s+import\\s+\\w+|import\\s+[\\w.]+|(?:const|let|var)\\s+\\w+\\s*=|function\\s+\\w+\\s*\\(|public\\s+(?:class|static|void)|private\\s+(?:class|static|void)|SELECT\\s+.+\\s+FROM\\s+\\w+)", @"source_code_snippet");
    self.blockingPatterns = patterns;
    self.blockingReasons = reasons;
    self.accessLogPattern = CompilePattern(@"\\b\\d{4}-\\d{2}-\\d{2}[ T]\\d{2}:\\d{2}:\\d{2}\\b[^\\n\\r]{0,40}\\b(?:INFO|WARN(?:ING)?|ERROR|DEBUG)\\b[^\\n\\r]{0,80}\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b[^\\n\\r]{0,80}\\\"(?:GET|POST|PUT|PATCH|DELETE|HEAD)\\s+/[^\\\"]*\\s+HTTP/\\d(?:\\.\\d)?\\\"");
    self.privateIpPattern = CompilePattern(@"\\b(?:10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})\\b");
    self.sensitiveLogPathPattern = CompilePattern(@"\\b/(?:admin|login|token|secret|backup|credentials?|keys?|api|wp-admin)\\b");
    self.lastBlockedHash = @"";
    self.lastBlockedAt = [NSDate distantPast];
    return self;
}

- (BOOL)shouldHandleEvent:(CGEventRef)event {
    int64_t keyCode = CGEventGetIntegerValueField(event, kCGKeyboardEventKeycode);
    if (keyCode != 36 && keyCode != 76) {
        return NO;
    }
    CGEventFlags flags = CGEventGetFlags(event);
    if ((flags & kCGEventFlagMaskCommand) || (flags & kCGEventFlagMaskControl) || (flags & kCGEventFlagMaskAlternate)) {
        return NO;
    }
    NSString *frontmost = NSWorkspace.sharedWorkspace.frontmostApplication.localizedName ?: @"";
    return [frontmost localizedCaseInsensitiveContainsString:self.desktopAppName]
        || [frontmost localizedCaseInsensitiveContainsString:@"Claude"];
}

- (BOOL)blockIfNeeded {
    AXUIElementRef focusedElement = [self focusedElement];
    if (!focusedElement) {
        return NO;
    }
    if (![self isEditableTextElement:focusedElement]) {
        CFRelease(focusedElement);
        return NO;
    }
    NSString *prompt = [self textFromElement:focusedElement];
    NSString *trimmed = [prompt stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSArray<NSString *> *reasonCodes = [self matchedReasonCodes:trimmed];
    if (trimmed.length == 0 || reasonCodes.count == 0) {
        CFRelease(focusedElement);
        return NO;
    }
    if ([self recentlyBlocked:trimmed]) {
        CFRelease(focusedElement);
        return YES;
    }
    [self rememberBlocked:trimmed];
    [self clearElement:focusedElement];
    CFRelease(focusedElement);
    [self reportInterceptedPrompt:trimmed];
    LogLine([NSString stringWithFormat:@"blocked Return for %@ (%@)", self.applicationName, [reasonCodes componentsJoinedByString:@","]]);
    ShowDialog(@"Hawk Desktop Guard: BLOCK", [NSString stringWithFormat:@"BLOCK for %@\n\n%@", self.applicationName, [reasonCodes componentsJoinedByString:@", "]]);
    return YES;
}

- (AXUIElementRef)focusedElement {
    AXUIElementRef systemWide = AXUIElementCreateSystemWide();
    CFTypeRef value = NULL;
    AXError result = AXUIElementCopyAttributeValue(systemWide, kAXFocusedUIElementAttribute, &value);
    if (systemWide) CFRelease(systemWide);
    if (result != kAXErrorSuccess || !value) {
        return NULL;
    }
    return (AXUIElementRef)value;
}

- (NSString *)textFromElement:(AXUIElementRef)element {
    CFTypeRef value = NULL;
    AXError result = AXUIElementCopyAttributeValue(element, kAXValueAttribute, &value);
    if (result != kAXErrorSuccess || !value) {
        return @"";
    }
    NSString *text = [(__bridge id)value isKindOfClass:NSString.class] ? [(__bridge NSString *)value copy] : @"";
    CFRelease(value);
    return text;
}

- (BOOL)isEditableTextElement:(AXUIElementRef)element {
    CFTypeRef roleValue = NULL;
    AXError result = AXUIElementCopyAttributeValue(element, kAXRoleAttribute, &roleValue);
    if (result != kAXErrorSuccess || !roleValue) {
        return NO;
    }
    NSString *role = [(__bridge id)roleValue isKindOfClass:NSString.class] ? (__bridge NSString *)roleValue : @"";
    BOOL editable = [role isEqualToString:@"AXTextArea"] || [role isEqualToString:@"AXTextField"] || [role isEqualToString:@"AXComboBox"];
    CFRelease(roleValue);
    return editable;
}

- (BOOL)clearElement:(AXUIElementRef)element {
    AXError result = AXUIElementSetAttributeValue(element, kAXValueAttribute, (__bridge CFTypeRef)@"");
    if (result == kAXErrorSuccess) {
        return YES;
    }
    SendKey(0, kCGEventFlagMaskCommand);
    SendKey(51, 0);
    return NO;
}

- (BOOL)regex:(NSRegularExpression *)regex matches:(NSString *)text {
    NSRange range = NSMakeRange(0, text.length);
    return [regex firstMatchInString:text options:0 range:range] != nil;
}

- (NSArray<NSString *> *)matchedReasonCodes:(NSString *)text {
    if (text.length == 0) {
        return @[];
    }
    NSMutableArray<NSString *> *reasons = [NSMutableArray array];
    for (NSUInteger index = 0; index < self.blockingPatterns.count; index++) {
        NSRegularExpression *pattern = self.blockingPatterns[index];
        if (![self regex:pattern matches:text]) {
            continue;
        }
        NSString *reason = self.blockingReasons[index];
        if (![reasons containsObject:reason]) {
            [reasons addObject:reason];
        }
    }
    if ([self matchesInternalAccessLogPattern:text] && ![reasons containsObject:@"local_terminal_log_pattern"]) {
        [reasons addObject:@"local_terminal_log_pattern"];
    }
    return reasons;
}

- (BOOL)matchesInternalAccessLogPattern:(NSString *)text {
    if (!self.accessLogPattern || !self.privateIpPattern || !self.sensitiveLogPathPattern) {
        return NO;
    }
    NSRange range = NSMakeRange(0, text.length);
    NSUInteger logCount = [self.accessLogPattern numberOfMatchesInString:text options:0 range:range];
    if (logCount < 2) {
        return NO;
    }
    return [self regex:self.privateIpPattern matches:text] || [self regex:self.sensitiveLogPathPattern matches:text];
}

- (BOOL)recentlyBlocked:(NSString *)text {
    NSString *digest = [NSString stringWithFormat:@"%lu", (unsigned long)text.hash];
    return [digest isEqualToString:self.lastBlockedHash] && fabs([self.lastBlockedAt timeIntervalSinceNow]) < 2.0;
}

- (void)rememberBlocked:(NSString *)text {
    self.lastBlockedHash = [NSString stringWithFormat:@"%lu", (unsigned long)text.hash];
    self.lastBlockedAt = [NSDate date];
}

- (void)reportInterceptedPrompt:(NSString *)text {
    NSString *executable = NSBundle.mainBundle.executablePath;
    NSString *macosDir = executable.stringByDeletingLastPathComponent;
    NSString *resourcesSrc = [[macosDir.stringByDeletingLastPathComponent stringByAppendingPathComponent:@"Resources"] stringByAppendingPathComponent:@"src"];
    NSMutableDictionary<NSString *, NSString *> *environment = [NSProcessInfo.processInfo.environment mutableCopy];
    environment[@"PYTHONPATH"] = resourcesSrc;

    NSTask *task = [[NSTask alloc] init];
    task.executableURL = [NSURL fileURLWithPath:@"/usr/bin/python3"];
    task.arguments = @[
        @"-m",
        @"hawk_desktop_guard",
        @"--config",
        self.configPath,
        @"--evaluate-stdin",
        @"--capture-method",
        @"macos_enter_intercept",
    ];
    task.environment = environment;
    // The prompt goes through a private pipe, never as a command-line argument: any local process can read another
    // process's arguments.
    NSPipe *input = [NSPipe pipe];
    task.standardInput = input;
    if (![task launchAndReturnError:nil]) {
        return;
    }
    NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data];
    NSFileHandle *writer = input.fileHandleForWriting;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        @try {
            [writer writeData:data];
        } @catch (NSException *exception) {
            // The helper exited before reading: nothing to report.
        }
        [writer closeFile];
    });
}

@end

static CGEventRef EventCallback(CGEventTapProxy proxy, CGEventType type, CGEventRef event, void *userInfo) {
    if (type != kCGEventKeyDown || userInfo == NULL) {
        return event;
    }
    HawkEnterGuard *guard = (__bridge HawkEnterGuard *)userInfo;
    if ([guard shouldHandleEvent:event] && [guard blockIfNeeded]) {
        return NULL;
    }
    return event;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSArray<NSString *> *arguments = NSProcessInfo.processInfo.arguments;
        // A helper that exits before reading its prompt must not take this process down with SIGPIPE.
        signal(SIGPIPE, SIG_IGN);
        HawkEnterGuard *guard = [[HawkEnterGuard alloc] initWithArguments:arguments];
        LogLine(@"starting native Return event tap");
        // Permission is an administrator/MDM decision. Never interrupt the user
        // with a recurring system prompt; the helper exits cleanly when absent.
        NSDictionary *options = @{(__bridge NSString *)kAXTrustedCheckOptionPrompt: @NO};
        AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options);

        CGEventMask mask = CGEventMaskBit(kCGEventKeyDown);
        CFMachPortRef eventTap = CGEventTapCreate(kCGSessionEventTap, kCGHeadInsertEventTap, kCGEventTapOptionDefault, mask, EventCallback, (__bridge void *)guard);
        if (!eventTap) {
            LogLine(@"failed to create event tap; Input Monitoring permission is required");
            ShowDialog(@"Hawk Desktop Guard", @"Input Monitoring permission is required for Enter-key blocking.");
            return 78;
        }
        LogLine(@"native Return event tap active");
        CFRunLoopSourceRef source = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, eventTap, 0);
        CFRunLoopAddSource(CFRunLoopGetCurrent(), source, kCFRunLoopCommonModes);
        CGEventTapEnable(eventTap, true);
        CFRunLoopRun();
        if (source) CFRelease(source);
        if (eventTap) CFRelease(eventTap);
    }
    return 0;
}
