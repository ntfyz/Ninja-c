#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <UIKit/UIKit.h>

#ifndef FLUORITE_AUTH_URL
#define FLUORITE_AUTH_URL "https://test.ntfyz.xyz/ninja_ios_v2/api/v1/auth/login/"
#endif

static NSString *const kFluoriteDeviceService = @"com.appdome.libloader.keyguard";
static NSString *const kFluoriteDeviceAccount = @"device-id";
static UIWindow *gFluoriteGuardWindow;
static id gFluoriteActivationObserver;

static NSString *FluoriteDeviceID(void) {
    NSDictionary *query = @{
        (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService : kFluoriteDeviceService,
        (__bridge id)kSecAttrAccount : kFluoriteDeviceAccount,
        (__bridge id)kSecReturnData : @YES,
        (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne,
    };
    CFTypeRef result = NULL;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)query, &result) == errSecSuccess) {
        NSData *data = CFBridgingRelease(result);
        NSString *value = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (value.length == 64) return value;
    }

    uint8_t randomBytes[32] = {0};
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(randomBytes), randomBytes) != errSecSuccess) {
        NSString *fallback = NSUUID.UUID.UUIDString.lowercaseString;
        fallback = [fallback stringByReplacingOccurrencesOfString:@"-" withString:@""];
        fallback = [fallback stringByAppendingString:fallback];
        return [fallback substringToIndex:64];
    }
    NSMutableString *deviceID = [NSMutableString stringWithCapacity:64];
    for (NSUInteger index = 0; index < sizeof(randomBytes); ++index) {
        [deviceID appendFormat:@"%02x", randomBytes[index]];
    }
    NSData *encoded = [deviceID dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableDictionary *writeQuery = [query mutableCopy];
    [writeQuery removeObjectForKey:(__bridge id)kSecReturnData];
    [writeQuery removeObjectForKey:(__bridge id)kSecMatchLimit];
    writeQuery[(__bridge id)kSecValueData] = encoded;
    SecItemDelete((__bridge CFDictionaryRef)query);
    SecItemAdd((__bridge CFDictionaryRef)writeQuery, NULL);
    return deviceID;
}

static void FluoriteDismissGuard(void) {
    UIWindow *guard = gFluoriteGuardWindow;
    guard.hidden = YES;
    gFluoriteGuardWindow = nil;
    for (UIWindow *window in UIApplication.sharedApplication.windows) {
        if (window != guard && !window.hidden) {
            [window makeKeyWindow];
            break;
        }
    }
}

@interface FluoriteKeyGuardController : UIViewController
@property(nonatomic, strong) UITextField *keyField;
@property(nonatomic, strong) UILabel *statusLabel;
@property(nonatomic, strong) UIButton *loginButton;
@end

@implementation FluoriteKeyGuardController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithRed:0.035 green:0.043 blue:0.065 alpha:1.0];

    UIView *card = [UIView new];
    card.translatesAutoresizingMaskIntoConstraints = NO;
    card.backgroundColor = [UIColor colorWithRed:0.075 green:0.090 blue:0.130 alpha:1.0];
    card.layer.cornerRadius = 18.0;
    card.layer.borderWidth = 1.0;
    card.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.10].CGColor;

    UILabel *title = [UILabel new];
    title.translatesAutoresizingMaskIntoConstraints = NO;
    title.text = @"Fluorite Key Login";
    title.textColor = UIColor.whiteColor;
    title.font = [UIFont boldSystemFontOfSize:24.0];
    title.textAlignment = NSTextAlignmentCenter;

    UILabel *subtitle = [UILabel new];
    subtitle.translatesAutoresizingMaskIntoConstraints = NO;
    subtitle.text = @"Paste your key, then tap Login";
    subtitle.textColor = [UIColor colorWithWhite:0.75 alpha:1.0];
    subtitle.font = [UIFont systemFontOfSize:14.0];
    subtitle.textAlignment = NSTextAlignmentCenter;

    self.keyField = [UITextField new];
    self.keyField.translatesAutoresizingMaskIntoConstraints = NO;
    self.keyField.text = @"1";
    self.keyField.placeholder = @"Key";
    self.keyField.textColor = UIColor.whiteColor;
    self.keyField.tintColor = [UIColor colorWithRed:0.34 green:0.73 blue:1.0 alpha:1.0];
    self.keyField.backgroundColor = [UIColor colorWithWhite:0.02 alpha:0.42];
    self.keyField.layer.cornerRadius = 11.0;
    self.keyField.layer.borderWidth = 1.0;
    self.keyField.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.12].CGColor;
    self.keyField.textAlignment = NSTextAlignmentCenter;
    self.keyField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    self.keyField.autocorrectionType = UITextAutocorrectionTypeNo;
    self.keyField.returnKeyType = UIReturnKeyGo;
    [self.keyField addTarget:self action:@selector(loginPressed) forControlEvents:UIControlEventEditingDidEndOnExit];

    self.loginButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.loginButton.translatesAutoresizingMaskIntoConstraints = NO;
    self.loginButton.backgroundColor = [UIColor colorWithRed:0.10 green:0.52 blue:0.94 alpha:1.0];
    self.loginButton.layer.cornerRadius = 11.0;
    self.loginButton.titleLabel.font = [UIFont boldSystemFontOfSize:17.0];
    [self.loginButton setTitle:@"Login" forState:UIControlStateNormal];
    [self.loginButton setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [self.loginButton addTarget:self action:@selector(loginPressed) forControlEvents:UIControlEventTouchUpInside];

    self.statusLabel = [UILabel new];
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.statusLabel.text = @"Key mặc định: 1";
    self.statusLabel.textColor = [UIColor colorWithWhite:0.68 alpha:1.0];
    self.statusLabel.font = [UIFont systemFontOfSize:13.0];
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.numberOfLines = 2;

    [self.view addSubview:card];
    [card addSubview:title];
    [card addSubview:subtitle];
    [card addSubview:self.keyField];
    [card addSubview:self.loginButton];
    [card addSubview:self.statusLabel];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [card.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [card.centerYAnchor constraintEqualToAnchor:safe.centerYAnchor],
        [card.widthAnchor constraintLessThanOrEqualToConstant:430.0],
        [card.widthAnchor constraintEqualToAnchor:safe.widthAnchor multiplier:0.62],
        [title.topAnchor constraintEqualToAnchor:card.topAnchor constant:26.0],
        [title.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:24.0],
        [title.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-24.0],
        [subtitle.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:7.0],
        [subtitle.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:24.0],
        [subtitle.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-24.0],
        [self.keyField.topAnchor constraintEqualToAnchor:subtitle.bottomAnchor constant:22.0],
        [self.keyField.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:28.0],
        [self.keyField.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-28.0],
        [self.keyField.heightAnchor constraintEqualToConstant:46.0],
        [self.loginButton.topAnchor constraintEqualToAnchor:self.keyField.bottomAnchor constant:14.0],
        [self.loginButton.leadingAnchor constraintEqualToAnchor:self.keyField.leadingAnchor],
        [self.loginButton.trailingAnchor constraintEqualToAnchor:self.keyField.trailingAnchor],
        [self.loginButton.heightAnchor constraintEqualToConstant:46.0],
        [self.statusLabel.topAnchor constraintEqualToAnchor:self.loginButton.bottomAnchor constant:15.0],
        [self.statusLabel.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:20.0],
        [self.statusLabel.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-20.0],
        [self.statusLabel.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-22.0],
    ]];
}

- (void)loginPressed {
    NSString *key = [self.keyField.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (!key.length) {
        self.statusLabel.text = @"Nhập key trước khi đăng nhập";
        self.statusLabel.textColor = [UIColor colorWithRed:1.0 green:0.45 blue:0.45 alpha:1.0];
        return;
    }
    self.loginButton.enabled = NO;
    self.keyField.enabled = NO;
    self.statusLabel.text = @"Đang xác thực…";
    self.statusLabel.textColor = [UIColor colorWithWhite:0.78 alpha:1.0];

    NSDictionary *body = @{
        @"username" : key,
        @"password" : key,
        @"device_id" : FluoriteDeviceID(),
    };
    NSError *jsonError = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:body options:0 error:&jsonError];
    NSURL *url = [NSURL URLWithString:@FLUORITE_AUTH_URL];
    if (!data || !url) {
        [self finishWithSuccess:NO message:@"Cấu hình login không hợp lệ"];
        return;
    }
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"POST";
    request.HTTPBody = data;
    request.timeoutInterval = 20.0;
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [request setValue:@"Fluorite-KeyGuard/1.0" forHTTPHeaderField:@"User-Agent"];

    __weak FluoriteKeyGuardController *weakSelf = self;
    NSURLSessionDataTask *task = [NSURLSession.sharedSession dataTaskWithRequest:request
        completionHandler:^(NSData *responseData, NSURLResponse *response, NSError *error) {
        NSDictionary *payload = nil;
        if (responseData.length) {
            id object = [NSJSONSerialization JSONObjectWithData:responseData options:0 error:nil];
            if ([object isKindOfClass:NSDictionary.class]) payload = object;
        }
        NSInteger status = [(NSHTTPURLResponse *)response statusCode];
        BOOL ok = status == 200 && [payload[@"ok"] boolValue];
        NSString *message = ok ? @"Login thành công" : payload[@"message"];
        if (![message isKindOfClass:NSString.class] || !message.length) message = payload[@"code"];
        if (![message isKindOfClass:NSString.class] || !message.length) message = error.localizedDescription;
        if (!message.length) message = [NSString stringWithFormat:@"Login lỗi (%ld)", (long)status];
        dispatch_async(dispatch_get_main_queue(), ^{
            [weakSelf finishWithSuccess:ok message:message];
        });
    }];
    [task resume];
}

- (void)finishWithSuccess:(BOOL)success message:(NSString *)message {
    self.statusLabel.text = message;
    if (success) {
        self.statusLabel.textColor = [UIColor colorWithRed:0.28 green:0.92 blue:0.55 alpha:1.0];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.65 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ FluoriteDismissGuard(); });
    } else {
        self.statusLabel.textColor = [UIColor colorWithRed:1.0 green:0.45 blue:0.45 alpha:1.0];
        self.loginButton.enabled = YES;
        self.keyField.enabled = YES;
    }
}

- (BOOL)prefersStatusBarHidden { return YES; }
@end

static UIWindowScene *FluoriteForegroundScene(void) API_AVAILABLE(ios(13.0)) {
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if ([scene isKindOfClass:UIWindowScene.class] &&
            scene.activationState == UISceneActivationStateForegroundActive) {
            return (UIWindowScene *)scene;
        }
    }
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if ([scene isKindOfClass:UIWindowScene.class]) return (UIWindowScene *)scene;
    }
    return nil;
}

static void FluoriteShowGuard(void) {
    if (gFluoriteGuardWindow) return;
    UIWindow *window = nil;
    if (@available(iOS 13.0, *)) {
        UIWindowScene *scene = FluoriteForegroundScene();
        if (scene) window = [[UIWindow alloc] initWithWindowScene:scene];
    }
    if (!window) window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    window.windowLevel = UIWindowLevelAlert + 100.0;
    window.backgroundColor = UIColor.blackColor;
    window.rootViewController = [FluoriteKeyGuardController new];
    gFluoriteGuardWindow = window;
    [window makeKeyAndVisible];
}

__attribute__((constructor)) static void FluoriteKeyGuardStart(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        gFluoriteActivationObserver = [NSNotificationCenter.defaultCenter
            addObserverForName:UIApplicationDidBecomeActiveNotification
            object:nil queue:NSOperationQueue.mainQueue usingBlock:^(__unused NSNotification *note) {
                FluoriteShowGuard();
            }];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ FluoriteShowGuard(); });
    });
}
