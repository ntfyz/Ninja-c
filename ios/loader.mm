#import <Foundation/Foundation.h>
#import <Security/Security.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>

#ifndef LOCAL_AUTH_URL
#define LOCAL_AUTH_URL "https://test.ntfyz.xyz/ninja_ios_v2/api/v1/auth/login/"
#endif

namespace {

struct NinjaLoaderLoginResult {
    uint32_t success;
    uint32_t reserved;
    int64_t expires_at;
    int64_t remaining_seconds;
    uint64_t generation;
    char message[64];
};

using InvalidationCallback = void (*)(uint64_t generation);

std::atomic<bool> g_session_valid{false};
std::atomic<int64_t> g_session_expires_at{0};
std::atomic<uint64_t> g_generation_counter{1};
std::atomic<uint64_t> g_active_generation{0};
std::atomic<InvalidationCallback> g_invalidation_callback{nullptr};
void *g_ninja_handle = nullptr;
void *g_guard_handle = nullptr;

NSString *const kDeviceAccount = @"ninja.local.device-id";
NSString *const kCredentialAccount = @"ninja.local.credentials";
NSString *const kKeychainService = @"com.ninja.local.auth";

void CopyMessage(char destination[64], NSString *message) {
    const char *source = message.length ? message.UTF8String : "internal_error";
    std::snprintf(destination, 64, "%s", source ?: "internal_error");
}

NSData *KeychainRead(NSString *account) {
    NSDictionary *query = @{
        (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService : kKeychainService,
        (__bridge id)kSecAttrAccount : account,
        (__bridge id)kSecReturnData : @YES,
        (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne,
    };
    CFTypeRef result = nullptr;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status != errSecSuccess || result == nullptr) {
        return nil;
    }
    return CFBridgingRelease(result);
}

bool KeychainWrite(NSString *account, NSData *data) {
    NSDictionary *identity = @{
        (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService : kKeychainService,
        (__bridge id)kSecAttrAccount : account,
    };
    NSDictionary *updates = @{(__bridge id)kSecValueData : data};
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)identity,
                                    (__bridge CFDictionaryRef)updates);
    if (status == errSecItemNotFound) {
        NSMutableDictionary *item = [identity mutableCopy];
        item[(__bridge id)kSecValueData] = data;
        item[(__bridge id)kSecAttrAccessible] =
            (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
        status = SecItemAdd((__bridge CFDictionaryRef)item, nullptr);
    }
    return status == errSecSuccess;
}

void KeychainDelete(NSString *account) {
    NSDictionary *query = @{
        (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService : kKeychainService,
        (__bridge id)kSecAttrAccount : account,
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
}

NSString *DeviceIdentifier(uint32_t *status_out) {
    NSData *saved = KeychainRead(kDeviceAccount);
    if (saved.length == 64) {
        NSString *value = [[NSString alloc] initWithData:saved encoding:NSASCIIStringEncoding];
        if (value.length == 64) {
            if (status_out) {
                *status_out = 1;
            }
            return value;
        }
    }

    uint8_t random_bytes[32] = {};
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(random_bytes), random_bytes) != errSecSuccess) {
        if (status_out) {
            *status_out = 0;
        }
        return nil;
    }
    static const char hex[] = "0123456789abcdef";
    char encoded[65] = {};
    for (size_t index = 0; index < sizeof(random_bytes); ++index) {
        encoded[index * 2] = hex[random_bytes[index] >> 4];
        encoded[index * 2 + 1] = hex[random_bytes[index] & 0x0f];
    }
    NSData *data = [NSData dataWithBytes:encoded length:64];
    if (!KeychainWrite(kDeviceAccount, data)) {
        if (status_out) {
            *status_out = 0;
        }
        return nil;
    }
    if (status_out) {
        *status_out = 2;
    }
    return [NSString stringWithUTF8String:encoded];
}

NSDictionary *PostLogin(NSString *username, NSString *password, NSString *device_id,
                        NSString **error_message) {
    NSURL *url = [NSURL URLWithString:[NSString stringWithUTF8String:LOCAL_AUTH_URL]];
    if (!url) {
        if (error_message) {
            *error_message = @"invalid_local_auth_url";
        }
        return nil;
    }

    NSDictionary *payload = @{
        @"username" : username ?: @"",
        @"password" : password ?: @"",
        @"device_id" : device_id ?: @"",
    };
    NSError *json_error = nil;
    NSData *body = [NSJSONSerialization dataWithJSONObject:payload options:0 error:&json_error];
    if (!body) {
        if (error_message) {
            *error_message = @"malformed_credentials";
        }
        return nil;
    }

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"POST";
    request.HTTPBody = body;
    request.timeoutInterval = 15.0;
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];

    NSURLSessionConfiguration *configuration =
        [NSURLSessionConfiguration ephemeralSessionConfiguration];
    configuration.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration];
    dispatch_semaphore_t completed = dispatch_semaphore_create(0);
    __block NSData *response_data = nil;
    __block NSError *response_error = nil;
    __block NSInteger status_code = 0;
    NSURLSessionDataTask *task =
        [session dataTaskWithRequest:request
                  completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                    response_data = data;
                    response_error = error;
                    if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
                        status_code = ((NSHTTPURLResponse *)response).statusCode;
                    }
                    dispatch_semaphore_signal(completed);
                  }];
    [task resume];
    long wait_result = dispatch_semaphore_wait(
        completed, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(16 * NSEC_PER_SEC)));
    if (wait_result != 0) {
        [task cancel];
        if (error_message) {
            *error_message = @"network_timeout";
        }
        return nil;
    }
    if (response_error || !response_data.length) {
        if (error_message) {
            *error_message = @"network_or_protocol_error";
        }
        return nil;
    }

    id value = [NSJSONSerialization JSONObjectWithData:response_data options:0 error:&json_error];
    if (![value isKindOfClass:[NSDictionary class]]) {
        if (error_message) {
            *error_message = @"network_or_protocol_error";
        }
        return nil;
    }
    NSDictionary *response = (NSDictionary *)value;
    if (status_code < 200 || status_code >= 300) {
        NSString *code = [response[@"code"] isKindOfClass:[NSString class]] ? response[@"code"] : nil;
        if (error_message) {
            *error_message = code ?: @"login_rejected";
        }
        return response;
    }
    return response;
}

void SaveCredentials(NSString *username, NSString *password) {
    NSDictionary *credentials = @{ @"username" : username, @"password" : password };
    NSData *data = [NSJSONSerialization dataWithJSONObject:credentials options:0 error:nil];
    if (data) {
        KeychainWrite(kCredentialAccount, data);
    }
}

void InvalidateSession(bool notify) {
    const bool was_valid = g_session_valid.exchange(false);
    const uint64_t generation = g_active_generation.exchange(0);
    g_session_expires_at.store(0);
    if (notify && was_valid && generation != 0) {
        InvalidationCallback callback = g_invalidation_callback.load();
        if (callback) {
            callback(generation);
        }
    }
}

}  // namespace

extern "C" bool ninja_loader_device_id(char *output, uint32_t capacity,
                                         uint32_t *status_out) {
    @autoreleasepool {
        if (!output || capacity < 65) {
            if (status_out) {
                *status_out = 0;
            }
            return false;
        }
        NSString *identifier = DeviceIdentifier(status_out);
        if (identifier.length != 64) {
            output[0] = '\0';
            return false;
        }
        std::snprintf(output, capacity, "%s", identifier.UTF8String);
        return true;
    }
}

extern "C" void ninja_loader_login(const char *username_utf8, const char *password_utf8,
                                     NinjaLoaderLoginResult *result) {
    if (!result) {
        return;
    }
    std::memset(result, 0, sizeof(*result));
    @autoreleasepool {
        NSString *username = username_utf8 ? [NSString stringWithUTF8String:username_utf8] : @"";
        NSString *password = password_utf8 ? [NSString stringWithUTF8String:password_utf8] : @"";
        if (!username.length || !password.length) {
            CopyMessage(result->message, @"malformed_credentials");
            return;
        }

        uint32_t device_status = 0;
        NSString *device_id = DeviceIdentifier(&device_status);
        if (!device_id.length) {
            CopyMessage(result->message, @"device_id_unavailable");
            return;
        }

        NSString *error_message = nil;
        NSDictionary *response = PostLogin(username, password, device_id, &error_message);
        const bool ok = [response[@"ok"] boolValue];
        NSString *scope = [response[@"scope"] isKindOfClass:[NSString class]]
                              ? response[@"scope"]
                              : @"";
        if (!ok || ![scope isEqualToString:@"authenticated"]) {
            NSString *code = [response[@"code"] isKindOfClass:[NSString class]]
                                 ? response[@"code"]
                                 : error_message;
            CopyMessage(result->message, code ?: @"login_rejected");
            InvalidateSession(false);
            return;
        }

        const int64_t now = (int64_t)[NSDate date].timeIntervalSince1970;
        int64_t expires_at = [response[@"expires_at"] longLongValue];
        int64_t remaining = [response[@"remaining_seconds"] longLongValue];
        if (expires_at <= now) {
            expires_at = now + (remaining > 0 ? remaining : 86400);
        }
        if (remaining <= 0) {
            remaining = expires_at - now;
        }
        uint64_t generation = [response[@"generation"] unsignedLongLongValue];
        if (generation == 0) {
            generation = g_generation_counter.fetch_add(1);
            if (generation == 0) {
                generation = g_generation_counter.fetch_add(1);
            }
        }

        g_session_expires_at.store(expires_at);
        g_active_generation.store(generation);
        g_session_valid.store(true);
        SaveCredentials(username, password);

        result->success = 1;
        result->expires_at = expires_at;
        result->remaining_seconds = remaining;
        result->generation = generation;
        CopyMessage(result->message, @"ok");
    }
}

extern "C" void ninja_loader_set_invalidation_callback(InvalidationCallback callback) {
    g_invalidation_callback.store(callback);
}

extern "C" bool ninja_loader_session_valid() {
    @autoreleasepool {
        if (!g_session_valid.load()) {
            return false;
        }
        const int64_t now = (int64_t)[NSDate date].timeIntervalSince1970;
        if (g_session_expires_at.load() <= now) {
            InvalidateSession(true);
            return false;
        }
        return true;
    }
}

extern "C" void ninja_loader_logout() {
    InvalidateSession(true);
    KeychainDelete(kCredentialAccount);
}

// The downloaded WASM planner is not present in the supplied IPA. These ABI-compatible
// stubs keep the native Ninja UI stable while leaving module-only autoplay disabled.
extern "C" bool ninja_autoplay_module_prepare(void *, ...) { return false; }
extern "C" bool ninja_autoplay_module_run_fast(void *, ...) { return false; }
extern "C" bool ninja_autoplay_module_run_slow_frame(void *, ...) { return false; }
extern "C" bool ninja_autoplay_module_authorized() { return false; }
extern "C" void ninja_autoplay_module_reset() {}

namespace {

void StartOriginalGuard() {
    @autoreleasepool {
        NSString *path = [[[NSBundle mainBundle] bundlePath]
            stringByAppendingPathComponent:@"Frameworks/guard.framework/guard"];
        g_guard_handle = dlopen(path.fileSystemRepresentation, RTLD_NOW | RTLD_GLOBAL);
    }
}

void RestoreSession(void *) {
    @autoreleasepool {
        NSData *data = KeychainRead(kCredentialAccount);
        NSDictionary *credentials = data
            ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil]
            : nil;
        if (![credentials isKindOfClass:[NSDictionary class]]) {
            return;
        }
        NSString *username = credentials[@"username"];
        NSString *password = credentials[@"password"];
        if (![username isKindOfClass:[NSString class]] ||
            ![password isKindOfClass:[NSString class]]) {
            return;
        }
        NinjaLoaderLoginResult ignored{};
        ninja_loader_login(username.UTF8String, password.UTF8String, &ignored);
    }
}

__attribute__((constructor)) void LoaderEntry() {
    // The original loader supplies the Appdome compatibility startup and loads Ninja.
    // Keep it intact under a distinct Mach-O install name; this framework only owns auth.
    StartOriginalGuard();
    dispatch_async_f(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), nullptr, RestoreSession);
}

}  // namespace
