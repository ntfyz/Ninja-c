// Offline key-1 auto-pass shim. It deliberately has no constructor, UI, or network path.
// Loading this dylib leaves Fluorite's original libloader startup and menu untouched.

extern "C" __attribute__((used, visibility("default")))
char fluorite_auto_key[] = "1";

extern "C" __attribute__((used, visibility("default")))
char fluorite_auth_mode[] = "offline-auto-pass";
