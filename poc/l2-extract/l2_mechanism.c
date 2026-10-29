/* ==========================================================================
 * L2 惰性回填 —— 机制验证 (self-contained, 真 x64)。
 *
 * 证明"函数体默认是垃圾, 被调用时才回填真码"这一核心机制 (抗内存 dump):
 *   1. 取目标函数边界 (RtlLookupFunctionEntry 读自身 .pdata)。
 *   2. 把整段函数体存进加密侧表, 原位覆盖成 0xCC (int3) —— 此刻 dump 拿到的是垃圾。
 *   3. 装 VEH: 命中该函数区间的 int3 → 从侧表解密回填真码 → 把 RIP 拨回函数入口 →
 *      CONTINUE_EXECUTION 重新执行真码。
 *   4. 调用前打印函数首字节=全 CC(垃圾); 调用得到正确结果; 调用后首字节=原码。
 *
 * 对应 app-hardening L2 "某类被用到才回填", 这里是 native 版 (VEH/int3 代替 ClassLoader 钩子)。
 * 诚实: 这是机制证明; 集成进 L1 packer(改字节 + 内嵌本 runtime) 是后续部署步。
 * ========================================================================== */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

/* 目标被保护函数: 有点计算, 别被内联。*/
#pragma optimize("", off)
__declspec(noinline) int secret(int x) {
    int r = x;
    for (int i = 0; i < 5; i++) r = r * 3 + 7;   /* 确定性算法, 便于对拍 */
    return r ^ 0x5A5A;
}
#pragma optimize("", on)

/* ---- 侧表: 原函数字节(此处简化为异或"加密")+ 位置信息 ---- */
static uint8_t  g_stash[4096];
static SIZE_T   g_len   = 0;
static uint8_t *g_begin = NULL;      /* 函数运行时地址 */
static int      g_filled = 0;
#define STASH_XOR 0xA7

/* VEH: 命中被抽函数区间的 int3 → 回填 → 拨回入口重执行 */
static LONG CALLBACK veh(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;
    uint8_t *addr = (uint8_t *)ep->ExceptionRecord->ExceptionAddress;
    if (addr < g_begin || addr >= g_begin + g_len)
        return EXCEPTION_CONTINUE_SEARCH;          /* 不是我们的桩 */

    DWORD old;
    VirtualProtect(g_begin, g_len, PAGE_EXECUTE_READWRITE, &old);
    for (SIZE_T i = 0; i < g_len; i++)             /* 解密回填 */
        g_begin[i] = g_stash[i] ^ STASH_XOR;
    VirtualProtect(g_begin, g_len, old, &old);
    FlushInstructionCache(GetCurrentProcess(), g_begin, g_len);
    g_filled = 1;
    ep->ContextRecord->Rip = (DWORD64)g_begin;     /* 从函数入口重新执行真码 */
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void dump_head(const char *tag) {
    printf("  [%s] %p: ", tag, g_begin);
    for (int i = 0; i < 12; i++) printf("%02x ", g_begin[i]);
    int allcc = 1; for (SIZE_T i = 0; i < g_len; i++) if (g_begin[i] != 0xCC) { allcc = 0; break; }
    printf(" (%s)\n", allcc ? "全CC=垃圾" : "含真码");
}

int main(void) {
    /* 期望值: 先算好正确结果 (此时函数还是真码)。volatile 防 /O2 折叠两次调用。*/
    volatile int in = 10;
    int expect = secret(in);

    /* 1) 取函数边界 (.pdata) */
    DWORD64 imgbase = 0;
    PRUNTIME_FUNCTION rf = RtlLookupFunctionEntry((DWORD64)&secret, &imgbase, NULL);
    if (!rf) { printf("no .pdata entry for secret\n"); return 2; }
    g_begin = (uint8_t *)(imgbase + rf->BeginAddress);
    g_len   = rf->EndAddress - rf->BeginAddress;
    if (g_len > sizeof(g_stash)) { printf("func too big\n"); return 2; }
    printf("L2 机制验证: secret @ %p, len=%llu\n", g_begin, (unsigned long long)g_len);

    /* 2) 抽取: 存进侧表(异或加密) + 原位覆盖成 int3 */
    DWORD old;
    VirtualProtect(g_begin, g_len, PAGE_EXECUTE_READWRITE, &old);
    for (SIZE_T i = 0; i < g_len; i++) { g_stash[i] = g_begin[i] ^ STASH_XOR; g_begin[i] = 0xCC; }
    VirtualProtect(g_begin, g_len, old, &old);
    FlushInstructionCache(GetCurrentProcess(), g_begin, g_len);

    printf("[抽取后 · 模拟此刻内存 dump]\n");
    dump_head("stub");

    /* 3) 装 VEH */
    PVOID h = AddVectoredExceptionHandler(1, veh);

    /* 4) 调用 → 触发回填 → 得正确结果 */
    int got = secret(in);
    printf("[调用后]\n");
    dump_head("restored");
    printf("  secret(10) = %d, expect = %d, filled=%d  => %s\n",
           got, expect, g_filled, (got == expect && g_filled) ? "PASS" : "FAIL");

    RemoveVectoredExceptionHandler(h);
    return (got == expect && g_filled) ? 0 : 1;
}
