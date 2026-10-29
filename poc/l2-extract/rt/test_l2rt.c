/* 进程内验证可嵌入 L2 运行时 (l2rt.asm): 多函数抽取(int3) + 自解析 + VEH 回填。*/
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

extern void l2_install(void *table, uint64_t image_base);

#define STASH_XOR 0xA7

#pragma optimize("", off)
__declspec(noinline) int secret1(int x) { int r = x; for (int i=0;i<5;i++) r = r*3+7; return r ^ 0x5A5A; }
__declspec(noinline) int secret2(int x) { int r = x; for (int i=0;i<4;i++) r = r*7-3; return r + 0x1234; }
#pragma optimize("", on)

static uint8_t g_table[8192];

typedef int (*fn_t)(int);

static SIZE_T func_len(void *f, uint64_t base) {
    uint64_t ib = 0;
    PRUNTIME_FUNCTION rf = RtlLookupFunctionEntry((DWORD64)f, &ib, NULL);
    return rf ? (rf->EndAddress - rf->BeginAddress) : 0;
}

int main(void) {
    uint64_t base = (uint64_t)GetModuleHandleW(NULL);
    volatile int in1 = 3, in2 = 4;
    int e1 = secret1(in1), e2 = secret2(in2);   /* 抽取前算好期望 */

    fn_t fns[2] = { secret1, secret2 };
    int n = 2;

    /* 表头: count */
    *(uint64_t *)(g_table + 0) = n;
    SIZE_T ent_off = 8;
    SIZE_T stash_off = 8 + n * 24;              /* 密文区起点 */

    for (int i = 0; i < n; i++) {
        uint8_t *f = (uint8_t *)fns[i];
        SIZE_T len = func_len(f, base);
        uint64_t rva = (uint64_t)f - base;
        /* entry: rva, len, stash_off */
        *(uint64_t *)(g_table + ent_off + 0)  = rva;
        *(uint64_t *)(g_table + ent_off + 8)  = len;
        *(uint64_t *)(g_table + ent_off + 16) = stash_off;
        ent_off += 24;
        /* 抽取: 存密文 + 原位覆盖 int3 */
        DWORD old;
        VirtualProtect(f, len, PAGE_EXECUTE_READWRITE, &old);
        for (SIZE_T k = 0; k < len; k++) { g_table[stash_off + k] = f[k] ^ STASH_XOR; f[k] = 0xCC; }
        VirtualProtect(f, len, old, &old);
        FlushInstructionCache(GetCurrentProcess(), f, len);
        stash_off += len;
        printf("extract: fn%d rva=0x%llx len=%llu  首字节=%02x %02x %02x (int3)\n",
               i+1, (unsigned long long)rva, (unsigned long long)len, f[0], f[1], f[2]);
    }

    l2_install(g_table, base);

    volatile int i1 = in1, i2 = in2;
    int g1 = secret1(i1), g2 = secret2(i2);
    printf("secret1(%d)=%d expect=%d  %s\n", in1, g1, e1, g1==e1?"OK":"FAIL");
    printf("secret2(%d)=%d expect=%d  %s\n", in2, g2, e2, g2==e2?"OK":"FAIL");
    /* 二次调用应仍正确(已回填保持) */
    int g1b = secret1(i1);
    int ok = (g1==e1) && (g2==e2) && (g1b==e1);
    printf("==> %s\n", ok ? "PASS (可嵌入 L2 runtime: 多函数抽取+自解析+VEH回填 全通)" : "FAIL");
    return ok ? 0 : 1;
}
