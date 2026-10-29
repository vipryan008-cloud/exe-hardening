/* 进程内验证"用完即擦"call-gate: 函数返回后重新抽成 int3。
 * 场景: outer() 调 inner() (嵌套) + rec() 递归。验证:
 *   - 结果正确; 执行期间函数明文; 返回后立即 int3 回填(用完即擦)。*/
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

extern void restub_tramp(void);

#define STASH_XOR 0xA7
#define MAXP 8

typedef struct { uint8_t *func; SIZE_T len; uint8_t stash[512]; int stubbed; } Prot;
static Prot g_prot[MAXP];
static int g_nprot = 0;

/* 影子栈: 每个被 hook 的调用一帧 */
typedef struct { int pi; void *realret; } Frame;
static Frame g_shadow[64];
static int g_sp = 0;

#pragma optimize("", off)
__declspec(noinline) int inner(int x) { return x * 3 + 7; }
__declspec(noinline) int outer(int x) { return inner(x) + inner(x + 1); }
__declspec(noinline) int rec(int n) { if (n <= 0) return 1; return n * rec(n - 1); }
#pragma optimize("", on)

static SIZE_T flen(void *f) {
    uint64_t b = 0; PRUNTIME_FUNCTION rf = RtlLookupFunctionEntry((DWORD64)f, &b, NULL);
    return rf ? rf->EndAddress - rf->BeginAddress : 0;
}
static void stub(Prot *p) {
    DWORD o; VirtualProtect(p->func, p->len, PAGE_EXECUTE_READWRITE, &o);
    for (SIZE_T i = 0; i < p->len; i++) p->func[i] = 0xCC;
    VirtualProtect(p->func, p->len, o, &o);
    FlushInstructionCache(GetCurrentProcess(), p->func, p->len);
    p->stubbed = 1;
}
static void restore(Prot *p) {
    DWORD o; VirtualProtect(p->func, p->len, PAGE_EXECUTE_READWRITE, &o);
    for (SIZE_T i = 0; i < p->len; i++) p->func[i] = p->stash[i] ^ STASH_XOR;
    VirtualProtect(p->func, p->len, o, &o);
    FlushInstructionCache(GetCurrentProcess(), p->func, p->len);
    p->stubbed = 0;
}

/* 蹦床里回调: 弹一帧, 把该函数重新抽成 int3, 返回真返回地址 */
void *restub_pop(void) {
    Frame f = g_shadow[--g_sp];
    stub(&g_prot[f.pi]);            /* 用完即擦 */
    return f.realret;
}

static LONG CALLBACK veh(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;
    uint8_t *addr = (uint8_t *)ep->ExceptionRecord->ExceptionAddress;
    for (int i = 0; i < g_nprot; i++) {
        Prot *p = &g_prot[i];
        if (p->stubbed && addr == p->func) {       /* 命中该函数入口 */
            restore(p);
            /* 入口处 [Rsp] = 返回地址; 改成蹦床, 记录真返回地址 */
            void **sp = (void **)ep->ContextRecord->Rsp;
            g_shadow[g_sp].pi = i;
            g_shadow[g_sp].realret = *sp;
            g_sp++;
            *sp = (void *)restub_tramp;
            ep->ContextRecord->Rip = (DWORD64)p->func;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static int addp(void *f) {
    Prot *p = &g_prot[g_nprot];
    p->func = (uint8_t *)f; p->len = flen(f);
    for (SIZE_T i = 0; i < p->len; i++) p->stash[i] = p->func[i] ^ STASH_XOR;
    stub(p);
    return g_nprot++;
}
static int all_stubbed(void) {
    for (int i = 0; i < g_nprot; i++) if (!g_prot[i].stubbed) return 0;
    return 1;
}

int main(void) {
    volatile int a = 4, b = 5;
    int e_outer = outer(a), e_rec = rec(b);    /* 抽取前算期望 */

    AddVectoredExceptionHandler(1, veh);
    int pi_outer = addp((void *)outer); (void)pi_outer;
    addp((void *)inner);
    addp((void *)rec);
    printf("抽取后全 int3: %s\n", all_stubbed() ? "是" : "否");

    int g_outer = outer(a);
    printf("outer(%d)=%d expect=%d  用完即擦→全回 int3: %s\n",
           a, g_outer, e_outer, all_stubbed() ? "是" : "否");
    int g_rec = rec(b);
    printf("rec(%d)=%d expect=%d  用完即擦→全回 int3: %s\n",
           b, g_rec, e_rec, all_stubbed() ? "是" : "否");

    int ok = (g_outer == e_outer) && (g_rec == e_rec) && all_stubbed();
    printf("==> %s\n", ok ? "PASS (call-gate 用完即擦: 嵌套+递归正确, 返回即擦回)" : "FAIL");
    return ok ? 0 : 1;
}
