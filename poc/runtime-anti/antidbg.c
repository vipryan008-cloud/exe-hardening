/* ==========================================================================
 * 运行时对抗模块 (x64) —— 反调试 / 反VM / 反dump 的检测原语。
 *
 * 类比 app-hardening 的"阶段3 native 运行时对抗": 加固后的程序在关键点
 * 调用这些检查, 命中 => 走处置(退出/损坏状态)。这里每个检查独立可验证:
 * 正常运行返回干净; 挂调试器/跑在VM里对应位翻转。
 *
 * 全部用文档化技术, 编译期无需额外依赖 (只 Win32 + 内联汇编读 PEB/CPUID)。
 * ========================================================================== */
#include <windows.h>
#include <intrin.h>
#include <stdint.h>

/* ---- PEB 直读 (不经 API, 反 hook): GS:[0x60] = PEB ---- */
static uint8_t *peb(void) { return (uint8_t *)__readgsqword(0x60); }

/* BeingDebugged 标志 (PEB+0x02) —— 等价 IsDebuggerPresent 但绕过对该 API 的 hook */
int adbg_peb_being_debugged(void) { return peb()[0x02] != 0; }

/* NtGlobalFlag (PEB+0xBC): 调试器启动的进程会置 heap 标志位 (0x70) */
int adbg_nt_global_flag(void) {
    uint32_t f = *(uint32_t *)(peb() + 0xBC);
    return (f & 0x70) != 0;   /* FLG_HEAP_ENABLE_TAIL/FREE_CHECK | HEAP_VALIDATE_PARAMETERS */
}

/* 官方 API 交叉验证 (本地+远程调试器) */
int adbg_api_present(void) {
    if (IsDebuggerPresent()) return 1;
    BOOL remote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    return remote ? 1 : 0;
}

/* 硬件断点: 读自身线程上下文的 DR0..DR3, 非零=有硬件断点 */
int adbg_hardware_breakpoints(void) {
    CONTEXT ctx; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &ctx)) return 0;
    return (ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3) != 0;
}

/* 时序: rdtsc 夹一段应极快的代码, 单步/断点会拉出巨大间隔 */
int adbg_timing_rdtsc(void) {
    uint64_t a = __rdtsc();
    /* 一点廉价工作, 防被优化掉 */
    volatile int x = 0; for (int i = 0; i < 16; i++) x += i;
    uint64_t b = __rdtsc();
    return (b - a) > 100000ULL;   /* 正常几十~几百周期; 被单步则爆表 */
}

/* 反VM: CPUID.1 ECX bit31 = hypervisor present */
int avm_hypervisor(void) {
    int r[4]; __cpuid(r, 1);
    return (r[2] >> 31) & 1;
}

/* 反VM: CPUID.0x40000000 返回 hypervisor vendor 串 (VMwareVMware/KVMKVM../Microsoft Hv..) */
int avm_hypervisor_vendor(char out[13]) {
    int r[4]; __cpuid(r, 0x40000000);
    ((int *)out)[0] = r[1]; ((int *)out)[1] = r[2]; ((int *)out)[2] = r[3];
    out[12] = 0;
    return r[0] >= 0x40000000;   /* 有效 hypervisor leaf */
}

/* 反dump: 运行时把自身 PE 头的 e_lfanew/魔数抹掉, 让内存 dump 拿到残缺 PE。
 * (演示: 返回是否成功改写了自己映像的 "MZ"。真实用法在 stub 解密后调用一次。) */
int adump_erase_header(void) {
    uint8_t *base = (uint8_t *)GetModuleHandleW(NULL);
    DWORD old;
    if (!VirtualProtect(base, 0x1000, PAGE_READWRITE, &old)) return 0;
    base[0] = 0; base[1] = 0;                 /* 抹 "MZ" */
    VirtualProtect(base, 0x1000, old, &old);
    return 1;
}

/* 汇总: 有没有被调试 (任一命中) */
int adbg_any(void) {
    return adbg_peb_being_debugged() | adbg_nt_global_flag()
         | adbg_api_present()        | adbg_hardware_breakpoints();
}
