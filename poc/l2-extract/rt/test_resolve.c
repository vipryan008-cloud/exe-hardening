/* 用真 GetModuleHandle/GetProcAddress 做 oracle, 对拍自解析 shellcode。*/
#include <windows.h>
#include <stdio.h>

extern void *get_kernel32_base(void);
extern void *get_proc(void *base, const char *name);

int main(void) {
    void *k_real = (void *)GetModuleHandleA("kernel32.dll");
    void *k_sc   = get_kernel32_base();
    printf("kernel32 base: real=%p  shellcode=%p  %s\n",
           k_real, k_sc, k_real == k_sc ? "MATCH" : "MISMATCH");

    /* 只需 shellcode 可靠拿到两个 bootstrap 函数(非转发导出); 其余由 C runtime
       用真 GetProcAddress 解析(它会跟 kernel32→ntdll 的 forwarder)。*/
    const char *boot[] = {"GetProcAddress", "LoadLibraryA"};
    int ok = (k_real == k_sc) && k_sc;
    for (int i = 0; i < 2; i++) {
        void *real = (void *)GetProcAddress((HMODULE)k_real, boot[i]);
        void *sc   = get_proc(k_sc, boot[i]);
        int m = (real == sc) && sc;
        ok &= m;
        printf("  [bootstrap] %-16s real=%p sc=%p  %s\n", boot[i], real, sc, m ? "OK" : "FAIL");
    }
    /* 信息性: 转发导出用我们的裸解析器会得到转发串地址(预期不等), 走 GPA 才对 */
    const char *fwd[] = {"VirtualProtect", "AddVectoredExceptionHandler", "FlushInstructionCache"};
    for (int i = 0; i < 3; i++) {
        void *real = (void *)GetProcAddress((HMODULE)k_real, fwd[i]);
        void *sc   = get_proc(k_sc, fwd[i]);
        printf("  [info]      %-28s real=%p sc=%p  %s\n", fwd[i], real, sc,
               real == sc ? "直接" : "转发(runtime走GPA)");
    }
    printf("==> %s\n", ok ? "PASS (bootstrap 可用: shellcode 拿到 GPA+LoadLibraryA)" : "FAIL");
    return ok ? 0 : 1;
}
