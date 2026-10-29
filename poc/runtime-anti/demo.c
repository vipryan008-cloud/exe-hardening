/* 运行时对抗自检 demo: 打印各检测结果。
 * 正常运行: 反调试全 0; 反VM 视宿主而定。挂调试器重跑 => 反调试位翻 1。*/
#include <stdio.h>

int adbg_peb_being_debugged(void);
int adbg_nt_global_flag(void);
int adbg_api_present(void);
int adbg_hardware_breakpoints(void);
int adbg_timing_rdtsc(void);
int avm_hypervisor(void);
int avm_hypervisor_vendor(char out[13]);
int adbg_any(void);

int main(void) {
    char vend[13] = {0};
    int has_leaf = avm_hypervisor_vendor(vend);
    printf("[anti-debug] PEB.BeingDebugged   = %d\n", adbg_peb_being_debugged());
    printf("[anti-debug] NtGlobalFlag(heap)  = %d\n", adbg_nt_global_flag());
    printf("[anti-debug] IsDbg/RemoteDbg API = %d\n", adbg_api_present());
    printf("[anti-debug] hardware breakpoints= %d\n", adbg_hardware_breakpoints());
    printf("[anti-debug] rdtsc timing spike  = %d\n", adbg_timing_rdtsc());
    printf("[anti-debug] ==> ANY debugger    = %d\n", adbg_any());
    printf("[anti-vm   ] CPUID hypervisor bit= %d\n", avm_hypervisor());
    printf("[anti-vm   ] hv vendor           = %s (leaf=%d)\n",
           has_leaf ? vend : "-", has_leaf);
    return adbg_any();   /* 退出码=是否检出调试器, 便于脚本判定 */
}
