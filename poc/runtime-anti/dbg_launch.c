/* 极简调试器: 以 DEBUG_ONLY_THIS_PROCESS 启动子进程并放行到结束。
 * 用途: 让 antidemo.exe 真的"被调试", 验证反调试检测会翻 1。
 * 子进程在调试器下: PEB.BeingDebugged=TRUE, IsDebuggerPresent()=TRUE。*/
#include <windows.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) { printf("usage: dbg_launch <child.exe>\n"); return 2; }
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessA(argv[1], NULL, NULL, NULL, FALSE,
                        DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed: %lu\n", GetLastError());
        return 3;
    }
    DEBUG_EVENT de;
    DWORD child_exit = 0;
    for (;;) {
        if (!WaitForDebugEvent(&de, INFINITE)) break;
        if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            child_exit = de.u.ExitProcess.dwExitCode;
            ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
            break;
        }
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
    }
    printf("[dbg_launch] child exit code = %lu (nonzero => 反调试命中)\n", child_exit);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return (int)child_exit;
}
