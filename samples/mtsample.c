/* 多线程靶子: 验证 call-gate 的 per-thread TLS 影子栈线程安全。
 * 4 线程并发调用被保护函数; TLS 正确则结果对且不崩, 全局影子栈会失步/崩。*/
#include <windows.h>
#include <stdio.h>

#pragma optimize("", off)
__declspec(noinline) int compute(int x) { int r = x; for (int i = 0; i < 3; i++) r = r * 5 + 1; return r; }
__declspec(noinline) int helper(int x) { return compute(x) ^ (x << 1); }   /* 嵌套调另一保护函数 */
#pragma optimize("", on)

#define ITERS 20000
volatile LONG64 g_sum = 0;

DWORD WINAPI worker(void *p) {
    long long s = 0;
    for (int i = 0; i < ITERS; i++) s += helper(i & 0xff);
    InterlockedAdd64(&g_sum, s);
    return 0;
}

int main(void) {
    long long exp = 0;
    for (int t = 0; t < 4; t++) for (int i = 0; i < ITERS; i++) exp += helper(i & 0xff);

    HANDLE h[4];
    for (int i = 0; i < 4; i++) h[i] = CreateThread(0, 0, worker, 0, 0, 0);
    WaitForMultipleObjects(4, h, TRUE, INFINITE);
    for (int i = 0; i < 4; i++) CloseHandle(h[i]);

    printf("mt: 4线程 sum=%lld expect=%lld  %s\n", g_sum, exp, g_sum == exp ? "OK" : "FAIL");
    return g_sum == exp ? 7 : 1;
}
