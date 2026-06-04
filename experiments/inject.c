/* 32-bit injector: launch CmRcViewer suspended, inject hook.dll, resume,
 * capture for N seconds, terminate. Build with i686-w64-mingw32-gcc.
 * Usage: inject.exe <target> <seconds> */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *exe = "\\\\SHARE\\RemoteTool\\CmRcViewer.exe";
    const char *target = argc > 1 ? argv[1] : "TARGET-HOST";
    int secs = argc > 2 ? atoi(argv[2]) : 14;
    const char *dll = "C:\\Users\\you\\dev\\sccm-rc\\hook.dll";

    char cmd[1024];
    _snprintf(cmd, sizeof(cmd), "\"%s\" %s", exe, target);

    STARTUPINFOA si; PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si); memset(&pi, 0, sizeof(pi));
    if (!CreateProcessA(exe, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed %lu\n", GetLastError()); return 1;
    }
    SIZE_T n = strlen(dll) + 1;
    void *rem = VirtualAllocEx(pi.hProcess, NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rem) { printf("VirtualAllocEx failed %lu\n", GetLastError()); TerminateProcess(pi.hProcess, 1); return 1; }
    if (!WriteProcessMemory(pi.hProcess, rem, dll, n, NULL)) {
        printf("WriteProcessMemory failed %lu\n", GetLastError()); TerminateProcess(pi.hProcess, 1); return 1;
    }
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE ll = (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "LoadLibraryA");
    HANDLE th = CreateRemoteThread(pi.hProcess, NULL, 0, ll, rem, 0, NULL);
    if (!th) { printf("CreateRemoteThread failed %lu\n", GetLastError()); TerminateProcess(pi.hProcess, 1); return 1; }
    WaitForSingleObject(th, 8000);
    DWORD exitCode = 0; GetExitCodeThread(th, &exitCode);
    printf("LoadLibrary remote returned (module handle) = 0x%lx\n", exitCode);
    CloseHandle(th);
    ResumeThread(pi.hThread);
    printf("injected into pid=%lu, capturing %d s ...\n", pi.dwProcessId, secs);
    Sleep(secs * 1000);
    TerminateProcess(pi.hProcess, 0);
    printf("done\n");
    return 0;
}
