/**
 *
 * Small lib to assist in the exploit process of HEVD
 *
 */

#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdint.h>
#include <tlhelp32.h>
#include <tchar.h>

#define SYSTEM_PROCESS_NAME "lsass.exe"

BOOL DebugMode = FALSE;


/**
 * Few basic logging functions.
 */
void static __xlog(const char* prio, const char* format, va_list args)
{
        size_t fmt_len = strlen(format)+strlen(prio)+2;
        uint8_t *fmt = alloca(fmt_len);
        RtlFillMemory(fmt, fmt_len, '\x00');
        // TODO: add timestamp
        sprintf(fmt, "%s %s", prio, format);
        vfprintf(stderr, fmt, args);
        fflush(stderr);
        return;
}


void info(const char* format, ... )
{
        va_list args;
        va_start(args, format);
        __xlog("[*] ", format, args);
        va_end(args);
}

void ok(const char* format, ... )
{
        va_list args;
        va_start(args, format);
        __xlog("[+] ", format, args);
        va_end(args);
}

void warn(const char* format, ... )
{
        va_list args;
        va_start(args, format);
        __xlog("[!] ", format, args);
        va_end(args);
}

void err(const char* format, ... )
{
        va_list args;
        va_start(args, format);
        __xlog("[-] ", format, args);
        va_end(args);
}

void perr(char* msg)
{
        DWORD eNum;
        char sysMsg[256];
        char* p;

        eNum = GetLastError();
        FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, eNum,
                       MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                       sysMsg, sizeof(sysMsg), NULL);

        p = sysMsg;
        while( ( *p > 31 ) || ( *p == 9 ) )
                ++p;
        do { *p-- = 0; } while( ( p >= sysMsg ) &&
                                ( ( *p == '.' ) || ( *p < 33 ) ) );

        err("%s: %s (%d)\n", msg, sysMsg, eNum);
}


/**
 * Post exploit
 */

DWORD GetProcessIdByName(LPTSTR processName)
{
        HANDLE hProcessSnap, hProcess;
        PROCESSENTRY32 pe32;
        DWORD dwPriorityClass, dwPid;

        dwPid = -1;

        hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if( hProcessSnap == INVALID_HANDLE_VALUE ){
                perr("CreateToolhelp32Snapshot failed");
                return -1;
        }

        pe32.dwSize = sizeof( PROCESSENTRY32 );

        if( !Process32First( hProcessSnap, &pe32 ) ){
                perr("Process32First failed");
                CloseHandle(hProcessSnap );
                return -1;
        }

        do
        {
                BOOL isMatch = FALSE;

                dwPriorityClass = 0;
                hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID );
                if(!hProcess)
                        continue;


                dwPriorityClass = GetPriorityClass( hProcess );
                if( !dwPriorityClass ){
                        CloseHandle(hProcess);
                        continue;
                }

                isMatch = strcmp(processName, pe32.szExeFile)==0;
                CloseHandle(hProcess);

                if (isMatch){
                        dwPid = pe32.th32ProcessID;
                        break;
                }

        } while( Process32Next( hProcessSnap, &pe32 ) );

        CloseHandle( hProcessSnap );
        return dwPid;
}


BOOL CheckIsSystem()
{
        HANDLE hProcess;
        DWORD dwCrssPid;

        dwCrssPid = GetProcessIdByName(SYSTEM_PROCESS_NAME);
        if (dwCrssPid==-1){
                err("GetProcessIdByName failed");
                return FALSE;
        }

        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwCrssPid);
        if( hProcess == NULL ){
                perr("OpenProcess(\""SYSTEM_PROCESS_NAME"\") failed");
                return FALSE;
        }

        CloseHandle(hProcess);
        return TRUE;
}



BOOL PopupNewProcess(LPTSTR lpCommandLine)
{
        STARTUPINFO si;
        PROCESS_INFORMATION pi;

        ZeroMemory( &si, sizeof(si) );
        si.cb = sizeof(si);
        ZeroMemory( &pi, sizeof(pi) );

        info("Spawning '%s'...\n", lpCommandLine);

        if( !CreateProcess(
                    NULL,                                    // No module name (use command line)
                    lpCommandLine,                           // Command line
                    NULL,                                    // Process handle not inheritable
                    NULL,                                    // Thread handle not inheritable
                    FALSE,                                   // Set handle inheritance to FALSE
                    CREATE_NEW_CONSOLE,                      // Creation flags
                    NULL,                                    // Use parent's environment block
                    NULL,                                    // Use parent's starting directory
                    &si,                                     // Pointer to STARTUPINFO structure
                    &pi)                                     // Pointer to PROCESS_INFORMATION structure
            ){
                perr("CreateProcess failed");
                return FALSE;
        }

        ok("'%s' spawned with PID %d\n", lpCommandLine, pi.dwProcessId);
        return TRUE;
}


void PopupCmd()
{
        PopupNewProcess("c:\\windows\\system32\\cmd.exe");
        return;
}
