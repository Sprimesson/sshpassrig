// based on sshpass.exe for windows: https://github.com/xhcoding/sshpass-win32, MIT License, see LICENSE file

#include <Windows.h>
#include <string>
#include <vector>
#include <locale>
#include <codecvt>
#include <map>
#include <wincred.h>
#include <process.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>
#include <tchar.h>
#include <signal.h>
#include "resource.h"

// Use windows credentials manager
#pragma comment(lib, "credui.lib")

//==============================================================================//
// Helper macros
//==============================================================================//

static bool g_NoInfoText = false;

#define CHUNK_BUFFER_SIZE 1024U

#define PRINTINFO(fmt, ...) do { if (!g_NoInfoText) fwprintf(stderr, L"-- " fmt L"\n", __VA_ARGS__); } while (0)

#define PRINTERR(fmt, ...) fwprintf(stderr, L"** " fmt L"\n", __VA_ARGS__)

HRESULT HR_INT(DWORD ex, LPCWSTR op)
{
    if (ex == 0)
    {
        // No error code provided? Hmm, weird.
        ex = 1U;
    }
    else if ((ex & 0x80000000U) == 0U)
    {
        // Provided value is not HRESULT. Convert to HRESULT.
        ex = HRESULT_FROM_WIN32(ex);
    }

    PRINTERR("failed with %u (%Xh): %s", ex & 0xFFFFU, ex, op);
    return (HRESULT)ex;
}

// Ingest error code from Win32 call returning BOOL
#define HR_CHECK_B(e) (hr = (TRUE == (e) ? S_OK : HR_INT(GetLastError(), L#e)), (void)0)

// Ingest error code from Win32 call returning HRESULT
#define HR_CHECK(e) (FAILED(hr = (e)) ? (void)HR_INT(hr, L#e) : (void)0)

// Ingest error code from a constant HRESULT
#define HR_SET(v, op) (FAILED(hr = (v)) ? (void)HR_INT(hr, L##op) : (void)0)

// Ingest error code from a constant Win32 error
#define HR_SET_B(v, op) (FAILED(hr = HRESULT_FROM_WIN32(v)) ? (void)HR_INT(hr, L##op) : (void)0)

#define VALID_HANDLE(h) ((h) != INVALID_HANDLE_VALUE && (h) != NULL)

#define SAFE_CLOSE_HANDLE(h) \
    do { \
        if (VALID_HANDLE(h)) { \
            CloseHandle(h); \
            h = NULL; \
        } \
    } while (0)

#define SAFE_FREE(m) \
    do { \
        if (NULL != m) { \
            free(m); \
            m = NULL; \
        } \
    } while (0)

typedef std::vector<HANDLE> Handles;

inline DWORD WaitForObjectsOfList(const Handles& objects, BOOL waitAll, DWORD timeout = INFINITE)
{
    DWORD dwWait = WaitForMultipleObjects((DWORD)objects.size(), objects.data(), waitAll, timeout);
    if (dwWait == WAIT_FAILED)
    {
        HRESULT hr;
        HR_SET_B(GetLastError(), "WaitForMultipleObjects");
    }
    return dwWait;
}

inline std::string WstrToUtf8(const std::wstring& wstr)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(wstr);
}

LPCSTR strstr_maxlen(LPCSTR target, size_t targetLength, const std::string& compare)
{
    size_t compareLen = (DWORD)compare.length();
    LPCSTR comparePtr = compare.c_str();
    
    if (targetLength < compareLen)
    {
        return NULL;
    }

    for (size_t i = 0; i <= targetLength; i++, target++)
    {
        if (strncmp(target, comparePtr, compareLen) == 0)
        {
            return target;
        }
    }

    return NULL;
}

// Escape '"' or ' ' or '\t' in a string.
std::wstring escape_and_quote_if_needed(const std::wstring& input) {
    bool needs_quotes = false;
    std::wstring result;

    // Check if the string contains any spaces, tabs, or double quotes
    for (wchar_t ch : input) {
        if (ch == L' ' || ch == L'\t' || ch == L'"') {
            needs_quotes = true;
        }
    }

    // If no spaces, tabs, or quotes, return the original string
    if (!needs_quotes) {
        return input;
    }

    result += L'"'; // Start the string with a double quote

    for (wchar_t ch : input)
    {
        if (ch == L'\\')
        {
            result += L"\\\\"; // Escape backslashes
        }
        else if (ch == L'"')
        {
            result += L"\\\""; // Escape double quotes
        }
        else
        {
            result += ch; // Copy other characters as-is
        }
    }

    result += L'"'; // End the string with a double quote
    return result;
}

// Here is a workaround for CreatePipe (anonymous pipe) not being able to create overlapped pipes.
// Apparently, this is somewhat similar to actual implemenation of CreatePipe() for Windows 7+.
BOOL CreateOverlappedUnnamedPipe(LPHANDLE lpReadPipe, LPHANDLE lpWritePipe)
{
    static volatile DWORD PipeIndex = 0U;
    HANDLE ReadPipeHandle, WritePipeHandle;
    DWORD dwError;
    WCHAR PipeNameBuffer[MAX_PATH];
    const DWORD dwWriteMode = FILE_FLAG_OVERLAPPED;
    const DWORD dwReadMode = FILE_FLAG_OVERLAPPED;
    DWORD nBufSize = 4096U;

    StringCchPrintfW(PipeNameBuffer,
        MAX_PATH,
        L"\\\\.\\Pipe\\Sshpassrig.%08x.%08x",
        GetCurrentProcessId(),
        InterlockedIncrement(&PipeIndex)
    );

    ReadPipeHandle = CreateNamedPipeW(
        PipeNameBuffer,
        PIPE_ACCESS_INBOUND | dwReadMode,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        1,             // Number of pipes
        nBufSize,      // Out buffer size
        nBufSize,      // In buffer size
        120 * 1000,    // Timeout in ms
        NULL
    );

    if (!ReadPipeHandle) {
        return FALSE;
    }

    WritePipeHandle = CreateFileW(
        PipeNameBuffer,
        GENERIC_WRITE,
        0,                         // No sharing
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | dwWriteMode,
        NULL                       // Template file
    );

    if (INVALID_HANDLE_VALUE == WritePipeHandle) {
        // Remember to close the handle, note: preserve error code
        dwError = GetLastError();
        SAFE_CLOSE_HANDLE(ReadPipeHandle);
        SetLastError(dwError);
        return FALSE;
    }

    *lpReadPipe = ReadPipeHandle;
    *lpWritePipe = WritePipeHandle;
    return(TRUE);
}

//==============================================================================//
// Structs
//==============================================================================//

struct SCredentialPassword
{
    std::wstring passwordBuf;
};

struct SCedentialPasswordReadoutWindow
{
    SCredentialPassword* readout;
    LPCWSTR targetName;
};

struct SRunParams
{
    // Cmdline args
    bool haveTimeout = false;      // -t flag
    bool haveLoop = false;         // -l flag
    bool haveNoEsc = false;        // -e flag
    std::wstring targetName;       // -n TARGET_NAME
    std::wstring subCmd;           // -- SUBCMD
    std::string passwordFieldSearch = "password:"; // -p PASS_FIELD

    // Timer
    uint32_t timerTimeout = 10000U;

    // Password
    bool useCredMgmt = false;
    bool readPassFromUser = false;
    std::wstring targetNameInCredMgmt;
    SCredentialPassword pass;

    // Run ctx
    HANDLE pipeIn{};
    HANDLE pipeOut{};

    HANDLE stdIn{};
    HANDLE stdOut{};
    bool stdOutIsCon{};

    HANDLE evPipeIn{};
    HANDLE evEndMain{};
    HANDLE evEndPipes{};

    HPCON pseudoConForSub{};

    // Carriage return post-processing when printing to stdOut
    char lastLinePrint[4096U];
    bool crSkipActive = false;
    int crSkipIndex = 0;
};

enum class EPipeOutState : DWORD
{
    INIT, VERIFY, EXEC, END
};

//==============================================================================//
// Credential Management
//==============================================================================//

// Function to check if a key exists in the vault
static BOOL CheckKeyExists(LPCWSTR targetName, SCredentialPassword* out)
{
    PCREDENTIAL pcred = NULL;

    if (!out)
    {
        return FALSE;
    }
    if (CredReadW(targetName, CRED_TYPE_GENERIC, 0, &pcred))
    {
        // Copy and truncate, put NUL
        out->passwordBuf = std::wstring((LPCWSTR)pcred->CredentialBlob, (size_t)(pcred->CredentialBlobSize / sizeof(WCHAR)));
        CredFree(pcred);
        return TRUE;  // Credential exists
    }
    else
    {
        PRINTERR(L"Credentials for %s do not exist yet in Windows Credential Manager.", targetName);
        return FALSE; // Credential doesn't exist
    }
}

// Function to store a new key in the Windows Vault
static BOOL WriteKey(LPCWSTR targetName, LPCWSTR password)
{
    CREDENTIAL cred = { 0 };

    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = (LPWSTR)targetName;
    cred.UserName = (LPWSTR)L"user";
    cred.CredentialBlobSize = (DWORD)(wcslen(password) * sizeof(WCHAR));
    cred.CredentialBlob = (LPBYTE)password;
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE;

    if (CredWriteW(&cred, 0))
    {
        return TRUE;
    }
    else
    {
        PRINTERR(L"failed to write password to vault");
        return FALSE;
    }
}

// Dialog callback function for the password prompt
INT_PTR CALLBACK PasswordDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message) {
    case WM_INITDIALOG:        
        // lParam has ref to SCedentialPasswordReadoutWindow
        {
            auto wndData = (SCedentialPasswordReadoutWindow*)lParam;
            SetDlgItemTextW(hDlg, IDC_PROMPT, (
                std::wstring(L"Please enter password for ") + (wndData->targetName[0] == 0 ? L"the target" : wndData->targetName) + L":"
                ).c_str());

            SetWindowLongPtrW(hDlg, GWLP_USERDATA, (LONG_PTR)lParam);
        }
        return TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK)
        {
            auto out = ((SCedentialPasswordReadoutWindow*)GetWindowLongPtr(hDlg, GWLP_USERDATA))->readout;

            int length = GetWindowTextLengthW(GetDlgItem(hDlg, IDC_PASSWORD));
            if (length >= 0) {
                out->passwordBuf = std::wstring(length, L'\0');
                GetDlgItemTextW(hDlg, IDC_PASSWORD, &out->passwordBuf[0], length + 1U);

                EndDialog(hDlg, TRUE);
                return TRUE;
            }
        }
        else if (LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, FALSE);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

// Function to get the password from the user via a simple dialog
static BOOL GetPasswordFromDialog(SCedentialPasswordReadoutWindow* wndData)
{
    if (!wndData || !wndData->readout)
    {
        return FALSE;
    }
    return DialogBoxParamW(GetModuleHandleW(NULL), MAKEINTRESOURCE(IDD_PASSWORD_DIALOG), NULL, PasswordDialogProc, (LPARAM)wndData) == TRUE;
}

//==============================================================================//
// Run Parameters (Cmdline arguments)
//==============================================================================//

static bool ParseArg(int argc, const WCHAR* argv[], SRunParams* params)
{
    if (!params) return false; // Ensure params is valid

    bool isParsingSubCmd = false; // Indicates if we're in the SUBCMD part
    std::wstring currentArg;

    for (int i = 1; i < argc; ++i) {
        currentArg = argv[i];

        if (currentArg == L"-t") {
            params->haveTimeout = true;
            params->timerTimeout = 10000U;
        }
        else if (currentArg == L"-T") {
            // Parse the -T TIME_S
            params->haveTimeout = true;

            if (i + 1 < argc) {
                int v = _wtoi(argv[++i]) * 1000;
                if (v <= 0) {
                    PRINTERR(L"-T requires a positive integer");
                    return false;
                }
                params->timerTimeout = (uint32_t)v;
            }
            else {
                PRINTERR(L"-n option requires a TARGET_NAME argument.");
                return false;
            }
        }
        else if (currentArg == L"-l") {
            params->haveLoop = true;
        }
        else if (currentArg == L"-e") {
            params->haveNoEsc = true;
        }
        else if (currentArg == L"-I") {
            g_NoInfoText = true;
        }
        else if (currentArg == L"-n") {
            // Parse the -n TARGET_NAME
            if (i + 1 < argc) {
                params->targetName = argv[++i];
            }
            else {
                PRINTERR(L"-n option requires a TARGET_NAME argument.");
                return false;
            }
        }
        else if (currentArg == L"-p") {
            // Parse the -p PASS_FIELD
            if (i + 1 < argc) {
                params->passwordFieldSearch = WstrToUtf8(argv[++i]);
            }
            else {
                PRINTERR(L"-n option requires a TARGET_NAME argument.");
                return false;
            }
        }
        else if (currentArg == L"--") {
            // Marks the beginning of SUBCMD arguments
            isParsingSubCmd = true;
        }
        else if (isParsingSubCmd) {
            // Parse SUBCMD arguments and concatenate them with spaces
            // If they contain spaces or double quotes, wrap in double quotes and escape the internal double quotes.
            // This is so that CreateProcessW parse the arguments correctly.
            if (!params->subCmd.empty()) {
                params->subCmd += L" ";
            }

            params->subCmd += escape_and_quote_if_needed(currentArg).c_str();
        }
        else {
            PRINTERR(L"Unexpected argument: %s", currentArg.c_str());
            return false;
        }
    }

    if (params->haveLoop && params->haveTimeout) {
        PRINTERR(L"Can't have -l and -t together.");
    }

    // Ensure that the SUBCMD was provided
    if (params->subCmd.empty())
    {
        PRINTERR(L"usage: %s [-t|-l|-T TIME] [-e] [-n TARGET_NAME] -- SUBCMD\n"
            L"Where:\n"
            L"    -t: Give max 10s for execution of the SUBCMD\n"
            L"    -T: Give max TIME_S seconds for execution of the SUBCMD\n"
            L"    -l: Interactive loop: If the subprocess dies with error, start it again.\n"
            L"    -e: Suppress any ANSI ESC char from output of SUBCMD\n"
            L"    -n: SSH TARGET_NAME, formatted as user@host[:port]\n"
            L"    SUBCMD: Command line to SSH/SCP, following tokens can be expanded:\n"
            L"       $FLAGS$        -o StrictHostKeyChecking=no\n"
            L"       $PORT$         port\n"
            L"       $TARGET$       user@host\n"
            L"       $SSHPARAMS$    -o StrictHostKeyChecking=no -p port user@host\n"
            L"    Other options:\n"
            L"    -I: Don't print informative text"
            ,argv[0]);
        return false;
    }

    return true;
}

//==============================================================================//
// Preparation of SUBCMD
//==============================================================================//
static void ReplaceTokens(std::wstring& str, const std::map<std::wstring, std::wstring>& dict) {
    std::wstring result;
    size_t i = 0;

    while (i < str.length()) {
        if (str[i] == L'$') {
            // Found the start of a token
            size_t start = i + 1;
            size_t end = str.find('$', start);
            if (end != std::string::npos) {
                // Extract the token within $...$
                std::wstring token = str.substr(start, end - start);

                // Replace the token if found in the dictionary
                auto it = dict.find(token);
                if (it != dict.end()) {
                    result += it->second;  // Append the replacement value
                }
                else {
                    // If not found, retain the original $TOKEN$
                    result += L"$" + token + L"$";
                }

                i = end + 1;  // Move past the closing '$'
            }
            else {
                // No closing '$', append the rest as is
                result += str.substr(i);
                break;
            }
        }
        else {
            result += str[i];  // Append the current character
            i++;
        }
    }

    str = std::move(result);  // Assign the modified string back
}

static void ReplaceSSHPARAMS(std::wstring& subcmd, std::wstring targetName)
{
    // Prep the token dicotionary. Extract the port number from targeName
    size_t pos = targetName.find(L':');
    std::wstring flags = L"-o StrictHostKeyChecking=no";
    std::wstring sshParams = flags + L" ";
    std::wstring port = L"22";

    if (pos != std::wstring::npos)
    {
        port = targetName.substr(pos + 1);
        targetName = targetName.substr(0U, pos);
        sshParams += L"-p " + port + L" " + targetName;
    }
    else
    {
        sshParams += targetName;
    }

    std::map<std::wstring, std::wstring> dict =
    {
        {L"TARGET", targetName},
        {L"FLAGS", flags},
        {L"PORT", port},
        {L"SSHPARAMS", sshParams},
    };

    ReplaceTokens(subcmd, dict);
}

//==============================================================================//
// Invocation of subprocess
//==============================================================================//

static void ClosePseudoConsoleAndPipes(SRunParams* ctx)
{
    if (ctx->pseudoConForSub)
    {
        ClosePseudoConsole(ctx->pseudoConForSub);
        ctx->pseudoConForSub = NULL;
    }
    SAFE_CLOSE_HANDLE(ctx->pipeOut);
    SAFE_CLOSE_HANDLE(ctx->pipeIn);
}

// Create a pseudo console, used to transfer console data to the subprocess.
static HRESULT CreatePseudoConsoleAndPipes(SRunParams* ctx)
{
    HRESULT hr = E_UNEXPECTED;
    HANDLE pipePtyIn = INVALID_HANDLE_VALUE;
    HANDLE pipePtyOut = INVALID_HANDLE_VALUE;
    
    ClosePseudoConsoleAndPipes(ctx);

    if (CreateOverlappedUnnamedPipe(&pipePtyIn, &ctx->pipeOut) &&
        CreateOverlappedUnnamedPipe(&ctx->pipeIn, &pipePtyOut))
    {
        COORD consoleSize = { 0 };

        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (ctx->stdOutIsCon && GetConsoleScreenBufferInfo(ctx->stdOut, &csbi))
        {
            consoleSize.X = csbi.srWindow.Right - csbi.srWindow.Left + 1;
            consoleSize.Y = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
        }
        if (consoleSize.X == 0 || consoleSize.Y == 0)
        {
            consoleSize = { 120U, 80U }; // use default size
        }
        if (ctx->haveNoEsc)
        {
            // The user is not aiming to interact with the console. No need to say
            //   real console sizes.
            consoleSize = { 1024U, 1024U };
        }
        HR_CHECK(CreatePseudoConsole(consoleSize, pipePtyIn, pipePtyOut, 0, &ctx->pseudoConForSub));

        // These handles are not used.
        SAFE_CLOSE_HANDLE(pipePtyIn);
        SAFE_CLOSE_HANDLE(pipePtyOut);
    }
    hr = S_OK;
    return hr;
}

static void UninitializeStartupInfo(STARTUPINFOEXW* startupInfo)
{
    if (startupInfo)
    {
        if (startupInfo->lpAttributeList)
        {
            DeleteProcThreadAttributeList(startupInfo->lpAttributeList);
            SAFE_FREE(startupInfo->lpAttributeList);
        }
    }
}

// Create startup info for child proc
static HRESULT InitializeStartupInfoAttachedToPseudoConsole(STARTUPINFOEXW* startupInfo, HPCON hpcon)
{
    HRESULT hr = S_OK;
    size_t attrListSize = 0;
    
    if (!startupInfo)
    {
        HR_SET(E_FAIL, "!startupInfo");
    }

    if (SUCCEEDED(hr))
    {
        // See how much data buffer is needed for these attributes.
        startupInfo->StartupInfo.cb = sizeof(STARTUPINFOEXW);
        InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);

        startupInfo->lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attrListSize);
        if (!startupInfo->lpAttributeList)
        {
            HR_SET(E_OUTOFMEMORY, "malloc(attrListSize)");
        }
    }

    if (SUCCEEDED(hr))
    {
        HR_CHECK_B(InitializeProcThreadAttributeList(startupInfo->lpAttributeList, 1, 0, &attrListSize));
    }

    if (SUCCEEDED(hr))
    {
        HR_CHECK_B(UpdateProcThreadAttribute(startupInfo->lpAttributeList, 0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, hpcon, sizeof(HPCON), NULL, NULL));
    }

    if (FAILED(hr))
    {
        UninitializeStartupInfo(startupInfo);
    }

    if (SUCCEEDED(hr))
    {
        // The following proves useful if the child process tries to find a way to access our stdin or stdout,
        //   which is not the intended behaviour. It needs to solely use the pty.
        startupInfo->StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
    }

    return hr;
}

//==============================================================================//
// Handling of Pty pipes
//==============================================================================//

// Check if the output pipe buffer has indication of a password field.
static bool IsWaitInputPass(SRunParams* ctx, LPCSTR buffer, DWORD len)
{
    auto pos = strstr_maxlen(buffer, len, ctx->passwordFieldSearch);
    return pos != NULL;
}

// Check if the output pipe buffer has indication of a password field.
// Return:
// +1: Correct, 0: Unknown, -1: Incorrect
static int CheckLoginResponse(SRunParams* ctx, LPCSTR buffer, DWORD len)
{
    // TODO: Search with Aho-Corasick
    static std::vector<std::string> pats;
    if (pats.empty())
    {
        pats = { "denined", "wrong", "permission", ctx->passwordFieldSearch };
    }
    
    for (const auto& pat : pats)
    {
        if (NULL != strstr_maxlen(buffer, len, pat))
            return -1;
    }

    // Only non readable ASCII or whitespace?
    for (DWORD i = 0; i < len; i++)
    {
        if (buffer[i] > 32)
            return +1;
    }

    return 0;
}

// Pass password to child proc
static void WritePass(SRunParams* ctx)
{
    wprintf(L"> Inputting password <\n");
    std::string passC = WstrToUtf8(ctx->pass.passwordBuf.c_str());
    WriteFile(ctx->pipeOut, passC.c_str(), (DWORD)passC.length(), NULL, NULL);
    WriteFile(ctx->pipeOut, "\n", 1U, NULL, NULL);
}

// Print text and post-process carriage return signs
// When we remove Esc sequences, we potentially need to account for '\r' characters
//   that are not accompanied by '\n'.
// This happens sometimes, and is sign that a previous line needs to be complemented with new characters.
static void PrintAndPostprocess_DropCR(SRunParams* ctx, LPSTR buffer, int32_t len)
{
    //TODO
    fprintf(stdout, "%.*s", len, &buffer[0]);
    return;
}

// Print text and drop ANSI Esc Csi sequences (which control caret, coloring, etc.)
static void PrintAndPostProcess_DropEscCsi(SRunParams* ctx, LPSTR buffer, int32_t len)
{
    // Remove any existance of ESC CSI.
    bool escCsi = false;
    int32_t i = 0;
    int32_t start = -1;
    int32_t csiStart = -1;
    int32_t v;
    for (i = 0; i < len; i++)
    {
        if (buffer[i] == 27 && i < len - 1 && buffer[i + 1] == '[') // beginning
        {
            if (start >= 0)
            {
                PrintAndPostprocess_DropCR(ctx, &buffer[start], i - start);
                start = -1;
            }

            i++;
            csiStart = i;
            escCsi = true;
        }
        else if (escCsi)
        {
            if (buffer[i] >= 0x40)
            {
                escCsi = false; // ending
            }

            if (buffer[i] == 'C') // ^[#C]  --> Print # spaces
            {
                v = atoi(&buffer[csiStart + 1]);
                while (v > 0 && v <= 256)
                {
                    v--;
                    fputc(' ', stdout);
                }
                
            }
            else if (buffer[i] == 'H') // ^[#;#H  --> Move to location (row and then column)
            {
                // As a rule of thumb, move to location column #1 can be emulated with going to a new line.
                if (buffer[i - 1] == '1' && buffer[i - 2] == ';')
                {
                    fputc('\n', stdout);
                }
            }
        }
        else
        {
            if (start == -1)
                start = i;
        }
    }

    if (start >= 0)
    {
        PrintAndPostprocess_DropCR(ctx, &buffer[start], i - start);
    }
}

// Process output of the child process
static EPipeOutState ProcessOutput(SRunParams* ctx, LPSTR buffer, DWORD len, EPipeOutState state)
{
    EPipeOutState nextState = EPipeOutState::END;
    int resp;

    if (ctx->haveNoEsc)
    {
        PrintAndPostProcess_DropEscCsi(ctx, buffer, (int32_t)len);
    }
    else
    {
        // Pass to output directly
        fprintf(stdout, "%.*s", len, buffer);
    }

    // Flush output
    fflush(stdout);

    // Look for password field
    switch (state)
    {
    case EPipeOutState::INIT:
        // Waiting for indication for passowrd field.
        if (!IsWaitInputPass(ctx, buffer, len))
        {
            nextState = EPipeOutState::INIT;
        }
        else
        {
            WritePass(ctx);
            nextState = EPipeOutState::VERIFY;
        }
        break;

    case EPipeOutState::VERIFY:
        // Check if the password was okay.
        // We deem it okay, if the next chunk of the buffer doesn't contain the
        //   same password prompt phrase.
        // The response sometimes comes in full, i.e. "\nIncorrect password, blah blah blah\nEnter password:"
        //   But sometimes comes in chunks: "\n" "Incorrect password...".
        // Search for specific patterns
        resp = CheckLoginResponse(ctx, buffer, len);
        if (resp == 0)
        {
            nextState = EPipeOutState::VERIFY;
            break;
        }
        else if (resp < 0)
        {
            PRINTERR("Wrong password");
            nextState = EPipeOutState::END;
            break;
        }

        nextState = EPipeOutState::EXEC;

        // Sounds good. Save the password.
        if (ctx->readPassFromUser && ctx->useCredMgmt)
        {
            if (TRUE == WriteKey(ctx->targetNameInCredMgmt.c_str(), ctx->pass.passwordBuf.c_str()))
            {
                PRINTINFO("saved password -- Open Windows Credential Manager to retract it later");
            }
        }
        // fall thru

    case EPipeOutState::EXEC:
        nextState = EPipeOutState::EXEC;
        break;

    default:
        nextState = EPipeOutState::END;
    }
    return nextState;
}

static unsigned int __stdcall HandleOutputToSubproc(LPVOID arg)
{
    auto ctx = (SRunParams *)arg;
    char buffer[CHUNK_BUFFER_SIZE] = { 0 };
    HRESULT hr = S_OK;
    DWORD dwErr;
    DWORD bytesRead;

    while (SUCCEEDED(hr))
    {
        if (FALSE == ReadFile(ctx->stdIn, buffer, CHUNK_BUFFER_SIZE, &bytesRead, NULL) || bytesRead == 0u)
        {
            dwErr = GetLastError();
            if (dwErr == ERROR_OPERATION_ABORTED)
            {
                // Asked to exit from main thread.
                break;
            }

            HR_SET_B(dwErr, "ReadFile(ctx->stdIn)");
            break;
        }

        if (bytesRead > 0U)
        {
            // Pass to child
            WriteFile(ctx->pipeOut, buffer, bytesRead, NULL, NULL);
        }
    }
    SetEvent(ctx->evEndMain);
    return 0;
}

static unsigned int __stdcall HandleInputFromSubproc(LPVOID arg)
{
    auto ctx = (SRunParams*)arg;
    char buffer[CHUNK_BUFFER_SIZE + 1U] = { 0 };
    OVERLAPPED overlappedRead{};
    HRESULT hr = S_OK;
    DWORD bytesRead;
    DWORD dwError;
    BOOL fRead;
    bool exitTriggered = false;
    EPipeOutState state = EPipeOutState::INIT;
    Handles waitList{ ctx->evEndPipes, ctx->evPipeIn };

    while (SUCCEEDED(hr))
    {
        // Read from pipe from subproc (overlapped fasion)
        overlappedRead = {};
        overlappedRead.hEvent = ctx->evPipeIn;
        fRead = ReadFile(ctx->pipeIn, buffer, CHUNK_BUFFER_SIZE, &bytesRead, &overlappedRead);
        if (fRead == FALSE)
        {
            dwError = GetLastError();
            if (dwError != ERROR_IO_PENDING)
            {
                // Operation failed. Not good.
                HR_SET_B(dwError, "ReadFile(ctx->pipeIn)");
            }

            // Wait
            if (SUCCEEDED(hr))
            {
                if (WaitForObjectsOfList(waitList, FALSE) == WAIT_OBJECT_0)
                {
                    // evEndPipes triggered
                    exitTriggered = true;

                    // We need to exit now. If this is due to the subprocess being finished,
                    //   we need to give a moment to make sure that the entire conout of the
                    //   subprocess is read. Otherwise the data might be truncated (race condition).
                    // Therefore we still check GetOverlappedResult() and perhaps yield a bit before that:

                    // The value 100 is fine tuned here.
                    Sleep(100);
                }
                
                // Finished read operation?
                BOOL overlappedFinished = GetOverlappedResult(ctx->pipeIn, &overlappedRead, &bytesRead, FALSE);

                if (FALSE == overlappedFinished)
                {
                    // Error occurred.
                    // - If we are exiting (exitTriggered), we got signaled by evEndPipes, we need to set hr=E_FAIL anyway.
                    // - Otherwise, we are signaled by pipeIn, in which case error is not tolerated.
                    dwError = GetLastError();
                    hr = E_FAIL;
                    if (dwError != ERROR_IO_INCOMPLETE)
                    {
                        HR_SET_B(dwError, "GetOverlappedResult(ctx->pipeIn)");
                    }
                    else
                    {
                        // A ERROR_IO_INCOMPLETE only happens in case of getting a signal from evEndPipes.
                        //   (otherwise there is no way WaitForObjectsOfList would finish)
                        // Cancel the I/O anyway.
                        CancelIo(ctx->pipeIn);
                    }
                }
            }
        }

        // Process read data
        if (SUCCEEDED(hr) && bytesRead > 0)
        {
            // For safety, NUL termiante the buffer.
            buffer[bytesRead] = 0;

            // State machine
            state = ProcessOutput(ctx, buffer, bytesRead, state);
            if (state == EPipeOutState::END)
            {
                hr = E_FAIL; // exit
            }
        }

        // Exit?
        if (exitTriggered)
        {
            hr = E_FAIL;
        }
    }
    SetEvent(ctx->evEndMain);
    return 0;
}

//==============================================================================//
// Main
//==============================================================================//
int wmain(int argc, const WCHAR* argv[])
{
    SRunParams ctx{};
    HRESULT hr = S_OK;
    DWORD conMode = 0;

    if (!ParseArg(argc, argv, &ctx))
    {
        return 1;
    }
    
    // Setup the console
    ctx.stdIn = GetStdHandle(STD_INPUT_HANDLE);
    ctx.stdOut = GetStdHandle(STD_OUTPUT_HANDLE);

    // We have some weird behaviour in MSYS/Mingw
    if (NULL != getenv("MSYSTEM"))
    {
        PRINTERR("CAUTION: MSYS/Mingw is not correctly supported.\n");
    }

    // Modify stdout if is a console
    if (GetFileType(ctx.stdOut) == FILE_TYPE_CHAR && S_OK == hr)
    {
        ctx.stdOutIsCon = true;
        GetConsoleMode(ctx.stdOut, &conMode);
        HR_CHECK_B(SetConsoleMode(ctx.stdOut, conMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING));
    }

    // Modify stdout if is a console
    if (GetFileType(ctx.stdIn) == FILE_TYPE_CHAR && S_OK == hr)
    {
        HR_CHECK_B(SetConsoleCtrlHandler(NULL, TRUE));
        
        if (S_OK == hr)
        {
            GetConsoleMode(ctx.stdIn, &conMode);
            DWORD unwantedFlags =
                (ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
            HR_CHECK_B(SetConsoleMode(ctx.stdIn, conMode & ~unwantedFlags));
        }
    }

    if (FAILED(hr))
    {
        PRINTERR(L"failed to init console");
        return hr;
    }

    // Look up or readout target credentials from user
    ctx.readPassFromUser = true;

    if (!ctx.targetName.empty())
    {
        ctx.useCredMgmt = true;
        ctx.targetNameInCredMgmt = L"sshpassrig/" + ctx.targetName;

        if (TRUE == CheckKeyExists(ctx.targetNameInCredMgmt.c_str(), &ctx.pass))
        {
            ctx.readPassFromUser = false;
            PRINTINFO(L"Password '%s' read from credential manager", ctx.targetNameInCredMgmt.c_str());
        }
    }

    if (ctx.readPassFromUser)
    {
        SCedentialPasswordReadoutWindow wndData;
        wndData.readout = &ctx.pass;
        wndData.targetName = ctx.targetName.c_str();

        PRINTINFO(L"Asking password for '%s'", ctx.targetName.c_str());
        if (FALSE == GetPasswordFromDialog(&wndData))
        {
            PRINTERR(L"No password provided, exiting");
            return 1;
        }
    }

    // Prepare SUBCMD
    ReplaceSSHPARAMS(ctx.subCmd, ctx.targetName);
    PRINTINFO(L"$ %s", ctx.subCmd.c_str());

    // Invoke the subprocess
    bool loopAgain = ctx.haveLoop;
    int subprocExitCode = 255;

    do
    {
        HANDLE hThInput{}, hThOutput{};
        STARTUPINFOEXW startupInfo{};
        PROCESS_INFORMATION cmdProc{};

        hr = S_OK;

        // Events to sync threads
        {
            ctx.evPipeIn = CreateEvent(NULL, FALSE, FALSE, NULL);
            ctx.evEndMain = CreateEvent(NULL, FALSE, FALSE, NULL);
            ctx.evEndPipes = CreateEvent(NULL, FALSE, FALSE, NULL);
        }

        // Create Pty to interact with the child process
        if (SUCCEEDED(hr))
        {
            HR_CHECK(CreatePseudoConsoleAndPipes(&ctx));
        }

        // Create individual threads handling Tx/Rx to/from child process
        if (SUCCEEDED(hr))
        {
            hThInput = (HANDLE)_beginthreadex(nullptr, 0, HandleInputFromSubproc, &ctx, 0, nullptr);
            hThOutput = (HANDLE)_beginthreadex(nullptr, 0, HandleOutputToSubproc, &ctx, 0, nullptr);
            HR_CHECK((VALID_HANDLE(hThOutput) && VALID_HANDLE(hThInput)) ? S_OK : E_FAIL);
        }

        // Create process StartupInfo that indicates the Pty
        if (SUCCEEDED(hr))
        {
            HR_CHECK(InitializeStartupInfoAttachedToPseudoConsole(&startupInfo, ctx.pseudoConForSub));
        }

        // Create the process
        if (SUCCEEDED(hr))
        {
            HR_CHECK_B(CreateProcessW(
                NULL, (LPWSTR)ctx.subCmd.c_str(), NULL, NULL, FALSE,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_PROCESS_GROUP,
                NULL, NULL, &startupInfo.StartupInfo, &cmdProc));
        }

        // Wait for completion of the process, or premature failure in one of the pipe worker threads.
        if (SUCCEEDED(hr))
        {
            DWORD waitRes = WaitForObjectsOfList(Handles{ cmdProc.hProcess, ctx.evEndMain }, FALSE, ctx.haveTimeout ? ctx.timerTimeout : INFINITE);
            if (waitRes == WAIT_TIMEOUT)
            {
                HR_SET(E_FAIL, "The subprocess is taking a long time -- Timeout");
            }
        }

        // Read exit code
        if (SUCCEEDED(hr))
        {
            HR_CHECK_B(GetExitCodeProcess(cmdProc.hProcess, (LPDWORD)&subprocExitCode));
            if (subprocExitCode == STILL_ACTIVE)
            {
                // Premature exit -- Kill the process (oj!)
                TerminateProcess(cmdProc.hProcess, (UINT)-1);
                hr = E_FAIL;
            }
            else
            {
                PRINTINFO("Child process ended with %d (%Xh)", subprocExitCode, subprocExitCode);
            }
        }

        // Call the worker threads to clean up
        Handles waitForThreads;
        if (VALID_HANDLE(hThInput))
        {
            waitForThreads.push_back(hThInput);
        }
        if (VALID_HANDLE(hThOutput))
        {
            waitForThreads.push_back(hThOutput);
        }
        if (!waitForThreads.empty())
        {
            SetEvent(ctx.evEndPipes);
            if (VALID_HANDLE(hThOutput))
            {
                CancelSynchronousIo(hThOutput); // hThOutput doesn't have a waitable event.
            }
            WaitForObjectsOfList(std::move(waitForThreads), TRUE, 10000U);
        }

        // Cleanup
        SAFE_CLOSE_HANDLE(cmdProc.hThread);
        SAFE_CLOSE_HANDLE(cmdProc.hProcess);
        UninitializeStartupInfo(&startupInfo);
        SAFE_CLOSE_HANDLE(hThInput);
        SAFE_CLOSE_HANDLE(hThOutput);
        ClosePseudoConsoleAndPipes(&ctx);
        SAFE_CLOSE_HANDLE(ctx.evEndMain);
        SAFE_CLOSE_HANDLE(ctx.evEndPipes);
        SAFE_CLOSE_HANDLE(ctx.evPipeIn);

        // In case of systematic error (not an error from the subprocess), stop right here.
        if (FAILED(hr))
        {
            PRINTERR(L"Execution of subprocess failed at some point -- %Xh", hr);
            loopAgain = false;
        }
        else if (subprocExitCode == 0U)
        {
            loopAgain = false;
        }
    } while (loopAgain);

    // Return systematic error or error of the child process
    return SUCCEEDED(hr) ? subprocExitCode : hr;
}
