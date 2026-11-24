#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>

#include <string>
#include <vector>

namespace {
constexpr wchar_t kServiceName[] = L"HawkEndpointAgent";
SERVICE_STATUS_HANDLE gStatusHandle = nullptr;
SERVICE_STATUS gStatus{};
HANDLE gStopEvent = nullptr;
HANDLE gChildProcess = nullptr;
HANDLE gChildJob = nullptr;

void Report(DWORD state, DWORD error = NO_ERROR, DWORD waitHint = 0) {
    gStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    gStatus.dwCurrentState = state;
    gStatus.dwWin32ExitCode = error;
    gStatus.dwWaitHint = waitHint;
    gStatus.dwControlsAccepted = state == SERVICE_RUNNING
        ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    SetServiceStatus(gStatusHandle, &gStatus);
}

std::wstring Quote(const std::wstring& value) {
    std::wstring result = L"\"";
    for (wchar_t character : value) {
        if (character == L'\"') result += L'\\';
        result += character;
    }
    return result + L"\"";
}

bool RuntimePath(std::wstring* path) {
    std::vector<wchar_t> buffer(32768);
    DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size()) return false;
    std::wstring module(buffer.data(), length);
    const auto separator = module.find_last_of(L"\\/");
    if (separator == std::wstring::npos) return false;
    *path = module.substr(0, separator + 1) + L"hawk-endpoint-agent-runtime.exe";
    return GetFileAttributesW(path->c_str()) != INVALID_FILE_ATTRIBUTES;
}

std::wstring ConfigPath() {
    int count = 0;
    LPWSTR* values = CommandLineToArgvW(GetCommandLineW(), &count);
    std::wstring result;
    if (values != nullptr) {
        for (int index = 1; index + 1 < count; ++index) {
            if (wcscmp(values[index], L"--config") == 0) {
                result = values[index + 1];
                break;
            }
        }
        LocalFree(values);
    }
    return result;
}

DWORD LaunchRuntime(const std::wstring& configPath) {
    std::wstring runtime;
    if (!RuntimePath(&runtime) || configPath.empty()) return ERROR_FILE_NOT_FOUND;
    std::wstring command = Quote(runtime) + L" --config " + Quote(configPath);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(
            runtime.c_str(), command.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &startup, &process)) {
        return GetLastError();
    }
    gChildJob = CreateJobObjectW(nullptr, nullptr);
    if (gChildJob == nullptr) {
        TerminateProcess(process.hProcess, ERROR_NOT_ENOUGH_MEMORY);
        CloseHandle(process.hThread); CloseHandle(process.hProcess);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(gChildJob, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) ||
        !AssignProcessToJobObject(gChildJob, process.hProcess)) {
        DWORD error = GetLastError();
        TerminateProcess(process.hProcess, error);
        CloseHandle(process.hThread); CloseHandle(process.hProcess);
        CloseHandle(gChildJob); gChildJob = nullptr;
        return error;
    }
    gChildProcess = process.hProcess;
    const DWORD resumeResult = ResumeThread(process.hThread);
    if (resumeResult == static_cast<DWORD>(-1)) {
        const DWORD error = GetLastError();
        TerminateProcess(process.hProcess, error);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        CloseHandle(gChildJob);
        gChildProcess = nullptr;
        gChildJob = nullptr;
        return error;
    }
    CloseHandle(process.hThread);
    return NO_ERROR;
}

void WINAPI ControlHandler(DWORD control) {
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        Report(SERVICE_STOP_PENDING, NO_ERROR, 5000);
        SetEvent(gStopEvent);
    }
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    gStatusHandle = RegisterServiceCtrlHandlerW(kServiceName, ControlHandler);
    if (gStatusHandle == nullptr) return;
    Report(SERVICE_START_PENDING, NO_ERROR, 10000);
    gStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (gStopEvent == nullptr) { Report(SERVICE_STOPPED, GetLastError()); return; }
    DWORD error = LaunchRuntime(ConfigPath());
    if (error != NO_ERROR) { CloseHandle(gStopEvent); Report(SERVICE_STOPPED, error); return; }
    Report(SERVICE_RUNNING);
    HANDLE waits[2] = {gStopEvent, gChildProcess};
    DWORD result = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
    const DWORD waitError = result == WAIT_FAILED ? GetLastError() : NO_ERROR;
    if (result == WAIT_OBJECT_0 && gChildJob != nullptr) TerminateJobObject(gChildJob, ERROR_OPERATION_ABORTED);
    DWORD childExit = NO_ERROR;
    if (gChildProcess != nullptr) GetExitCodeProcess(gChildProcess, &childExit);
    DWORD serviceError = NO_ERROR;
    if (result == WAIT_OBJECT_0 + 1) {
        serviceError = childExit != NO_ERROR ? childExit : ERROR_PROCESS_ABORTED;
    } else if (result == WAIT_FAILED) {
        serviceError = waitError;
    } else if (result != WAIT_OBJECT_0) {
        serviceError = ERROR_INVALID_STATE;
    }
    if (gChildProcess != nullptr) CloseHandle(gChildProcess);
    if (gChildJob != nullptr) CloseHandle(gChildJob);
    CloseHandle(gStopEvent);
    gChildProcess = nullptr; gChildJob = nullptr; gStopEvent = nullptr;
    Report(SERVICE_STOPPED, serviceError);
}
}  // namespace

int wmain() {
    SERVICE_TABLE_ENTRYW table[] = {
        {const_cast<LPWSTR>(kServiceName), ServiceMain},
        {nullptr, nullptr},
    };
    return StartServiceCtrlDispatcherW(table) ? 0 : static_cast<int>(GetLastError());
}
