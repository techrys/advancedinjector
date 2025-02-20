#include <windows.h>
#include <iostream>

#define IOCTL_INJECT_DLL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

struct INJECTION_REQUEST {
    ULONG TargetPid;
    WCHAR DllPath[260];
};

int main() {
    HANDLE hDevice = CreateFileW(L"\\\\.\\ModernInjector", GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open driver: " << GetLastError() << std::endl;
        return 1;
    }

    INJECTION_REQUEST Request = { 0 };
    Request.TargetPid = 1234; // Replace with your game's PID
    wcscpy_s(Request.DllPath, L"C:\\path\\to\\your\\test.dll"); // Replace with DLL path

    DWORD BytesReturned;
    if (!DeviceIoControl(hDevice, IOCTL_INJECT_DLL, &Request, sizeof(Request),
        NULL, 0, &BytesReturned, NULL)) {
        std::cerr << "IOCTL failed: " << GetLastError() << std::endl;
    }
    else {
        std::cout << "DLL injection requested successfully!" << std::endl;
    }

    CloseHandle(hDevice);
    return 0;
}


