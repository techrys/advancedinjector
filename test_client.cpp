#include <windows.h>
#include <iostream>

#define IOCTL_ENUM_PROCESSES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

struct PROCESS_INFO {
    ULONG Pid;
    WCHAR Name[260];
};

struct MEMORY_REQUEST {
    ULONG TargetPid;
    PVOID Address;
    SIZE_T Size;
    UCHAR Data[1];
};

int main() {
    HANDLE hDevice = CreateFileW(L"\\\\.\\TestCapabilities", GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open driver: " << GetLastError() << std::endl;
        return 1;
    }

    // Test 1: Enumerate processes
    PROCESS_INFO ProcessList[100];
    DWORD BytesReturned;
    if (DeviceIoControl(hDevice, IOCTL_ENUM_PROCESSES, NULL, 0, ProcessList, sizeof(ProcessList),
        &BytesReturned, NULL)) {
        ULONG Count = BytesReturned / sizeof(PROCESS_INFO);
        std::wcout << L"Found " << Count << L" processes:\n";
        for (ULONG i = 0; i < Count; i++) {
            std::wcout << L"PID: " << ProcessList[i].Pid << L", Name: " << ProcessList[i].Name << L"\n";
        }
    }

    // Test 2: Read memory (example: read 4 bytes from a process)
    MEMORY_REQUEST ReadReq = { 1234, (PVOID)0x7FF712345678, 4 }; // Replace PID and Address
    UCHAR ReadBuffer[4];
    if (DeviceIoControl(hDevice, IOCTL_READ_MEMORY, &ReadReq, sizeof(ReadReq), ReadBuffer, sizeof(ReadBuffer),
        &BytesReturned, NULL)) {
        std::cout << "Read memory: ";
        for (DWORD i = 0; i < BytesReturned; i++) {
            std::cout << std::hex << (int)ReadBuffer[i] << " ";
        }
        std::cout << std::dec << "\n";
    }
    else {
        std::cerr << "Read failed: " << GetLastError() << std::endl;
    }

    // Test 3: Write memory (example: write 4 bytes)
    UCHAR WriteData[] = { 0x90, 0x90, 0x90, 0x90 }; // NOPs
    MEMORY_REQUEST WriteReq = { 1234, (PVOID)0x7FF712345678, 4 };
    memcpy(WriteReq.Data, WriteData, sizeof(WriteData));
    if (!DeviceIoControl(hDevice, IOCTL_WRITE_MEMORY, &WriteReq, sizeof(WriteReq) + sizeof(WriteData) - 1,
        NULL, 0, &BytesReturned, NULL)) {
        std::cerr << "Write failed: " << GetLastError() << std::endl;
    }
    else {
        std::cout << "Write succeeded\n";
    }

    CloseHandle(hDevice);
    return 0;
}