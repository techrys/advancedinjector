# advancedinjector
Kernel-Mode DLL Injector  A C++ kernel-level DLL injector for testing anti-cheat systems in game development on Windows 11. Features manual mapping, thread hijacking, and payload encryption to challenge modern kernel anti-cheats like BattlEye and EAC. Includes a kernel driver (.sys) and user-mode loader (.exe). For educational use only.

Kernel-Mode DLL Injector

A C++ kernel-level DLL injector for testing anti-cheat systems in game development on Windows 11.
Overview

    modern_injector.cpp: Kernel driver (.sys) that manually maps a DLL into a process.
    loader.cpp: User-mode app (.exe) to trigger injection.

How It Works

    Loader: Sends PID and DLL path to the driver via IOCTL.
    Driver: Encrypts DLL, maps it into the target process, and hijacks a thread to run DllMain.
    Stealth: Avoids user-mode APIs, uses kernel memory ops.

Prerequisites

    Windows 11
    Visual Studio 2022
    WDK 10.0.26100.2454
    Windows SDK 10.0.26100.x
    Admin access

Project Structure
text
kernelmode/
├── kernelmode.vcxproj
├── modern_injector.cpp
└── x64/Release/ (output: modern_injector.sys)
loader/
├── loader.vcxproj
├── loader.cpp
└── x64/Release/ (output: loader.exe)
README.md
Compilation
Setup

    Install Visual Studio 2022 with "Desktop development with C++".
    Add WDK:
        Download WDK 10.0.26100.2454.
        Run wdksetup.exe → Install with matching SDK.

Build Driver (.sys)

    Open kernelmode.vcxproj or create an "Empty WDM Driver" project.
    Add modern_injector.cpp to "Source Files".
    Properties:
        Configuration Type: Driver
        Target Name: modern_injector
        Output File: $(OutDir)\modern_injector.sys
        Config: Release, Platform: x64
    Build > Rebuild Solution.

Build Loader (.exe)

    Open loader.vcxproj or create a "Console App" project.
    Add loader.cpp.
    Config: Release, Platform: x64.
    Build > Rebuild Solution.

Running

    Enable test signing:
    text

bcdedit /set testsigning on
Reboot.
Load driver (Admin CMD):
text

    sc create ModernInjector binPath="path\to\modern_injector.sys" type=kernel
    sc start ModernInjector
    Run loader:
        Edit loader.cpp: Set PID and DLL path.
        Rebuild → Run loader.exe as Admin.

Troubleshooting

    LNK1169: Ensure only one .cpp in driver project; clean and rebuild.
    .exe Output: Set Configuration Type to Driver.
    Driver Fails: Verify test signing; check Event Viewer.

Contributing

Fork, edit, and PR. Report issues on GitHub.
License

For testing only—use responsibly. No warranty.
