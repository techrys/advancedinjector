<div align="center"> <h1>Kernel-Mode DLL Injector</h1> <p><em>Advanced Anti-Cheat Testing for Game Development</em></p> <img src="https://img.shields.io/badge/Windows-11-blue?style=flat-square&logo=windows" alt="Windows 11"> <img src="https://img.shields.io/badge/Language-C++-green?style=flat-square" alt="C++"> <img src="https://img.shields.io/badge/License-MIT-orange?style=flat-square" alt="MIT License"> </div>
🚀 Overview

The Kernel-Mode DLL Injector is a cutting-edge tool built in C++ to test anti-cheat systems in game development. Targeting Windows 11, it uses kernel-level techniques to inject DLLs into processes, challenging modern anti-cheats like BattlEye and EAC.

    Components:
        modern_injector.sys: Kernel driver for injection.
        loader.exe: User-mode utility to trigger it.
    Purpose: Research and anti-cheat validation.

🛠️ How It Works

This injector leverages advanced kernel techniques:

    Payload Encryption: XOR-encrypts the DLL to evade static detection.
    Manual Mapping: Maps the DLL directly into the target process’s memory.
    Thread Hijacking: Executes DllMain via an existing thread, avoiding new thread creation.
    Stealth: Bypasses user-mode hooks with kernel memory operations.

Perfect for simulating sophisticated injection methods in a controlled environment.
📋 Prerequisites

    OS: Windows 11 (23H2+, Build 22631.xxx)
    IDE: Visual Studio 2022
    Tools: WDK 10.0.26100.2454, Windows SDK 10.0.26100.x
    Privileges: Admin access

📂 Project Structure
text
├── kernelmode/
│   ├── modern_injector.cpp    # Kernel driver source
│   └── x64/Release/           # Output: modern_injector.sys
├── loader/
│   ├── loader.cpp            # User-mode loader source
│   └── x64/Release/           # Output: loader.exe
└── README.md                 # Documentation
🔧 Compilation
1. Environment Setup

    Install Visual Studio 2022: Include "Desktop development with C++".
    Add WDK:
        Download WDK 10.0.26100.2454.
        Run wdksetup.exe → Install with matching SDK.

2. Build the Driver (.sys)

    Open kernelmode/kernelmode.vcxproj or create an "Empty WDM Driver" project.
    Add modern_injector.cpp to "Source Files".
    Configure:
        Configuration Type: Driver
        Target Name: modern_injector
        Output File: $(OutDir)\modern_injector.sys
        Release | x64
    Build: Build > Rebuild Solution.

3. Build the Loader (.exe)

    Open loader/loader.vcxproj or create a "Console App".
    Add loader.cpp.
    Set: Release | x64.
    Build: Build > Rebuild Solution.

▶️ Running

    Enable Test Signing:
    cmd

bcdedit /set testsigning on
Reboot.
Load Driver (Admin CMD):
cmd

    sc create ModernInjector binPath="path\to\modern_injector.sys" type=kernel
    sc start ModernInjector
    Run Loader:
        Edit loader.cpp: Set target PID and DLL path.
        Rebuild → Run loader.exe as Admin.

⚠️ Troubleshooting

    Linker Errors (LNK1169): Ensure only modern_injector.cpp in driver project; clean and rebuild.
    Wrong Output: Verify Configuration Type is Driver for .sys.
    Driver Load Fails: Check test signing; review Event Viewer logs.

🤝 Contributing

    Fork → Modify → Pull Request.
    Open issues for bugs or enhancements.

📜 License

MIT License – For testing only. Use responsibly in development environments.
<div align="center"> <p><strong>Built for innovation, tested with precision.</strong></p> </div>
