# Remote Named Pipe Impersonation PoC

This project demonstrates a proof-of-concept (PoC) for user-to-user impersonation in Active Directory (AD) environments by abusing remote named pipes. It specifically addresses the challenge of impersonating standard users, which existing tools often fail to do due to privilege limitations. By leveraging a rogue virtual machine (VM) with SYSTEM privileges, this PoC enables impersonation of both administrators and standard users, overcoming common errors like `0xc0000142`.

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Windows Installation](#windows-installation)
  - [Cross-Compilation from Linux](#cross-compilation-from-linux)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Mitigation Strategies](#mitigation-strategies)
- [License](#license)

## Introduction
Named pipes in Windows can be a powerful yet overlooked attack vector in Active Directory environments. This PoC showcases how remote named pipe abuse can be used to impersonate users, including standard users who lack elevated privileges. Existing tools often fail to impersonate standard users due to insufficient environmental privileges, resulting in errors like `0xc0000142` (application unable to start correctly). This project fills that gap, providing a reliable method for user-to-user impersonation, making it invaluable for penetration testers and security researchers.

## Features
- Impersonates both administrative and standard AD users, including those without elevated privileges.
- Overcomes the `0xc0000142` error commonly encountered when attempting to impersonate standard users.
- Utilizes a rogue VM running with SYSTEM privileges to handle token creation and environment setup.
- Lightweight and focused on demonstrating the exploit for educational and testing purposes.

## Requirements
To run this PoC, you’ll need:
- A Windows Server 2019 (or similar) Active Directory environment.
- A rogue VM configured with SYSTEM privileges (e.g., via a compromised admin account).
- Visual Studio 2019 (or later) with C++ support installed (for Windows compilation).
- Basic knowledge of AD, named pipes, and Windows security concepts.

## Installation

### Windows Installation
Follow these steps to set up the PoC on a Windows machine:
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/remote-named-pipe-impersonation-poc.git
   ```
2. Open the project in Visual Studio.
3. Ensure the C++ compiler is set up (e.g., MSVC).
4. Build the solution in Release mode.

### Cross-Compilation from Linux
If you're working on a Linux machine and want to compile this project to run on Windows, you can use the MinGW-w64 cross-compiler. This allows you to generate a Windows executable without needing a Windows environment.

#### Prerequisites
- Install the `x86_64-w64-mingw32-g++` compiler on your Linux system. For example:
  - On Ubuntu: `sudo apt-get install g++-mingw-w64-x86-64`
  - On Fedora: `sudo dnf install mingw64-gcc-c++`

#### Compilation Command
Run the following command to compile `pipeserver_poc.cpp` into a Windows executable:

```bash
x86_64-w64-mingw32-g++ \
  -std=c++17 \
  -O2 \
  -Wall \
  -municode \
  -static \
  -static-libgcc \
  -static-libstdc++ \
  pipeserver_poc.cpp \
  -o pipeserver_poc.exe \
  -lws2_32 \
  -ladvapi32 \
  -luserenv \
  -lkernel32
```

#### Command Breakdown
- `x86_64-w64-mingw32-g++`: Cross-compiler targeting 64-bit Windows.
- `-std=c++17`: Uses the C++17 standard.
- `-O2`: Optimizes the code for better performance.
- `-Wall`: Enables all compiler warnings.
- `-municode`: Supports Unicode for Windows APIs.
- `-static`, `-static-libgcc`, `-static-libstdc++`: Links libraries statically to avoid runtime dependencies.
- `pipeserver_poc.cpp`: The source file to compile.
- `-o pipeserver_poc.exe`: Names the output executable.
- `-lws2_32`, `-ladvapi32`, `-luserenv`, `-lkernel32`: Links required Windows libraries for networking, security, user environment, and kernel functions.

This produces a standalone `pipeserver_poc.exe` that can be run on Windows without additional dependencies.

## Usage
1. **Deploy the Rogue VM**:
   - Set up a VM in your AD environment with SYSTEM privileges.
   - Ensure the VM can communicate with the target AD domain.
2. **Redirect Named Pipe Requests**:
   - Configure the target system to redirect named pipe requests to the rogue VM (e.g., via LLMNR or NetBIOS spoofing).
3. **Run the PoC**:
   - Execute the compiled binary on the rogue VM:
     ```cmd
     pipeserver_poc.exe
     ```
   - The PoC will create a named pipe and wait for connections from standard or administrative users.
4. **Interpret Results**:
   - Check the console output for successful impersonation details, including the user token obtained and any processes launched in their context.

## How It Works
The PoC operates by:
1. Creating a named pipe on the rogue VM with permissive access control lists (ACLs), allowing connections from any user.
2. Using SYSTEM privileges to capture and manipulate incoming named pipe requests from the target AD environment.
3. Properly setting up the token and environment to avoid errors like `0xc0000142`, which occurs due to insufficient session or token rights when impersonating standard users.
4. Impersonating the connecting user, enabling actions to be performed as that user within the AD domain.

This approach overcomes the limitations of existing tools by ensuring that even standard users can be impersonated without requiring elevated privileges on their part.

## Mitigation Strategies
To protect against this type of attack:
- Harden named pipe ACLs to restrict access to trusted entities only.
- Disable LLMNR and NetBIOS to prevent request redirection.
- Monitor named pipe creation and activity for suspicious behavior.
- Apply least privilege principles to minimize the impact of compromised accounts.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.