# Shellcode Injection Techniques
A collection of C# shellcode injection techniques. All techniques use an AES encrypted meterpreter payload.

I will be building this project up as I learn, discover or develop more techniques.

**Note:** The project is not intended to be used as-is. If you are going to use any of the techniques there is a better chance of bypassing AV if you create a smaller, customised project with your chosen technique.

## Classic Injection
[ClassicInjection.cs](https://github.com/plackyhacker/Shellcode-Injection-Techniques/blob/master/ShellcodeInjectionTechniques/Techniques/ClassicInjection.cs) : This technique allocates memory in the target process, injects the shellcode and starts a new thread.

```
[+] Found process: 18244
[+] Using technique: ShellcodeInjectionTechniques.ClassicInjection
[+] VirtualAllocEx(), assigned: 0x1ACCD600000
[+] WriteProcessMemory(): 0x1ACCD600000
[+] CreateRemoteThread(): 0x1ACCD600000
```

## Thread Hijacking
[ThreadHijack.cs](https://github.com/plackyhacker/Shellcode-Injection-Techniques/blob/master/ShellcodeInjectionTechniques/Techniques/ThreadHijack.cs) : This technique hijacks a thread by injection code into the target process, suspends the hijacked thread, sets the instruction pointer (RIP) to our injected code and then resumes the thread.

```
[+] Found process: 16572
[+] Using technique: ShellcodeInjectionTechniques.ThreadHijack
[+] Found thread: 16180
[+] OpenThread() - Thread handle: 0x334
[+] VirtualAllocEx(), assigned: 0x211E4730000
[+] WriteProcessMemory(): 0x211E4730000
[+] SuspendThread(): 0x334
[+] GetThreadContext(): 0x334
[+] RIP is: 0x7FFA77D21104
[+] SetThreadContext(), RIP assigned: 0x211E4730000
[+] ResumeThread(): 0x334
```

## Process Hollowing
[ProcessHollow.cs](https://github.com/plackyhacker/Shellcode-Injection-Techniques/blob/master/ShellcodeInjectionTechniques/Techniques/ProcessHollow.cs) : This technique starts an executable in the suspended state (svchost.exe), finds the main thread entry point, injects our shellcode into it then resumes the thread.

```
[+] Using technique: ShellcodeInjectionTechniques.ProcessHollow
[+] CreateProcess(): C:\Windows\System32\svchost.exe
[+] Pointer to ImageBase: 0xD31E956010
[+] ReadProcessMemory(): 0xD31E956010
[+] ImageBase: 0x7FF6116C0000
[+] ReadProcessMemory(): 0x7FF6116C0000
[+] EntryPoint: 0xD31E956010
[+] WriteProcessMemory(): 0x7FF6116C4E80
[+] ResumeThread(): 0x454
```
