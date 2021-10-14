# Shellcode Injection Techniques
A collection of C# shellcode injection techniques. All techniques use an AES encrypted meterpreter payload.

I will be building this project up as I learn, discover or develop more techniques.

**Note:** The project is not intended to be used as-is. If you are going to use any of the techniques there is a better chance of bypassing AV if you create a smaller, customised project with your chosen technique.

## Thread Hijacking
[ThreadHijack](https://github.com/plackyhacker/Shellcode-Injection-Techniques/blob/master/ShellcodeInjectionTechniques/Techniques/ThreadHijack.cs) : This technique hijacks a thread by injection code into the target process, suspends the hijacked thread, sets the instruction pointer (RIP) to our injected code and then resumes the thread.
