
The program `level0` takes command-line arguments as input. When executed without any arguments, it results in a segmentation fault:

```
level0@RainFall:~$ ./level0
Segmentation fault (core dumped)
```

When executed with arbitrary arguments, it outputs "No !":

```
level0@RainFall:~$ ./level0 sfs
No !
level0@RainFall:~$ ./level0 hello
No !
```

To better understand the program's behavior, we will analyze it using a debugger (`gdb`) and disassemble its code.

---

#### **3. Tools Used**
- **GDB (GNU Debugger):** To debug and analyze the program.

---

#### **4. Vulnerability Analysis**
```
gdb -> b main
gdb -> run 
gdb -> disassemble
```
Using `gdb`, we set a breakpoint at the `main` function and analyzed the disassembled code:
```
Dump of assembler code for function main:
   0x08048ec0 <+0>:	push   ebp
   0x08048ec1 <+1>:	mov    ebp,esp
=> 0x08048ec3 <+3>:	and    esp,0xfffffff0
   0x08048ec6 <+6>:	sub    esp,0x20
   0x08048ec9 <+9>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048ecc <+12>:	add    eax,0x4
   0x08048ecf <+15>:	mov    eax,DWORD PTR [eax]
   0x08048ed1 <+17>:	mov    DWORD PTR [esp],eax
   0x08048ed4 <+20>:	call   0x8049710 <atoi>
   0x08048ed9 <+25>:	cmp    eax,0x1a7
   0x08048ede <+30>:	jne    0x8048f58 <main+152>
   0x08048ee0 <+32>:	mov    DWORD PTR [esp],0x80c5348
   0x08048ee7 <+39>:	call   0x8050bf0 <strdup>
   0x08048eec <+44>:	mov    DWORD PTR [esp+0x10],eax
   0x08048ef0 <+48>:	mov    DWORD PTR [esp+0x14],0x0
   0x08048ef8 <+56>:	call   0x8054680 <getegid>
   0x08048efd <+61>:	mov    DWORD PTR [esp+0x1c],eax
   0x08048f01 <+65>:	call   0x8054670 <geteuid>
   0x08048f06 <+70>:	mov    DWORD PTR [esp+0x18],eax
   0x08048f0a <+74>:	mov    eax,DWORD PTR [esp+0x1c]
   0x08048f0e <+78>:	mov    DWORD PTR [esp+0x8],eax
   0x08048f12 <+82>:	mov    eax,DWORD PTR [esp+0x1c]
   0x08048f16 <+86>:	mov    DWORD PTR [esp+0x4],eax
   0x08048f1a <+90>:	mov    eax,DWORD PTR [esp+0x1c]
   0x08048f1e <+94>:	mov    DWORD PTR [esp],eax
   0x08048f21 <+97>:	call   0x8054700 <setresgid>
   0x08048f26 <+102>:	mov    eax,DWORD PTR [esp+0x18]
   0x08048f2a <+106>:	mov    DWORD PTR [esp+0x8],eax
   0x08048f2e <+110>:	mov    eax,DWORD PTR [esp+0x18]
   0x08048f32 <+114>:	mov    DWORD PTR [esp+0x4],eax
   0x08048f36 <+118>:	mov    eax,DWORD PTR [esp+0x18]
   0x08048f3a <+122>:	mov    DWORD PTR [esp],eax
   0x08048f3d <+125>:	call   0x8054690 <setresuid>
   0x08048f42 <+130>:	lea    eax,[esp+0x10]
   0x08048f46 <+134>:	mov    DWORD PTR [esp+0x4],eax
   0x08048f4a <+138>:	mov    DWORD PTR [esp],0x80c5348
   0x08048f51 <+145>:	call   0x8054640 <execv>
   0x08048f56 <+150>:	jmp    0x8048f80 <main+192>
   0x08048f58 <+152>:	mov    eax,ds:0x80ee170
   0x08048f5d <+157>:	mov    edx,eax
   0x08048f5f <+159>:	mov    eax,0x80c5350
   0x08048f64 <+164>:	mov    DWORD PTR [esp+0xc],edx
   0x08048f68 <+168>:	mov    DWORD PTR [esp+0x8],0x5
   0x08048f70 <+176>:	mov    DWORD PTR [esp+0x4],0x1
   0x08048f78 <+184>:	mov    DWORD PTR [esp],eax
   0x08048f7b <+187>:	call   0x804a230 <fwrite>
   0x08048f80 <+192>:	mov    eax,0x0
   0x08048f85 <+197>:	leave  
   0x08048f86 <+198>:	ret    
End of assembler dump.
```

From the disassembly, we can observe the following:

## Explanation of assembly :
---------------------------
Now we see this assembly, and we found that it calls atoi at 0x08048ed4 <+20>, which is used to convert the argument to a number. The next instruction is at 0x08048ed9 <+25>, where it compares the value in eax with 0x1a7 (which is '423' in decimal). If they don't match, it jumps to 0x08048ede <+30> with the instruction jne (jump if not equal) to 0x8048f58 <main+152>.

```
Dump of assembler code for function main:
   0x08048ed4 <+20>:	call   0x8049710 <atoi>
   0x08048ed9 <+25>:	cmp    eax,0x1a7
   0x08048ede <+30>:	jne    0x8048f58 <main+152>
   ...
```

---------------------------

1. **Argument Handling:** The program retrieves the second command-line argument (`argv[1]`) and passes it to the `atoi` function at address `0x08048ed4`. This converts the string input into an integer.

2. **Comparison:** At address `0x08048ed9`, the program compares the result of `atoi` with the value `0x1a7` (which is `423` in decimal). If the values do not match, the program jumps to address `0x8048f58`.

3. **Jump Target:** At `0x8048f58`, the program writes "No !" to the output and exits.

This indicates that the program expects a specific numeric value as input. If the input matches `423`, the program continues execution; otherwise, it terminates with the message "No !".

---

#### **5. Solution**
Based on the analysis, the solution is straightforward:

- Provide the correct numeric value (`423`) as the first argument to the program.

```
level0@RainFall:~$ ./level0 423
```

If the input is correct, the program should execute /bin/sh
```
level0@RainFall:~$ ./level0 423
$ whoami
level1
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```
