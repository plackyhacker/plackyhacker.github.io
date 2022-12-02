[Home](https://plackyhacker.github.io)

# Finding Windows APIs for ROP Chaining with Python

**Note:** This article is aimed at people that understand what ROP and ASLR is. There is a good introduction here: [Hands Up! Give Us the Stack! This is a ROPpery](https://connormcgarr.github.io/ROP/)

Just take me to the script: [find-win32apis.py](https://github.com/plackyhacker/plackyhacker.github.io/blob/master/code/find-win32apis.py)

I was recently reading [Playing ROP'em COP'em Robots with WriteProcessMemory()](https://connormcgarr.github.io/ROP2/) by Connor McGarr as part of my OSED studies. And whilst the entire article is a good read, there is also a little gem about a quarter in to the article which shows how to find Win32 API references using Windbg.

## ASLR

Here's the problem; the built in Windows modules (particularly kernel32.dll) are all compiled with ASLR (address space layout randomization). ASLR is used to radnomize the address space of modules upon each Windows reboot. The objective is to make it difficult to exploit stack based buffer overflows without knowing the address space of usable instructions, such as `jmp esp`.

Why do we care about this if we are using ROP (return oriented programming). Isn't ROP used to bypass DEP (data execution prevention)? **Yes it is!** But we need to use one of the Win32 APIs to change the memory protection in order to execute our shellcode on the stack. If we don't know the memory address of the Win32 APIs we can't call them using ROP.

Other modules need to reference the Win32 APIs in order to use them, that's where the IAT comes in. If we can read the import address table of a non-ASLR module at runtime we can find the dynamic address of the Win32 API.

Furthermore, if there is no entry in the IAT for the API we want to reference, we can find an entry for another API in kernel32 and then simply find the offset of the target API in kernel32. Easy!

## Python

If you want further background information, read Connor's explanation. I wrote a simple Python script to automate this in Windbg, using PYKD. The Windows User Mode Exploit Development (EXP-301) course shows how to find references to Win32 APIs in ASLR modules in the IAT (import address table) of non-ASLR modules.

<img width="972" alt="Screenshot 2022-12-02 at 07 59 50" src="https://user-images.githubusercontent.com/42491100/205244386-6c6c41ea-6296-446f-b5c3-36e6468475f6.png">

You might find out the hard way... you can't always rely on IDA. ;-)

The script: [find-win32apis.py](https://github.com/plackyhacker/plackyhacker.github.io/blob/master/code/find-win32apis.py)

[Home](https://plackyhacker.github.io)
