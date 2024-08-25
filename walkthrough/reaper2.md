# VulnLab Reaper 2 Walkthrough

## Introduction

[Reaper 2](https://www.vulnlab.com/machines) was the second lab recommended to me for my [OffSec Advanced Windows Exploitation (AWE)](https://www.offsec.com/courses/exp-401/) preperations. It was written by [xct](https://x.com/xct_de) and is part of the training and labs offered by [VulnLab](https://vunlab.com). The lab was rated **Insane** and it didn't dissapoint!

The [wiki](https://wiki.vulnlab.com/guidance/insane/reaper2) for the lab gives several clues that definitely helped me on my journey to pwning it.

In this post I'm going to do something a little different. I am not going to post any full exploit code, and I am not going to write about the way I defeated the lab. I am going to write about how I would take on the lab now I know everything I have learned. So, this isn't going to be a walthrough you can follow, copy and paste a few things and beat the lab. It will act as a guide on how you can approach the lab, and write your own exploits to get `SYSTEM` access to **Reaper 2**.

I will be showing how this can all be done without using the clues given in in the [wiki](https://wiki.vulnlab.com/guidance/insane/reaper2). Let's go!

## Initial Access

### Reconnaissance

As with most labs you can start with an `nmap` scan to see what services are running on the target:

```
nmap reaper2.vulnlab.local -Pn -p- 
...
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49668/tcp open  unknown
```

It's a Windows operating system, as expected. It has the **RPC** and **SMB** ports open and it also has a web service running on **HTTP**, and Terminal Services (**RDP**).

Visiting the wensite we are presented with the following:

<img width="1498" alt="Screenshot 2024-08-25 at 13 43 24" src="https://github.com/user-attachments/assets/7d6cd890-2fde-4bbd-a7d3-b55ea71a54bc">

From here we can input some JavaScript and the **V8** engine will process it and display the output. We can test this with an input of `print(version());`, and we will get an output of `12.2.0 (candidate)`.

### Type Confusion Bug

### Exploitation

### Enumeration

## Privilege Escalation

### Enumeration

### Custom Driver

### Kernel Base Address Disclosure Bug

### Arbitrary Code Execution Bug

### Kernel Debugging

### Exploitation
