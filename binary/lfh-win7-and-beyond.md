[Home](https://plackyhacker.github.io)

# Low Fragmentation Heap Windows 7 and Beyond

It's a new year (2025) and I am still studying Use-after-free (UaF) bugs and the Low Fragmentation Heap. When I was preparing for the Advanced Windows Exploitation course I could not find a great deal of **basic** material explaining the heap in Windows. So... here are some basics!

## Introduction to the Windows Heap

We've all heard of the stack and the heap right? The stack is a memory region used to store local variables and function call data, such as the saved return address. The variables stored on the stack are known at compile-time; the size of them, their usage, location etc. This is very useful, but it does not cater for variables and memory allocations that are dynamic and required at runtime. Memory is allocated and freed dynamically at runtime in a memory region referred to as the heap.

In Windows, the heap manager is a software layer that resides on top of the virtual memory interfaces provided by the Windows kernel. This allows applications running in Windows to dynamically allocate and release memory via the Windows APIs such as `HeapAlloc` and `HeapFree`.

If you have written code in `C` or `C++`, you may have used functions such as `malloc` and `free` or keywords (in `C++`) such as `new` and `delete` to allocate and free virtual memory. In Windows these are higher-level abstractions that ultimately rely on the Windows APIs (depending upon how the runtime implements memory allocations).

Windows 10 introduced something called the segment heap but I'm not going to write about that, not today anyway!

### Front End Allocator

The front end allocator is used to serve small allocation requests and is built to optimise performance. 

The Low Fragmentation Heap (LFH) was introduced in Windows XP and minimises fragmentation by organising memory into **fixed-size blocks** and efficiently reusing them. These replaced lookaside lists which were much simpler, and stored freed memory blocks for quick reuse but they lacked the fragmentation management features of LFH.

### Back End Allocator

The back end allocator serves memory allocations when the front end allocator cannot; such as an exhaustion of chunks in the front end, the size of the request, or that LFH is not active.

## What is the LFH?

The LFH organises allocations into **chunks**, that are stored in **buckets**:

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
  char *alloc1 = (char *)HeapAlloc(GetProcessHeap(), 0, 0x18); 
  memset(alloc1, 0x41, 0xaf);

  // print the memory location and the string
  printf("Allocation 1 0x%p\n", alloc1);
  printf("Allocation 1 string: %s\n\n", alloc1);

  // free the allocation
  printf("Freeing allocation 1\n\n");
  free(alloc1);

  // this is a trivial Uaf bug
  printf("Allocation 1 string: %s\n\n", alloc1);
}
```

The code is trying to print the string from the freed memory, this prints random data (as the memory allocation has been freed):

<img width="1110" alt="Screenshot 2025-01-16 at 08 39 41" src="https://github.com/user-attachments/assets/e6fdc0d5-44ea-451b-bdff-6d7d0d8306f4" style="border: 1px solid black;"/>

Yes this is trivial, in a real-world example this might crash if it is dereferencing a function pointer (such as **vptr**) and present us with a code execution opportunity. I am looking to see if I can reallocate to the freed memory address, and if the technique differs between Windows 7 and Windows 10.

## Use After Free

Explain


Include examples (such as IE8).

Why allocating to a freed allocation wins.

## Windows 7 Allocation

Some Code

Some Testing

LIFO explain why

## Windows 10 Allocation

Test same code, crash!

Explain randomised allocations

Brute force

Code

Test

## A Real-world Example in IE8

MS013...

[Home](https://plackyhacker.github.io)
