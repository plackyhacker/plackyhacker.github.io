[Home](https://plackyhacker.github.io)

# Use After Free (UaF) Bugs and Virtual Function Tables

After some time away from study I have started going over the [OffSec Advanced Windows Exploitation](https://www.offsec.com/courses/exp-401/) courseware again. As I was going over the VMWare Escape chapter it wasn't initially clear **why** code execution was acheived by exploiting a known Use after Free (UaF) bug, well not to me anyway! The course does a great job explaining **how** to get code execution (and way beyond taking control of RIP) but I thought I would explore **why**. The bug used in the example was discovered in 2017, so it is an oldie, but it is a good case study of how code execution can be acheived from exploiting a UaF bug.

## What are UaF Bugs?

A UaF bug occurs when a program continues to access memory after it has been freed, leading to undefined behavior, crashes, or security vulnerabilities. The code within a program allocates memory on the heap, and at some point the program code will free that memory on the heap to avoid memory leaks. A UaF bug is when that freed memory location is accessed unintentionally through errors in the code. It is the job of a security researcher to find these UaF bugs before they can be exploited by the malicious actors.

# Polymorphism

To understand Virtual Function Tables (vftables) we first need to understand why they exist. Polymorphism in programming allows objects of different classes to be treated as objects of a common base class, this is supported in object-oriented languages such as `C++`, `C#`, and `Java`. For example:

<img width="636" alt="Screenshot 2024-12-07 at 17 50 36" src="https://github.com/user-attachments/assets/f65cb032-156e-4755-8da7-be33b219e1ea" style="border: 1px solid black;">

In the image **A** is the base class and **B** and **C** are the sub classes.

One of the advantages of polymorphism is code reuse, where the base class may implement a common function inherited by all sub classes. However, sub classes can also override these functions with their own implementation, with the option to call the super class function:

<img width="255" alt="Screenshot 2024-12-07 at 17 53 20" src="https://github.com/user-attachments/assets/6a215544-a118-40ec-b940-d2083a1c73ae" style="border: 1px solid black;">

In this image **B** overrides the base classes **func2()** function, but inherits **A**s **func1()** function.

In C++, polymorphism is primarily achieved through inheritance and virtual functions. At runtime, the appropriate function for an object is dynamically selected based on its **actual** type, enabling behaviour specific to derived classes. In our example:

```c++
A* a = new B();
a->func2();
```

Although the pointer `a` was declared as a pointer to an object of type `A`, it actually points to an object of type `B`, and `a->func2()` should call the implementation for `B::func2()`, and not `A::func2()`.

# Virtual Function Tables (vftables)

A vftable (or vtable) is a lookup table used in C++ to support polymorphism and is created whenever a class implements virtual functions. It stores pointers to virtual functions of a class, allowing objects to dynamically resolve function calls at runtime based on their actual type. Let's take a look at classes **A** and **B** again and show how their virtual function tables might look:

<img width="610" alt="Screenshot 2024-12-07 at 18 01 48" src="https://github.com/user-attachments/assets/58470747-a122-4d15-b2a3-5c02d1bb2f73" style="border: 1px solid black;">

Each class with virtual functions has a vftable (and only one per class, not a vftable for every instance of a class), and objects of that class store a pointer to it (called a vpointer). When a virtual function is called, the vftable is used to find and execute the correct implementation for the object's type. This mechanism enables dynamic dispatch, a key feature of object-oriented programming.

Dynamic dispatch is what enables an object that has been declared as a base type but has been assigned as a derived type.

# Virtual Pointers (vptr)

Virtual pointers (vptr) are simply pointers that point to a corresponding vftable, and each instantiation of a class will contain a pointer to the corresponding vftable, it is a _hidden_ member that has been added to each class that contains virtual functions (functions that can be overriden). This enables dynamic dispatching of the correct function based upon the type an object is. This will become clear in the UaF example soon. Here is an updated image to depict the addition of the vptr:

<img width="864" alt="Screenshot 2024-12-07 at 18 19 33" src="https://github.com/user-attachments/assets/27283dd2-7656-4b2b-b2e0-7f2d8dd22686" style="border: 1px solid black;">

So what has all this got to do with code execution on a UaF bug in VMWare, let's look at that next.

# The Use After Silence Bug

The term "Use After Silence" refers to a [UaF vulnerability](https://www.zerodayinitiative.com/blog/2017/6/26/use-after-silence-exploiting-a-quietly-patched-uaf-in-vmware) in VMware that was quietly patched without public disclosure. VMware backdoor commands are undocumented instructions allowing a guest OS to communicate with the host through a virtual machine. These commands enable features like clipboard sharing, drag-and-drop, and time synchronisation within VMware environments. This particular bug was triggered by issuing the following backdoor commands in sequence:

```
tools.capability.dnd_version
vmx.capability.dnd_version
tools.capability.dnd_version
vmx.capability.dnd_version
dnd.setGuestFileRoot AAAAA
```

The first four commands free a representation of a "dnd.setGuestFileRoot" object, along with it's vptr to a vftable. The fifth command tries to reference this object after it has been freed and attempts to execute a function pointed in the objects vftable. Because the object has been freed an exception is triggered and VMWare crashes.

To exploit the bug an attacker can brute force the low fragmentation heap (LFH) after the free (first four commands) but before the fifth command (which triggers the UaF). Brute forcing the LFH can reallocate an address pointing to a fake vftable and take control of code execution by hijacking the freed object with a fake vftable.

<img width="1373" alt="Screenshot 2024-12-08 at 11 15 12" src="https://github.com/user-attachments/assets/d8cb3a03-4e10-4ac1-b95d-9643ad00f471" style="border: 1px solid black;">

This doesn't explain **how** to exploit this bug (as in actual code), that is where the AWE course does a great job. I enjoyed taking a deeper look at the use after silence use case and it has helped me to understand the exploit a little bit more.

That is all, goodbye!

# Useful References

- [C++ Polymorphism, W3Schools](https://www.w3schools.com/cpp/cpp_polymorphism.asp)
- [Understandig Virtual Tables in C++, Pablo Arias](https://pabloariasal.github.io/2017/06/10/understanding-virtual-tables/)
- [USE-AFTER-SILENCE: EXPLOITING A QUIETLY PATCHED UAF IN VMWARE, Zero Day Initiative](https://www.zerodayinitiative.com/blog/2017/6/26/use-after-silence-exploiting-a-quietly-patched-uaf-in-vmware)

[Home](https://plackyhacker.github.io)
