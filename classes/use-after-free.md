[Home](https://plackyhacker.github.io)

# Use After Free (UaF) Bugs and Virtual Function Tables

After some time away from study I have started going over the [OffSec Advanced Windows Exploitation](https://www.offsec.com/courses/exp-401/) courseware again. As I was going over the VMWare Escape chapter it wasn't initially clear **why** code execution was acheived by exploiting a known Use after Free (UaF) bug. The course does a great job explaining **how** to get code execution (and way beyond taking control of RIP) but I thought I would expand on the **why**. The bug used in the example was discovered in 2017 but is a good case study of how code execution can be acheived from exploiting a UaF bug.

As I wrote this I was extremely careful not to breach any non-disclosure agreements or copyright infringements with [OffSec](https://www.offsec.com), I have used open source references throughout.

## What are UaF Bugs?

# Polymorphism

To understand Virtual Function Tables (vftables) we first need to understand why they exist. Polymorphism in programming allows objects of different classes to be treated as objects of a common base class, this is supported in object-oriented languages such as `C++`, `C#`, and `Java`. For example:

<img width="716" alt="Screenshot 2024-12-07 at 09 24 24" src="https://github.com/user-attachments/assets/0ebdb844-40da-4074-ad0d-c0640b81be4a">

One of the advantages of polymorphism is code reuse, where the base class may implement a common function inherited by all sub-classes. However, sub-classes can also override these functions with their own implementation, with the option to call the super-class function.

In C++, polymorphism is primarily achieved through inheritance and virtual functions. At runtime, the appropriate function for an object is dynamically selected based on its actual type, enabling behavior specific to derived classes. For example, a base class `Animal` may have a virtual `speak()` function (yeah I know animals can't speak), and derived classes like `Cat` or `Dog` override it, providing their unique implementations. This flexibility simplifies code reuse and extensibility.

# Virtual Function Tables (vftables)

A vftable is a lookup table used in C++ to support polymorphism and is created whenever a class implements virtual functions. It stores pointers to virtual functions of a class, allowing objects to dynamically resolve function calls at runtime based on their actual type.

Each class with virtual functions has a vftable, and objects of that class store a pointer to it. When a virtual function is called, the vftable is used to find and execute the correct implementation for the object's type. This mechanism enables dynamic dispatch, a key feature of object-oriented programming.

# Virtual Pointers (vpointers)

So what has all this got to do with code execution on a UaF bug in VMWare, let's look at that next.

# The Use After Silence Bug


# Useful References

- [C++ Polymorphism, W3Schools](https://www.w3schools.com/cpp/cpp_polymorphism.asp)
- [Understandig Virtual Tables in C++, Pablo Arias](https://pabloariasal.github.io/2017/06/10/understanding-virtual-tables/)
- [USE-AFTER-SILENCE: EXPLOITING A QUIETLY PATCHED UAF IN VMWARE, Zero Day Initiative]([https://www.zerodayinitiative.com/blog/2017/6/26/use-after-silence-exploiting-a-quietly-patched-uaf-in-vmware](https://www.zerodayinitiative.com/blog/2017/6/26/use-after-silence-exploiting-a-quietly-patched-uaf-in-vmware))

[Home](https://plackyhacker.github.io)
