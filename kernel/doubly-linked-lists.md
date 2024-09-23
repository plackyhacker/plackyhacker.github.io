# Doubly-Linked Lists in the Windows Kernel

Recently I have been studying different Kernel structures and it suddenly occurred to me that there is a pattern used by Microsoft to impleemnt doubly-linked lists within their structures. I'm pretty sure this is common knowledge to a lot of people, but I thought I would put a brief post together explaining them... just in case, like me you need it.

## Why Should We Care?

If you have ever studied Kernel driver exploitation or even done a lab where a custom driver is used to get privilege escalation then you are probably familiar with token stealing shellcode. Now, you may have just copied and pasted the shellcode into your exploit but if you understand how the `System` process is enumerated then doesn't that feel a bit better?

If you didn't just copy and paste the sheelcode and you tried to understand it then you will have noticed that there is a doubly-linked list that you need to traverse until you find the `System` process. This is the `ActiveProcessLinks` field in the `_EPROCESS` structure.

## Doubly-Linked Lists

The next image will explain what a doubly-linked list looks like. It is simply a collection of `_LIST_ENTRY` structs, each containing a `Flink` (forward link), and a `Blink` (backwards link) field:

<img width="1429" alt="Screenshot 2024-09-23 at 20 20 31" src="https://github.com/user-attachments/assets/94743df7-75dd-470b-87b5-7b252ff0dcda">

The `Flink` contains a pointer to the next `_LIST_ENTRY` and the `Blink` contains a pointer to the previous `_LIST_ENTRY`. Also notice that they are circular, meaning the tail (last entry) has an `Flink` to the head (first entry) and vice-versa. All good so far.

Now the confusion (at least for me). If the doubly-linked list is inside an `_EPROCESS` structure, say the `ActiveProcessLinks` field, where is the field that points to the `_EPROCESS`?

## Doubly-Linked Lists in Structures

It turns out it isn't confusing at all, it's actually really easy to understand, I just didn't know until after observing a few of these lists it just occurde to me. **_Yeah I know!_**

<img width="1333" alt="Screenshot 2024-09-23 at 20 31 53" src="https://github.com/user-attachments/assets/2095981f-9818-4d23-9ead-0e62360a230c">

The address of the `Flink` field, and of course the `Blink` field are simply offsets of the `_EPROCESS` structure! That is the address of `_LIST_ENTRY` is inside the `_EPROCESS` structure at an offset, to traverse the link, say to get the next `_EPROCESS` we dereference the `Flink` and use that address minus the offset of `ActiveProcessLinks` to get the address of the next `_EPROCESS`.
