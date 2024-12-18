[Home](https://plackyhacker.github.io)

# Mixing it up: ROP and COP

We all know what ROP chains are right? No? If you want to do binary exploitation of any kind then you need to understand ROP, this post is about COP so I'm going to be lazy and post a link: [Return-oriented Programming](https://en.wikipedia.org/wiki/Return-oriented_programming).

Studying for my OffSec Exploitation Expert (OSEE) exam, more specifically the VMWare escape use case, we find that one of the ROP chains contains a `call rsi` instruction. Becasue of the way `call` instructions work this presents a problemm as they modify the stack which disrupts the normal flow of a ROP chain. 

## The Problem


[Home](https://plackyhacker.github.io)
