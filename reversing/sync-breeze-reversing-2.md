[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/reversing/sync-breeze-reversed)

# Sync Breeze Revisited Part 2

In the second parrt of my reverse engineering adventures I decided that I would trace the `Sync Breeze` instrcutions and try to locate the vulnerability. I already knew from the first chapter in the OSED course that the `username` field is vulnerable, but I still thought it a good idea to reverse the application and try to find the exact instructions that make it vulnerable.

I changed my approach slightly, I decided to create two different character pattersn for the `usernme` and `password` fields. This would allow me to trace them easier in memory. I assumed at some point the application is going to parse these values to process:

```python
username = b"A" * 100
password = b"B" * 100
content = b"username=" + username + b"&password=" + password
```
