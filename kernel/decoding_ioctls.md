[Home](https://plackyhacker.github.io)

# Decoding IOCTLs

I have been looking at a kernel mode driver CVE (CVE-2024-38041) relating to `appid.sys` (part of AppLocker). This driver requires `FILE_WRITE_ACCESS` which triggered me into understanding what an `IOCTL` code is and what I need to know as an amateur exploit developer.

# Introduction


[Home](https://plackyhacker.github.io)
