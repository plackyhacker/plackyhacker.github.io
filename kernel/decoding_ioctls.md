[Home](https://plackyhacker.github.io)

# Decoding IOCTLs

I have been looking at a kernel mode driver CVE (CVE-2024-38041) relating to `appid.sys` (part of AppLocker). This driver requires `FILE_WRITE_ACCESS` which triggered me into understanding what an `IOCTL` code is and what I need to know as an amateur exploit developer.

# Introduction

An `IOCTL` has six elements to it:

- Common: `0x1` indicates a vendor assigned device type.
- Device Type: describes the type of device, commonly `FILE_DEVICE_UNKNOWN`.
- Function Code: < `0x800` reserved for Microsoft, > `0x7ff` vendor defined.
- Access: `FILE_ANY_ACCESS`, `FILE_READ_ACCESS`, `FILE_WRITE_ACCESS`, or `FILE_READ_ACCESS | FILE_WRITE_ACCESS`.
- Custom: `0x1` indicates a vendor assigned `IOCTL`.
- Method: `METHOD_BUFFERED`, `METHOD_IN_DIRECT`, `METHOD_OUT_DIRECT`, or `METHOD_NEITHER`.

# Example

The example `IOCTL` I was looking at was `0x22a014`, broken down this is:

- `0x22` = `FILE_DEVICE_UNKNOWN`.
- `0x805` = vendor defined (although it is a Microsoft driver).
- `0x2` = `FILE_WRITE_ACCESS`.
- `0x0` = `METHOD_BUFFERED`.

Looking at this you might think the `IOCTL` should equal `0x2280520`, but we all know that isn't how binary works... right?

Microsoft documents the `IOCTL` <a href="https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes" >layout</a>:

<img width="1095" height="139" alt="image" src="https://github.com/user-attachments/assets/be46d256-c043-4894-a612-973cc67b3cbc" />

Lets inspect the `IOCTL`:

```
0x22a014 = 00000000 00100010 10100000 00010100

0 000000000100010 10 1 00000000101 00
| |               |  | |           |
| |               |  | |           +- Method = 0x0
| |               |  | +------------- Function = 0x5          
| |               |  +--------------- Cutsom = 0x1
| |               +------------------ Access = 0x2         
| +---------------------------------- Device Type = 
```




[Home](https://plackyhacker.github.io)
