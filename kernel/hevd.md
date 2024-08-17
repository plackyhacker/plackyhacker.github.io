# HEVD Type Confusion Exploit in Windows 2022

## Gathering Information

Typically the first stage in reverse engineering a driver is to understand how we can interact with it from user mode. Drivers register a **Symlink** which is effectively the ID used to communicate with the driver from user mode, they also register **dispatch routines**; in simple terms these are functions that execute the driver code when data is received from user mode.
