# melf - Mini ELF Header parser

### Building
Just type `make` in this directory.

### Example
```
$ ./melf melf
Magic   : 7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
Class                              : ELF64
Data                               : little-endian
Version                            : Current
OS/ABI                             : UNIX - System V
ABI version                        : 0
Type                               : DYN (Shared object)
Entry virtual address              : 0x10d0
Program header table's file offset : 64 bytes
Section header table's file offset : 15488 bytes
Flags                              : 0
Size of this ELF header            : 64 bytes
Size of program header table       : 56 bytes
Number of program header table     : 11
Size of section header's           : 64 bytes
Number of section header table     : 30
Section header table index         : 29
```
