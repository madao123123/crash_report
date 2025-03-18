# a heap-use-after-free vulnerability in jhead 3.08
A heap-use-after-free vulnerability was discovered in jhead within the ProcessFile function in the jhead.c file. The issue arises when processing a crafted JPEG file, where a 19-byte write operation via memcpy targets a previously freed memory region. The freed memory was allocated and later reallocated (and possibly invalidated) by CheckSectionsAllocated in jpgfile.c during ReadJpegSections. This occurs due to improper lifecycle management of memory buffers used for JPEG section data. An attacker could exploit this by supplying a malicious file, leading to a denial of service (application crash) or potential code execution via memory corruption.

## 1.Environment
```
Ubuntu 20.04.6 LTS
jhead 3.08
```
## 2.reproduction
```
git clone https://github.com/Matthias-Wandel/jhead.git                  
cd jhead                                                                     
AFL_USE_ASAN=1 CC=afl-gcc make
./jhead jhead_input                        
```
ASAN report :
``
==3490493==ERROR: AddressSanitizer: heap-use-after-free on address 0x60b000000200 at pc 0x7f35f110b58d bp 0x7fffa92b2d10 sp 0x7fffa92b24b8
WRITE of size 19 at 0x60b000000200 thread T0
    #0 0x7f35f110b58c in __interceptor_memcpy ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:790
    #1 0x55c4cb4a0cd8 in ProcessFile jhead.c:1200
    #2 0x55c4cb49872c in main jhead.c:1805
    #3 0x7f35f0d53082 in __libc_start_main ../csu/libc-start.c:308
    #4 0x55c4cb49acdd in _start (/home/fuzz/jhead_asan/jhead+0x12cdd)

0x60b000000210 is located 0 bytes to the right of 112-byte region [0x60b0000001a0,0x60b000000210)
freed by thread T0 here:
    #0 0x7f35f117dc3e in __interceptor_realloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cc:163
    #1 0x55c4cb4a6e93 in CheckSectionsAllocated jpgfile.c:107
    #2 0x55c4cb4a6e93 in ReadJpegSections jpgfile.c:139

previously allocated by thread T0 here:
    #0 0x7f35f117dc3e in __interceptor_realloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cc:163
    #1 0x55c4cb4a6e93 in CheckSectionsAllocated jpgfile.c:107
    #2 0x55c4cb4a6e93 in ReadJpegSections jpgfile.c:139

SUMMARY: AddressSanitizer: heap-use-after-free ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:790 in __interceptor_memcpy
Shadow bytes around the buggy address:
  0x0c167fff7ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c167fff8000: fa fa fa fa fa fa fa fa fd fd fd fd fd fd fd fd
  0x0c167fff8010: fd fd fd fd fd fa fa fa fa fa fa fa fa fa 00 00
  0x0c167fff8020: 00 00 00 00 00 00 00 00 00 00 00 fa fa fa fa fa
  0x0c167fff8030: fa fa fa fa fd fd fd fd fd fd fd fd fd fd fd fd
=>0x0c167fff8040:[fd]fd fa fa fa fa fa fa fa fa fd fd fd fd fd fd
  0x0c167fff8050: fd fd fd fd fd fd fd fa fa fa fa fa fa fa fa fa
  0x0c167fff8060: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c167fff8070: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c167fff8080: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c167fff8090: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
  Shadow gap:              cc
==3490493==ABORTING

```
the POC file is:[poc](https://github.com/madao123123/crash_report/tree/main/poc/jhead_input)

## 3.finder
Teng Zhang, Mingxuan Liu, Chengsiyuan Yang, Heng Zhang, Hao Liu,Yaoliang Zhang,Dawei Guo , Hang Liu(all from NPU Unmanned Systems Safety Laboratory)



