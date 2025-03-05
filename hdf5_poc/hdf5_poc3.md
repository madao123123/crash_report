### POC3
# a heap-buffer-overflow vulnerability in hdf5-1.14.6
The HDF5 library contains a heap-based buffer overflow vulnerability in the `H5T__bit_copy` function. This vulnerability occurs during the bitwise copying of data in the HDF5 type conversion logic, where the library attempts to read 1 byte of data beyond the bounds of an allocated heap memory region. This could lead to memory corruption, application crashes, or potential exploitation for arbitrary code execution.

## 1.Environment
```
Ubuntu 20.04.6 LTS
hdf5-1.14.6
```
## 2.reproduction
```
git clone https://github.com/HDFGroup/hdf5.git

cd hdf5

export CC='clang'

export CFLAGS='-fsanitize=address'

export Cxx='clang++'

export CXXFLAGS='-fsanitize=address'

mkdir build && cd build

cmake ..

cmake --build . --config Release -j$(nproc)

./bin/h5dump /poc/hdf5/seed3
```



ASAN report :
```
==3854092==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x606000007136 at pc 0x7fb4d4a41d2a bp 0x7ffd10591050 sp 0x7ffd10591048
READ of size 1 at 0x606000007136 thread T0
    #0 0x7fb4d4a41d29 in H5T__bit_copy (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x186ad29)
    #1 0x7fb4d4a99cb3 in H5T__conv_b_b (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x18c2cb3)
    #2 0x7fb4d4a28592 in H5T_convert_with_ctx (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1851592)
    #3 0x7fb4d4a12893 in H5T_convert (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x183b893)
    #4 0x7fb4d3727c9a in H5A__read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x550c9a)
    #5 0x7fb4d513c473 in H5VL__native_attr_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1f65473)
    #6 0x7fb4d5077705 in H5VL__attr_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ea0705)
    #7 0x7fb4d50769e2 in H5VL_attr_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1e9f9e2)
    #8 0x7fb4d36d139f in H5A__read_api_common (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x4fa39f)
    #9 0x7fb4d36d051b in H5Aread (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x4f951b)
    #10 0x7fb4d59dcd0c in h5tools_dump_simple_mem (/home/fuzz/cve/hdf5/build/bin/libhdf5_tools.so.1000+0xd9d0c)
    #11 0x7fb4d59dbc5c in h5tools_dump_mem (/home/fuzz/cve/hdf5/build/bin/libhdf5_tools.so.1000+0xd8c5c)
    #12 0x7fb4d59ca29b in h5tools_dump_data (/home/fuzz/cve/hdf5/build/bin/libhdf5_tools.so.1000+0xc729b)
    #13 0x7fb4d59e7d5f in h5tools_dump_attribute (/home/fuzz/cve/hdf5/build/bin/libhdf5_tools.so.1000+0xe4d5f)
    #14 0x4d304c in dump_attr_cb (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4d304c)
    #15 0x7fb4d37382ba in H5A__attr_iterate_table (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x5612ba)
    #16 0x7fb4d43ad021 in H5O_attr_iterate_real (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x11d6021)
    #17 0x7fb4d43b5add in H5O__attr_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x11deadd)
    #18 0x7fb4d37443fc in H5A__iterate_common (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x56d3fc)
    #19 0x7fb4d374373d in H5A__iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x56c73d)
    #20 0x7fb4d5141800 in H5VL__native_attr_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1f6a800)
    #21 0x7fb4d507d765 in H5VL__attr_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ea6765)
    #22 0x7fb4d507ca60 in H5VL_attr_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ea5a60)
    #23 0x7fb4d36e1ea5 in H5Aiterate2 (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x50aea5)
    #24 0x4d33a7 in attr_iteration (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4d33a7)
    #25 0x4dd1aa in dump_dataset (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4dd1aa)
    #26 0x4d59cf in dump_all_cb (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4d59cf)
    #27 0x7fb4d403e1c5 in H5G__iterate_cb (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xe671c5)
    #28 0x7fb4d407f0ac in H5G__node_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xea80ac)
    #29 0x7fb4d37914ce in H5B__iterate_helper (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x5ba4ce)
    #30 0x7fb4d3790182 in H5B_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x5b9182)
    #31 0x7fb4d40addd7 in H5G__stab_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xed6dd7)
    #32 0x7fb4d4090b11 in H5G__obj_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xeb9b11)
    #33 0x7fb4d403ce07 in H5G_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xe65e07)
    #34 0x7fb4d42d6d54 in H5L_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10ffd54)
    #35 0x7fb4d516c6c6 in H5VL__native_link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1f956c6)
    #36 0x7fb4d50ca5e5 in H5VL__link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ef35e5)
    #37 0x7fb4d50c98e0 in H5VL_link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ef28e0)
    #38 0x7fb4d42a4622 in H5L__iterate_api_common (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10cd622)
    #39 0x7fb4d42a3269 in H5Literate2 (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10cc269)
    #40 0x4d3599 in link_iteration (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4d3599)
    #41 0x4dada6 in dump_group (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4dada6)
    #42 0x4d439e in dump_all_cb (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4d439e)
    #43 0x7fb4d403e1c5 in H5G__iterate_cb (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xe671c5)
    #44 0x7fb4d407f0ac in H5G__node_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xea80ac)
    #45 0x7fb4d37914ce in H5B__iterate_helper (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x5ba4ce)
    #46 0x7fb4d3790182 in H5B_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x5b9182)
    #47 0x7fb4d40addd7 in H5G__stab_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xed6dd7)
    #48 0x7fb4d4090b11 in H5G__obj_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xeb9b11)
    #49 0x7fb4d403ce07 in H5G_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xe65e07)
    #50 0x7fb4d42d6d54 in H5L_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10ffd54)
    #51 0x7fb4d516c6c6 in H5VL__native_link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1f956c6)
    #52 0x7fb4d50ca5e5 in H5VL__link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ef35e5)
    #53 0x7fb4d50c98e0 in H5VL_link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ef28e0)
    #54 0x7fb4d42a4622 in H5L__iterate_api_common (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10cd622)
    #55 0x7fb4d42a3269 in H5Literate2 (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10cc269)
    #56 0x4d3599 in link_iteration (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4d3599)
    #57 0x4dada6 in dump_group (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4dada6)
    #58 0x4c89bb in main (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4c89bb)
    #59 0x7fb4d2e4f082 in __libc_start_main /build/glibc-FcRMwW/glibc-2.31/csu/../csu/libc-start.c:308:16
    #60 0x41ec1d in _start (/home/fuzz/cve/hdf5/build/bin/h5dump+0x41ec1d)

Address 0x606000007136 is a wild pointer.
SUMMARY: AddressSanitizer: heap-buffer-overflow (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x186ad29) in H5T__bit_copy
Shadow bytes around the buggy address:
  0x0c0c7fff8dd0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c0c7fff8de0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c0c7fff8df0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c0c7fff8e00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c0c7fff8e10: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0x0c0c7fff8e20: fa fa fa fa fa fa[fa]fa fa fa fa fa fa fa fa fa
  0x0c0c7fff8e30: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c0c7fff8e40: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c0c7fff8e50: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c0c7fff8e60: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c0c7fff8e70: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==3854092==ABORTING
```
the POC file is:

## 3.finder
Teng Zhang, Mingxuan Liu, Chengsiyuan Yang, Heng Zhang, Hao Liu,Yaoliang Zhang,Dawei Guo , Hang Liu(all from NPU Unmanned Systems Safety Laboratory)