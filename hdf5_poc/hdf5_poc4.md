# a heap-buffer-overflow vulnerability in hdf5-1.14.6
The HDF5 library contains a heap-based buffer overflow vulnerability in the `strndup` function, which is called by H5MM_strndup during the decoding of attribute metadata. This vulnerability occurs when the library attempts to read 5 bytes of data beyond the bounds of an allocated 320-byte heap memory region. This could lead to memory corruption, application crashes, or potential exploitation for arbitrary code execution.

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

./bin/h5dump /poc/hdf5/seed4
```


ASAN report :

```
==3900376==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x612000038100 at pc 0x000000431d51 bp 0x7fff531ecfb0 sp 0x7fff531ec768
READ of size 5 at 0x612000038100 thread T0
    #0 0x431d50 in strndup (/home/fuzz/cve/hdf5/build/bin/h5dump+0x431d50)
    #1 0x7f69f0ffec2c in H5MM_strndup (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1157c2c)
    #2 0x7f69f106a63f in H5O__attr_decode (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x11c363f)
    #3 0x7f69f105f2b0 in H5O__attr_shared_decode (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x11b82b0)
    #4 0x7f69f11ec913 in H5O__msg_iterate_real (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1345913)
    #5 0x7f69f040291b in H5A__compact_build_table (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x55b91b)
    #6 0x7f69f107cd1a in H5O_attr_iterate_real (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x11d5d1a)
    #7 0x7f69f1085add in H5O__attr_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x11deadd)
    #8 0x7f69f04143fc in H5A__iterate_common (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x56d3fc)
    #9 0x7f69f041373d in H5A__iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x56c73d)
    #10 0x7f69f1e11800 in H5VL__native_attr_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1f6a800)
    #11 0x7f69f1d4d765 in H5VL__attr_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ea6765)
    #12 0x7f69f1d4ca60 in H5VL_attr_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ea5a60)
    #13 0x7f69f03b1ea5 in H5Aiterate2 (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x50aea5)
    #14 0x4d33a7 in attr_iteration (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4d33a7)
    #15 0x4dd1aa in dump_dataset (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4dd1aa)
    #16 0x4d59cf in dump_all_cb (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4d59cf)
    #17 0x7f69f0d0e1c5 in H5G__iterate_cb (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xe671c5)
    #18 0x7f69f0d4f0ac in H5G__node_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xea80ac)
    #19 0x7f69f04614ce in H5B__iterate_helper (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x5ba4ce)
    #20 0x7f69f0460182 in H5B_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x5b9182)
    #21 0x7f69f0d7ddd7 in H5G__stab_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xed6dd7)
    #22 0x7f69f0d60b11 in H5G__obj_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xeb9b11)
    #23 0x7f69f0d0ce07 in H5G_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xe65e07)
    #24 0x7f69f0fa6d54 in H5L_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10ffd54)
    #25 0x7f69f1e3c6c6 in H5VL__native_link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1f956c6)
    #26 0x7f69f1d9a5e5 in H5VL__link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ef35e5)
    #27 0x7f69f1d998e0 in H5VL_link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ef28e0)
    #28 0x7f69f0f74622 in H5L__iterate_api_common (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10cd622)
    #29 0x7f69f0f73269 in H5Literate2 (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10cc269)
    #30 0x4d3599 in link_iteration (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4d3599)
    #31 0x4dada6 in dump_group (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4dada6)
    #32 0x4c89bb in main (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4c89bb)
    #33 0x7f69efb1f082 in __libc_start_main /build/glibc-FcRMwW/glibc-2.31/csu/../csu/libc-start.c:308:16
    #34 0x41ec1d in _start (/home/fuzz/cve/hdf5/build/bin/h5dump+0x41ec1d)

0x612000038100 is located 0 bytes to the right of 320-byte region [0x612000037fc0,0x612000038100)
allocated by thread T0 here:
    #0 0x49735d in malloc (/home/fuzz/cve/hdf5/build/bin/h5dump+0x49735d)
    #1 0x7f69f0c2e48f in H5FL__malloc (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xd8748f)
    #2 0x7f69f0c3108d in H5FL_blk_malloc (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xd8a08d)
    #3 0x7f69f10a9aa3 in H5O__chunk_deserialize (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1202aa3)
    #4 0x7f69f1096a7f in H5O__cache_deserialize (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x11efa7f)
    #5 0x7f69f05af097 in H5C__load_entry (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x708097)
    #6 0x7f69f0590ec0 in H5C_protect (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x6e9ec0)
    #7 0x7f69f043241f in H5AC_protect (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x58b41f)
    #8 0x7f69f11851bc in H5O_protect (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x12de1bc)
    #9 0x7f69f1194684 in H5O_get_info (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x12ed684)
    #10 0x7f69f0d2d576 in H5G__loc_info_cb (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xe86576)
    #11 0x7f69f0d99a7b in H5G__traverse_real (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xef2a7b)
    #12 0x7f69f0d976b6 in H5G_traverse (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xef06b6)
    #13 0x7f69f0d2cacb in H5G_loc_info (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xe85acb)
    #14 0x7f69f1e432f6 in H5VL__native_object_get (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1f9c2f6)
    #15 0x7f69f1da3ee5 in H5VL__object_get (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1efcee5)
    #16 0x7f69f1da31c0 in H5VL_object_get (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1efc1c0)
    #17 0x7f69f1014b2d in H5O__get_info_by_name_api_common (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x116db2d)
    #18 0x7f69f1013b4b in H5Oget_info_by_name3 (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x116cb4b)
    #19 0x7f69f26df37f in traverse_cb (/home/fuzz/cve/hdf5/build/bin/libhdf5_tools.so.1000+0x10c37f)
    #20 0x7f69f0d11411 in H5G__visit_cb (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xe6a411)
    #21 0x7f69f0d4f0ac in H5G__node_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xea80ac)
    #22 0x7f69f04614ce in H5B__iterate_helper (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x5ba4ce)
    #23 0x7f69f0460182 in H5B_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x5b9182)
    #24 0x7f69f0d7ddd7 in H5G__stab_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xed6dd7)
    #25 0x7f69f0d60b11 in H5G__obj_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xeb9b11)
    #26 0x7f69f0d0fcee in H5G_visit (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xe68cee)
    #27 0x7f69f1e3ca58 in H5VL__native_link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1f95a58)
    #28 0x7f69f1d9a5e5 in H5VL__link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ef35e5)
    #29 0x7f69f1d998e0 in H5VL_link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ef28e0)

SUMMARY: AddressSanitizer: heap-buffer-overflow (/home/fuzz/cve/hdf5/build/bin/h5dump+0x431d50) in strndup
Shadow bytes around the buggy address:
  0x0c247fffefd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c247fffefe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 fa
  0x0c247fffeff0: fa fa fa fa fa fa fa fa 00 00 00 00 00 00 00 00
  0x0c247ffff000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c247ffff010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c247ffff020:[fa]fa fa fa fa fa fa fa 00 00 00 00 00 00 00 00
  0x0c247ffff030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c247ffff040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c247ffff050: fa fa fa fa fa fa fa fa 00 00 00 00 00 00 00 00
  0x0c247ffff060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c247ffff070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 fa fa
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
==3900376==ABORTING
```
the POC file is:[poc](https://github.com/madao123123/crash_report/tree/main/poc/seed4)

## 3.finder
Teng Zhang, Mingxuan Liu, Chengsiyuan Yang, Heng Zhang, Hao Liu,Yaoliang Zhang,Dawei Guo , Hang Liu(all from NPU Unmanned Systems Safety Laboratory)
