# a heap-buffer-overflow vulnerability in hdf5-1.14.6

The HDF5 library contains a heap-based buffer overflow vulnerability in the `H5VM_memcpyvv` function. This vulnerability occurs when reading data from a compact dataset, where the library attempts to copy data beyond the bounds of an allocated heap memory region. This could result in memory corruption, application crashes, or potential security risks.

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

./bin/h5dump /poc/hdf5/seed1
```
ASAN report :
```
==1590680==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6040000087be at pc 0x0000004967aa bp 0x7fff424ecc20 sp 0x7fff424ec3e8
READ of size 12 at 0x6040000087be thread T0
    #0 0x4967a9 in __asan_memcpy (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4967a9)
    #1 0x7fe2b8ccf640 in H5VM_memcpyvv (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1fc6640)
    #2 0x7fe2b75fb1ff in H5D__compact_readvv (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x8f21ff)
    #3 0x7fe2b77016f2 in H5D__select_io (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x9f86f2)
    #4 0x7fe2b76feea6 in H5D__select_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x9f5ea6)
    #5 0x7fe2b758494d in H5D__chunk_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x87b94d)
    #6 0x7fe2b76be719 in H5D__read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x9b5719)
    #7 0x7fe2b8c7ab7e in H5VL__native_dataset_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1f71b7e)
    #8 0x7fe2b8bbbb5f in H5VL__dataset_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1eb2b5f)
    #9 0x7fe2b8bbad32 in H5VL_dataset_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1eb1d32)
    #10 0x7fe2b7523a9a in H5D__read_api_common (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x81aa9a)
    #11 0x7fe2b75220a6 in H5Dread (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x8190a6)
    #12 0x7fe2b950b442 in h5tools_dump_simple_dset (/home/fuzz/cve/hdf5/build/bin/libhdf5_tools.so.1000+0xd6442)
    #13 0x7fe2b9508de2 in h5tools_dump_dset (/home/fuzz/cve/hdf5/build/bin/libhdf5_tools.so.1000+0xd3de2)
    #14 0x7fe2b94fc225 in h5tools_dump_data (/home/fuzz/cve/hdf5/build/bin/libhdf5_tools.so.1000+0xc7225)
    #15 0x4dd0a0 in dump_dataset (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4dd0a0)
    #16 0x4d59cf in dump_all_cb (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4d59cf)
    #17 0x7fe2b7b701c5 in H5G__iterate_cb (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xe671c5)
    #18 0x7fe2b7bb10ac in H5G__node_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xea80ac)
    #19 0x7fe2b72c34ce in H5B__iterate_helper (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x5ba4ce)
    #20 0x7fe2b72c2182 in H5B_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x5b9182)
    #21 0x7fe2b7bdfdd7 in H5G__stab_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xed6dd7)
    #22 0x7fe2b7bc2b11 in H5G__obj_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xeb9b11)
    #23 0x7fe2b7b6ee07 in H5G_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xe65e07)
    #24 0x7fe2b7e08d54 in H5L_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10ffd54)
    #25 0x7fe2b8c9e6c6 in H5VL__native_link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1f956c6)
    #26 0x7fe2b8bfc5e5 in H5VL__link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ef35e5)
    #27 0x7fe2b8bfb8e0 in H5VL_link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ef28e0)
    #28 0x7fe2b7dd6622 in H5L__iterate_api_common (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10cd622)
    #29 0x7fe2b7dd5269 in H5Literate2 (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10cc269)
    #30 0x4d3599 in link_iteration (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4d3599)
    #31 0x4dada6 in dump_group (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4dada6)
    #32 0x4c89bb in main (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4c89bb)
    #33 0x7fe2b6981082 in __libc_start_main /build/glibc-FcRMwW/glibc-2.31/csu/../csu/libc-start.c:308:16
    #34 0x41ec1d in _start (/home/fuzz/cve/hdf5/build/bin/h5dump+0x41ec1d)

0x6040000087be is located 0 bytes to the right of 46-byte region [0x604000008790,0x6040000087be)
allocated by thread T0 here:
    #0 0x49735d in malloc (/home/fuzz/cve/hdf5/build/bin/h5dump+0x49735d)
    #1 0x7fe2b7a9048f in H5FL__malloc (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xd8748f)
    #2 0x7fe2b7a9308d in H5FL_blk_malloc (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xd8a08d)
    #3 0x7fe2b759e3b1 in H5D__chunk_mem_alloc (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x8953b1)
    #4 0x7fe2b75b7222 in H5D__chunk_lock (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x8ae222)
    #5 0x7fe2b758436b in H5D__chunk_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x87b36b)
    #6 0x7fe2b76be719 in H5D__read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x9b5719)
    #7 0x7fe2b8c7ab7e in H5VL__native_dataset_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1f71b7e)
    #8 0x7fe2b8bbbb5f in H5VL__dataset_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1eb2b5f)
    #9 0x7fe2b8bbad32 in H5VL_dataset_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1eb1d32)
    #10 0x7fe2b7523a9a in H5D__read_api_common (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x81aa9a)
    #11 0x7fe2b75220a6 in H5Dread (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x8190a6)
    #12 0x7fe2b950b442 in h5tools_dump_simple_dset (/home/fuzz/cve/hdf5/build/bin/libhdf5_tools.so.1000+0xd6442)
    #13 0x7fe2b9508de2 in h5tools_dump_dset (/home/fuzz/cve/hdf5/build/bin/libhdf5_tools.so.1000+0xd3de2)
    #14 0x7fe2b94fc225 in h5tools_dump_data (/home/fuzz/cve/hdf5/build/bin/libhdf5_tools.so.1000+0xc7225)
    #15 0x4dd0a0 in dump_dataset (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4dd0a0)
    #16 0x4d59cf in dump_all_cb (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4d59cf)
    #17 0x7fe2b7b701c5 in H5G__iterate_cb (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xe671c5)
    #18 0x7fe2b7bb10ac in H5G__node_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xea80ac)
    #19 0x7fe2b72c34ce in H5B__iterate_helper (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x5ba4ce)
    #20 0x7fe2b72c2182 in H5B_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x5b9182)
    #21 0x7fe2b7bdfdd7 in H5G__stab_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xed6dd7)
    #22 0x7fe2b7bc2b11 in H5G__obj_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xeb9b11)
    #23 0x7fe2b7b6ee07 in H5G_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xe65e07)
    #24 0x7fe2b7e08d54 in H5L_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10ffd54)
    #25 0x7fe2b8c9e6c6 in H5VL__native_link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1f956c6)
    #26 0x7fe2b8bfc5e5 in H5VL__link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ef35e5)
    #27 0x7fe2b8bfb8e0 in H5VL_link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ef28e0)
    #28 0x7fe2b7dd6622 in H5L__iterate_api_common (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10cd622)
    #29 0x7fe2b7dd5269 in H5Literate2 (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10cc269)

SUMMARY: AddressSanitizer: heap-buffer-overflow (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4967a9) in __asan_memcpy
Shadow bytes around the buggy address:
  0x0c087fff90a0: fa fa fd fd fd fd fd fd fa fa fd fd fd fd fd fd
  0x0c087fff90b0: fa fa fd fd fd fd fd fd fa fa fd fd fd fd fd fd
  0x0c087fff90c0: fa fa fd fd fd fd fd fd fa fa fd fd fd fd fd fd
  0x0c087fff90d0: fa fa fd fd fd fd fd fd fa fa fd fd fd fd fd fd
  0x0c087fff90e0: fa fa fd fd fd fd fd fa fa fa 00 00 00 00 00 fa
=>0x0c087fff90f0: fa fa 00 00 00 00 00[06]fa fa fa fa fa fa fa fa
  0x0c087fff9100: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c087fff9110: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c087fff9120: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c087fff9130: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c087fff9140: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==1590680==ABORTING
```
the POC file is:[poc](https://github.com/madao123123/crash_report/tree/main/poc/seed1)

## 3.finder
Dawei Guo , Hang Liu,Yaoliang Zhang,Teng Zhang, Mingxuan Liu, Chengsiyuan Yang, Heng Zhang, Hao Liu(all from NPU Unmanned Systems Safety Laboratory)


