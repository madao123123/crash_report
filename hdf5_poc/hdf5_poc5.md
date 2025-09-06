# a heap-buffer-overflow vulnerability in hdf5-1.14.6
The HDF5 library contains a heap-based buffer overflow vulnerability in the `H5Z__filter_scaleoffset` function. This vulnerability occurs during the decompression of data using the Scale-Offset filter, where the library attempts to read 1 byte of data beyond the bounds of an allocated 1-byte heap memory region. This could lead to memory corruption, application crashes, or potential exploitation for arbitrary code execution.


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

./bin/h5dump /poc/hdf5/seed5
```

ASAN report :

```
==3941059==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000009051 at pc 0x7f5d5a974818 bp 0x7ffcb6eeaa10 sp 0x7ffcb6eeaa08
READ of size 1 at 0x602000009051 thread T0
    #0 0x7f5d5a974817 in H5Z__filter_scaleoffset (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x2000817)
    #1 0x7f5d5a952afe in H5Z_pipeline (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1fdeafe)
    #2 0x7f5d59222876 in H5D__chunk_lock (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x8ae876)
    #3 0x7f5d591ef36b in H5D__chunk_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x87b36b)
    #4 0x7f5d59329719 in H5D__read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x9b5719)
    #5 0x7f5d5a8e5b7e in H5VL__native_dataset_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1f71b7e)
    #6 0x7f5d5a826b5f in H5VL__dataset_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1eb2b5f)
    #7 0x7f5d5a825d32 in H5VL_dataset_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1eb1d32)
    #8 0x7f5d5918ea9a in H5D__read_api_common (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x81aa9a)
    #9 0x7f5d5918d0a6 in H5Dread (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x8190a6)
    #10 0x7f5d5b176442 in h5tools_dump_simple_dset (/home/fuzz/cve/hdf5/build/bin/libhdf5_tools.so.1000+0xd6442)
    #11 0x7f5d5b173de2 in h5tools_dump_dset (/home/fuzz/cve/hdf5/build/bin/libhdf5_tools.so.1000+0xd3de2)
    #12 0x7f5d5b167225 in h5tools_dump_data (/home/fuzz/cve/hdf5/build/bin/libhdf5_tools.so.1000+0xc7225)
    #13 0x4dd0a0 in dump_dataset (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4dd0a0)
    #14 0x4d59cf in dump_all_cb (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4d59cf)
    #15 0x7f5d597db1c5 in H5G__iterate_cb (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xe671c5)
    #16 0x7f5d5981c0ac in H5G__node_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xea80ac)
    #17 0x7f5d58f2e4ce in H5B__iterate_helper (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x5ba4ce)
    #18 0x7f5d58f2d182 in H5B_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x5b9182)
    #19 0x7f5d5984add7 in H5G__stab_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xed6dd7)
    #20 0x7f5d5982db11 in H5G__obj_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xeb9b11)
    #21 0x7f5d597d9e07 in H5G_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xe65e07)
    #22 0x7f5d59a73d54 in H5L_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10ffd54)
    #23 0x7f5d5a9096c6 in H5VL__native_link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1f956c6)
    #24 0x7f5d5a8675e5 in H5VL__link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ef35e5)
    #25 0x7f5d5a8668e0 in H5VL_link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ef28e0)
    #26 0x7f5d59a41622 in H5L__iterate_api_common (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10cd622)
    #27 0x7f5d59a40269 in H5Literate2 (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10cc269)
    #28 0x4d3599 in link_iteration (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4d3599)
    #29 0x4dada6 in dump_group (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4dada6)
    #30 0x4c89bb in main (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4c89bb)
    #31 0x7f5d585ec082 in __libc_start_main /build/glibc-FcRMwW/glibc-2.31/csu/../csu/libc-start.c:308:16
    #32 0x41ec1d in _start (/home/fuzz/cve/hdf5/build/bin/h5dump+0x41ec1d)

0x602000009051 is located 0 bytes to the right of 1-byte region [0x602000009050,0x602000009051)
allocated by thread T0 here:
    #0 0x49735d in malloc (/home/fuzz/cve/hdf5/build/bin/h5dump+0x49735d)
    #1 0x7f5d59209398 in H5D__chunk_mem_alloc (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x895398)
    #2 0x7f5d59222222 in H5D__chunk_lock (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x8ae222)
    #3 0x7f5d591ef36b in H5D__chunk_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x87b36b)
    #4 0x7f5d59329719 in H5D__read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x9b5719)
    #5 0x7f5d5a8e5b7e in H5VL__native_dataset_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1f71b7e)
    #6 0x7f5d5a826b5f in H5VL__dataset_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1eb2b5f)
    #7 0x7f5d5a825d32 in H5VL_dataset_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1eb1d32)
    #8 0x7f5d5918ea9a in H5D__read_api_common (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x81aa9a)
    #9 0x7f5d5918d0a6 in H5Dread (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x8190a6)
    #10 0x7f5d5b176442 in h5tools_dump_simple_dset (/home/fuzz/cve/hdf5/build/bin/libhdf5_tools.so.1000+0xd6442)
    #11 0x7f5d5b173de2 in h5tools_dump_dset (/home/fuzz/cve/hdf5/build/bin/libhdf5_tools.so.1000+0xd3de2)
    #12 0x7f5d5b167225 in h5tools_dump_data (/home/fuzz/cve/hdf5/build/bin/libhdf5_tools.so.1000+0xc7225)
    #13 0x4dd0a0 in dump_dataset (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4dd0a0)
    #14 0x4d59cf in dump_all_cb (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4d59cf)
    #15 0x7f5d597db1c5 in H5G__iterate_cb (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xe671c5)
    #16 0x7f5d5981c0ac in H5G__node_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xea80ac)
    #17 0x7f5d58f2e4ce in H5B__iterate_helper (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x5ba4ce)
    #18 0x7f5d58f2d182 in H5B_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x5b9182)
    #19 0x7f5d5984add7 in H5G__stab_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xed6dd7)
    #20 0x7f5d5982db11 in H5G__obj_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xeb9b11)
    #21 0x7f5d597d9e07 in H5G_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xe65e07)
    #22 0x7f5d59a73d54 in H5L_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10ffd54)
    #23 0x7f5d5a9096c6 in H5VL__native_link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1f956c6)
    #24 0x7f5d5a8675e5 in H5VL__link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ef35e5)
    #25 0x7f5d5a8668e0 in H5VL_link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ef28e0)
    #26 0x7f5d59a41622 in H5L__iterate_api_common (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10cd622)
    #27 0x7f5d59a40269 in H5Literate2 (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10cc269)
    #28 0x4d3599 in link_iteration (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4d3599)
    #29 0x4dada6 in dump_group (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4dada6)

SUMMARY: AddressSanitizer: heap-buffer-overflow (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x2000817) in H5Z__filter_scaleoffset
Shadow bytes around the buggy address:
  0x0c047fff91b0: fa fa fd fa fa fa fd fa fa fa fd fa fa fa fd fa
  0x0c047fff91c0: fa fa fd fa fa fa fd fa fa fa fd fa fa fa fd fa
  0x0c047fff91d0: fa fa fd fa fa fa fd fa fa fa 00 fa fa fa fd fa
  0x0c047fff91e0: fa fa 00 fa fa fa fd fa fa fa 00 fa fa fa fd fa
  0x0c047fff91f0: fa fa 00 fa fa fa 04 fa fa fa 04 fa fa fa 04 fa
=>0x0c047fff9200: fa fa fd fa fa fa fd fa fa fa[01]fa fa fa fa fa
  0x0c047fff9210: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff9220: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff9230: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff9240: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff9250: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==3941059==ABORTING
```
the POC file is:[poc](https://github.com/madao123123/crash_report/tree/main/poc/seed5)

## 3.finder
Dawei Guo , Hang Liu,Yaoliang Zhang,Teng Zhang, Mingxuan Liu, Chengsiyuan Yang, Heng Zhang, Hao Liu(all from NPU Unmanned Systems Safety Laboratory)
