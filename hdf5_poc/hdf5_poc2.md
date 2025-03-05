# a heap-buffer-overflow vulnerability in hdf5-1.14.6

The HDF5 library contains a heap-based buffer overflow vulnerability in the `H5Z__scaleoffset_decompress_one_byte` function. This vulnerability occurs during the decompression of data using the Scale-Offset filter, where the library attempts to read 1 byte of data beyond the bounds of an allocated 26-byte heap memory region. 

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

./bin/h5dump /poc/hdf5/seed2
```
ASAN report :
```
==3725051==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x603000006e0a at pc 0x7f029bce5435 bp 0x7ffe8e1a3150 sp 0x7ffe8e1a3148
READ of size 1 at 0x603000006e0a thread T0
    #0 0x7f029bce5434 in H5Z__scaleoffset_decompress_one_byte (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x2027434)
    #1 0x7f029bce4a77 in H5Z__scaleoffset_decompress_one_atomic (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x2026a77)
    #2 0x7f029bcc7bc6 in H5Z__scaleoffset_decompress (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x2009bc6)
    #3 0x7f029bcbf541 in H5Z__filter_scaleoffset (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x2001541)
    #4 0x7f029bc9cafe in H5Z_pipeline (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1fdeafe)
    #5 0x7f029a56c876 in H5D__chunk_lock (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x8ae876)
    #6 0x7f029a53936b in H5D__chunk_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x87b36b)
    #7 0x7f029a673719 in H5D__read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x9b5719)
    #8 0x7f029bc2fb7e in H5VL__native_dataset_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1f71b7e)
    #9 0x7f029bb70b5f in H5VL__dataset_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1eb2b5f)
    #10 0x7f029bb6fd32 in H5VL_dataset_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1eb1d32)
    #11 0x7f029a4d8a9a in H5D__read_api_common (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x81aa9a)
    #12 0x7f029a4d70a6 in H5Dread (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x8190a6)
    #13 0x7f029c4c0442 in h5tools_dump_simple_dset (/home/fuzz/cve/hdf5/build/bin/libhdf5_tools.so.1000+0xd6442)
    #14 0x7f029c4bdde2 in h5tools_dump_dset (/home/fuzz/cve/hdf5/build/bin/libhdf5_tools.so.1000+0xd3de2)
    #15 0x7f029c4b1225 in h5tools_dump_data (/home/fuzz/cve/hdf5/build/bin/libhdf5_tools.so.1000+0xc7225)
    #16 0x4dd0a0 in dump_dataset (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4dd0a0)
    #17 0x4d59cf in dump_all_cb (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4d59cf)
    #18 0x7f029ab251c5 in H5G__iterate_cb (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xe671c5)
    #19 0x7f029ab660ac in H5G__node_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xea80ac)
    #20 0x7f029a2784ce in H5B__iterate_helper (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x5ba4ce)
    #21 0x7f029a277182 in H5B_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x5b9182)
    #22 0x7f029ab94dd7 in H5G__stab_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xed6dd7)
    #23 0x7f029ab77b11 in H5G__obj_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xeb9b11)
    #24 0x7f029ab23e07 in H5G_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xe65e07)
    #25 0x7f029adbdd54 in H5L_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10ffd54)
    #26 0x7f029bc536c6 in H5VL__native_link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1f956c6)
    #27 0x7f029bbb15e5 in H5VL__link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ef35e5)
    #28 0x7f029bbb08e0 in H5VL_link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ef28e0)
    #29 0x7f029ad8b622 in H5L__iterate_api_common (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10cd622)
    #30 0x7f029ad8a269 in H5Literate2 (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10cc269)
    #31 0x4d3599 in link_iteration (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4d3599)
    #32 0x4dada6 in dump_group (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4dada6)
    #33 0x4c89bb in main (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4c89bb)
    #34 0x7f0299936082 in __libc_start_main /build/glibc-FcRMwW/glibc-2.31/csu/../csu/libc-start.c:308:16
    #35 0x41ec1d in _start (/home/fuzz/cve/hdf5/build/bin/h5dump+0x41ec1d)

0x603000006e0a is located 0 bytes to the right of 26-byte region [0x603000006df0,0x603000006e0a)
allocated by thread T0 here:
    #0 0x49735d in malloc (/home/fuzz/cve/hdf5/build/bin/h5dump+0x49735d)
    #1 0x7f029a553398 in H5D__chunk_mem_alloc (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x895398)
    #2 0x7f029a56c222 in H5D__chunk_lock (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x8ae222)
    #3 0x7f029a53936b in H5D__chunk_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x87b36b)
    #4 0x7f029a673719 in H5D__read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x9b5719)
    #5 0x7f029bc2fb7e in H5VL__native_dataset_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1f71b7e)
    #6 0x7f029bb70b5f in H5VL__dataset_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1eb2b5f)
    #7 0x7f029bb6fd32 in H5VL_dataset_read (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1eb1d32)
    #8 0x7f029a4d8a9a in H5D__read_api_common (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x81aa9a)
    #9 0x7f029a4d70a6 in H5Dread (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x8190a6)
    #10 0x7f029c4c0442 in h5tools_dump_simple_dset (/home/fuzz/cve/hdf5/build/bin/libhdf5_tools.so.1000+0xd6442)
    #11 0x7f029c4bdde2 in h5tools_dump_dset (/home/fuzz/cve/hdf5/build/bin/libhdf5_tools.so.1000+0xd3de2)
    #12 0x7f029c4b1225 in h5tools_dump_data (/home/fuzz/cve/hdf5/build/bin/libhdf5_tools.so.1000+0xc7225)
    #13 0x4dd0a0 in dump_dataset (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4dd0a0)
    #14 0x4d59cf in dump_all_cb (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4d59cf)
    #15 0x7f029ab251c5 in H5G__iterate_cb (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xe671c5)
    #16 0x7f029ab660ac in H5G__node_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xea80ac)
    #17 0x7f029a2784ce in H5B__iterate_helper (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x5ba4ce)
    #18 0x7f029a277182 in H5B_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x5b9182)
    #19 0x7f029ab94dd7 in H5G__stab_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xed6dd7)
    #20 0x7f029ab77b11 in H5G__obj_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xeb9b11)
    #21 0x7f029ab23e07 in H5G_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0xe65e07)
    #22 0x7f029adbdd54 in H5L_iterate (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10ffd54)
    #23 0x7f029bc536c6 in H5VL__native_link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1f956c6)
    #24 0x7f029bbb15e5 in H5VL__link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ef35e5)
    #25 0x7f029bbb08e0 in H5VL_link_specific (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x1ef28e0)
    #26 0x7f029ad8b622 in H5L__iterate_api_common (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10cd622)
    #27 0x7f029ad8a269 in H5Literate2 (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x10cc269)
    #28 0x4d3599 in link_iteration (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4d3599)
    #29 0x4dada6 in dump_group (/home/fuzz/cve/hdf5/build/bin/h5dump+0x4dada6)

SUMMARY: AddressSanitizer: heap-buffer-overflow (/home/fuzz/cve/hdf5/build/bin/libhdf5.so.1000+0x2027434) in H5Z__scaleoffset_decompress_one_byte
Shadow bytes around the buggy address:
  0x0c067fff8d70: fd fd fd fd fa fa fd fd fd fd fa fa fd fd fd fd
  0x0c067fff8d80: fa fa fd fd fd fd fa fa 00 00 00 07 fa fa 00 00
  0x0c067fff8d90: 00 00 fa fa fd fd fd fd fa fa fd fd fd fd fa fa
  0x0c067fff8da0: fd fd fd fd fa fa 00 00 00 00 fa fa 00 00 00 fa
  0x0c067fff8db0: fa fa fd fd fd fd fa fa fd fd fd fa fa fa 00 00
=>0x0c067fff8dc0: 00[02]fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c067fff8dd0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c067fff8de0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c067fff8df0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c067fff8e00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c067fff8e10: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==3725051==ABORTING
```
the POC file is:[poc](https://github.com/madao123123/crash_report/tree/main/poc/seed2)


## 3.finder
Teng Zhang, Mingxuan Liu, Chengsiyuan Yang, Heng Zhang, Hao Liu,Yaoliang Zhang,Dawei Guo , Hang Liu(all from NPU Unmanned Systems Safety Laboratory)
