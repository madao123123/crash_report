# A heap-buffer-overflow vulnerability in mp3gain v1.6.2

A heap-buffer-overflow vulnerability in mp3gain v1.6.2 allows an attacker to cause a denial of service via the ReadMP3APETag function at apetag.c:256. The reproduction process is as follows:
## 1.Environment
Ubuntu 20.04.6 LTS
mp3gain 1.6.2

## 2.Compilation

`export CC="clang -fsanitize=address"`
`export CC="clang -fsanitize=address"`
`make`

## 3.reproduction

`./mp3gain crash1`  

the POC file is:

## 4.finder
Teng Zhang, Mingxuan Liu, Chengsiyuan Yang, Heng Zhang, Hao Liu,Yaoliang Zhang,Dawei Guo , Hang Liu(all from NPU Unmanned Systems Safety Laboratory)

