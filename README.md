# CrossLZ

**CrossLZ** is a tiny cross-platform fast stream compression library.

When should you use CrossLZ:
* When you need a cross-platform compression stream library.
* When you need standard glibc file stream equivalent APIs.
* When you need a tiny extensive compression stream framework.
* When you need a small compression library to build into program.


## Catalogue

* [Features and Highlights](#Features-and-Highlights)
* [Background](#Background)
* [APIs](#APIs)
* [New Compressor](#New-Compressor)
* [clz-cli tool](#clz-cli-tool)
* [Compressed File Format](#Compressed-File-Format)
* [Example](#Example)
* [Build and Test](#build-and-Test)
* [Related Projects](#Related-Projects)


## Features and Highlights

* Support many platforms: Windows, Linux, Unix, MacOS.
* Support similar standard glibc TEXT and Binary file stream APIs.
* Stream APIs can support either standard glibc FILE pointer or clz_FILE pointer.
* clz_fopen can open either compressed or regular file.
* Stream APIs can append or overwrite existing compressed or regular file.
* A common API based on CrossLZ can create or read regular/compressed file with different option.   
* Support default LZ77(data-shrinker) compressor which is very fast and very tiny.
* Support LZ4 compressor which is extremely fast.
* Support registering new compressors.
* clz-cli tool can compress/decompress file and support pipe as input or output.
* Pure C MIT license source code, no 3rd library dependency(except LZ4 or new compressors).
* Very small only about 900 LOC.


## Background

I need a tiny and fast cross-platform compression library to do backup/restore work. **lz4** is the first option, which is extremely fast, however I think it's too big and the stream APIs are not easy to use. Then I found a tiny and fast data-shrinker algorithm. I referred lz4 frame/block format and created the standard glibc stream equivalent APIs and these APIs can either work on regular file or compressed file. Then the backup/restore work will be very easy to just write one backup code and can generate either compressed or regular file, and this file can be sent to other device by network also. When do recovery, the input file can be either compressed or regular file, and you also only need to write one recovery code, that's all, very convenient to use.


## APIs

```c
// Compression Algorithm
#define CLZ_ALG_NONE        0
#define CLZ_ALG_LZ77        1
#define CLZ_ALG_LZ4         2
#define CLZ_ALG_LZ4FAST     3
#define CLZ_ALG_DFT         CLZ_ALG_LZ77

// Compression Block size
#define CLZ_BLK_128K        0
#define CLZ_BLK_256K        1
#define CLZ_BLK_512K        2
#define CLZ_BLK_1M          3
#define CLZ_BLK_2M          4
#define CLZ_BLK_4M          5
#define CLZ_BLK_8M          6
#define CLZ_BLK_16M         7
#define CLZ_BLK_DFT         CLZ_BLK_1M

// crosslz FILE struct, equivalent to FILE
typedef struct clz_FILE clz_FILE;

/* Open compressed/regular file, equivalent to fread. 
 * for write, alg will output file to compressed(>0) or regular(0)
 * for read, compressed/regular file is identified automatically and no need to set alg
 */
extern clz_FILE *clz_fopen (const char *file, const char *mode, int alg, int blk_cfg);

// Close compressed/regular file, compatible with FILE* handler
extern int clz_fclose (clz_FILE *pClzFile);

// Flush a stream of compressed/regular file, equivalent to fflush, compatible with FILE* handler
extern int clz_fflush (clz_FILE *pClzFile);
```

* Stream APIs

```c
/* Read strings from compressed/regular file, equivalent to fgets, compatible with FILE* handler 
 * Note fgets returns buf pointer, but clz_fgets returns strings length which is more efficient.
 */
extern int clz_fgets (char *buf, int size, clz_FILE *pClzFile);

// Output strings to compressed/regular file, equivalent to fputs, compatible with FILE* handler 
extern int clz_fputs (const char *str, clz_FILE *pClzFile);

// Formatted output to compressed/regular file, equivalent to fprintf, compatible with FILE* handler 
extern int clz_fprintf (clz_FILE *pClzFile, const char *format, ...);

// Binary stream read compressed/regular file, equivalent to fread, compatible with FILE* handler
extern int clz_fread (void *ptr, int size, int nmemb, clz_FILE *pClzFile);

// Binary stream write compressed/regular file, equivalent to fwrite, compatible with FILE* handler
extern int clz_fwrite (const void *ptr, int size, int nmemb, clz_FILE *pClzFile);
```

* Compressor APIs

```c
// Compressor prototype
typedef int (*clz_alg_fn) (void *in_buf, int in_size, void *out_buf, int out_size);

// Register new Compressor
extern int clz_alg_register (int alg, char *name, clz_alg_fn compress_cb, clz_alg_fn decompress_cb);

// Get Compressor name by id
extern const char* clz_alg_get (int alg);

// Get Compressor id by name
extern int clz_alg_get_byname (const char *name);
```

* Misc APIs

```c
// Return regular file size, pCompSize is the compressed file size, not compatible with FILE* handler
extern size_t clz_get_size (clz_FILE *pClzFile, size_t *pCompSize);

/* If in_file is compressed file, then output decompressed content to out_file
 * if in_file is regular file, then output compressed content to out_file
 * return regular file size, pCompSize is the compressed file size
 */
extern size_t    clz_file_compress (const char *in_file, const char *out_file, int alg, int blk_cfg, size_t *pCompSize);
```


## New Compressor

First create the compress and decompress wrapper funtions, then register it to CrossLZ.
```c
static int clz_lz4_compress (void *in_buf, int in_size, void *out_buf, int out_size)
{
    return LZ4_compress_default (in_buf, out_buf, in_size, out_size);
}
static int clz_lz4_decompress (void *in_buf, int in_size, void *out_buf, int out_size)
{
    return LZ4_decompress_safe (in_buf, out_buf, in_size, out_size);
}

clz_alg_register (5, "test", clz_lz4_compress, clz_lz4_decompress);
```


## clz-cli tool
```
./clz-cli
CrossLZ command line interface 64-bits v1.0.0, by JC Wang
Usage : 
    clz-cli [-c lz77|lz4|lz4fast|...] [-b 128k|256k|512k|1m|2m|4m|8m|16m] <infile|-> [outfile|-]

Default compressor is lz77 and block size is 1m, '-' means stdin(infile) or stdout(outfile)
If outfile is missed, then default outfile will add/remove .clz suffix

Supported Compressor list
   1    lz77
   2    lz4
   3    lz4fast
```

    Compress file to default logs.txt.clz
    clz-cli logs.txt
    Size 36041013B Compress 2694916B Ratio 7.48%. Time 97000us Speed 354.344208MB/s

    Compress file to logs2.txt.clz
    clz-cli logs.txt logs2.txt.clz

    Compress file to logs3.txt.clz with LZ4
    clz-cli -c lz4 logs.txt logs3.txt.clz
    Size 36041013B Compress 2737295B Ratio 7.59%. Time 61663us Speed 563.465332MB/s

    Decompress file to logs3.txt
    clz-cli logs.txt.clz logs3.txt
    Size 36041013B Compress 2694916B Ratio 7.48%. Time 54000us Speed 636.507141MB/s

    Decompress file to default logs2.txt 
    clz-cli logs2.txt.clz
    Size 36041013B Compress 2694916B Ratio 7.48%. Time 54000us Speed 636.507141MB/s

    Decompress file to stdout (text only)
    clz-cli logs.txt.clz -

    Compress file from pipe
    cat logs.txt | clz-cli - logs.txt.clz
	type logs.txt | clz-cli - logs.txt.clz (Windows)

    Decompress file from pipe and output to stdout (text only)
    cat logs.txt.clz | clz-cli - -


## Compressed File Format

The format refers [lz4_Block_format](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md) and [lz4_Frame_format](https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md), but it's a simplified version.

```
Head: 
    magic(4B):      0x0C0D0B81
    flag(1B):       b7~4 Rsvd, b3 F-checksum(0), b2~0 Version(01)
    blk_desc(1B):   b5~3 Alorithm(0-LZ77 1-LZ4 2-LZ4FAST), 
                    b2-0 Block MaxSize(0-128K 1-256K 2-512K 3-1M 4-2M 5-4M 6-8M 7-16M)

Data Blocks
    compress size(3B) + orig size(3B) + DATA
    (compress size msb=1 then no compress)

END Block
    compress size=0
```


## Example

`example.c` shows how to read/write regular/compressed text/binary file, the APIs are compatible with FILE pointer, so you can use fopen to open file then pass FILE pointer to the APIs, then it's equivalent to call standard glibc file stream APIs. 

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crosslz.h"

int main (int argc, char **argv) 
{
    clz_FILE     *pFile;
    if (argc < 3) {
        printf ("Write regular text file:     %s wt txtfile.txt\n", argv[0]);
        printf ("Write compressed text file:  %s wt txtfile.clz\n", argv[0]);
        printf ("Append regular text file:    %s at txtfile.txt\n", argv[0]);
        printf ("Append compressed text file: %s at txtfile.clz\n", argv[0]);
        printf ("Read regular text file:      %s rt txtfile.txt\n", argv[0]);
        printf ("Read compressed text file:   %s rt txtfile.clz\n", argv[0]);

        printf ("Write regular bin file:      %s wb binfile.bin\n", argv[0]);
        printf ("Write compressed bin file:   %s wb binfile.clz\n", argv[0]);
        printf ("Append regular bin file:     %s ab binfile.bin\n", argv[0]);
        printf ("Append compressed bin file:  %s ab binfile.clz\n", argv[0]);
        printf ("Read regular bin file:       %s rb binfile.bin\n", argv[0]);
        printf ("Read compressed bin file:    %s rb binfile.clz\n", argv[0]);
        return 0;
    }

    char *file = argv[2];
    char *mode = argv[1];
    char buf[1024];
    int len;

    if (strstr(mode, "wt") || strstr(mode, "at")) {
        if (strstr(file, ".clz")) {
            printf ("Write/Append compressed text file: %s\n", file);
            pFile = clz_fopen (file, mode, CLZ_ALG_DFT, CLZ_BLK_DFT);
        } else {
            printf ("Write/Append regular text file: %s\n", file);
            pFile = clz_fopen (file, mode, 0, 0);
        }
        if (NULL == pFile) {
            printf ("Can't open file %s\n", file);
            return -1;
        }
        for (int i=0; i<100000; ++i) {
            len = clz_fprintf (pFile, "count number: %06d\n", i);
            if (i == 0) {
                printf ("Each fprintf: %d\n", len);
            }
        }
        clz_fclose (pFile);
    } else if (strstr(mode, "rt")) {
        printf ("Read regular/compressed text file: %s\n", file);
        pFile = clz_fopen (file, "rt", 0, 0);
        if (NULL == pFile) {
            printf ("Can't open file %s\n", file);
            return -1;
        }
        len = clz_fgets (buf, sizeof(buf), pFile);
        printf ("First row(%d): %s", len, buf);
        while ((len = clz_fgets (buf, sizeof(buf), pFile)) > 0) {
        }
        printf ("Last row: %s", buf);
        clz_fclose (pFile);
    } else if (strstr(mode, "wb") || strstr(mode, "ab")) {
        if (strstr(file, ".clz")) {
            printf ("Write/Append compressed bin file: %s\n", file);
            pFile = clz_fopen (file, mode, CLZ_ALG_DFT, CLZ_BLK_DFT);
        } else {
            printf ("Write regular bin file: %s\n", file);
            pFile = clz_fopen (file, mode, 0, 0);
        }
        if (NULL == pFile) {
            printf ("Can't open file %s\n", file);
            return -1;
        }
        for (int i=0; i<100000; ++i) {
            len = sprintf (buf, "count number: %06d\n", i);
            len = clz_fwrite (buf, 1, len, pFile);
            if (i == 0) {
                printf ("Each clz_fwrite: %d\n", len);
            }
        }
        clz_fclose (pFile);
    } else if (strstr(mode, "rb")) {
        printf ("Read compressed/regular bin file: %s\n", file);
        pFile = clz_fopen (file, "rb", 0, 0);
        if (NULL == pFile) {
            printf ("Can't open file %s\n", file);
            return -1;
        }
        buf[21] = '\0';
        len = clz_fread (buf, 1, 21, pFile);
        printf ("First row(%d): %s", len, buf);
        while ((len = clz_fread (buf, 1, 21, pFile)) > 0) {
        }
        printf ("Last row: %s", buf);
        clz_fclose (pFile);
    } else {
        printf ("Unkown mode: %s\n", mode);
    }

    return 0;
}
```


## Build and Test

On Windows, you can add the source code to a Visual Studio project to build or enter `Tools Command Prompt for VS` from menu to build in command line which is more efficient.

**Windows MSVC**

    cl -D_CRT_SECURE_NO_WARNINGS -W4 User32.Lib crosslz.c clz-cli.c /Feclz-cli.exe
    cl -D_CRT_SECURE_NO_WARNINGS -W4 User32.Lib crosslz.c example.c /Feexample.exe
    To support LZ4 (static link, copy lz4.c and lz.h to same folder):
    cl -D_CRT_SECURE_NO_WARNINGS -W4 User32.Lib -DCLZ_LZ4 lz4.c crosslz.c clz-cli.c /Feclz-cli.exe

**GCC(Linux, MinGW, Cygwin, MSYS2)**

    gcc -Wall crosslz.c clz-cli.c -o clz-cli
    gcc -Wall crosslz.c example.c -o example
    To support LZ4 (dynamic link):
    gcc -Wall crosslz.c clz-cli.c -DCLZ_LZ4 -llz4 -o clz-cli

## Related Projects

* [LZ4](https://github.com/lz4/lz4) is an extremely fast compression algorithm, providing compression speed > 500 MB/s per core, scalable with multi-cores CPU. It features an extremely fast decoder, with speed in multiple GB/s per core, typically reaching RAM speed limits on multi-core systems.
* [data-shrinker](http://code.google.com/archive/p/data-shrinker/) is a LZ77-based data compression program that can be used in high performance demand environment, it's can remove much of the redundancy in data at the speed of hundreds of megabytes per second.

[Goto Top](#Catalogue)