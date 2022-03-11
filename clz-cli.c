/* clz-cli.c -- Version 1.0
 *
 * clz-cli is a command line tool to compress/decompress file.
 *
 * You can find the latest source code and description at:
 *   https://github.com/jcwangxp/crosslz
 *
 * ------------------------------------------------------------------------
 *
 * MIT License
 *
 * Copyright (c) 2022, JC Wang (wang_junchuan@163.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * ------------------------------------------------------------------------
 */

/* 

Build

#Windows MSVC
    cl -D_CRT_SECURE_NO_WARNINGS -W4 User32.Lib crosslz.c clz-cli.c /Feclz-cli.exe
	To support LZ4 (static link, copy lz4.c and lz.h to same folder):
	cl -D_CRT_SECURE_NO_WARNINGS -W4 User32.Lib -DCLZ_LZ4 lz4.c crosslz.c clz-cli.c /Feclz-cli.exe

#GCC(Linux, MinGW, Cygwin, MSYS2)
    gcc -Wall crosslz.c clz-cli.c -o clz-cli
	To support LZ4 (dynamic link):
	gcc -Wall crosslz.c clz-cli.c -DCLZ_LZ4 -llz4 -o clz-cli

*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <ctype.h>

#include "crosslz.h"

static uint32_t time_measure (int round, int print)
{
    static clock_t beg;

	if (!round) {
	    beg = clock();
		return 0;
	} else {
		clock_t end = clock();
	    uint32_t ts = (end - beg)*1000000/CLOCKS_PER_SEC;
		if (!ts) { ts = 1; }
		if (print) {
			printf ("Use time %d us QPS %d\n", ts, (uint32_t)((uint64_t)1000000LL*round/ts));
		}
		beg = end;
		return ts;
	}
}

int main (int argc, char **argv)
{
	int i, alg = CLZ_ALG_DFT, blk_cfg = CLZ_BLK_DFT;
	size_t size, comp_size;
	const char *in_file = NULL, *out_file = NULL;

	if (--argc <= 0) {
		printf ("CrossLZ command line interface %d-bits v%s, by JC Wang\n", (int)(sizeof(void*)*8), CLZ_VER_STR);
		printf ("Usage : \n");
		printf ("    clz-cli [-c lz77|lz4|lz4fast|...] [-b 128k|256k|512k|1m|2m|4m|8m|16m] <infile|-> [outfile|-]\n\n");
		printf ("Default compressor is lz77 and block size is 1m, '-' means stdin(infile) or stdout(outfile)\n");
		printf ("If outfile is missed, then default outfile will add/remove .clz suffix\n\n");
		printf ("Supported Compressor list\n");
		for (i = 0; i < CLZ_ALG_MAX; ++ i) {
			const char *alg_name = clz_alg_get (i);
			if (NULL != alg_name) {
				printf ("  %2d\t%s\n", i, alg_name);
			}
		}
		return -1;
	}

	argv++;
	while (argc > 0) {
		if (!strcmp (*argv, "-c")) {
			if (argc < 2) {
				printf ("Missed lz77|lz4|lz4fast|...\n");
				return -1;
			}
			alg = clz_alg_get_byname (argv[1]);
			if (alg <= 0) {
				printf ("Unknown compressor %s\n", argv[1]);
				return -1;
			}
		} else if (!strcmp (*argv, "-b")) {
			const char *blk_str[] = {"128k", "256k", "512k", "1m", "2m", "4m", "8m", "16m"};
			if (argc < 2) {
				printf ("Missed 128k|256k|512k|1m|2m|4m|8m|16m\n");
				return -1;
			}
			for (i = sizeof(blk_str)/sizeof(blk_str[0]) - 1; i >= 0; --i) {
				if (!strcmp(blk_str[i], argv[1])) {
					break;
				}
			}
			if (i < 0) {
				printf ("Unknown block size %s\n", argv[1]);
				return -1;
			}
		} else {
			break;
		}
		argc -= 2;
		argv += 2;
	}

	if (argc-- <= 0) {
		printf ("Missed infile\n");
		return -1;
	}
	in_file = *argv++;
	if (argc-- > 0) {
		out_file = *argv++;
	}
	if (argc > 0) {
		printf ("Use text way\n");
	}

	//printf ("alg %s blk %d in %s out %s\n", clz_alg_get(alg), blk_cfg, in_file, out_file?out_file:"");

	int time = time_measure (0, 0);
	size = clz_file_compress (in_file, out_file, alg, blk_cfg, &comp_size);
	time = time_measure (1, 0) - time;
	if ((NULL == out_file) || strcmp(out_file, "-")) {
	 	printf ("Size %dB Compress %dB Ratio %.2f%%. Time %dus Speed %fMB/s\n", (int)size, (int)comp_size, (double)comp_size*100/size, 
			time, (float)size*1000/(time/1000)/1024/1024);
	}

	return 0;
}
