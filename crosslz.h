/* crosslz.h -- Version 1.0
 *
 * CrossLZ is a tiny cross-platform fast stream compression library.
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

#ifndef __CROSSLZ_H
#define __CROSSLZ_H

#ifdef __cplusplus
extern "C" {
#endif

#define CLZ_VER_MAJOR    		1
#define CLZ_VER_MINOR    		0
#define CLZ_VER_PATCH			0

#define CLZ_LIB_VER 			CLZ_VER_MAJOR.CLZ_VER_MINOR.CLZ_VER_PATCH
#define CLZ_STR(str)			#str
#define CLZ_VER_EXPAND(str)		CLZ_STR(str)
#define CLZ_VER_STR				CLZ_VER_EXPAND(CLZ_LIB_VER)

/* 
Compress file format

Head: 
	magic(4B):		0x0C0D0B81
	flags(1B):		b7~4 Rsvd, b3 F-checksum(0), b2~0 Version(01)
	blk_desc(1B):	b5~3 Alorithm(0-LZ77 1-LZ4 2-LZ4FAST), b2-0 Block MaxSize(0-128K 1-256K 2-512K 3-1M 4-2M 5-4M 6-8M 7-16M)

Data Blocks
	compress size(3B) + orig size(3B) + DATA
	(compress size msb=1 then no compress)

END Block
	compress size=0
*/

// Compression Algorithm
#define CLZ_ALG_NONE		0
#define CLZ_ALG_LZ77		1
#define CLZ_ALG_LZ4			2
#define CLZ_ALG_LZ4FAST		3
#define CLZ_ALG_MAX			8
#define CLZ_ALG_DFT			CLZ_ALG_LZ77

// Compression Block size
#define CLZ_BLK_128K		0
#define CLZ_BLK_256K		1
#define CLZ_BLK_512K		2
#define CLZ_BLK_1M			3
#define CLZ_BLK_2M			4
#define CLZ_BLK_4M			5
#define CLZ_BLK_8M			6
#define CLZ_BLK_16M			7
#define CLZ_BLK_DFT			CLZ_BLK_1M


// crosslz FILE struct, equivalent to FILE
typedef struct clz_FILE clz_FILE;

// Compressor prototype
typedef int (*clz_alg_fn) (void *in_buf, int in_size, void *out_buf, int out_size);
// Register new Compressor
extern int clz_alg_register (int alg, char *name, clz_alg_fn compress_cb, clz_alg_fn decompress_cb);
// Get Compressor name by id
extern const char* clz_alg_get (int alg);
// Get Compressor id by name
extern int clz_alg_get_byname (const char *name);

/* Open compressed/regular file, equivalent to fread. 
 * for write, alg will output file to compressed(>0) or regular(0)
 * for read, compressed/regular file is identified automatically and no need to set alg
 */
extern clz_FILE *clz_fopen (const char *file, const char *mode, int alg, int blk_cfg);
// Close compressed/regular file, compatible with FILE* handler
extern int clz_fclose (clz_FILE *pClzFile);
// Flush a stream of compressed/regular file, equivalent to fflush, compatible with FILE* handler
extern int clz_fflush (clz_FILE *pClzFile);

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

// Return regular file size, pCompSize is the compressed file size, not compatible with FILE* handler
extern size_t clz_get_size (clz_FILE *pClzFile, size_t *pCompSize);

/* If in_file is compressed file, then output decompressed content to out_file
 * if in_file is regular file, then output compressed content to out_file
 * return regular file size, pCompSize is the compressed file size
 */
extern size_t	clz_file_compress (const char *in_file, const char *out_file, int alg, int blk_cfg, size_t *pCompSize);

#ifdef __cplusplus
}
#endif
#endif // __CROSSLZ_H
