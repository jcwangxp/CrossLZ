/* crosslz.c -- Version 1.0
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include "crosslz.h"

#ifdef CLZ_LZ4
#include <lz4.h>
#endif

#ifndef clz_malloc
	#define clz_malloc	malloc
#endif
#ifndef clz_free
	#define clz_free	free
#endif


/*------------------------------------------
  Begin https://code.google.com/p/data-shrinker/
  JC Wang: remove all MSCV compiler warnings
  License: New BSD
  -----------------------------------------*/

#if defined(_MSC_VER)
typedef unsigned __int8 u8;
typedef unsigned __int16 u16;
typedef unsigned __int32 u32;
typedef unsigned __int64 u64;
#else
#include <stdint.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#endif

//the code from LZ4
#ifndef expect
#if (GCC_VERSION >= 302) || (__INTEL_COMPILER >= 800) || defined(__clang__)
# define expect(expr,value)    (__builtin_expect ((expr),(value)) )
#else
# define expect(expr,value)    (expr)
#endif
#define likely(expr)     expect((expr) != 0, 1)
#define unlikely(expr)   expect((expr) != 0, 0)
#endif
////////////////////

#define HASH_BITS 15
#define HASH(a) ((a*21788233) >> (32 - HASH_BITS))
#define MINMATCH 4

#include <limits.h>
#if ULONG_MAX == UINT_MAX //32bit
#define MEMCPY_NOOVERLAP(a, b, c) do{do{*(u32*)a = *(u32*)b;a+=4;b+=4;}while(b<c);a-=(b-c);b=c;}while(0)
#define MEMCPY_NOOVERLAP_NOSURPASS(a, b, c) do{c-=4;while(b<c){*(u32*)(a) = *(u32*)(b);a+=4;b+=4;}c+=4;while(b<c)*a++=*b++;}while(0)
#define MEMCPY(a, b, c) do{if (likely(a>b+4)) MEMCPY_NOOVERLAP(a, b, c); else while(b<c) *a++=*b++;}while(0)
#else
#define MEMCPY_NOOVERLAP(a, b, c) do{do{*(u64*)a = *(u64*)b;a+=8;b+=8;}while(b<c);a-=(b-c);b=c;}while(0)
#define MEMCPY_NOOVERLAP_NOSURPASS(a, b, c) do{c-=8;while(b<c){*(u64*)(a) = *(u64*)(b);a+=8;b+=8;}c+=8;while(b<c)*a++=*b++;}while(0)
#define MEMCPY(a, b, c) do{if (likely(a>b+8)) MEMCPY_NOOVERLAP(a, b, c); else while(b<c) *a++=*b++;}while(0)
#endif

static int shrinker_compress (void *in, int size, void *out, int out_size)
{
    u32 ht[(1<<HASH_BITS)];
    u8 *src = (u8*)in, *dst = (u8*)out;
    u8 *src_end = src + size - MINMATCH - 8;
    u8 *dst_end = dst + size - MINMATCH - 8;
    u8 *pfind, *pcur;
    u32 cur_hash;
    u8  *p_last_lit = src;
    u32 cpy_len, match_dist;
    u8 flag, *pflag, cache;
    u32 cur_u32;
	(void)out_size;

    if (size < 32) return -1;
    if (size > (1 << 27) - 1) return -1;

    cur_u32 = *(u32*)src;
    while(likely(src < src_end) && likely(dst < dst_end))
    {
        u32 tmp = (u32)(src - (u8*)in);
        pcur = src;
        cur_u32 = *(u32*)pcur;
        cur_hash = HASH(cur_u32);
        cache = ht[cur_hash] >> 27;
        pfind = (u8*)in + (ht[cur_hash] & 0x07ffffff);
        ht[cur_hash] = tmp|(*src<<27);

        if (unlikely(cache == (*pcur & 0x1f))
            && pfind + 0xffff >= (u8*)pcur
            && pfind < pcur
            &&*(u32*)pfind == *(u32*)pcur) 
        {  
            pfind += 4; pcur += 4;
            while(likely(pcur < src_end) && *(u32*)pfind == *(u32*)pcur)
            { pfind += 4; pcur += 4;}

            if (likely(pcur < src_end))
            if (*(u16*)pfind == *(u16*)pcur) {pfind += 2; pcur += 2;}
            if (*pfind == *pcur) {pfind++; pcur++;}

            pflag = dst++;
            cpy_len = (u32)(src - p_last_lit);
            if (likely(cpy_len < 7)) flag = (u8)(cpy_len << 5);
            else {
                cpy_len -= 7;flag = (7<<5);
                while (cpy_len >= 255)
                { *dst++ = 255;cpy_len -= 255;}
                *dst++ = (u8)cpy_len;
            }

            cpy_len = (u32)(pcur - src  - MINMATCH);
            if (likely(cpy_len < 15))  flag |= cpy_len;
            else {
                cpy_len -= 15; flag |= 15;
                while (cpy_len >= 255)
                { *dst++ = 255;cpy_len -= 255;}
                *dst++ = (u8)cpy_len;
            }
            match_dist = (u32)(pcur - pfind - 1);
            *pflag = flag;
            *dst++ = match_dist & 0xff;
            if (match_dist > 0xff) {
                *pflag |= 16;
                *dst++ = (u8)(match_dist >> 8);
            }
            MEMCPY_NOOVERLAP(dst, p_last_lit, src);

            cur_u32 = *(u32*)(src+1);
            ht[HASH(cur_u32)] = (u32)((src - (u8*)in + 1)|(*(src+1)<<27));
            cur_u32 = *(u32*)(src+3);
            ht[HASH(cur_u32)] = (u32)((src - (u8*)in + 3)|(*(src+3)<<27));
            src = pcur;
            p_last_lit = src;
            continue;
        }
        src++;
    }

    if (dst - (u8*)out + 3 >= src - (u8*)in) return -1;
    src = (u8*)in + size;
    pflag = dst++;
    cpy_len = (u32)(src - p_last_lit);
    if (likely(cpy_len < 7)) flag = (u8)(cpy_len << 5);
    else {
        cpy_len -= 7; flag = (7<<5);
        while (cpy_len >= 255)
        { *dst++ = 255; cpy_len -= 255;}
        *dst++ = (u8)cpy_len;
    }

    flag |= 7 + 16; // any number
    *pflag = flag;
    *dst++ = 0xff; *dst++ = 0xff;
    MEMCPY_NOOVERLAP_NOSURPASS(dst, p_last_lit, src);

    if (dst > dst_end) return -1;
    else return (int)(dst - (u8*)out);
}

static int shrinker_decompress (void *in, int in_size, void *out, int size)
{
    u8 *src = (u8*)in, *dst = (u8*)out;
    u8 *end = dst + size;
    u8 *pcpy, *pend;
    u8 flag, long_dist;
    u32 literal_len;
    u32 match_len, match_dist;
	(void)in_size;

    for(;;) {
        flag = *src++;
        literal_len = flag >> 5; // 3-bits
        match_len = flag & 0xf; // 4-bits
        long_dist = flag & 0x10; // 1-bit

        if (unlikely(literal_len == 7)) {
            while((flag = *src++) == 255)
                literal_len += 255;
            literal_len += flag;
        }

        if (unlikely(match_len == 15)) {
            while((flag = *src++) == 255)
                match_len += 255;
            match_len += flag;
        }

        match_dist = *src++;
        if (long_dist) 
        {
            match_dist |= ((*src++) << 8);
            if (unlikely(match_dist == 0xffff)) {
                pend = src + literal_len;
                if (unlikely(dst + literal_len > end)) return -1;
                MEMCPY_NOOVERLAP_NOSURPASS(dst, src, pend);
                break;
            }
        }

        pend = src + literal_len;
        if (unlikely(dst + literal_len > end)) return -1;
        MEMCPY_NOOVERLAP(dst, src, pend);
        pcpy = dst - match_dist - 1;
        pend = pcpy + match_len + MINMATCH;
        if (unlikely(pcpy < (u8*)out || dst + match_len + MINMATCH > end)) return -1;
        MEMCPY(dst, pcpy, pend);
    }
    return (int)(dst - (u8*)out);
}

/*------------------------------------------
  End https://code.google.com/p/data-shrinker/
  License: New BSD
  -----------------------------------------*/


#define CLZ_FRAME_VER			1

#if defined(__BIG_ENDIAN__) || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define CLZ_MAGIC_NUM			0x0C0D0B81
#else
#define CLZ_MAGIC_NUM			0x810B0D0C
#endif

#define CLZ_BLK_SIZE(cfg)		(1<<((cfg)+17))

#define CLZ_BLK_SIZE_DFT		CLZ_BLK_SIZE(CLZ_BLK_DFT)

#define CLZ_MAX_PRINT_SIZE		65536	// 64K

#define CLZ_LEN_SIZE			3

#ifdef CLZ_DEBUG
static int s_clz_dbg = 1;
#else
static int s_clz_dbg = 0;
#endif
#define clz_debug	if (s_clz_dbg) printf

#define CLZ_GETLEN(len, ptr)	{uint8_t *p=(uint8_t*)(ptr); len = ((p[0]<<16) | (p[1]<<8) | p[2]);}
#define CLZ_SETLEN(len, ptr)	{uint8_t *p=(uint8_t*)(ptr); p[0]=(uint8_t)(len>>16); p[1]=(uint8_t)(len>>8); p[2]=(uint8_t)len;}


typedef struct clz_FILE {
	uint32_t		magic;
	FILE			*pFile;
	uint8_t 		*pOffset;
	uint8_t			bCompress;
	uint8_t			bWrite;
	uint8_t			alg;
	int				block_size;	// for read
	int				nxt_blk_csz;
	int				block_max;
	clz_alg_fn 		compress_cb;
	clz_alg_fn		decompress_cb;
	size_t			orig_size;
	size_t			comp_size;
	uint8_t			pBuf[1];
} clz_FILE;

#pragma pack(push, 1)
typedef struct {
	uint32_t	magic;
	uint8_t		flags; 		// 7~4 Rsvd, 3 F-checksum(0), 2~0 Version(01)
	uint8_t		blk_desc;	// 5~3 Alorithm(0-LZ77 1-LZ4 2-LZ4FAST), 2-0 Block MaxSize(0-128K 1-256K 2-512K 3-1M 4-2M 5-4M 6-8M 7-16M)
} clz_clzhdr_t;
#pragma pack(pop)


#ifdef CLZ_LZ4
static int clz_lz4_compress (void *in_buf, int in_size, void *out_buf, int out_size)
{
	return LZ4_compress_default (in_buf, out_buf, in_size, out_size);
}
static int clz_lz4fast_compress (void *in_buf, int in_size, void *out_buf, int out_size)
{
	return LZ4_compress_fast (in_buf, out_buf, in_size, out_size, 99);
}
static int clz_lz4_decompress (void *in_buf, int in_size, void *out_buf, int out_size)
{
	return LZ4_decompress_safe (in_buf, out_buf, in_size, out_size);
}
#endif

struct {
	char		*name;
	clz_alg_fn	compress_cb;
	clz_alg_fn	decompress_cb;
} s_clz_alg[CLZ_ALG_MAX] = {
	{"lz77", 			shrinker_compress,		shrinker_decompress},
#ifdef CLZ_LZ4
	{"lz4", 			clz_lz4_compress, 		clz_lz4_decompress},
	{"lz4fast", 		clz_lz4fast_compress,	clz_lz4_decompress},	
#endif
};

int clz_alg_register (int alg, char *name, clz_alg_fn compress_cb, clz_alg_fn decompress_cb)
{
	if ((alg <=0) || (alg >= CLZ_ALG_MAX)) {
		return -1;
	}
	alg--;
	if (NULL != s_clz_alg[alg].name) {
		printf ("%d is register as %s\n", alg+1, s_clz_alg[alg].name);
		return -1;
	}
	s_clz_alg[alg].name = name;
	s_clz_alg[alg].compress_cb = compress_cb;
	s_clz_alg[alg].decompress_cb = decompress_cb;
	return 0;
}

const char* clz_alg_get (int alg)
{
	if ((alg <= 0) || (alg >= CLZ_ALG_MAX)) {
		return NULL;
	}
	return s_clz_alg[alg-1].name;
}

int clz_alg_get_byname (const char *name)
{
	for (int i = 0; i < CLZ_ALG_MAX; ++i) {
		if ((NULL != s_clz_alg[i].name) && !strcmp(name, s_clz_alg[i].name)) {
			return i + 1;
		}
	}
	return 0;
}

clz_FILE *clz_fopen (const char *file, const char *mode, int alg, int blk_cfg)
{
	FILE			*pFile = NULL;
	int				len = 0;
	uint8_t			bWrite = (NULL == strchr (mode, 'r'));
	int				bStdInOut = (0 == strcmp (file, "-"));
	clz_clzhdr_t	clz_hdr = {.magic = CLZ_MAGIC_NUM, .flags = CLZ_FRAME_VER, .blk_desc = (uint8_t)blk_cfg};
	uint32_t		buffer[(sizeof(clz_clzhdr_t)+CLZ_LEN_SIZE+3)/4];
	clz_clzhdr_t	*clz_hdr_file = (clz_clzhdr_t*)buffer; 
	clz_FILE 		*pClzFile;
	int				block_max = CLZ_BLK_SIZE(blk_cfg);
	uint8_t			bCompress = alg > 0;

	if (alg > 0 ) {
		alg--;
	}

	if (!bWrite) {
		// read first head and check magic number
		pFile = bStdInOut ? stdin : fopen (file, "rb");
		if (NULL == pFile) {
		printf ("Can't open %s\n", file);
			return NULL;
		}
		len = (int)fread (clz_hdr_file, 1, sizeof(clz_clzhdr_t)+CLZ_LEN_SIZE, pFile);
		bCompress = 0;
  		if ((len >= sizeof(clz_clzhdr_t)+CLZ_LEN_SIZE) && (clz_hdr_file->magic == CLZ_MAGIC_NUM)) {
			if ((clz_hdr_file->flags&0x7) > CLZ_FRAME_VER) {
				printf ("CLZ file version %d > %d, can't read\n", clz_hdr_file->flags&0x7, CLZ_FRAME_VER);
				if (!bStdInOut) {
					fclose (pFile);
				}
				return NULL;
			}
			block_max = CLZ_BLK_SIZE(clz_hdr_file->blk_desc&0x7);
			alg = (clz_hdr_file->blk_desc>>3)&0x7;
			clz_debug ("Read %s a clz file max block %d\n", file, block_max);
			bCompress = 1; // clz file
		} else {
			if (!bStdInOut) {
				fclose (pFile);
			}
			pFile = NULL;
		}
	}

	if ((alg > 0) && ((alg > CLZ_ALG_MAX) || (NULL == s_clz_alg[alg].name))) {
		if ((NULL != pFile) && !bStdInOut) {
			fclose (pFile);
		}
		return NULL;
	}

	if (!bCompress) {
		// open in normal mode
		if (!bStdInOut) {
			pFile = fopen (file, mode);
		} else {
			pFile = bWrite ? stdout : stdin;
		}
		clz_debug ("Open a norm file %s\n", file);
	} else if (bWrite) {
		if (strchr (mode, 'a')) {
			pFile = bStdInOut ? stdin : fopen (file, "ab"); // append mode
		} else {
			pFile = bStdInOut ? stdin : fopen (file, "wb"); // write mode
		}
		clz_debug ("Write clz %s\n", file);
	}

	if (NULL == pFile) {
		printf ("Can't open %s\n", file);
		return NULL;
	}

	pClzFile = clz_malloc (sizeof (clz_FILE) - 1 + bCompress ? (block_max*2 + CLZ_LEN_SIZE*2) : 0);
	if (NULL == pClzFile) {
		if (!bStdInOut) {
			fclose (pFile);
		}
		return NULL;
	}
	pClzFile->magic = CLZ_MAGIC_NUM;
	pClzFile->pFile = pFile;
	pClzFile->bCompress = bCompress;
	pClzFile->bWrite = bWrite;
	pClzFile->block_max = block_max;
	pClzFile->orig_size = 0;
	pClzFile->comp_size = 0;

	if (bCompress) {
		if (!bStdInOut) {
			clz_debug ("Use %s, block size %d\n", s_clz_alg[alg].name, pClzFile->block_max);
		}
		pClzFile->alg = (uint8_t)alg;
		pClzFile->compress_cb = s_clz_alg[alg].compress_cb;
		pClzFile->decompress_cb = s_clz_alg[alg].decompress_cb;
		if (bWrite) {
			pClzFile->pOffset = pClzFile->pBuf;
			clz_hdr.blk_desc |= (alg<<3);
			len = (int)fwrite (&clz_hdr, 1, sizeof (clz_hdr), pClzFile->pFile);
			if (len < sizeof (clz_hdr)) {
				clz_fclose (pClzFile);
				return NULL;
			}
		} else {
			pClzFile->pOffset = NULL;
			CLZ_GETLEN (pClzFile->nxt_blk_csz, clz_hdr_file+1);
			clz_debug ("====== %s first block compress size %d\n", file, pClzFile->nxt_blk_csz);
		}
		pClzFile->comp_size += len;
	}

	return pClzFile;
}

static int __clz_compress_block (clz_FILE *pClzFile, int bLast)
{
	int 		size = (int)(pClzFile->pOffset - pClzFile->pBuf), len, wlen;
	int			dsz, dsz_le = 0;

	if (0 == size) {
		return 0;
	}

	if (size < 20) {
		dsz = -1;
	} else {
		dsz_le = dsz = pClzFile->compress_cb (pClzFile->pBuf, size, pClzFile->pOffset+CLZ_LEN_SIZE*2, pClzFile->block_max);
	}
	if ((dsz < 0) || (dsz > ((size*3)>>2))) { // at lease <=75%
		// no compress
		clz_debug ("Don't compress orig %d dsz %d\n", size, dsz);
		dsz  = size;
		dsz_le = size | (1<<23);
		memcpy (pClzFile->pOffset+CLZ_LEN_SIZE, pClzFile->pBuf, size);
	}

	CLZ_SETLEN (dsz_le, pClzFile->pOffset);
	wlen = dsz + CLZ_LEN_SIZE;
	if (dsz < size) {
		CLZ_SETLEN (size, pClzFile->pOffset+CLZ_LEN_SIZE);
		wlen += CLZ_LEN_SIZE;
	}

	if (bLast) {
		// EOF Block Mark
		memset (pClzFile->pOffset + wlen, 0, CLZ_LEN_SIZE);
		wlen += CLZ_LEN_SIZE;
	}

	len = (int)fwrite (pClzFile->pOffset, 1, wlen, pClzFile->pFile);
	pClzFile->comp_size += len;
	clz_debug ("====== %d orig %d ratio %f%%\n", dsz, size, (float)dsz*100/size);
	if (len < wlen) {
		return -1;
	}

	pClzFile->pOffset = pClzFile->pBuf;

	return len;
}

size_t clz_get_size (clz_FILE *pClzFile, size_t *pCompSize)
{
	if (pClzFile->magic != CLZ_MAGIC_NUM) {
		return 0;
	}

	if (pClzFile->bWrite && pClzFile->bCompress) {
		__clz_compress_block (pClzFile, 1);
	}

	if (pClzFile->comp_size == 0) {
		pClzFile->comp_size = pClzFile->orig_size;
	}
	if (pCompSize != NULL) {
		*pCompSize = pClzFile->comp_size;
	}
	return pClzFile->orig_size;
}

int clz_fflush (clz_FILE *pClzFile)
{
	if (pClzFile->magic != CLZ_MAGIC_NUM) {
		return fflush ((FILE*)pClzFile);
	}

	if (pClzFile->bWrite && pClzFile->bCompress) {
		__clz_compress_block (pClzFile, 1);
	}

	return fflush (pClzFile->pFile);
}

int clz_fclose (clz_FILE *pClzFile)
{
	int ret = 0, ret2;

	if (pClzFile->magic != CLZ_MAGIC_NUM) {
		return fclose ((FILE*)pClzFile);
	}

	if (pClzFile->bWrite && pClzFile->bCompress) {
		ret = __clz_compress_block (pClzFile, 1);
	}

	if ((stdin != pClzFile->pFile) && (stdout != pClzFile->pFile)) {
		ret2 = fclose (pClzFile->pFile);
		if (0 == ret) {
			ret = ret2;
		}
	}

	clz_free (pClzFile);
	return ret;
}

static int __clz_decompress_block (clz_FILE *pClzFile)
{
	int 		len, orig_size = 0, meta_len = 2*CLZ_LEN_SIZE;
	uint8_t		*pDecompPtr, alg, bCompress = 1;
	int			block_max;

	if (0 == pClzFile->nxt_blk_csz) {
		// read next frame
		uint32_t		buffer[(sizeof(clz_clzhdr_t)+CLZ_LEN_SIZE+3)/4];
		clz_clzhdr_t	*clz_hdr_file = (clz_clzhdr_t*)buffer; 
		len = (int)fread (clz_hdr_file, 1, sizeof(clz_clzhdr_t)+CLZ_LEN_SIZE, pClzFile->pFile);
  		if ((len < sizeof(clz_clzhdr_t)+CLZ_LEN_SIZE) || (clz_hdr_file->magic != CLZ_MAGIC_NUM)) {
			// end of file
			return 0;
		}
		pClzFile->comp_size += len;
		pClzFile->pOffset = NULL;
		CLZ_GETLEN (pClzFile->nxt_blk_csz, clz_hdr_file+1);
		clz_debug ("====== next frame first block compress size %d\n", pClzFile->nxt_blk_csz);
		alg = (clz_hdr_file->blk_desc>>3)&0x7;
		if (alg != pClzFile->alg) {
			if ((alg > 0) && ((alg > CLZ_ALG_MAX) || (NULL == s_clz_alg[alg].name))) {
				printf ("Compressor %d is not supported\n", alg);
				pClzFile->nxt_blk_csz = 0;
				return -1;
			}
			pClzFile->alg = alg;
			pClzFile->compress_cb = s_clz_alg[alg].compress_cb;
			pClzFile->decompress_cb = s_clz_alg[alg].decompress_cb;
		}
		block_max = CLZ_BLK_SIZE(clz_hdr_file->blk_desc&0x7);
		if (block_max > pClzFile->block_max) {
			printf ("Nex frame max block %d > first frame %d\n", block_max, pClzFile->block_max);
			return -1;
		}
	}

	if (0 == pClzFile->nxt_blk_csz) {
		return 0;
	}

	if (pClzFile->nxt_blk_csz & (1<<23)) {
		pClzFile->nxt_blk_csz &= ~(1<<23);
		bCompress = 0;
		meta_len = CLZ_LEN_SIZE;
	}
	if (pClzFile->nxt_blk_csz > pClzFile->block_max) {
		printf ("error nxt_blk_csz %d > max block %d\n", pClzFile->nxt_blk_csz, pClzFile->block_max);
		return -1;
	}
	pDecompPtr = pClzFile->pBuf+pClzFile->block_max;
	len = (int)fread (pDecompPtr, 1, pClzFile->nxt_blk_csz+meta_len, pClzFile->pFile);
	if (len < pClzFile->nxt_blk_csz+meta_len) {
		clz_debug ("wong read %d %d\n", pClzFile->nxt_blk_csz+meta_len, len);
		return -1;
	}
	pClzFile->comp_size += len;
	if (bCompress) {
		CLZ_GETLEN (orig_size, pDecompPtr);
		pClzFile->block_size = pClzFile->decompress_cb (pDecompPtr+CLZ_LEN_SIZE, pClzFile->nxt_blk_csz, 
														pClzFile->pBuf, pClzFile->block_max);
		if (pClzFile->block_size < 0) {
			printf ("Can't decompress %d\n", pClzFile->block_size);
			return -1;
		}
		clz_debug ("====== %d orig %d ratio %f%%\n", pClzFile->nxt_blk_csz,
					pClzFile->block_size, (float)pClzFile->nxt_blk_csz*100/pClzFile->block_size);
		if (pClzFile->block_size != orig_size) {
			printf ("Decompress size %d != orignal size %d\n", pClzFile->block_size, orig_size);
			return -1;
		}
		meta_len = CLZ_LEN_SIZE;
	} else {
		// no compress
		pClzFile->block_size = pClzFile->nxt_blk_csz;
		pClzFile->pOffset = pClzFile->pBuf + pClzFile->block_max;
		memcpy (pClzFile->pBuf, pDecompPtr, pClzFile->block_size);
		meta_len = 0;
	}

	CLZ_GETLEN (pClzFile->nxt_blk_csz, pDecompPtr + meta_len + pClzFile->nxt_blk_csz);
	clz_debug ("====== next block compress size %d\n", pClzFile->nxt_blk_csz);
	pClzFile->pOffset = pClzFile->pBuf;

	return pClzFile->block_size;
}

int clz_fgets (char *buf, int size, clz_FILE *pClzFile)
{
	int len = size - 1, left, copy_len;
	char *ptr = buf;

	if (pClzFile->magic != CLZ_MAGIC_NUM) {
		ptr = fgets (buf, size, (FILE*)pClzFile);
		if (NULL == ptr) {
			return -1;
		}
		return (int)strlen(buf);
	}

	if (!pClzFile->bCompress) {
		ptr = fgets (buf, size, pClzFile->pFile);
		if (NULL == ptr) {
			return -1;
		}
		len = (int)strlen (buf);
		pClzFile->orig_size += len;
		return len;
	}

	while (1) {
		if (NULL == pClzFile->pOffset) {
			if (__clz_decompress_block (pClzFile) <= 0) {
				break;
			}
		}
		left = (int)(pClzFile->block_size - (pClzFile->pOffset - pClzFile->pBuf));
		if (left <= 0) {
			pClzFile->pOffset = NULL;
			continue;
		}
		copy_len = (len <= left) ? len : left;	
		while ((copy_len-->0) && ('\n' != (*ptr++ = *pClzFile->pOffset++)))
			;
		if ((len > left) && (*(ptr-1) != '\n')) {
			clz_debug ("read again\n");
			pClzFile->pOffset = NULL;
			len -= left;
		} else {
			break;
		}
	}

	len = (int)(ptr - buf);
	if (len > 0) {
		*ptr = '\0';
		pClzFile->orig_size += len;
	}
	return len;
}

int clz_fputs (const char *str, clz_FILE *pClzFile)
{
	int size, len, left, ret;

	if (pClzFile->magic != CLZ_MAGIC_NUM) {
		return fputs (str, (FILE*)pClzFile);
	}

   	size = len = (int)strlen (str);

	if (!pClzFile->bCompress) {
		ret = fputs (str, pClzFile->pFile);
		pClzFile->orig_size += len;
		return ret >= 0 ? len : ret;
	}

	while (1) {
		if (pClzFile->pOffset-pClzFile->pBuf >= pClzFile->block_max) {
			if (__clz_compress_block (pClzFile, 0) < 0) {
				break;
			}
		}
		left = (int)(pClzFile->block_max - (pClzFile->pOffset-pClzFile->pBuf));
		if (len > left) {
		   	memcpy ((char*)pClzFile->pOffset, str, left);
			pClzFile->pOffset += left;
			str += left;
			len -= left;
		} else {
		   	memcpy ((char*)pClzFile->pOffset, str, len);
			pClzFile->pOffset += len;
			len = 0;
			break;
		}
	}

	len = size - len;
	pClzFile->orig_size += len;
	return len;
}

int clz_fread (void *ptr, int size, int nmemb, clz_FILE *pClzFile)
{
	int left, len = size*nmemb, total = len;

	if (pClzFile->magic != CLZ_MAGIC_NUM) {
		return (int)fread (ptr, size, nmemb, (FILE*)pClzFile);
	}

	if (!pClzFile->bCompress) {
		len = (int)fread (ptr, size, nmemb, pClzFile->pFile);
		pClzFile->orig_size += len;
		return len;
	}

	while (1) {
		if (NULL == pClzFile->pOffset) {
			if (__clz_decompress_block (pClzFile) <= 0) {
				break;
			}
		}
		left = (int)(pClzFile->block_size - (pClzFile->pOffset - pClzFile->pBuf));
		if (left <= 0) {
			pClzFile->pOffset = NULL;
			continue;
		}
		if (len > left) {
		   	memcpy (ptr, (char*)pClzFile->pOffset, left);
			pClzFile->pOffset = NULL;
			ptr = (u8*)ptr + left;
			len -= left;
		} else {
		   	memcpy (ptr, (char*)pClzFile->pOffset, len);
			pClzFile->pOffset += len;
			len = 0;
			break;
		}
	}

	len = total - len;
	pClzFile->orig_size += len;
	return len;
}

int clz_fwrite (const void *ptr, int size, int nmemb, clz_FILE *pClzFile)
{
	int left, len = size*nmemb, total = len;

	if (pClzFile->magic != CLZ_MAGIC_NUM) {
		return (int)fwrite (ptr, size, nmemb, (FILE*)pClzFile);
	}
	
	if (!pClzFile->bCompress) {
		len = (int)fwrite (ptr, size, nmemb, pClzFile->pFile);
		pClzFile->orig_size += len;
		return len;
	}

	while (1) {
		if (pClzFile->pOffset-pClzFile->pBuf >= pClzFile->block_max) {
			if (__clz_compress_block (pClzFile, 0) < 0) {
				return -1;
			}
		}
		left = (int)(pClzFile->block_max - (pClzFile->pOffset-pClzFile->pBuf));
		if (len > left) {
		   	memcpy ((char*)pClzFile->pOffset, ptr, left);
			pClzFile->pOffset += left;
			ptr = (u8*)ptr + left;
			len -= left;
		} else {
		   	memcpy ((char*)pClzFile->pOffset, ptr, len);
			pClzFile->pOffset += len;
			len = 0;
			break;
		}
	}

	len = total - len;
	pClzFile->orig_size += len;
	return len;
}

int clz_fprintf (clz_FILE *pClzFile, const char *format, ...)
{
	int			len;
    va_list 	vargs;

	if (pClzFile->magic != CLZ_MAGIC_NUM) {
	    va_start(vargs, format);
		len = vfprintf ((FILE*)pClzFile, format, vargs);
		va_end(vargs);
		return len;
	}

	if (!pClzFile->bCompress) {
	    va_start(vargs, format);
		len = vfprintf (pClzFile->pFile, format, vargs);
		va_end(vargs);
		pClzFile->orig_size += len;
		return len;
	}

	if (pClzFile->pOffset-pClzFile->pBuf >= (pClzFile->block_max-CLZ_MAX_PRINT_SIZE)) {
		if (__clz_compress_block (pClzFile, 0) < 0) {
			return -1;
		}
	}

    va_start(vargs, format);
	len = vsprintf ((char*)pClzFile->pOffset, format, vargs);
	va_end(vargs);
	pClzFile->pOffset += len;
	pClzFile->orig_size += len;
	return len;
}

size_t	clz_file_compress (const char *in_file, const char *out_file, int alg, int blk_cfg, size_t *pCompSize)
{
	int		len, ret = 0;
	size_t 		size = 0;
	char 		file[512];
	clz_FILE 	*pInFile = clz_fopen (in_file, "rb", alg, blk_cfg);
	clz_FILE 	*pOutFile = NULL;
	int			blk_size = CLZ_BLK_SIZE(blk_cfg);
	char		*buf = clz_malloc (blk_size);

	if (NULL == pInFile) {
		printf ("Can't open %s\n", in_file);
		if (NULL != buf) {
			clz_free (buf);
		}
		return 0;
	}
	if (NULL == buf) {
		printf ("Can't clz_malloc %d memory\n", blk_size);
		clz_fclose (pInFile);
		return 0;
	}

	if (!pInFile->bCompress) {
		// Compress
		if (NULL == out_file) {
			strcpy (file, in_file);
			strcat (file, ".clz");
			out_file = file;
		}
		pOutFile = clz_fopen (out_file, "wb", alg, blk_cfg);
		if (NULL == pOutFile) {
			printf ("Can't open %s\n", out_file);
			ret = -1;
			goto exit;
		}

		clz_debug ("Begin compress ...\n");
		while ((len = clz_fread (buf, 1, blk_size, pInFile)) > 0) {
			clz_debug ("Compress %d\n", len);
			clz_fwrite (buf, len, 1, pOutFile);
		}
	} else {
		// Decompress
		if (NULL == out_file) {
			char *dot = strrchr (in_file, '.');
			if ((NULL != dot) && !strcmp (dot, ".clz")) {
				memcpy (file, in_file, dot-in_file);
				file[dot-in_file] = '\0';
			} else {
				strcpy (file, in_file);
				strcat (file, ".clx");
			}
			out_file = file;
		}
		pOutFile = clz_fopen (out_file, "ab", 0, 0);
		if (NULL == pOutFile) {
			printf ("Can't open %s\n", out_file);
			ret = -1;
			goto exit;
		}

		clz_debug ("Begin decompress ...\n");
		while ((len = clz_fread (buf, 1, blk_size, pInFile)) > 0) {
			clz_debug ("Decompress %d\n", len);
			clz_fwrite (buf, len, 1, pOutFile);
		}
	}

exit:
	if (0 == ret) {
		size = clz_get_size (pInFile->bCompress?pInFile:pOutFile, pCompSize);
	}
	if (pInFile != NULL) {
		clz_fclose (pInFile);
	}
	if (pOutFile != NULL) {
		clz_fclose (pOutFile);
	}
	clz_free (buf);

	return size;
}
