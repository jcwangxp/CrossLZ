/* 

Build

#Windows MSVC
	cl -D_CRT_SECURE_NO_WARNINGS -W4 User32.Lib crosslz.c example.c /Feexample.exe

#GCC(Linux, MinGW, Cygwin, MSYS2)
    gcc -Wall crosslz.c example.c -o example

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crosslz.h"

int main (int argc, char **argv) 
{
	clz_FILE 	*pFile;
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
