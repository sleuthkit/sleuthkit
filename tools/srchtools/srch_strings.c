/*
 * From binutils-2.15 removed getopt_long stuff
 * 
 */

/*
 * strings -- print the strings of printable characters in files Copyright
 * 1993, 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003 Free
 * Software Foundation, Inc.
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any later
 * version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


/*
 * Usage: strings [options] file...
 * 
 * Options: -a -		Do not scan only the initialized data section of
 * object files.
 * 
 * -f		Print the name of the file before each string.
 * 
 * -n min-len -min-len	Print graphic char sequences, MIN-LEN or more bytes
 * long, that are followed by a NUL or a newline.  Default is 4.
 * 
 * -t {o,x,d}	Print the offset within the file before each string, in
 * octal/hex/decimal.
 * 
 * -o		Like -to.  (Some other implementations have -o like -to,
 * others like -td.  We chose one arbitrarily.)
 * 
 * -e {s,S,b,l,B,L} Select character encoding: 7-bit-character, 8-bit-character,
 * bigendian 16-bit, littleendian 16-bit, bigendian 32-bit, littleendian
 * 32-bit.
 * 
 * -h		Print the usage message on the standard output.
 * 
 * -v		Print the program version number.
 * 
 * Written by Richard Stallman <rms@gnu.ai.mit.edu> and David MacKenzie
 * <djm@gnu.ai.mit.edu>.
 */

#if HAVE_CONFIG_H
#include "tsk_config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <inttypes.h>

/*
 * Some platforms need to put stdin into binary mode, to read binary files.
 */
#ifdef HAVE_SETMODE
#ifndef O_BINARY
#ifdef _O_BINARY
#define O_BINARY _O_BINARY
#define setmode _setmode
#else
#define O_BINARY 0
#endif
#endif
#if O_BINARY
#include <io.h>
#define SET_BINARY(f) do { if (!isatty (f)) setmode (f,O_BINARY); } while (0)
#endif
#endif

#ifndef PRIx64
#define PRIx64 "llx"
#endif

#ifndef PRId64
#define PRId64 "lld"
#endif

#ifndef PRIo64
#define PRIo64 "llo"
#endif


/* The following were taken from other files in binutils */
// from include / libiberty.h
enum {
        /* In C99 */
        _sch_isblank = 0x0001,  /* space \t */
        _sch_iscntrl = 0x0002,  /* nonprinting characters */
        _sch_isdigit = 0x0004,  /* 0-9 */
        _sch_islower = 0x0008,  /* a-z */
        _sch_isprint = 0x0010,  /* any printing character including ' ' */
        _sch_ispunct = 0x0020,  /* all punctuation */
        _sch_isspace = 0x0040,  /* space \t \n \r \f \v */
        _sch_isupper = 0x0080,  /* A-Z */
        _sch_isxdigit = 0x0100, /* 0-9A-Fa-f */

        /* Extra categories useful to cpplib.  */
        _sch_isidst = 0x0200,   /* A-Za-z_ */
        _sch_isvsp = 0x0400,    /* \n \r */
        _sch_isnvsp = 0x0800,   /* space \t \f \v \0 */

        /* Combinations of the above.  */
        _sch_isalpha = _sch_isupper | _sch_islower,     /* A-Za-z */
        _sch_isalnum = _sch_isalpha | _sch_isdigit,     /* A-Za-z0-9 */
        _sch_isidnum = _sch_isidst | _sch_isdigit,      /* A-Za-z0-9_ */
        _sch_isgraph = _sch_isalnum | _sch_ispunct,     /* isprint and not space */
        _sch_iscppsp = _sch_isvsp | _sch_isnvsp,        /* isspace + \0 */
        _sch_isbasic = _sch_isprint | _sch_iscppsp      /* basic charset of ISO
                                                         * C (plus ` and @)  */
};


//from libiberty / safe - ctype.h

/* Shorthand */
#define bl _sch_isblank
#define cn _sch_iscntrl
#define di _sch_isdigit
#define is _sch_isidst
#define lo _sch_islower
#define nv _sch_isnvsp
#define pn _sch_ispunct
#define pr _sch_isprint
#define sp _sch_isspace
#define up _sch_isupper
#define vs _sch_isvsp
#define xd _sch_isxdigit

/* Masks.  */
#define L  (const unsigned short) (lo|is   |pr) /* lower case letter */
#define XL (const unsigned short) (lo|is|xd|pr) /* lowercase hex digit */
#define U  (const unsigned short) (up|is   |pr) /* upper case letter */
#define XU (const unsigned short) (up|is|xd|pr) /* uppercase hex digit */
#define D  (const unsigned short) (di   |xd|pr) /* decimal digit */
#define P  (const unsigned short) (pn      |pr) /* punctuation */
#define _  (const unsigned short) (pn|is   |pr) /* underscore */

#define C  (const unsigned short) (         cn) /* control character */
#define Z  (const unsigned short) (nv      |cn) /* NUL */
#define M  (const unsigned short) (nv|sp   |cn) /* cursor movement: \f \v */
#define V  (const unsigned short) (vs|sp   |cn) /* vertical space: \r \n */
#define T  (const unsigned short) (nv|sp|bl|cn) /* tab */
#define S  (const unsigned short) (nv|sp|bl|pr) /* space */


const unsigned short _sch_istable[256] =
{
        Z, C, C, C, C, C, C, C, /* NUL SOH STX ETX  EOT ENQ ACK BEL */
        C, T, V, M, M, V, C, C, /* BS  HT  LF  VT   FF  CR  SO  SI  */
        C, C, C, C, C, C, C, C, /* DLE DC1 DC2 DC3  DC4 NAK SYN ETB */
        C, C, C, C, C, C, C, C, /* CAN EM  SUB ESC  FS  GS  RS  US  */
        S, P, P, P, P, P, P, P, /* SP  !   "   #    $   %   &   '   */
        P, P, P, P, P, P, P, P, /* (   )   *   +    ,   -   .   /   */
        D, D, D, D, D, D, D, D, /* 0   1   2   3    4   5   6   7   */
        D, D, P, P, P, P, P, P, /* 8   9   :   ;    <   =   >   ?   */
        P, XU, XU, XU, XU, XU, XU, U,   /* @   A   B   C    D   E   F   G   */
        U, U, U, U, U, U, U, U, /* H   I   J   K    L   M   N   O   */
        U, U, U, U, U, U, U, U, /* P   Q   R   S    T   U   V   W   */
        U, U, U, P, P, P, P, _, /* X   Y   Z   [    \   ]   ^   _   */
        P, XL, XL, XL, XL, XL, XL, L,   /* `   a   b   c    d   e   f   g   */
        L, L, L, L, L, L, L, L, /* h   i   j   k    l   m   n   o   */
        L, L, L, L, L, L, L, L, /* p   q   r   s    t   u   v   w   */
        L, L, L, P, P, P, P, C, /* x   y   z   {    |   }   ~   DEL */

        /*
         * high half of unsigned char is locale-specific, so all tests are
         * false in "C" locale
         */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};


#define _sch_test(c, bit) (_sch_istable[(c) & 0xff] & (unsigned short)(bit))
#define ISPRINT(c)  _sch_test(c, _sch_isprint)

#define bfd_boolean unsigned char
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif
char           *program_name;

/* End of stuff added by brian */



#define STRING_ISGRAPHIC(c) \
      (   (c) >= 0 \
       && (c) <= 255 \
       && ((c) == '\t' || ISPRINT (c) || (encoding == 'S' && (c) > 127)))


#ifndef errno
extern int      errno;
#endif

#ifdef HAVE_FOPEN64
//typedef off64_t file_off;
#define file_open(s,m) fopen64(s, m)
#else
//typedef off_t file_off;
#define file_open(s,m) fopen(s, m)
#endif


/* Radix for printing addresses (must be 8, 10 or 16).  */
static int      address_radix;

/* Minimum length of sequence of graphic chars to trigger output.  */
static int      string_min;

/* TRUE means print address within file for each string.  */
static bfd_boolean print_addresses;

/* TRUE means print filename for each string.  */
static bfd_boolean print_filenames;


/* The character encoding format.  */
static char     encoding;
static int      encoding_bytes;

static bfd_boolean strings_file(char *file);
static int      integer_arg(char *s);
static void     print_strings(const char *, FILE *, uint64_t, uint64_t, int, char *);
static void     usage(FILE *, int);
static long     get_char(FILE *, uint64_t *, int *, char **);


int             main(int, char **);

int
main(int argc, char **argv)
{
        int             optc;
        int             exit_status = 0;
        bfd_boolean     files_given = FALSE;

        program_name = argv[0];
        string_min = -1;
        print_addresses = FALSE;
        print_filenames = FALSE;
        encoding = 's';

        while ((optc = getopt(argc, argv, "afhHn:ot:e:Vv0123456789")) != EOF) {
                switch (optc) {
                case 'a':
                        break;

                case 'f':
                        print_filenames = TRUE;
                        break;

                case 'H':
                case 'h':
                        usage(stdout, 0);

                case 'n':
                        string_min = integer_arg(optarg);
                        if (string_min < 1) {
                                fprintf(stderr, "invalid number %s\n", optarg);
                        }
                        break;

                case 'o':
                        print_addresses = TRUE;
                        address_radix = 8;
                        break;

                case 't':
                        print_addresses = TRUE;
                        if (optarg[1] != '\0')
                                usage(stderr, 1);
                        switch (optarg[0]) {
                        case 'o':
                                address_radix = 8;
                                break;

                        case 'd':
                                address_radix = 10;
                                break;

                        case 'x':
                                address_radix = 16;
                                break;

                        default:
                                usage(stderr, 1);
                        }
                        break;


                case 'e':
                        if (optarg[1] != '\0')
                                usage(stderr, 1);
                        encoding = optarg[0];
                        break;

                case 'V':
                case 'v':
#ifdef VER
                        printf("The Sleuth Kit ver %s\n", VER);
#else
                        printf("The Sleuth Kit\n");
#endif
                        printf("Modified version of strings from GNU binutils-2.15\n");
                        exit(0);

                case '?':
                        usage(stderr, 1);

                default:
                        if (string_min < 0)
                                string_min = optc - '0';
                        else
                                string_min = string_min * 10 + optc - '0';
                        break;
                }
        }

        if (string_min < 0)
                string_min = 4;

        switch (encoding) {
        case 'S':
        case 's':
                encoding_bytes = 1;
                break;
        case 'b':
        case 'l':
                encoding_bytes = 2;
                break;
        case 'B':
        case 'L':
                encoding_bytes = 4;
                break;
        default:
                usage(stderr, 1);
        }


        if (optind >= argc) {
#ifdef SET_BINARY
                SET_BINARY(fileno(stdin));
#endif
                print_strings("{standard input}", stdin, 0, 0, 0, (char *)NULL);
                files_given = TRUE;
        }
        else {
                for (; optind < argc; ++optind) {
                        files_given = TRUE;
                        exit_status |= strings_file(argv[optind]) == FALSE;
                }
        }

        if (!files_given)
                usage(stderr, 1);

        return (exit_status);
}

/*
 * Returns the size of the named file.  If the file does not exist, or if it
 * is not a real file, then a suitable non-fatal error message is printed and
 * zero is returned.
 */

off_t
get_file_size(const char *file_name)
{
        struct stat     statbuf;

        if (stat(file_name, &statbuf) < 0) {
                if (errno == ENOENT)
                        fprintf(stderr, "'%s': No such file\n", file_name);
                else
                        fprintf(stderr, "Warning: could not locate '%s'.  reason: %s\n",
                                file_name, strerror(errno));
        }
        else if (!S_ISREG(statbuf.st_mode)) {
                fprintf(stderr, "Warning: '%s' is not an ordinary file\n", file_name);
        }
        else
                return statbuf.st_size;

        return 0;
}




/* Print the strings in FILE.  Return TRUE if ok, FALSE if an error occurs.  */

static          bfd_boolean
strings_file(char *file)
{
        FILE           *stream;
        if (get_file_size(file) < 1)
                return FALSE;


        stream = file_open(file, "r");
        if (stream == NULL) {
                fprintf(stderr, "%s: ", program_name);
                perror(file);
                return FALSE;
        }

        print_strings(file, stream, (uint64_t) 0, 0, 0, (char *)0);

        if (fclose(stream) == EOF) {
                fprintf(stderr, "%s: ", program_name);
                perror(file);
                return FALSE;
        }

        return TRUE;
}


/*
 * Read the next character, return EOF if none available. Assume that STREAM
 * is positioned so that the next byte read is at address ADDRESS in the
 * file.
 * 
 * If STREAM is NULL, do not read from it. The caller can supply a buffer of
 * characters to be processed before the data in STREAM. MAGIC is the address
 * of the buffer and MAGICCOUNT is how many characters are in it.
 */

static long
get_char(FILE * stream, uint64_t * address, int *magiccount, char **magic)
{
        int             c, i;
        long            r = EOF;
        unsigned char   buf[4];

        for (i = 0; i < encoding_bytes; i++) {
                if (*magiccount) {
                        (*magiccount)--;
                        c = *(*magic)++;
                }
                else {
                        if (stream == NULL)
                                return EOF;
#ifdef HAVE_GETC_UNLOCKED
                        c = getc_unlocked(stream);
#else
                        c = getc(stream);
#endif
                        if (c == EOF)
                                return EOF;
                }

                (*address)++;
                buf[i] = c;
        }

        switch (encoding) {
        case 'S':
        case 's':
                r = buf[0];
                break;
        case 'b':
                r = (buf[0] << 8) | buf[1];
                break;
        case 'l':
                r = buf[0] | (buf[1] << 8);
                break;
        case 'B':
                r = ((long)buf[0] << 24) | ((long)buf[1] << 16) |
                        ((long)buf[2] << 8) | buf[3];
                break;
        case 'L':
                r = buf[0] | ((long)buf[1] << 8) | ((long)buf[2] << 16) |
                        ((long)buf[3] << 24);
                break;
        }

        if (r == EOF)
                return 0;

        return r;
}


/*
 * Find the strings in file FILENAME, read from STREAM. Assume that STREAM is
 * positioned so that the next byte read is at address ADDRESS in the file.
 * Stop reading at address STOP_POINT in the file, if nonzero.
 * 
 * If STREAM is NULL, do not read from it. The caller can supply a buffer of
 * characters to be processed before the data in STREAM. MAGIC is the address
 * of the buffer and MAGICCOUNT is how many characters are in it. Those
 * characters come at address ADDRESS and the data in STREAM follow.
 */

static void
print_strings(const char *filename, FILE * stream, uint64_t address,
        uint64_t stop_point, int magiccount, char *magic)
{
        char           *buf = (char *)malloc(sizeof(char) * (string_min + 1));
        if (buf == NULL) {
                fprintf(stderr, "Error allocating memory\n");
                return;
        }

        while (1) {
                uint64_t        start;
                int             i;
                long            c;

                /* See if the next `string_min' chars are all graphic chars.  */
tryline:
                if (stop_point && address >= stop_point)
                        break;
                start = address;
                for (i = 0; i < string_min; i++) {
                        c = get_char(stream, &address, &magiccount, &magic);
                        if (c == EOF) {
                                free(buf);
                                return;
                        }
                        if (!STRING_ISGRAPHIC(c))
                                /*
                                 * Found a non-graphic.  Try again starting
                                 * with next char.
                                 */
                                goto tryline;
                        buf[i] = c;
                }

                /*
                 * We found a run of `string_min' graphic characters.  Print
                 * up to the next non-graphic character.
                 */

                if (print_filenames)
                        printf("%s: ", filename);
                if (print_addresses)
                        switch (address_radix) {
                        case 8:
                                printf("%10" PRIo64 " ", start);
                                break;

                        case 10:
                                printf("%10" PRId64 " ", start);
                                break;

                        case 16:
                                printf("%10" PRIx64 " ", start);
                                break;
                        }

                buf[i] = '\0';
                fputs(buf, stdout);

                while (1) {
                        c = get_char(stream, &address, &magiccount, &magic);
                        if (c == EOF)
                                break;
                        if (!STRING_ISGRAPHIC(c))
                                break;
                        putchar(c);
                }

                putchar('\n');
        }
        free(buf);
}


/*
 * Parse string S as an integer, using decimal radix by default, but allowing
 * octal and hex numbers as in C.
 * 
 * Return 0 on error
 */

static int
integer_arg(char *s)
{
        int             value;
        int             radix = 10;
        char           *p = s;
        int             c;

        if (*p != '0')
                radix = 10;
        else if (*++p == 'x') {
                radix = 16;
                p++;
        }
        else
                radix = 8;

        value = 0;
        while (((c = *p++) >= '0' && c <= '9')
                || (radix == 16 && (c & ~40) >= 'A' && (c & ~40) <= 'Z')) {
                value *= radix;
                if (c >= '0' && c <= '9')
                        value += c - '0';
                else
                        value += (c & ~40) - 'A';
        }

        if (c == 'b')
                value *= 512;
        else if (c == 'B')
                value *= 1024;
        else
                p--;

        if (*p) {
                fprintf(stderr, "invalid integer argument %s\n", s);
                return 0;
        }

        return value;
}

static void
usage(FILE * stream, int status)
{
        fprintf(stream, "Usage: %s [option(s)] [file(s)]\n", program_name);
        fprintf(stream, " Display printable strings in [file(s)] (stdin by default)\n");
        fprintf(stream, " The options are:\n\
  -a -                 Scan the entire file, not just the data section\n\
  -f       Print the name of the file before each string\n\
  -n number       Locate & print any NUL-terminated sequence of at\n\
  -<number>                 least [number] characters (default 4).\n\
  -t {o,x,d}        Print the location of the string in base 8, 10 or 16\n\
  -o                        An alias for --radix=o\n\
  -e {s,S,b,l,B,L} Select character size and endianness:\n\
                            s = 7-bit, S = 8-bit, {b,l} = 16-bit, {B,L} = 32-bit\n\
  -h                  Display this information\n\
  -v               Print the program's version number\n");
        exit(status);
}
