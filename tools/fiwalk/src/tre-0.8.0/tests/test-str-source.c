/*
  test-str-source.c - Sample program for using tre_reguexec()

  This software is released under a BSD-style license.
  See the file LICENSE for details and copyright.

*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "regex.h"
#include "tre-internal.h"

/* Context structure for the tre_str_source wrappers.  */
typedef struct {
  /* Our string. */
  const char *str;
  /* Current position in the string. */
  size_t pos;
} str_handler_ctx;

/* The get_next_char() handler.  Sets `c' to the value of the next character,
   and increases `pos_add' by the number of bytes read.  Returns 1 if the
   string has ended, 0 if there are more characters. */
static int
str_handler_get_next(tre_char_t *c, unsigned int *pos_add, void *context)
{
  str_handler_ctx *ctx = context;
  unsigned char ch = ctx->str[ctx->pos];

  printf("str[%lu] = %d\n", (unsigned long)ctx->pos, ch);
  *c = ch;
  if (ch)
    ctx->pos++;
  *pos_add = 1;

  return ch == '\0';
}

/* The rewind() handler.  Resets the current position in the input string. */
static void
str_handler_rewind(size_t pos, void *context)
{
  str_handler_ctx *ctx = context;

  printf("rewind to %lu\n", (unsigned long)pos);
  ctx->pos = pos;
}

/* The compare() handler.  Compares two substrings in the input and returns
   0 if the substrings are equal, and a nonzero value if not. */
static int
str_handler_compare(size_t pos1, size_t pos2, size_t len, void *context)
{
  str_handler_ctx *ctx = context;
  printf("comparing %lu-%lu and %lu-%lu\n",
	 (unsigned long)pos1, (unsigned long)pos1 + len,
	 (unsigned long)pos2, (unsigned long)pos2 + len);
  return strncmp(ctx->str + pos1, ctx->str + pos2, len);
}

/* Creates a tre_str_source wrapper around the string `str'.  Returns the
   tre_str_source object or NULL if out of memory. */
static tre_str_source *
make_str_source(const char *str)
{
  tre_str_source *s;
  str_handler_ctx *ctx;

  s = calloc(1, sizeof(*s));
  if (!s)
    return NULL;

  ctx = malloc(sizeof(str_handler_ctx));
  if (!ctx)
    {
      free(s);
      return NULL;
    }

  ctx->str = str;
  ctx->pos = 0;
  s->context = ctx;
  s->get_next_char = str_handler_get_next;
  s->rewind = str_handler_rewind;
  s->compare = str_handler_compare;

  return s;
}

/* Frees the memory allocated for `s'. */
static void
free_str_source(tre_str_source *s)
{
  free(s->context);
  free(s);
}

/* Run one test with tre_reguexec */
static void
test_reguexec(const char *str, const char *regex)
{
  regex_t preg;
  tre_str_source *source;
  regmatch_t pmatch[5];

  source = make_str_source(str);
  if (!source)
    return;

  tre_regcomp(&preg, regex, REG_EXTENDED);
  if (tre_reguexec(&preg, source, elementsof(pmatch), pmatch, 0) == 0)
    printf("Match: %d - %d\n", (int)pmatch[0].rm_so, (int)pmatch[0].rm_eo);

  free_str_source(source);
  tre_regfree(&preg);
}

int
main(int argc, char **argv)
{
  test_reguexec("xfoofofoofoo","(foo)\\1");
  test_reguexec("catcat","(cat|dog)\\1");
  test_reguexec("catdog","(cat|dog)\\1");
  test_reguexec("dogdog","(cat|dog)\\1");
  test_reguexec("dogcat","(cat|dog)\\1");

  return 0;
}
