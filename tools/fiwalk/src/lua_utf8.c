/*==================================================================*/
/*			C program by sarnold@free.fr 2007, MIT license
			based on the work of Rici Lake rici@ricilake.net		*/
/*==================================================================*/

#include <memory.h>
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#define INVALID_UTF8 "invalid utf-8 string"
#define POINTS_ASCII(p) (*((unsigned char*)p) < 128)
#define RANGE(x, min, max) ((x)>=min && (x)<=max)
#define RANGE_SND(x) RANGE(x,128,191)
#define UTF8_BOM(p) (p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF)
int sarn_utf8_next(const unsigned char* str)
{
	if (*str < 128)
		return 1;
	if (UTF8_BOM(str))
		return 3;
	if (*str < 194)
		return 0;
	if (*str > 244)
		return 0;
	if (*str < 224 && RANGE_SND(str[1]))
		return 2;
	if (RANGE(*str, 225, 239) && *str != 237 
		&& RANGE_SND(str[1]) && RANGE_SND(str[2]))
		return 3;
	if (*str == 224 && RANGE(str[1],160,191) && RANGE_SND(str[2]))
		return 3;
	if (*str == 237 && RANGE(str[1],128,159) && RANGE_SND(str[2]))
		return 3;
	if (RANGE(*str, 241, 243) && RANGE_SND(str[1]) 
		&& RANGE_SND(str[2]) && RANGE_SND(str[3]))
		return 4;
	if (*str == 240 && RANGE(str[1],144,191) 
		&& RANGE_SND(str[2]) && RANGE_SND(str[3]))
		return 4;
	if (*str == 244 && RANGE(str[1],128,143) 
		&& RANGE_SND(str[2]) && RANGE_SND(str[3]))
		return 4;
	return 0;
}

#define BACK(str, remain) if (--remain == 0) return 0; else str--
int sarn_utf8_prev(unsigned char* str, int remain)
{
	BACK(str,remain);
	if (*str < 128)
		return 1;
	
	BACK(str,remain);
	if (RANGE(*str,195,224) && RANGE_SND(str[1]))
		return 2;
	
	BACK(str,remain);
	if (UTF8_BOM(str))
		return 3;
	if (RANGE(*str, 225, 239) && *str != 237 
		&& RANGE_SND(str[1]) && RANGE_SND(str[2]))
		return 3;
	if (*str == 224 && RANGE(str[1],160,191) && RANGE_SND(str[2]))
		return 3;
	if (*str == 237 && RANGE(str[1],160,191) && RANGE_SND(str[2]))
		return 3;
	
	BACK(str,remain);
	if (RANGE(*str, 241, 243) && RANGE_SND(str[1]) 
		&& RANGE_SND(str[2]) && RANGE_SND(str[3]))
		return 4;
	if (*str == 240 && RANGE(str[1],144,191) 
		&& RANGE_SND(str[2]) && RANGE_SND(str[3]))
		return 4;
	if (*str == 244 && RANGE(str[1],128,143) 
		&& RANGE_SND(str[2]) && RANGE_SND(str[3]))
		return 4;
	/* fail back */
	return 0;
}


/** Realign index on an UTF-8 char boundary in str.
	Returns the offset (0 to 3) to be seeked backwards, or -1 if it fails.
 */
int sarn_utf8_realign(unsigned char* str, size_t index)
{
	size_t size, i;
	
	for (i = 0; i<4 && index>=i;i++) {
		if (sarn_utf8_next(str-i)!=0)
			return i;
	}
	return -1;
}
		

int sarn_utf8_next_func(lua_State* L)
{
	const char *str;
	size_t pos, clen;
	char utf8[5];
	
	str = luaL_checkstring(L, 1);
	pos = luaL_checklong(L, 2);
	if (strlen(str)<pos) {
		lua_pushnil(L);
		return 1;
	}
	memset(utf8, '\0', sizeof(utf8));
	
	if (pos == 0)
		return luaL_error(L, "bad index value : 0");
	
	clen = sarn_utf8_next((unsigned char *)str+pos-1);
	if (!clen)
		return luaL_error(L, INVALID_UTF8);
	
	lua_pushnumber(L, pos+clen);
	strncpy(utf8, str+pos-1, clen);
	lua_pushstring(L, utf8);
	return 2;
}

int sarn_utf8_len_func(lua_State *L)
{
	unsigned char *str;
	int l;
	size_t len = 0;
	
	str = (unsigned char*) luaL_checkstring(L, 1);
	
	while (*str) {
		if (POINTS_ASCII(str)) {
			str++;
			len++;
			continue;
		}
		l = sarn_utf8_next(str);
		if (!l)
			return luaL_error(L, INVALID_UTF8);
		
		len++;
		str+=l;
	}
	lua_pushnumber(L, len);
	return 1;
}

int sarn_utf8_seek_func(lua_State *L)
{
	unsigned char* str;
	int pos, shift;
	int clen, len;

	str = (unsigned char*)luaL_checkstring(L, 1);
	pos = luaL_checklong(L, 2);
	shift = luaL_checklong(L, 3);
	len = strlen(str);
	
	if (shift == 0) {
		lua_pushinteger(L, pos);
		return 1;
	}
	
	if (pos > len || pos < 1)
		return luaL_error(L, "invalid index (arg #2)");
	
	/* then, pos is 0-based */
	pos--;
	
	if (abs(shift) > len) {
		/* out of range */
		lua_pushnil(L);
		return 1;
	}
	
	if (shift < 0) {
		while ((shift++) != 0) {
			clen = sarn_utf8_prev(str+pos, pos+1);
			if (clen == 0 || pos+1 < clen) {
				lua_pushnil(L);
				return 1;
			}
			pos -= clen;
		}
	} else {
		while ((shift--) != 0) {
			if (POINTS_ASCII(str+pos)) {
				pos ++;
				continue;
			}
			clen = sarn_utf8_next(str+pos);
			if (clen == 0 || pos+clen >= len) {
				lua_pushnil(L);
				return 1;
			}
			pos += clen;
		}
	}
	
	lua_pushinteger(L, pos+1);
	return 1;
}

int sarn_utf8_char_func(lua_State *L)
{
	unsigned char str[2];
	long int i;
	uint32_t code;
	unsigned char result[5];
	
	i = luaL_checklong(L, 1);
	memset(result, '\0', sizeof(result));
	code = i;
	
	if (i >= 0xD800 && i <= 0xDFFF)
		return luaL_error(L, "invalid utf-8 code");
	
	if (i >= 0 && i < 0x110000UL) {
		if (code == 0) {
			/* UTF8 BOM */
			lua_pushstring(L, "\xEF\xBB\xBF");
			return 1;
		}
		if (code < 128) {
			result[0] = code;
			lua_pushstring(L, (char*)result);
			return 1;
		}
		str[0] = 0x80 + (code & 63);
		code = code >> 6;
		if (code < 32) {
			result[0] = 0xC0+code;
			result[1] = str[0];
			lua_pushstring(L, (char*)result);
			return 1;
		}
		str[1] = code & 0x3f;
		code = code >> 6;
		if (code < 16 && (code != 13 || str[1] < 32)) {
			result[0] = 0xE0 + code;
			result[1] = str[1] + 0x80;
			result[2] = str[0];
			lua_pushstring(L, (char*)result);
			return 1;
		} else if (code >= 16 && code < 0x110) {
			result[1] = 0x80 + (code & 0x3f);
			result[0] = 0xF0 + (code >> 6);
			result[2] = str[1] + 0x80;
			result[3] = str[0];
			lua_pushstring(L, (char*) result);
			return 1;
		}
	}
	return luaL_error(L, "invalid utf-8 code");
}
	
int sarn_utf8_code_func(lua_State *L)
{
	unsigned char* str;
	size_t len, i;
	uint32_t code;
	uint32_t offset[] = {0, 0x3000,
  0xE0000UL,
  0x3C00000UL};
	
	str = (unsigned char*)luaL_checklstring(L, 1, &len);
	
	if (len != sarn_utf8_next(str))
		return luaL_error(L, INVALID_UTF8);
	
	if (UTF8_BOM(str)) {
		lua_pushinteger(L, 0);
		return 1;
	}
		
	
	code = str[0];
	for (i = 1; i < len; i++) {
		code = (code << 6) + (str[i] & 63);
	}
	lua_pushinteger(L, code - offset[len-1]);
	
	return 1;
}
	
	
int luaopen_libluautf8 (lua_State *L)
{
	lua_getglobal(L, "string");
	lua_pushcfunction(L, sarn_utf8_next_func);
	lua_setfield(L, -2, "nextutf8");
	lua_pushcfunction(L, sarn_utf8_len_func);
	lua_setfield(L, -2, "utf8len");
	lua_pushcfunction(L, sarn_utf8_seek_func);
	lua_setfield(L, -2, "seekutf8");
	lua_pushcfunction(L, sarn_utf8_code_func);
	lua_setfield(L, -2, "utf8code");
	lua_pushcfunction(L, sarn_utf8_char_func);
	lua_setfield(L, -2, "utf8char");
	return 0;
}

