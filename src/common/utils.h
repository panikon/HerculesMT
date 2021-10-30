/**
 * This file is part of Hercules.
 * http://herc.ws - http://github.com/HerculesWS/Hercules
 *
 * Copyright (C) 2012-2021 Hercules Dev Team
 * Copyright (C) Athena Dev Teams
 *
 * Hercules is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef COMMON_UTILS_H
#define COMMON_UTILS_H

#include "common/hercules.h"

#include <stdio.h> // FILE*
#ifndef WIN32
#	include <unistd.h> // sleep()
#endif

/* [HCache] 1-byte key to ensure our method is the latest, we can modify to ensure the method matches */
#define HCACHE_KEY 'k'

#ifndef MAX_DIR_PATH
#ifdef WIN32
#define MAX_DIR_PATH MAX_PATH
#else
#define MAX_DIR_PATH 2048
#endif
#endif

#define STRINGISE_IMPL(x) #x
#define STRINGISE(x) STRINGISE_IMPL(x)

/**
 * Portable warning preprocessor directive
 * Adapted from stackoverflow.com/a/1911632/
 *
 * Usage: #pragma WARN("warning message")
 **/
#if _MSC_VER
#   define FILE_LINE_LINK __FILE__ "(" STRINGISE(__LINE__) ") : "
// Including warning() before is a hack to make MSVC consider
// this message as a warning in the 'Error list'
#   define WARN(exp) warning() __pragma(message(FILE_LINE_LINK exp))
#else // CLANG and GCC
#   define WARN(exp) GCC warning (exp)
#endif

#define SIZEOF_MEMBER(type, member) sizeof(((type *)0)->member)

//Caps values to min/max
#define cap_value(a, min, max) (((a) >= (max)) ? (max) : ((a) <= (min)) ? (min) : (a))

#ifdef HERCULES_CORE
// generate a hex dump of the first 'length' bytes of 'buffer'
void WriteDump(FILE* fp, const void* buffer, size_t length);
void ShowDump(const void* buffer, size_t length);

void findfile(const char *p, const char *pat, void (func)(const char *, void *), void *context);
bool is_file(const char *path);
bool exists(const char* filename);

/// calculates the value of A / B, in percent (rounded down)
unsigned int get_percentage(const unsigned int A, const unsigned int B);
uint64 get_percentage64(const uint64 A, const uint64 B);

int64 apply_percentrate64(int64 value, int rate, int maxrate);
int apply_percentrate(int value, int rate, int maxrate);

const char* timestamp2string(char* str, size_t size, time_t timestamp, const char* format);

// target = target variable, b=bit number to act upon 0-n
// @see https://stackoverflow.com/a/263738/
#define BIT_SET(target,b) ((target) |= (1ULL<<(b)))
#define BIT_CLEAR(target,b) ((target) &= ~(1ULL<<(b)))
#define BIT_FLIP(target,b) ((target) ^= (1ULL<<(b)))
#define BIT_CHECK(target,b) (!!((target) & (1ULL<<(b))))
uint32_t find_first_set(uint32_t v);
int32_t find_first_set_array(uint32_t *v, uint32_t length, bool clear_bit);

//////////////////////////////////////////////////////////////////////////
// byte word dword access [Shinomori]
//////////////////////////////////////////////////////////////////////////

extern uint8 GetByte(uint32 val, int idx);
extern uint16 GetWord(uint32 val, int idx);
extern uint16 MakeWord(uint8 byte0, uint8 byte1);
extern uint32 MakeDWord(uint16 word0, uint16 word1);

//////////////////////////////////////////////////////////////////////////
// Big-endian compatibility functions
//////////////////////////////////////////////////////////////////////////
extern int16 MakeShortLE(int16 val);
extern int32 MakeLongLE(int32 val);
extern uint16 GetUShort(const unsigned char* buf);
extern uint32 GetULong(const unsigned char* buf);
extern int32 GetLong(const unsigned char* buf);
extern float GetFloat(const unsigned char* buf);

size_t hread(void * ptr, size_t size, size_t count, FILE * stream);
size_t hwrite(const void * ptr, size_t size, size_t count, FILE * stream);
#endif // HERCULES_CORE

#ifdef WIN32
#define HSleep(x) Sleep(1000 * (x))
#else // ! WIN32
#define HSleep(x) sleep(x)
#endif

enum {
	READ_LOCK,
	WRITE_LOCK
} lock_type;

/* [Ind/Hercules] Caching */
struct HCache_interface {
	void (*init) (void);
	/* */
	bool (*check) (const char *file);
	FILE *(*open) (const char *file, const char *opt);
	/* */
	time_t recompile_time;
	bool enabled;
};

#ifdef HERCULES_CORE
void HCache_defaults(void);
#endif // HERCULES_CORE

HPShared struct HCache_interface *HCache;

#endif /* COMMON_UTILS_H */
