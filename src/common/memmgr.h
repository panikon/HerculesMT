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
#ifndef COMMON_MEMMGR_H
#define COMMON_MEMMGR_H

#include "common/hercules.h"

#define ALC_MARK __FILE__, __LINE__, __func__


// default use of the built-in memory manager
#if !defined(NO_MEMMGR) && !defined(USE_MEMMGR)
#if defined(MEMWATCH) || defined(DMALLOC) || defined(GCOLLECT)
// disable built-in memory manager when using another memory library
#define NO_MEMMGR
#else
// use built-in memory manager by default
#define USE_MEMMGR
#endif
#endif

enum memory_type {
	MEMORYTYPE_NOT_SET,
	MEMORYTYPE_SHARED,
	MEMORYTYPE_LOCAL,
};

//////////////////////////////////////////////////////////////////////
// Enable memory manager logging by default
#define LOG_MEMMGR

// athena-*
#	define aMalloc(n)    (iMalloc->malloc((n),ALC_MARK))
#	define aCalloc(m,n)  (iMalloc->calloc((m),(n),ALC_MARK))
#	define aRealloc(p,n) (iMalloc->realloc((p),(n),ALC_MARK))
#	define aReallocz(p,n) (iMalloc->reallocz((p),(n),ALC_MARK))
#	define aStrdup(p)    (iMalloc->astrdup((p),ALC_MARK))
#	define aStrndup(p,n) (iMalloc->astrndup((p),(n),ALC_MARK))
#	define aFree(p)      (iMalloc->free((p),ALC_MARK))

// athena-local-*
#	define alMalloc(n)    (iMalloc->malloc_thread((n),ALC_MARK))
#	define alCalloc(m,n)  (iMalloc->calloc_thread((m),(n),ALC_MARK))
#	define alRealloc(p,n) (iMalloc->realloc_thread((p),(n),ALC_MARK))
#	define alReallocz(p,n) (iMalloc->reallocz_thread((p),(n),ALC_MARK))
#	define alStrdup(p)    (iMalloc->astrdup_thread((p),ALC_MARK))
#	define alStrndup(p,n) (iMalloc->astrndup_thread((p),(n),ALC_MARK))
#	define alFree(p)      (iMalloc->free_thread((p),ALC_MARK))

/**
 * Convenience macros to define the flavor of *alloc that's
 * going to be called, depending on _memtype (@see enum memory_type)_
 * athena-memory-*
 **/
#	define amMalloc(n,_memtype) \
	( ((_memtype) == MEMORYTYPE_LOCAL)? alMalloc((n)):aMalloc((n)) )
#	define amCalloc(m,n,_memtype) \
	( ((_memtype) == MEMORYTYPE_LOCAL)? alCalloc((m),(n)):aCalloc((m),(n)) )
#	define amRealloc(p,n,_memtype) \
	( ((_memtype) == MEMORYTYPE_LOCAL)? alRealloc((p),(n)):aRealloc((p),(n)) )
#	define amReallocz(p,n,_memtype) \
	( ((_memtype) == MEMORYTYPE_LOCAL)? alReallocz((p),(n)):aReallocz((p),(n)) )
#	define amStrdup(p,_memtype) \
	( ((_memtype) == MEMORYTYPE_LOCAL)? alStrdup((p)):aStrdup((p)) )
#	define amStrndup(p,n,_memtype) \
	( ((_memtype) == MEMORYTYPE_LOCAL)? alStrndup((p),(n)):aStrndup((p),(n)) )
#	define amFree(p,_memtype) \
	( ((_memtype) == MEMORYTYPE_LOCAL)? alFree((p)):aFree((p)) )

/////////////// Buffer Creation /////////////////
// Full credit for this goes to Shinomori [Ajarn]

#ifdef __GNUC__ // GCC has variable length arrays

#define CREATE_BUFFER(name, type, size) type name[size]
#define DELETE_BUFFER(name) (void)0

#else // others don't, so we emulate them

/**
 * TODO: Verify the feasibility of replacing aCalloc with alloca. [Panikon]
 * FIXME: The current 'portable' implementation of CREATE_BUFFER behaves differently
 * depending on the compiler, while in GCC it allocates memory on the stack (without
 * any initialization whatsoever) in other compilers it's allocating initialized memory
 * on the heap via aCalloc. [Panikon]
 **/
#define CREATE_BUFFER(name, type, size) type *name = (type *) aCalloc((size), sizeof(type))
#define DELETE_BUFFER(name) aFree(name)

#endif

////////////// Others //////////////////////////
// should be merged with any of above later
#define CREATE(result, type, number) ((result) = (type *) aCalloc((number), sizeof(type)))
#define RECREATE(result, type, number) ((result) = (type *) aReallocz((result), sizeof(type) * (number)))

#define lCREATE(result, type, number) ((result) = (type *) alCalloc((number), sizeof(type)))
#define lRECREATE(result, type, number) ((result) = (type *) alReallocz((result), sizeof(type) * (number)))

#define CREATE_MEMORY(_res, _t, _n, _memtype) ( (_res) = amCalloc((_n), sizeof(_t), (_memtype)) )
#define RECREATE_MEMORY(_res, _t, _n, _memtype) ( (_res) = amReallocz((_res), (sizeof(_t)*(_n)), (_memtype)) )
////////////////////////////////////////////////

struct s_memory_information;

struct malloc_interface {
	void (*init) (void);
	void (*final) (void);
	/* Thread */
	void  (*local_storage_init)(void);
	void  (*local_storage_final)(void);
	void* (*malloc_thread)(size_t size, const char *file, int line, const char *func);
	void* (*calloc_thread)(size_t num, size_t size, const char *file, int line, const char *func);
	void* (*realloc_thread)(void *p, size_t size, const char *file, int line, const char *func);
	void* (*reallocz_thread)(void *p, size_t size, const char *file, int line, const char *func);
	char* (*astrdup_thread)(const char *p, const char *file, int line, const char *func);
	char *(*astrndup_thread)(const char *p, size_t size, const char *file, int line, const char *func);
	void  (*free_thread)(void *p, const char *file, int line, const char *func);
	/* Shared */
	struct mutex_data *(*shared_mutex)(void);
	void* (*malloc_shared)(size_t size, const char *file, int line, const char *func);
	void* (*calloc_shared)(size_t num, size_t size, const char *file, int line, const char *func);
	void* (*realloc_shared)(void *p, size_t size, const char *file, int line, const char *func);
	void* (*reallocz_shared)(void *p, size_t size, const char *file, int line, const char *func);
	char* (*astrdup_shared)(const char *p, const char *file, int line, const char *func);
	char *(*astrndup_shared)(const char *p, size_t size, const char *file, int line, const char *func);
	void  (*free_shared)(void *p, const char *file, int line, const char *func);

	void* (*malloc_shared_no_mutex)(size_t size, const char *file, int line, const char *func);
	void* (*calloc_shared_no_mutex)(size_t num, size_t size, const char *file, int line, const char *func);
	void* (*realloc_shared_no_mutex)(void *p, size_t size, const char *file, int line, const char *func);
	void* (*reallocz_shared_no_mutex)(void *p, size_t size, const char *file, int line, const char *func);
	char* (*astrdup_shared_no_mutex)(const char *p, const char *file, int line, const char *func);
	char *(*astrndup_shared_no_mutex)(const char *p, size_t size, const char *file, int line, const char *func);
	void  (*free_shared_no_mutex)(void *p, const char *file, int line, const char *func);
	/* Memory (internal calls) */
	void* (*malloc_mem)(struct s_memory_information *mem, size_t size, const char *file, int line, const char *func);
	void  (*free_mem)(struct s_memory_information *mem, void *p, const char *file, int line, const char *func);
	void* (*calloc_mem)(struct s_memory_information *mem, size_t num, size_t size, const char *file, int line, const char *func);
	void* (*realloc_mem)(struct s_memory_information *mem, void *p, size_t size, const char *file, int line, const char *func);
	void* (*reallocz_mem)(struct s_memory_information *mem, void *p, size_t size, const char *file, int line, const char *func);
	char* (*astrdup_mem)(struct s_memory_information *mem, const char *p, const char *file, int line, const char *func);
	char *(*astrndup_mem)(struct s_memory_information *mem, const char *p, size_t size, const char *file, int line, const char *func);
	/* Allocation outside memory management */
	void* (*rmalloc)(size_t size);
	void  (*rfree)(void *p);
	/* */
	void* (*malloc)(size_t size, const char *file, int line, const char *func);
	void* (*calloc)(size_t num, size_t size, const char *file, int line, const char *func);
	void* (*realloc)(void *p, size_t size, const char *file, int line, const char *func);
	void* (*reallocz)(void *p, size_t size, const char *file, int line, const char *func);
	char* (*astrdup)(const char *p, const char *file, int line, const char *func);
	char *(*astrndup)(const char *p, size_t size, const char *file, int line, const char *func);
	void  (*free)(void *p, const char *file, int line, const char *func);
	/* */
	void (*memory_check)(void);
	bool (*verify_ptr_mem)(struct s_memory_information *mem, void* ptr);
	bool (*verify_ptr_thread)(void* ptr);
	bool (*verify_ptr_shared)(void* ptr);
	bool (*verify_ptr)(void* ptr);
	size_t (*usage) (enum memory_type type);
	/* */
	void (*post_shutdown) (void);
	void (*init_messages) (void);
};

#ifdef HERCULES_CORE
void malloc_defaults(void);

void memmgr_report(int extra, enum memory_type type);

HPShared struct malloc_interface *iMalloc;
#else
#define iMalloc HPMi->memmgr
#endif // HERCULES_CORE

#endif /* COMMON_MEMMGR_H */
