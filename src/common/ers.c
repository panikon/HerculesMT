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

/*****************************************************************************\
 *  <H1>Entry Reusage System</H1>                                            *
 *                                                                           *
 *  There are several root entry managers, each with a different entry size. *
 *  Each manager will keep track of how many instances have been 'created'.  *
 *  They will only automatically destroy themselves after the last instance  *
 *  is destroyed.                                                            *
 *                                                                           *
 *  Entries can be allocated from the managers.                              *
 *  If it has reusable entries (freed entry), it uses one.                   *
 *  So no assumption should be made about the data of the entry.             *
 *  Entries should be freed in the manager they where allocated from.        *
 *  Failure to do so can lead to unexpected behaviors.                       *
 *                                                                           *
 *  <H2>Advantages:</H2>                                                     *
 *  - The same manager is used for entries of the same size.                 *
 *    So entries freed in one instance of the manager can be used by other   *
 *    instances of the manager.                                              *
 *  - Much less memory allocation/deallocation - program will be faster.     *
 *  - Avoids memory fragmentation - program will run better for longer.      *
 *                                                                           *
 *  <H2>Disadvantages:</H2>                                                  *
 *  - Unused entries are almost inevitable - memory being wasted.            *
 *  - A  manager will only auto-destroy when all of its instances are        *
 *    destroyed so memory will usually only be recovered near the end.       *
 *  - Always wastes space for entries smaller than a pointer.                *
 *                                                                           *
 *                                                                           *
 *  HISTORY:                                                                 *
 *    0.1 - Initial version                                                  *
 *    1.0 - ERS Rework                                                       *
 *    1.5 - ERS Options and optimization                                     *
 *    2.0 - Thread Safety                                                    *
 *                                                                           *
 * @version 2.0 - Thread Safety                                              *
 * @author Flavio @ Amazon Project    0.1                                    *
 * @author GreenBox @ rAthena Project 1.0                                    *
 * @author Ind @ Hercules Project     1.5                                    *
 * @author Panikon @ Hercules Project 2.0                                    *
 * @encoding US-ASCII                                                        *
 * @see common#ers.h                                                         *
\*****************************************************************************/

#define HERCULES_CORE

#include "ers.h"

#include "common/cbasetypes.h"
#include "common/memmgr.h" // CREATE, RECREATE, aMalloc, aFree
#include "common/nullpo.h"
#include "common/showmsg.h" // ShowMessage, ShowError, ShowFatalError, CL_BOLD, CL_NORMAL
#include "common/rwlock.h"
#include "common/mutex.h"
#include "common/utils.h"
#include "common/db.h" // INDEX_MAP_

#include <stdlib.h>
#include <string.h>

#ifndef DISABLE_ERS

#define ERS_BLOCK_ENTRIES 2048


struct ers_list
{
	struct ers_list *Next;
};

struct ers_instance_t;

/**
 * ERS cache for an entry size
 *
 * @lock ers_cache::mutex
 **/
typedef struct ers_cache
{
	/**
	 * Lock used on all cache operations
	 **/
	struct mutex_data *mutex;

	// Allocated object size, including ers_list size
	unsigned int ObjectSize;

	// Number of ers_instances referencing this
	int ReferenceCount;

	// Reuse linked list
	struct ers_list *ReuseList;

	// Memory blocks array
	unsigned char **Blocks;

	// Max number of blocks
	unsigned int Max;

	// Free objects count
	unsigned int Free;

	// Used blocks count
	unsigned int Used;

	// Objects in-use count
	unsigned int UsedObjs;

	// Default = ERS_BLOCK_ENTRIES, can be adjusted for performance for individual cache sizes.
	unsigned int ChunkSize;

	// Misc options, some options are shared from the instance
	enum ERSOptions Options;

	/**
	 * Position in cache list
	 **/
	uint32_t pos;
} ers_cache_t;

struct ers_instance_t {
	/**
	 * Interface to ERS
	 * @remarks This must be the first member of this structure
	 **/
	struct eri VTable;

	// Name, used for debugging purposes
	char *Name;

	// Misc options
	enum ERSOptions Options;

	// Our cache
	ers_cache_t *Cache;

	// Count of objects in use, used for detecting memory leaks
	unsigned int Count;

#ifdef DEBUG
	/* for data analysis [Ind/Hercules] */
	unsigned int Peak;
#endif
	struct ers_instance_t *Next, *Prev;
};

// Cache list type
INDEX_MAP_STRUCT_DECL(s_cache_list, ers_cache_t);

/**
 * ERS instances and caches
 *
 * Each ers_collection is a separate entry-reusage system,
 * so it's possible to have multiple managers with the same
 * entry size in the server.
 *
 * All collection objects are in a doubly-linked list
 * @see g_ers_list
 * @lock g_ers_list_lock
 *
 * @remarks
 * rwlock were chosen because currently most operations involving ERS
 * managed data are read operations.
 * The locks are only used when using shared memory, so if
 * ERS_OPT_MEMORY_LOCAL is set they are NULL.
 **/
struct ers_collection_t {
	/**
	 * Type of memory management used for this collection
	 *
	 * This is used in order to let the memory manager know
	 * where to store pertinent data.
	 * @remarks This value never changes after setup
	 *
	 * @readlock g_ers_list_lock
	 * @writelock ers_collection_t::lock
	 **/
	enum memory_type type;  //< Memory management used in this collection

	/**
	 * Doubly-linked list of active instances
	 *
	 * This list is used to debug usage data, each
	 * of these instances is also accounted for in
	 * its cache (via ReferenceCount)
	 *
	 * @readlock g_ers_list_lock
	 * @writelock ers_collection_t::lock
	 **/
	struct ers_instance_t *instance_list;

	/**
	 * List of all caches of this collection
	 * @lock ers_collection_t::lock
	 **/
	struct s_cache_list cache_list;

	/**
	 * Lock used to handle any operations in this collection
	 **/
	struct rwlock_data *lock;

	/**
	 * Position in ers collection list
	 **/
	uint32_t pos;
};

/**
 * Global ERS
 *
 * This is the default entry reusage system.
 **/
static struct ers_collection_t *ers_global = NULL;

/**
 * All ERS collections of this server
 **/
INDEX_MAP_STRUCT_DECL(s_collection_list, struct ers_collection_t);
static struct s_collection_list g_ers_list = INDEX_MAP_STATIC_INITIALIZER(MEMORYTYPE_SHARED);
struct mutex_data *g_ers_list_mutex = NULL; //< Free index list mutex

static thread_local struct s_collection_list l_ers_list = INDEX_MAP_STATIC_INITIALIZER(MEMORYTYPE_LOCAL);

/**
 * Initial length of free index lists, the length of the lists is always
 * ers_list_free_length * 32
 **/
#define ERS_LIST_FREE_INITIAL 2
#define ERS_CACHE_LIST_FREE_INITIAL 2

/**
 * Creates an ERS cache
 *
 * @param size Object size
 * @param options Miscelaneous cache options (@see ers_cache::Options)
 * @return New cache
 **/
static ers_cache_t *ers_create_cache(unsigned int size, enum ERSOptions options)
{
	ers_cache_t *cache;
	enum memory_type memory_type =
		(options&ERS_OPT_MEMORY_LOCAL)?MEMORYTYPE_LOCAL:MEMORYTYPE_SHARED;

	CREATE_MEMORY(cache, ers_cache_t, 1, memory_type);
	cache->ObjectSize = size;
	cache->ReferenceCount = 0;
	cache->ReuseList = NULL;
	cache->Blocks = NULL;
	cache->Free = 0;
	cache->Used = 0;
	cache->UsedObjs = 0;
	cache->Max = 0;
	cache->ChunkSize = ERS_BLOCK_ENTRIES;
	cache->Options = (options & ERS_CACHE_OPTIONS);

	if(memory_type == MEMORYTYPE_SHARED)
		cache->mutex = mutex->create();

	return cache;
}

/**
 * Finds an ERS cache
 *
 * If a cache matching provided data is not found a new one is created and added to the cache list
 *
 * @param cache_list List to be searched.
                     When empty a new cache is created and returned.
 * @param size Object size
 * @param Options Options from the instance seeking a cache
 * @return Cache
 *
 * @writelock ers_collection_t::lock
 **/
static ers_cache_t *ers_find_cache(struct s_cache_list *cache_list, unsigned int size,
	enum ERSOptions Options
) {
	ers_cache_t *cache;

	for(uint32_t i = 0; i < INDEX_MAP_LENGTH(*cache_list); i++) {
		cache = INDEX_MAP_INDEX(*cache_list, i);
		if(!cache)
			continue;
		if ( cache->ObjectSize == size && cache->Options == ( Options & ERS_CACHE_OPTIONS ) )
			return cache;
	}

	cache = ers_create_cache(size, Options);
	INDEX_MAP_ADD(*cache_list, cache, cache->pos);
	return cache;
}

/**
 * Frees memory blocks of provided cache and removes it from cache list
 *
 * @param cache_list Cache list.
 * @param cache Cache to be freed.
 *
 * @writelock ers_collection_t::lock
 * @mutex cache_mutex
 * @remark The cache mutex is destroyed in this call
 **/
static void ers_free_cache(struct s_cache_list *cache_list, ers_cache_t *cache)
{
	unsigned int i;

	nullpo_retv(cache);
	enum memory_type memory_type =
		(cache->Options&ERS_OPT_MEMORY_LOCAL)?MEMORYTYPE_LOCAL:MEMORYTYPE_SHARED;

	for (i = 0; i < cache->Used; i++)
		amFree(cache->Blocks[i], memory_type);

	INDEX_MAP_REMOVE(*cache_list, cache->pos);

	amFree(cache->Blocks, memory_type);
	if(cache->mutex) {
		mutex->unlock(cache->mutex);
		mutex->destroy(cache->mutex);
	}

	amFree(cache, memory_type);
}

/// @copydoc eri::alloc
static void *ers_obj_alloc_entry(ERS *self)
{
	struct ers_instance_t *instance = (struct ers_instance_t *)self;
	void *ret;

	if (instance == NULL) {
		ShowError("ers_obj_alloc_entry: NULL object, aborting entry freeing.\n");
		return NULL;
	}
	enum memory_type memory_type =
		(instance->Options&ERS_OPT_MEMORY_LOCAL)?MEMORYTYPE_LOCAL:MEMORYTYPE_SHARED;

#define ERS_BLOCK_POS_TEMP (instance->Cache->Free * instance->Cache->ObjectSize + sizeof(struct ers_list))

	if (instance->Cache->ReuseList != NULL) {
		ret = (void *)((unsigned char *)instance->Cache->ReuseList + sizeof(struct ers_list));
		instance->Cache->ReuseList = instance->Cache->ReuseList->Next;
	} else if (instance->Cache->Free > 0) {
		instance->Cache->Free--;
		ret = &instance->Cache->Blocks[instance->Cache->Used - 1][ERS_BLOCK_POS_TEMP];
	} else {
		if (instance->Cache->Used == instance->Cache->Max) {
			instance->Cache->Max = (instance->Cache->Max * 4) + 3;
			RECREATE_MEMORY(instance->Cache->Blocks, unsigned char *,
				instance->Cache->Max, memory_type);
		}

		CREATE_MEMORY(instance->Cache->Blocks[instance->Cache->Used], unsigned char,
			instance->Cache->ObjectSize * instance->Cache->ChunkSize, memory_type);
		instance->Cache->Used++;

		instance->Cache->Free = instance->Cache->ChunkSize -1;
		ret = &instance->Cache->Blocks[instance->Cache->Used - 1][ERS_BLOCK_POS_TEMP];
	}
#undef ERS_BLOCK_POS_TEMP

	instance->Count++;
	instance->Cache->UsedObjs++;

#ifdef DEBUG
	if( instance->Count > instance->Peak )
		instance->Peak = instance->Count;
#endif

	return ret;
}

/// @copydoc eri::free
static void ers_obj_free_entry(ERS *self, void *entry)
{
	struct ers_instance_t *instance = (struct ers_instance_t *)self;
	struct ers_list *reuse = (struct ers_list *)((unsigned char *)entry - sizeof(struct ers_list));

	if (instance == NULL) {
		ShowError("ers_obj_free_entry: NULL object, aborting entry freeing.\n");
		return;
	} else if (entry == NULL) {
		ShowError("ers_obj_free_entry: NULL entry, nothing to free.\n");
		return;
	}

	if( instance->Cache->Options & ERS_OPT_CLEAN )
		memset((unsigned char*)reuse + sizeof(struct ers_list), 0, instance->Cache->ObjectSize - sizeof(struct ers_list));

	reuse->Next = instance->Cache->ReuseList;
	instance->Cache->ReuseList = reuse;
	instance->Count--;
	instance->Cache->UsedObjs--;
}

/// @copydoc eri::entry_size
static size_t ers_obj_entry_size(ERS *self)
{
	struct ers_instance_t *instance = (struct ers_instance_t *)self;

	if (instance == NULL) {
		ShowError("ers_obj_entry_size: NULL object, aborting entry freeing.\n");
		return 0;
	}

	return instance->Cache->ObjectSize;
}

/// @copydoc eri::destroy
static int ers_obj_destroy(ERS *self)
{
	struct ers_instance_t *instance = (struct ers_instance_t *)self;
	int leak_count = 0;
	int cache_reference = 0;

	if (instance == NULL) {
		ShowError("ers_obj_destroy: NULL object, aborting entry freeing.\n");
		return 0;
	}

	if(self->cache_mutex)
		mutex->lock(self->cache_mutex);

	if (instance->Count > 0) {
		if (!(instance->Options & ERS_OPT_CLEAR)) {
			ShowWarning("Memory leak detected at ERS '%s', %u objects not freed.\n",
				instance->Name, instance->Count);
		}
		leak_count = instance->Count;
	}

	if (--instance->Cache->ReferenceCount <= 0)
		ers_free_cache(&self->collection->cache_list, instance->Cache);
	else if(self->cache_mutex)
		mutex->unlock(self->cache_mutex);

	if (instance->Next)
		instance->Next->Prev = instance->Prev;

	if (instance->Prev)
		instance->Prev->Next = instance->Next;
	else
		self->collection->instance_list = instance->Next;

	if( instance->Options & ERS_OPT_FREE_NAME )
		amFree(instance->Name, self->collection->type);

	amFree(instance, self->collection->type);
	return leak_count;
}

/// @copydoc eri::chunk_size
static void ers_cache_size(ERS *self, unsigned int new_size)
{
	struct ers_instance_t *instance = (struct ers_instance_t *)self;

	nullpo_retv(instance);

	if( !(instance->Cache->Options&ERS_OPT_FLEX_CHUNK) ) {
		ShowWarning("ers_cache_size: '%s' has adjusted its chunk size to '%u', "
			        "however ERS_OPT_FLEX_CHUNK is missing!\n",
			        instance->Name, new_size);
	}

	instance->Cache->ChunkSize = new_size;
}

/// @copydoc ers_new
ERS *ers_new(struct ers_collection_t *collection, uint32 size, char *name,
	enum ERSOptions options
) {
	struct ers_instance_t *instance;

	nullpo_retr(NULL, name);
	enum memory_type memory_type =
		(options&ERS_OPT_MEMORY_LOCAL)?MEMORYTYPE_LOCAL:MEMORYTYPE_SHARED;
	assert(memory_type == collection->type); // Memory types must be the same

	CREATE_MEMORY(instance, struct ers_instance_t, 1, memory_type);

	size += sizeof(struct ers_list);

#if ERS_ALIGNED > 1 // If it's aligned to 1-byte boundaries, no need to bother.
	if (size % ERS_ALIGNED)
		size += ERS_ALIGNED - size % ERS_ALIGNED;
#endif

	instance->VTable.alloc = ers_obj_alloc_entry;
	instance->VTable.free = ers_obj_free_entry;
	instance->VTable.entry_size = ers_obj_entry_size;
	instance->VTable.destroy = ers_obj_destroy;
	instance->VTable.chunk_size = ers_cache_size;

	instance->Name = ( options & ERS_OPT_FREE_NAME ) ? amStrdup(name, memory_type) : name;
	instance->Options = options;

	instance->Cache = ers_find_cache(&collection->cache_list, size,instance->Options);
	instance->VTable.collection = collection;
	instance->VTable.collection_lock = collection->lock;
	instance->VTable.cache_mutex = instance->Cache->mutex;
	mutex->lock(instance->Cache->mutex);
	instance->Cache->ReferenceCount++;
	mutex->unlock(instance->Cache->mutex);

	if (collection->instance_list == NULL) {
		collection->instance_list = instance;
	} else {
		instance->Next = collection->instance_list;
		instance->Next->Prev = instance;
		collection->instance_list = instance;
		collection->instance_list->Prev = NULL;
	}

	instance->Count = 0;

	return &instance->VTable;
}

/**
 * Prints cache information report.
 *
 * @see ers_report
 * @mutex g_ers_list_free_mutex when MEMORY_SHARED
 **/
void ers_report_cache(struct s_cache_list *cache_list)
{
	struct ers_cache *cache;
	unsigned int cache_c = 0, blocks_u = 0, blocks_a = 0, memory_b = 0, memory_t = 0;
	for(uint32_t i = 0; i < INDEX_MAP_LENGTH(*cache_list); i++) {
		cache = INDEX_MAP_INDEX(*cache_list, i);
		if(!cache)
			continue;
		mutex->lock(cache->mutex);
		double memory_use, memory_allocated;
		cache_c++;
		ShowMessage(
			CL_BOLD"[ERS Cache of size "
			"'"CL_NORMAL""CL_WHITE"%u"CL_NORMAL""CL_BOLD"' report]\n"CL_NORMAL,
			cache->ObjectSize);
		ShowMessage("\tinstances          : %d\n", cache->ReferenceCount);
		ShowMessage("\tblocks in use      : %u/%u\n", cache->UsedObjs,
			cache->UsedObjs+cache->Free);
		ShowMessage("\tblocks unused      : %u\n", cache->Free);
		if(cache->UsedObjs == 0)
			memory_use = 0.;
		else
			memory_use = ((cache->UsedObjs * cache->ObjectSize)/1024)/1024;
		ShowMessage("\tmemory in use      : %.2f MB\n", memory_use);
		if(cache->Free+cache->UsedObjs == 0)
			memory_allocated = 0.;
		else
			memory_allocated = (((cache->UsedObjs+cache->Free) * cache->ObjectSize)/1024)/1024;
		ShowMessage("\tmemory allocated   : %.2f MB\n", memory_allocated);
		blocks_u += cache->UsedObjs;
		blocks_a += cache->UsedObjs + cache->Free;
		memory_b += cache->UsedObjs * cache->ObjectSize;
		memory_t += (cache->UsedObjs+cache->Free) * cache->ObjectSize;
		mutex->unlock(cache->mutex);
	}
	ShowInfo("ers_report: '"CL_WHITE"%u"CL_NORMAL"' caches in use\n",cache_c);
	ShowInfo("ers_report: '"CL_WHITE"%u"CL_NORMAL"' blocks in use, consuming "
		"'"CL_WHITE"%.2f MB"CL_NORMAL"'\n", blocks_u, (double)((memory_b)/1024)/1024);
	ShowInfo("ers_report: '"CL_WHITE"%u"CL_NORMAL"' blocks total, consuming "
		"'"CL_WHITE"%.2f MB"CL_NORMAL"' \n",blocks_a,(double)((memory_t)/1024)/1024);
}

/**
 * Prints instance information report.
 *
 * @see ers_report
 * @mutex g_ers_list_free_mutex when MEMORY_SHARED
 **/
#ifdef DEBUG
void ers_report_instance(struct ers_instance_t *instance_list)
{
	struct ers_instance_t *instance;
	unsigned int instance_c = 0, instance_c_d = 0;

	for (instance = instance_list; instance; instance = instance->Next) {
		double memory_usage;
		instance_c++;
		if( (instance->Options & ERS_OPT_WAIT) && !instance->Count )
			continue;
		instance_c_d++;

		ShowMessage(
			CL_BOLD"[ERS Instance "
			""CL_NORMAL""CL_WHITE"%s"CL_NORMAL""CL_BOLD" report]\n"CL_NORMAL,
			instance->Name);
		ShowMessage("\tblock size        : %u\n", instance->Cache->ObjectSize);
		ShowMessage("\tblocks being used : %u\n", instance->Count);
		ShowMessage("\tpeak blocks       : %u\n", instance->Peak);
		
		if(instance->Count == 0)
			memory_usage = 0.;
		else
			memory_usage = ((instance->Count * instance->Cache->ObjectSize)/1024)/1024;
		ShowMessage("\tmemory in use     : %.2f MB\n", memory_usage);
	}
	ShowInfo("ers_report: '"CL_WHITE"%u"CL_NORMAL"' instances in use, "
		"'"CL_WHITE"%u"CL_NORMAL"' displayed\n",instance_c, instance_c_d);
}
#endif

/**
 * Prints a report about the current state of the Entry Reusage System.
 * Shows information about the global system and each entry manager.
 * The number of entries are checked and a warning is shown if extra reusable
 * entries are found.
 * The extra entries are included in the count of reusable entries.
 *
 * @remarks This function will try to acquire the following read locks:
 *            - ers_collection_t::lock
 *            - cache_list::lock
 * @remarks This function acquires g_ers_list_free_mutex
 **/
void ers_report(void)
{
	ShowMessage(CL_BOLD"[ERS Global Report]\n"CL_NORMAL);

	mutex->lock(g_ers_list_mutex);
	for(uint32_t i = 0; i < INDEX_MAP_LENGTH(g_ers_list); i++) {
		struct ers_collection_t *collection = INDEX_MAP_INDEX(g_ers_list, i);
		if(!collection)
			continue;
		rwlock->read_lock(collection->lock);
#ifdef DEBUG
		ers_report_instance(collection->instance_list);
#endif
		ers_report_cache(&collection->cache_list);
		rwlock->read_unlock(collection->lock);
	}
	mutex->unlock(g_ers_list_mutex);
}

/**
 * Creates a new ERS collection
 *
 * @param memory_type Type of memory allocation
 * @mutex g_ers_list_free_mutex when MEMORY_SHARED
 **/
struct ers_collection_t *ers_collection_create(enum memory_type memory_type) {
	struct ers_collection_t *ers_collection;
	CREATE_MEMORY(ers_collection, struct ers_collection_t, 1, memory_type);
	ers_collection->lock = rwlock->create();
	if(!ers_collection->lock) {
		ShowError("ers_collection_create: Failed to create lock!\n");
		amFree(ers_collection, memory_type);
		return NULL;
	}
	ers_collection->type = memory_type;
	INDEX_MAP_CREATE(ers_collection->cache_list, ERS_CACHE_LIST_FREE_INITIAL, memory_type);

	// Add this collection to the correct list
	if(memory_type == MEMORYTYPE_SHARED) {
		mutex->lock(g_ers_list_mutex);
		INDEX_MAP_ADD(g_ers_list, ers_collection, ers_collection->pos);
		mutex->unlock(g_ers_list_mutex);
		return ers_collection;
	}
	if(!INDEX_MAP_LENGTH(l_ers_list)) {
		INDEX_MAP_CREATE(l_ers_list, ERS_LIST_FREE_INITIAL, MEMORYTYPE_LOCAL);
	}
	INDEX_MAP_ADD(l_ers_list, ers_collection, ers_collection->pos);
	return ers_collection;
}

/**
 * Clears remaining entries in this collection.
 *
 * @writelock g_ers_list_lock
 **/
void ers_collection_destroy(struct ers_collection_t *ers_cur) {
	rwlock->write_lock(ers_cur->lock);
	while(ers_cur->instance_list)
		ers_obj_destroy((ERS*)ers_cur->instance_list);
	/**
	 * When there are no instances a cache is freed, so we don't
	 * need to try to free any more caches.
	 **/

	if(ers_cur->type == MEMORYTYPE_SHARED) {
		mutex->lock(g_ers_list_mutex);
		INDEX_MAP_REMOVE(g_ers_list, ers_cur->pos);
		mutex->unlock(g_ers_list_mutex);
	} else {
		INDEX_MAP_REMOVE(l_ers_list, ers_cur->pos);
	}

	if(ers_cur == ers_global)
		ers_global = NULL;

	INDEX_MAP_DESTROY(ers_cur->cache_list);

	rwlock->write_unlock(ers_cur->lock);
	rwlock->destroy(ers_cur->lock);
	amFree(ers_cur, ers_cur->type);
}

/**
 * Creates global ERS state
 **/
void ers_init(void)
{
	if(ers_global)
		return;

	g_ers_list_mutex = mutex->create();
	if(!g_ers_list_mutex) {
		ShowFatalError("ers_init: Failed to setup global ERS collection list mutex!\n");
		exit(EXIT_FAILURE);
	}
	INDEX_MAP_CREATE(g_ers_list, ERS_LIST_FREE_INITIAL, MEMORYTYPE_SHARED);

	ers_global = ers_collection_create(MEMORYTYPE_SHARED);
	if(!ers_global) {
		ShowFatalError("ers_init: Failed to setup global ERS state!\n");
		exit(EXIT_FAILURE);
	}
}

struct rwlock_data *ers_collection_lock(struct ers_collection_t *collection)
{
	return collection->lock;
}

/**
 * Call on shutdown to clear remaining entries
 *
 * @param memory_type Type of list to be cleared
 * @writelock g_ers_list_lock
 **/
void ers_final(enum memory_type memory_type)
{
	if(memory_type == MEMORYTYPE_SHARED) {
		for(uint32_t i = 0; i < INDEX_MAP_LENGTH(g_ers_list); i++) {
			if(!INDEX_MAP_INDEX(g_ers_list, i))
				continue;
			ers_collection_destroy(INDEX_MAP_INDEX(g_ers_list, i));
		}
		if(g_ers_list_mutex) {
			mutex->destroy(g_ers_list_mutex);
			g_ers_list_mutex = NULL;
		}
		return;
	}

	if(!INDEX_MAP_LENGTH(l_ers_list))
		return;

	for(uint32_t i = 0; i < INDEX_MAP_LENGTH(l_ers_list); i++) {
		if(!INDEX_MAP_INDEX(l_ers_list, i))
			continue;
		ers_collection_destroy(INDEX_MAP_INDEX(l_ers_list, i));
	}
}

#endif /* DISABLE_ERS */
