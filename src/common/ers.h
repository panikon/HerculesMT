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
#ifndef COMMON_ERS_H
#define COMMON_ERS_H

#include "common/cbasetypes.h"

/*****************************************************************************\
 *  (1) All public parts of the Entry Reusage System.                        *
 *  DISABLE_ERS           - Define to disable this system.                   *
 *  ERS_ALIGNED           - Alignment of the entries in the blocks.          *
 *  ERS                   - Entry manager.                                   *
 *  ers_new               - Allocate an instance of an entry manager.        *
 *  ers_report            - Print a report about the current state.          *
 *  ers_final             - Clears the remainder of the managers.            *
\*****************************************************************************/

/**
 * Define this to disable the Entry Reusage System.
 * All code except the typedef of ERInterface will be disabled.
 * To allow a smooth transition,
 */
//#define DISABLE_ERS

/**
 * Entries are aligned to ERS_ALIGNED bytes in the blocks of entries.
 * By default it aligns to one byte, using the "natural order" of the entries.
 * This should NEVER be set to zero or less.
 * If greater than one, some memory can be wasted. This should never be needed
 * but is here just in case some alignment issues arise.
 */
#ifndef ERS_ALIGNED
#	define ERS_ALIGNED 1
#endif /* not ERS_ALIGN_ENTRY */

enum ERSOptions {
	ERS_OPT_NONE        = 0x00,
	/**
	 * Silences leak count warning when destroying an instance
	 * @see eri::destroy
	 **/
	ERS_OPT_CLEAR       = 0x01,
	/**
	 * When set the instance will not be reported in ers_report_instance if
	 * there are no objects in use.
	 * @see ers_report_instance
	 **/
	ERS_OPT_WAIT        = 0x02,
	/**
	 * Duplicates name when setting up a new instance, frees upon destruction
	 *
	 * When not set ers_instance_t::Name only points to provided data, so it's
	 * responsability of the caller to ensure that this pointer remains valid
	 * while the instance is active.
	 * @see ers_new
	 **/
	ERS_OPT_FREE_NAME   = 0x04,
	/**
	 * Clears used memory upon ers_free (memset to 0), so it's all new to be
	 * reused on the next alloc
	 **/
	ERS_OPT_CLEAN       = 0x08,
	/**
	 * Signs that it should look for its own cache given it'll have a dynamic
	 * chunk size, so that it doesn't affect the other ERS it'd otherwise be
	 * sharing.
	 * This is enforced in ers_find_cache, and only warned when trying to resize.
	 * See commit 209d15e for implementation details.
	 **/
	ERS_OPT_FLEX_CHUNK  = 0x10,

	/**
	 * Memory management options
	 *
	 * These options don't need to be set when creating a new instance,
	 * they're defined depending on the collection that the instance will
	 * belong to.
	 **/
	//ERS_OPT_MEMORY_SHARED - Treat heap as shared (default behaviour)
	ERS_OPT_MEMORY_LOCAL  = 0x20, /* Treat heap as thread memory */

	/* Compound, is used to determine whether it should be looking for a cache of matching options */
	ERS_CACHE_OPTIONS   = ERS_OPT_CLEAN|ERS_OPT_FLEX_CHUNK,
};

/**
 * Public interface of the entry manager.
 * @param alloc Allocate an entry from this manager
 * @param free Free an entry allocated from this manager
 * @param entry_size Return the size of the entries of this manager
 * @param destroy Destroy this instance of the manager
 *
 * @lock g_ers_list_lock
 * @lock collection_lock
 */
typedef struct eri {
	// ERS collection that this instance is member of
	struct ers_collection_t *collection;
	/**
	 * Lock pointers
	 *
	 * @remarks
	 * All acquirals of cache_lock must be preceded by an acquiral
	 * of collection_lock (read or write)
	 **/
	struct rwlock_data *cache_lock;      //< @see cache_list::lock
	struct rwlock_data *collection_lock; //< @see ers_collection_t::lock

	/**
	 * Allocates an entry from this entry manager.
	 *
	 * If there are reusable entries available, it reuses one instead.
	 *
	 * @param self Interface of the entry manager
	 * @return An entry
	 *
	 * @readlock g_ers_list_lock
	 * @readlock collection_lock
	 * @writelock cache_lock
	 */
	void *(*alloc)(struct eri *self);

	/**
	 * Frees an entry allocated from this manager.
	 *
	 * @warning Does not check if the entry was allocated by this manager.
	 *          Freeing such an entry can lead to unexpected behavior.
	 * @param self Interface of the entry manager
	 * @param entry Entry to be freed
	 *
	 * @readlock g_ers_list_lock
	 * @readlock collection_lock
	 * @writelock cache_lock
	 */
	void (*free)(struct eri *self, void *entry);

	/**
	 * Returns the size of the entries allocated from this manager.
	 *
	 * @param self Interface of the entry manager
	 * @return Size of the entries of this manager in bytes
	 *
	 * @readlock g_ers_list_lock
	 * @readlock collection_lock
	 * @readlock cache_lock
	 */
	size_t (*entry_size)(struct eri *self);

	/**
	 * Destroys this instance of the manager.
	 *
	 * The manager is actually only destroyed when all the instances are destroyed.
	 * When destroying the manager a warning is shown if the manager has
	 * missing/extra entries.
	 *
	 * @param self Interface of the entry manager
	 * @return Number of leaks detected
	 *
	 * @readlock g_ers_list_lock
	 * @writelock collection_lock
	 */
	int (*destroy)(struct eri *self);

	/**
	 * Sets a new chunk size for this instance.
	 *
	 * @param self Interface of the entry manager
	 * @param new_size New chunk size in bytes
	 * @see ers_cache::ChunkSize
	 *
	 * @readlock ers_list_lock
	 * @writelock cache_lock
	 */
	void (*chunk_size) (struct eri *self, unsigned int new_size);
} ERS;

#ifdef DISABLE_ERS
// Use memory manager to allocate/free and disable other interface functions
#	define ers_alloc(obj,type) ((void)(obj), (type *)aMalloc(sizeof(type)))
#	define ers_free(obj,entry) ((void)(obj), aFree(entry))
#	define ers_entry_size(obj) ((void)(obj), (size_t)0)
#	define ers_destroy(obj) ((void)(obj), (void)0)
#	define ers_chunk_size(obj,size) ((void)(obj), (void)(size), (size_t)0)
// Disable the public functions
#	define ers_new(size,name,options) NULL
#	define ers_report() (void)0
#	define ers_final() (void)0
#	define ers_init() (void)0
#	define ers_collection_create() (void)0
#	define ers_collection_final() (void)0
#else /* not DISABLE_ERS */
// These defines should be used to allow the code to keep working whenever
// the system is disabled
#	define ers_alloc(obj,type) ((type *)(obj)->alloc(obj))
#	define ers_free(obj,entry) ((obj)->free((obj),(entry)))
#	define ers_entry_size(obj) ((obj)->entry_size(obj))
#	define ers_destroy(obj)    ((obj)->destroy(obj))
#	define ers_chunk_size(obj,size) ((obj)->chunk_size((obj),(size)))

#ifdef HERCULES_CORE

/**
 * Gets a new instance of the manager that handles the specified entry size.
 *
 * @param collection Collection to use.
 * @param size Entry size in bytes.
 *             If the specified size is smaller than a pointer, the size of a
 *             pointer is used instead.
 *             Aligned to ERS_ALIGNED bytes, so the smallest multiple of
 *             ERS_ALIGNED that is greater or equal to size is what's actually used.
 * @param name Instance name (debugging purposes).
 * @param options ERS options (@see ERSOptions)
 * @return Interface of the object
 *
 * @readlock g_ers_list_lock
 * @writelock ers_collection_t::lock
 * @warning Be extra careful when setting up a new instance, because internally
 *          this function tries to acquire the write lock of the cache.
 */
ERS *ers_new(struct ers_collection_t *collection, uint32 size, char *name, enum ERSOptions options);
void ers_report(void);

struct ers_collection_t *ers_collection_create(enum memory_type memory_type);
void ers_collection_destroy(struct ers_collection_t *ers_cur);
struct rwlock_data *ers_collection_lock(struct ers_collection_t *collection);

struct rwlock_data *ers_global_lock(void);

/**
 * Clears the remainder of the managers
 **/
void ers_final(enum memory_type memory_type);
void ers_init(void);
#endif // HERCULES_CORE
#endif /* DISABLE_ERS / not DISABLE_ERS */

#endif /* COMMON_ERS_H */
