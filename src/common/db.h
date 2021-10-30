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
 *  This file is separated in three sections:                                *
 *  (1) public typedefs, enums, unions, structures and defines               *
 *  (2) public functions                                                     *
 *  (3) helper macros                                                        *
 *                                                                           *
 *  <B>Notes on the release system:</B>                                      *
 *  Whenever an entry is removed from the database both the key and the      *
 *  data are requested to be released.                                       *
 *  At least one entry is removed when replacing an entry, removing an       *
 *  entry, clearing the database or destroying the database.                 *
 *  What is actually released is defined by the release function, the        *
 *  functions of the database only ask for the key and/or data to be         *
 *  released.                                                                *
 *                                                                           *
 *  TODO:                                                                    *
 *  - create a custom database allocator                                     *
 *                                                                           *
 *  HISTORY:                                                                 *
 *    2013/08/25 - Added int64/uint64 support for keys                       *
 *    2012/03/09 - Added enum for data types (int, uint, void*)              *
 *    2007/11/09 - Added an iterator to the database.                        *
 *    2.1 (Athena build #???#) - Portability fix                             *
 *      - Fixed the portability of casting to union and added the functions  *
 *        struct DBMap#ensure() and struct DBMap#clear().                    *
 *    2.0 (Athena build 4859) - Transition version                           *
 *      - Almost everything recoded with a strategy similar to objects,      *
 *        database structure is maintained.                                  *
 *    1.0 (up to Athena build 4706)                                          *
 *      - Previous database system.                                          *
 *                                                                           *
 * @version 2.1 (Athena build #???#) - Portability fix                       *
 * @author (Athena build 4859) Flavio @ Amazon Project                       *
 * @author (up to Athena build 4706) Athena Dev Teams                        *
 * @encoding US-ASCII                                                        *
 * @see common#db.c                                                          *
\*****************************************************************************/
#ifndef COMMON_DB_H
#define COMMON_DB_H

#include "common/hercules.h"

#include <stdarg.h>

/*****************************************************************************
 *  (1) Section with public typedefs, enums, unions, structures and defines. *
 *  HASH_SIZE            - Initial bucket count used by db alloc and destroy.*
 *  LOAD_FACTOR          - Default load factor.                              *
 *  enum DBReleaseOption - Enumeration of release options.                   *
 *  enum DBType          - Enumeration of database types.                    *
 *  enum DBOptions       - Bitfield enumeration of database options.         *
 *  union DBKey          - Union of used key types.                          *
 *  struct DBKey_s       - Struct representation of keys.                    *
 *  enum DBDataType      - Enumeration of data types.                        *
 *  struct DBData        - Struct for used data types.                       *
 *  DBApply              - Format of functions applied to the databases.     *
 *  DBMatcher            - Format of matchers used in struct DBMap#getall(). *
 *  DBComparator         - Format of the comparators used by the databases.  *
 *  DBHasher             - Format of the hashers used by the databases.      *
 *  DBReleaser           - Format of the releasers used by the databases.    *
 *  struct DBIterator    - Database iterator.                                *
 *  struct DBMap         - Database interface.                               *
 *****************************************************************************/

/**
 * Size of the hashtable in the database (number of buckets).
 * @see struct DBMap_impl#ht
 * @remarks To minimize collisions this number should be a prime.
 */
#define HASH_SIZE (256+27)

/**
 * Default load factor.
 * The ratio of item_count and bucket_count that triggers a capacity increase.
 * @see struct DBMap_impl#ht
 * @see db_alloc
 **/
#define LOAD_FACTOR (0.75f)

/**
 * Bitfield with what should be released by the releaser function (if the
 * function supports it).
 * @public
 * @see #DBReleaser
 * @see #db_custom_release()
 */
enum DBReleaseOption {
	DB_RELEASE_NOTHING = 0x0,
	DB_RELEASE_KEY     = 0x1,
	DB_RELEASE_DATA    = 0x2,
	DB_RELEASE_BOTH    = DB_RELEASE_KEY|DB_RELEASE_DATA,
};

/**
 * Supported types of database.
 *
 * See #db_fix_options() for restrictions of the types of databases.
 *
 * @param DB_INT Uses int's for keys
 * @param DB_UINT Uses unsigned int's for keys
 * @param DB_STRING Uses strings for keys.
 * @param DB_ISTRING Uses case insensitive strings for keys.
 * @param DB_INT64 Uses int64's for keys
 * @param DB_UINT64 Uses uint64's for keys
 * @public
 * @see enum DBOptions
 * @see union DBKey
 * @see #db_fix_options()
 * @see #db_default_cmp()
 * @see #db_default_hash()
 * @see #db_default_release()
 * @see #db_alloc()
 */
enum DBType {
	DB_INT,
	DB_UINT,
	DB_STRING,
	DB_ISTRING,
	DB_INT64,
	DB_UINT64,
	DB_ERROR,
};

/**
 * Bitfield of options that define the behavior of the database.
 *
 * See #db_fix_options() for restrictions of the types of databases.
 *
 * @param DB_OPT_BASE Base options: does not duplicate keys, releases nothing
 *          and does not allow NULL keys or NULL data.
 * @param DB_OPT_DUP_KEY Duplicates the keys internally. If DB_OPT_RELEASE_KEY
 *          is defined, the real key is freed as soon as the entry is added.
 * @param DB_OPT_RELEASE_KEY Releases the key.
 * @param DB_OPT_RELEASE_DATA Releases the data whenever an entry is removed
 *          from the database.
 *          WARNING: for functions that return the data (like struct DBMap#remove()),
 *          a dangling pointer will be returned.
 * @param DB_OPT_RELEASE_BOTH Releases both key and data.
 * @param DB_OPT_ALLOW_NULL_KEY Allow NULL keys in the database.
 * @param DB_OPT_ALLOW_NULL_DATA Allow NULL data in the database.
 * @param DB_OPT_DISABLE_GROWTH Disables increase of buckets with changes in loading factor
 * @param DB_OPT_DISABLE_LOCK Disables database lock
 * @public
 * @see #db_fix_options()
 * @see #db_default_release()
 * @see #db_alloc()
 */
enum DBOptions {
	DB_OPT_BASE            = 0x00,
	DB_OPT_DUP_KEY         = 0x01,
	DB_OPT_RELEASE_KEY     = 0x02,
	DB_OPT_RELEASE_DATA    = 0x04,
	DB_OPT_RELEASE_BOTH    = DB_OPT_RELEASE_KEY|DB_OPT_RELEASE_DATA,
	DB_OPT_ALLOW_NULL_KEY  = 0x08,
	DB_OPT_ALLOW_NULL_DATA = 0x10,
	DB_OPT_DISABLE_GROWTH  = 0x20,
	DB_OPT_DISABLE_LOCK    = 0x40,
};

/**
 * Union of key types used by the database.
 * @param i Type of key for DB_INT databases
 * @param ui Type of key for DB_UINT databases
 * @param str Type of key for DB_STRING and DB_ISTRING databases
 * @public
 * @see enum DBType
 * @see struct DBMap#get()
 * @see struct DBMap#put()
 * @see struct DBMap#remove()
 */
union DBKey {
	int i;
	unsigned int ui;
	const char *str;
	char *mutstr;
	int64 i64;
	uint64 ui64;
};
/**
 * Database key.
 * @param u   Key value.
 * @param len Length of value.
 * @public
 * @see union DBkey
 * @see enum DBType
 * @see struct DBMap#get()
 * @see struct DBMap#put()
 * @see struct DBMap#remove()
 **/
struct DBKey_s {
	union DBKey u;
	// Even if the key length isn't used for all of the types adding it as an field
	// in DBKey would increase the total type length in 64bit machines. I believe that
	// using a struct in this instance is clearer and also eases future usage
	// in more than one key type. [Panikon]
	// union DBKey { union { char *ptr; uint16_t len; } str; ... }
	int16_t len; // int16 so we can safely do subtractions.
};

/**
 * Supported types of database data.
 * @param DB_DATA_INT Uses ints for data.
 * @param DB_DATA_UINT Uses unsigned ints for data.
 * @param DB_DATA_PTR Uses void pointers for data.
 * @public
 * @see struct DBData
 */
enum DBDataType {
	DB_DATA_NOT_INIT,
	DB_DATA_INT,
	DB_DATA_UINT,
	DB_DATA_PTR,
};

/**
 * Struct for data types used by the database.
 * @param type Type of data
 * @param u Union of available data types
 * @param u.i Data of int type
 * @param u.ui Data of unsigned int type
 * @param u.ptr Data of void* type
 * @public
 */
struct DBData {
	enum DBDataType type;
	union {
		int i;
		unsigned int ui;
		void *ptr;
	} u;
};

/**
 * Format of functions that create the data for the key when the entry doesn't
 * exist in the database yet.
 * @param key Key of the database entry
 * @param args Extra arguments of the function
 * @return Data identified by the key to be put in the database
 * @public
 * @see struct DBMap#vensure()
 * @see struct DBMap#ensure()
 */
typedef struct DBData (*DBCreateData)(const struct DBKey_s *key, va_list args);

/**
 * Format of functions to be applied to an unspecified quantity of entries of
 * a database.
 * Any function that applies this function to the database will return the sum
 * of values returned by this function.
 * @param key Key of the database entry
 * @param data Data of the database entry
 * @param args Extra arguments of the function
 * @return Value to be added up by the function that is applying this
 * @public
 * @see struct DBMap#vforeach()
 * @see struct DBMap#foreach()
 * @see struct DBMap#vdestroy()
 * @see struct DBMap#destroy()
 */
typedef int (*DBApply)(const struct DBKey_s *key, struct DBData *data, va_list args);

/**
 * Format of functions that match database entries.
 * The purpose of the match depends on the function that is calling the matcher.
 * Returns 0 if it is a match, another number otherwise.
 * @param key Key of the database entry
 * @param data Data of the database entry
 * @param args Extra arguments of the function
 * @return 0 if a match, another number otherwise
 * @public
 * @see struct DBMap#getall()
 */
typedef int (*DBMatcher)(const struct DBKey_s *key, struct DBData data, va_list args);

/**
 * Format of the comparators used internally by the database system.
 * Compares key1 to key2.
 * Returns 0 is equal, negative if lower and positive is higher.
 * @param key1 Key being compared
 * @param key2 Key we are comparing to
 * @return 0 if equal, negative if lower and positive if higher
 * @public
 * @see #db_default_cmp()
 */
typedef int (*DBComparator)(const struct DBKey_s *key1, const struct DBKey_s *key2);

/**
 * Format of the hashers used internally by the database system.
 * Creates the hash of the key.
 * @param key Key being hashed
 * @return Hash of the key
 * @public
 * @see #db_default_hash()
 */
typedef uint64 (*DBHasher)(const struct DBKey_s *key);

/**
 * Format of the releaser used by the database system.
 * Releases nothing, the key, the data or both.
 * All standard releasers use aFree to release.
 * @param key Key of the database entry
 * @param data Data of the database entry
 * @param which What is being requested to be released
 * @public
 * @see enum DBReleaseOption
 * @see #db_default_releaser()
 * @see #db_custom_release()
 */
typedef void (*DBReleaser)(struct DBKey_s *key, struct DBData data, enum DBReleaseOption which);

/**
 * Database iterator.
 *
 * Supports forward iteration, backward iteration and removing entries from the database.
 * The iterator is initially positioned before the first entry of the database.
 *
 * While the iterator exists the database is locked internally, so invoke
 * struct DBIterator#destroy() as soon as possible.
 *
 * @public
 * @see struct DBMap
 */
struct DBIterator {
	/**
	 * Fetches the first entry in the database.
	 * Returns the data of the entry.
	 * Puts the key in out_key, if out_key is not NULL.
	 * @param self Iterator
	 * @param out_key Key of the entry
	 * @return Data of the entry
	 * @protected
	 */
	struct DBData *(*first)(struct DBIterator *self, struct DBKey_s *out_key);

	/**
	 * Fetches the last entry in the database.
	 * Returns the data of the entry.
	 * Puts the key in out_key, if out_key is not NULL.
	 * @param self Iterator
	 * @param out_key Key of the entry
	 * @return Data of the entry
	 * @protected
	 */
	struct DBData *(*last)(struct DBIterator *self, struct DBKey_s *out_key);

	/**
	 * Fetches the next entry in the database.
	 * Returns the data of the entry.
	 * Puts the key in out_key, if out_key is not NULL.
	 * @param self Iterator
	 * @param out_key Key of the entry
	 * @return Data of the entry
	 * @protected
	 */
	struct DBData *(*next)(struct DBIterator *self, struct DBKey_s *out_key);

	/**
	 * Fetches the previous entry in the database.
	 * Returns the data of the entry.
	 * Puts the key in out_key, if out_key is not NULL.
	 * @param self Iterator
	 * @param out_key Key of the entry
	 * @return Data of the entry
	 * @protected
	 */
	struct DBData *(*prev)(struct DBIterator *self, struct DBKey_s *out_key);

	/**
	 * Returns true if the fetched entry exists.
	 * The databases entries might have NULL data, so use this to to test if
	 * the iterator is done.
	 * @param self Iterator
	 * @return true is the entry exists
	 * @protected
	 */
	bool (*exists)(struct DBIterator *self);

	/**
	 * Removes the current entry from the database.
	 *
	 * NOTE: struct DBIterator#exists() will return false until another
	 * entry is fetched.
	 *
	 * Puts data of the removed entry in out_data, if out_data is not NULL.
	 * @param self Iterator
	 * @param out_data Data of the removed entry.
	 * @return 1 if entry was removed, 0 otherwise
	 * @protected
	 * @see struct DBMap#remove()
	 */
	int (*remove)(struct DBIterator *self, struct DBData *out_data);

	/**
	 * Destroys this iterator and unlocks the database.
	 * @param self Iterator
	 * @protected
	 */
	void (*destroy)(struct DBIterator *self);

};

/**
 * Public interface of a database. Only contains functions.
 * All the functions take the interface as the first argument.
 *
 * @public
 * @see #db_alloc()
 * @remarks All functions in the interface must be preceded by a lock call!
 *          The lock can be either READ_LOCK or WRITE_LOCK depending on the
 *          types of most operations that'll be performed. The database automatically
 *          switches to WRITE_LOCK if required and then reacquires READ_LOCK.
 *          Thus all the described lock types in the documentation of these protected
 *          functions are suggestions.
 */
struct DBMap {

	/**
	 * Returns a new iterator for this database.
	 * The iterator keeps the database locked until it is destroyed.
	 * The database will keep functioning normally but will only free internal
	 * memory when unlocked, so destroy the iterator as soon as possible.
	 * @param self Database
	 * @return New iterator
	 * @protected
	 */
	struct DBIterator *(*iterator)(struct DBMap *self);

	/**
	 * Returns true if the entry exists.
	 * @param self Database
	 * @param key Key that identifies the entry
	 * @return true is the entry exists
	 * @protected
	 */
	bool (*exists)(struct DBMap *self, struct DBKey_s key);

	/**
	 * Get the data of the entry identified by the key.
	 * @param self Database
	 * @param key Key that identifies the entry
	 * @return Data of the entry or NULL if not found
	 * @protected
	 */
	struct DBData *(*get)(struct DBMap *self, struct DBKey_s key);

	/**
	 * Just calls struct DBMap#vgetall().
	 *
	 * Get the data of the entries matched by <code>match</code>.
	 * It puts a maximum of <code>max</code> entries into <code>buf</code>.
	 * If <code>buf</code> is NULL, it only counts the matches.
	 * Returns the number of entries that matched.
	 * NOTE: if the value returned is greater than <code>max</code>, only the
	 * first <code>max</code> entries found are put into the buffer.
	 * @param self Database
	 * @param buf Buffer to put the data of the matched entries
	 * @param max Maximum number of data entries to be put into buf
	 * @param match Function that matches the database entries
	 * @param ... Extra arguments for match
	 * @return The number of entries that matched
	 * @protected
	 * @see struct DBMap#vgetall()
	 */
	unsigned int (*getall)(struct DBMap *self, struct DBData **buf, unsigned int max, DBMatcher match, ...);

	/**
	 * Get the data of the entries matched by <code>match</code>.
	 * It puts a maximum of <code>max</code> entries into <code>buf</code>.
	 * If <code>buf</code> is NULL, it only counts the matches.
	 * Returns the number of entries that matched.
	 * NOTE: if the value returned is greater than <code>max</code>, only the
	 * first <code>max</code> entries found are put into the buffer.
	 * @param self Database
	 * @param buf Buffer to put the data of the matched entries
	 * @param max Maximum number of data entries to be put into buf
	 * @param match Function that matches the database entries
	 * @param ... Extra arguments for match
	 * @return The number of entries that matched
	 * @protected
	 * @see struct DBMap#getall()
	 */
	unsigned int (*vgetall)(struct DBMap *self, struct DBData **buf, unsigned int max, DBMatcher match, va_list args);

	/**
	 * Just calls struct DBMap#vensure().
	 *
	 * Get the data of the entry identified by the key.  If the entry does
	 * not exist, an entry is added with the data returned by `create`.
	 *
	 * @param self Database
	 * @param key Key that identifies the entry
	 * @param create Function used to create the data if the entry doesn't exist
	 * @param ... Extra arguments for create
	 * @return Data of the entry
	 * @protected
	 * @see struct DBMap#vensure()
	 */
	struct DBData *(*ensure)(struct DBMap *self, struct DBKey_s key, DBCreateData create, ...);

	/**
	 * Get the data of the entry identified by the key.
	 * If the entry does not exist, an entry is added with the data returned by
	 * <code>create</code>.
	 * @param self Database
	 * @param key Key that identifies the entry
	 * @param create Function used to create the data if the entry doesn't exist
	 * @param args Extra arguments for create
	 * @return Data of the entry
	 * @protected
	 * @see struct DBMap#ensure()
	 */
	struct DBData *(*vensure)(struct DBMap *self, struct DBKey_s key, DBCreateData create, va_list args);

	/**
	 * Put the data identified by the key in the database.
	 * Puts the previous data in out_data, if out_data is not NULL.
	 * NOTE: Uses the new key, the old one is released.
	 * @param self Database
	 * @param key Key that identifies the data
	 * @param data Data to be put in the database
	 * @param out_data Previous data if the entry exists
	 * @return 1 if if the entry already exists, 0 otherwise
	 * @protected
	 */
	int (*put)(struct DBMap *self, struct DBKey_s key, struct DBData data, struct DBData *out_data);

	/**
	 * Remove an entry from the database.
	 * Puts the previous data in out_data, if out_data is not NULL.
	 * NOTE: The key (of the database) is released.
	 * @param self Database
	 * @param key Key that identifies the entry
	 * @param out_data Previous data if the entry exists
	 * @return 1 if if the entry already exists, 0 otherwise
	 * @protected
	 */
	int (*remove)(struct DBMap *self, const struct DBKey_s key, struct DBData *out_data);

	/**
	 * Just calls struct DBMap#vforeach().
	 *
	 * Apply <code>func</code> to every entry in the database.
	 * Returns the sum of values returned by func.
	 * @param self Database
	 * @param func Function to be applied
	 * @param ... Extra arguments for func
	 * @return Sum of the values returned by func
	 * @protected
	 * @see struct DBMap#vforeach()
	 */
	int (*foreach)(struct DBMap *self, DBApply func, ...);

	/**
	 * Apply <code>func</code> to every entry in the database.
	 * Returns the sum of values returned by func.
	 * @param self Database
	 * @param func Function to be applied
	 * @param args Extra arguments for func
	 * @return Sum of the values returned by func
	 * @protected
	 * @see struct DBMap#foreach()
	 */
	int (*vforeach)(struct DBMap *self, DBApply func, va_list args);

	/**
	 * Just calls struct DBMap#vclear().
	 *
	 * Removes all entries from the database.
	 * Before deleting an entry, func is applied to it.
	 * Releases the key and the data.
	 * Returns the sum of values returned by func, if it exists.
	 * @param self Database
	 * @param func Function to be applied to every entry before deleting
	 * @param ... Extra arguments for func
	 * @return Sum of values returned by func
	 * @protected
	 * @see struct DBMap#vclear()
	 */
	int (*clear)(struct DBMap *self, DBApply func, ...);

	/**
	 * Removes all entries from the database.
	 * Before deleting an entry, func is applied to it.
	 * Releases the key and the data.
	 * Returns the sum of values returned by func, if it exists.
	 * @param self Database
	 * @param func Function to be applied to every entry before deleting
	 * @param args Extra arguments for func
	 * @return Sum of values returned by func
	 * @protected
	 * @see struct DBMap#clear()
	 */
	int (*vclear)(struct DBMap *self, DBApply func, va_list args);

	/**
	 * Just calls DBMap#vdestroy().
	 * Finalize the database, feeing all the memory it uses.
	 * Before deleting an entry, func is applied to it.
	 * Releases the key and the data.
	 * Returns the sum of values returned by func, if it exists.
	 * NOTE: This locks the database globally. Any attempt to insert or remove
	 * a database entry will give an error and be aborted (except for clearing).
	 * @param self Database
	 * @param func Function to be applied to every entry before deleting
	 * @param ... Extra arguments for func
	 * @return Sum of values returned by func
	 * @protected
	 * @see struct DBMap#vdestroy()
	 */
	int (*destroy)(struct DBMap *self, DBApply func, ...);

	/**
	 * Finalize the database, feeing all the memory it uses.
	 * Before deleting an entry, func is applied to it.
	 * Returns the sum of values returned by func, if it exists.
	 * NOTE: This locks the database globally. Any attempt to insert or remove
	 * a database entry will give an error and be aborted (except for clearing).
	 * @param self Database
	 * @param func Function to be applied to every entry before deleting
	 * @param args Extra arguments for func
	 * @return Sum of values returned by func
	 * @protected
	 * @see struct DBMap#destroy()
	 */
	int (*vdestroy)(struct DBMap *self, DBApply func, va_list args);

	/**
	 * Return the size of the database (number of items in the database).
	 * @param self Database
	 * @return Size of the database
	 * @protected
	 */
	unsigned int (*size)(struct DBMap *self);

	/**
	 * Return the type of the database.
	 * @param self Database
	 * @return Type of the database
	 * @protected
	 */
	enum DBType (*type)(struct DBMap *self);

	/**
	 * Return the options of the database.
	 * @param self Database
	 * @return Options of the database
	 * @protected
	 */
	enum DBOptions (*options)(struct DBMap *self);

	/**
	 * Sets a new hashing function for provided table
	 * Fails if there are already any entries in the table.
	 * @return Success
	 **/
	bool (*set_hash)(struct DBMap *self, DBHasher new_hash);

	/**
	 * Sets a new releasal function for provided table
	 **/
	void (*set_release)(struct DBMap *self, DBReleaser new_release);

	/**
	 * Locks database
	 **/
	void (*lock)(struct DBMap *self, enum lock_type type);

	/**
	 * Unlocks database
	 **/
	void (*unlock)(struct DBMap *self);
};

// For easy access to the common functions.

#define db_exists(db,k)     ( (db)->exists((db),(k)) )
#define idb_exists(db,k)    ( (db)->exists((db),DB->i2key(k)) )
#define uidb_exists(db,k)   ( (db)->exists((db),DB->ui2key(k)) )
#define strdb_exists(db,k,l)( (db)->exists((db),DB->str2key((k),(l))) )
#define i64db_exists(db,k)  ( (db)->exists((db),DB->i642key(k)) )
#define ui64db_exists(db,k) ( (db)->exists((db),DB->ui642key(k)) )

// Get pointer-type data from DBMaps of various key types
#define db_get(db,k)     ( DB->data2ptr((db)->get((db),(k))) )
#define idb_get(db,k)    ( DB->data2ptr((db)->get((db),DB->i2key(k))) )
#define uidb_get(db,k)   ( DB->data2ptr((db)->get((db),DB->ui2key(k))) )
#define strdb_get(db,k,l)( DB->data2ptr((db)->get((db),DB->str2key((k),(l)))) )
#define i64db_get(db,k)  ( DB->data2ptr((db)->get((db),DB->i642key(k))) )
#define ui64db_get(db,k) ( DB->data2ptr((db)->get((db),DB->ui642key(k))) )

// Get int-type data from DBMaps of various key types
#define db_iget(db,k)     ( DB->data2i((db)->get((db),(k))) )
#define idb_iget(db,k)    ( DB->data2i((db)->get((db),DB->i2key(k))) )
#define uidb_iget(db,k)   ( DB->data2i((db)->get((db),DB->ui2key(k))) )
#define strdb_iget(db,k,l)( DB->data2i((db)->get((db),DB->str2key((k),(l)))) )
#define i64db_iget(db,k)  ( DB->data2i((db)->get((db),DB->i642key(k))) )
#define ui64db_iget(db,k) ( DB->data2i((db)->get((db),DB->ui642key(k))) )

// Get uint-type data from DBMaps of various key types
#define db_uiget(db,k)     ( DB->data2ui((db)->get((db),(k))) )
#define idb_uiget(db,k)    ( DB->data2ui((db)->get((db),DB->i2key(k))) )
#define uidb_uiget(db,k)   ( DB->data2ui((db)->get((db),DB->ui2key(k))) )
#define strdb_uiget(db,k,l)( DB->data2ui((db)->get((db),DB->str2key((k),(l)))) )
#define i64db_uiget(db,k)  ( DB->data2ui((db)->get((db),DB->i642key(k))) )
#define ui64db_uiget(db,k) ( DB->data2ui((db)->get((db),DB->ui642key(k))) )

// Put pointer-type data into DBMaps of various key types
#define db_put(db,k,d)     ( (db)->put((db),(k),DB->ptr2data(d),NULL) )
#define idb_put(db,k,d)    ( (db)->put((db),DB->i2key(k),DB->ptr2data(d),NULL) )
#define uidb_put(db,k,d)   ( (db)->put((db),DB->ui2key(k),DB->ptr2data(d),NULL) )
#define strdb_put(db,k,l,d)( (db)->put((db),DB->str2key((k),(l)),DB->ptr2data(d),NULL) )
#define i64db_put(db,k,d)  ( (db)->put((db),DB->i642key(k),DB->ptr2data(d),NULL) )
#define ui64db_put(db,k,d) ( (db)->put((db),DB->ui642key(k),DB->ptr2data(d),NULL) )

// Put int-type data into DBMaps of various key types
#define db_iput(db,k,d)     ( (db)->put((db),(k),DB->i2data(d),NULL) )
#define idb_iput(db,k,d)    ( (db)->put((db),DB->i2key(k),DB->i2data(d),NULL) )
#define uidb_iput(db,k,d)   ( (db)->put((db),DB->ui2key(k),DB->i2data(d),NULL) )
#define strdb_iput(db,k,l,d)( (db)->put((db),DB->str2key((k),(l)),DB->i2data(d),NULL) )
#define i64db_iput(db,k,d)  ( (db)->put((db),DB->i642key(k),DB->i2data(d),NULL) )
#define ui64db_iput(db,k,d) ( (db)->put((db),DB->ui642key(k),DB->i2data(d),NULL) )

// Put uint-type data into DBMaps of various key types
#define db_uiput(db,k,d)     ( (db)->put((db),(k),DB->ui2data(d),NULL) )
#define idb_uiput(db,k,d)    ( (db)->put((db),DB->i2key(k),DB->ui2data(d),NULL) )
#define uidb_uiput(db,k,d)   ( (db)->put((db),DB->ui2key(k),DB->ui2data(d),NULL) )
#define strdb_uiput(db,k,l,d)( (db)->put((db),DB->str2key((k),(l)),DB->ui2data(d),NULL) )
#define i64db_uiput(db,k,d)  ( (db)->put((db),DB->i642key(k),DB->ui2data(d),NULL) )
#define ui64db_uiput(db,k,d) ( (db)->put((db),DB->ui642key(k),DB->ui2data(d),NULL) )

// Remove entry from DBMaps of various key types
#define db_remove(db,k)       ( (db)->remove((db),(k),NULL) )
#define idb_remove(db,k)      ( (db)->remove((db),DB->i2key(k),NULL) )
#define uidb_remove(db,k)     ( (db)->remove((db),DB->ui2key(k),NULL) )
#define strdb_remove(db,k,l)  ( (db)->remove((db),DB->str2key((k),(l)),NULL) )
#define i64db_remove(db,k)    ( (db)->remove((db),DB->i642key(k),NULL) )
#define ui64db_remove(db,k)   ( (db)->remove((db),DB->ui642key(k),NULL) )

//These are discarding the possible vargs you could send to the function, so those
//that require vargs must not use these defines.
#define db_ensure(db,k,f)     ( DB->data2ptr((db)->ensure((db),(k),(f))) )
#define idb_ensure(db,k,f)    ( DB->data2ptr((db)->ensure((db),DB->i2key(k),(f))) )
#define uidb_ensure(db,k,f)   ( DB->data2ptr((db)->ensure((db),DB->ui2key(k),(f))) )
#define strdb_ensure(db,k,l,f)( DB->data2ptr((db)->ensure((db),DB->str2key((k),(l)),(f))) )
#define i64db_ensure(db,k,f)  ( DB->data2ptr((db)->ensure((db),DB->i642key(k),(f))) )
#define ui64db_ensure(db,k,f) ( DB->data2ptr((db)->ensure((db),DB->ui642key(k),(f))) )

// Database creation and destruction macros
#define idb_alloc(opt)            DB->alloc(__FILE__,__func__,__LINE__,DB_INT,(opt),sizeof(int), HASH_SIZE, LOAD_FACTOR)
#define uidb_alloc(opt)           DB->alloc(__FILE__,__func__,__LINE__,DB_UINT,(opt),sizeof(unsigned int), HASH_SIZE, LOAD_FACTOR)
#define strdb_alloc(opt,maxlen)   DB->alloc(__FILE__,__func__,__LINE__,DB_STRING,(opt),(maxlen), HASH_SIZE, LOAD_FACTOR)
#define stridb_alloc(opt,maxlen)  DB->alloc(__FILE__,__func__,__LINE__,DB_ISTRING,(opt),(maxlen), HASH_SIZE, LOAD_FACTOR)
#define i64db_alloc(opt)          DB->alloc(__FILE__,__func__,__LINE__,DB_INT64,(opt),sizeof(int64), HASH_SIZE, LOAD_FACTOR)
#define ui64db_alloc(opt)         DB->alloc(__FILE__,__func__,__LINE__,DB_UINT64,(opt),sizeof(uint64), HASH_SIZE, LOAD_FACTOR)
#define db_destroy(db)            ( (db)->destroy((db),NULL) )
// Other macros
#define db_clear(db)        ( (db)->clear((db),NULL) )
#define db_size(db)         ( (db)->size(db) )
#define db_iterator(db)     ( (db)->iterator(db) )
#define dbi_first(dbi)      ( DB->data2ptr((dbi)->first((dbi),NULL)) )
#define dbi_last(dbi)       ( DB->data2ptr((dbi)->last((dbi),NULL)) )
#define dbi_next(dbi)       ( DB->data2ptr((dbi)->next((dbi),NULL)) )
#define dbi_prev(dbi)       ( DB->data2ptr((dbi)->prev((dbi),NULL)) )
#define dbi_remove(dbi)     ( (dbi)->remove((dbi),NULL) )
#define dbi_exists(dbi)     ( (dbi)->exists(dbi) )
#define dbi_destroy(dbi)    ( (dbi)->destroy(dbi) )
#define db_lock(db,t)       ( (db)->lock((db),(t)) )
#define db_unlock(db)       ( (db)->unlock((db)) )

/*****************************************************************************
 *  (2) Section with public functions.                                       *
 *  db_fix_options     - Fix the options for a type of database.             *
 *  db_default_cmp     - Get the default comparator for a type of database.  *
 *  db_default_hash    - Get the default hasher for a type of database.      *
 *  db_default_release - Get the default releaser for a type of database     *
 *           with the fixed options.                                         *
 *  db_custom_release  - Get the releaser that behaves as specified.         *
 *  db_alloc           - Allocate a new database.                            *
 *  db_i2key           - Manual cast from `int` to `union DBKey`.            *
 *  db_ui2key          - Manual cast from `unsigned int` to `union DBKey`.   *
 *  db_str2key         - Manual cast from `unsigned char *` to `union DBKey`.*
 *  db_i642key         - Manual cast from `int64` to `union DBKey`.          *
 *  db_ui642key        - Manual cast from `uint64` to `union DBKey`.         *
 *  db_i2data          - Manual cast from `int` to `struct DBData`.          *
 *  db_ui2data         - Manual cast from `unsigned int` to `struct DBData`. *
 *  db_ptr2data        - Manual cast from `void*` to `struct DBData`.        *
 *  db_data2i          - Gets `int` value from `struct DBData`.              *
 *  db_data2ui         - Gets `unsigned int` value from `struct DBData`.     *
 *  db_data2ptr        - Gets `void*` value from `struct DBData`.            *
 *  db_init            - Initializes the database system.                    *
 *  db_final           - Finalizes the database system.                      *
 *****************************************************************************/

struct db_interface {
/**
 * Returns the fixed options according to the database type.
 * Sets required options and unsets unsupported options.
 * For numeric databases DB_OPT_DUP_KEY and DB_OPT_RELEASE_KEY are unset.
 * @param type Type of the database
 * @param options Original options of the database
 * @return Fixed options of the database
 * @private
 * @see enum DBType
 * @see enum DBOptions
 * @see #db_default_release()
 */
enum DBOptions (*fix_options) (enum DBType type, enum DBOptions options);

/**
 * Returns the default comparator for the type of database.
 * @param type Type of database
 * @return Comparator for the type of database or NULL if unknown database
 * @public
 * @see enum DBType
 * @see #DBComparator
 */
DBComparator (*default_cmp) (enum DBType type);

/**
 * Returns the default hasher for the specified type of database.
 * @param type Type of database
 * @return Hasher of the type of database or NULL if unknown database
 * @public
 * @see enum DBType
 * @see #DBHasher
 */
DBHasher (*default_hash) (enum DBType type);

/**
 * Returns the default releaser for the specified type of database with the
 * specified options.
 *
 * NOTE: the options are fixed by #db_fix_options() before choosing the
 * releaser.
 *
 * @param type Type of database
 * @param options Options of the database
 * @return Default releaser for the type of database with the fixed options
 * @public
 * @see enum DBType
 * @see enum DBOptions
 * @see #DBReleaser
 * @see #db_fix_options()
 * @see #db_custom_release()
 */
DBReleaser (*default_release) (enum DBType type, enum DBOptions options);

/**
 * Returns the releaser that behaves as <code>which</code> specifies.
 * @param which Defines what the releaser releases
 * @return Releaser for the specified release options
 * @public
 * @see enum DBReleaseOption
 * @see #DBReleaser
 * @see #db_default_release()
 */
DBReleaser (*custom_release)  (enum DBReleaseOption which);

/**
 * Allocate a new database of the specified type.
 *
 * It uses the default comparator, hasher and releaser of the specified
 * database type and fixed options.
 *
 * NOTE: the options are fixed by #db_fix_options() before creating the
 * database.
 *
 * @param file File where the database is being allocated
 * @param line Line of the file where the database is being allocated
 * @param type Type of database
 * @param options Options of the database
 * @param maxlen Maximum length of the string to be used as key in string
 *          databases. If 0, the maximum number of maxlen is used (64K).
 * @param initial_capacity Initial number of buckets, historically this has been
 *                         set to HASH_SIZE.
 * @param load_factor The ratio of item_count and bucket_count that triggers a
 *                    capacity increase. When DB_OPT_DISABLE_GROWTH is set this
 *                    number is ignored. If 0 ignored.
 * @return The interface of the database
 * @public
 * @see enum DBType
 * @see struct DBMap
 * @see #db_default_cmp()
 * @see #db_default_hash()
 * @see #db_default_release()
 * @see #db_fix_options()
 */
struct DBMap *(*alloc) (const char *file, const char *func, int line, enum DBType type, enum DBOptions options, unsigned short maxlen, uint32_t initial_capacity, float load_factor);

/**
 * Manual cast from 'int' to the union DBKey.
 * @param key Key to be casted
 * @return The key as a DBKey struct
 * @public
 */
struct DBKey_s (*i2key) (int key);

/**
 * Manual cast from 'unsigned int' to the union DBKey.
 * @param key Key to be casted
 * @return The key as a DBKey struct
 * @public
 */
struct DBKey_s (*ui2key) (unsigned int key);

/**
 * Manual cast from 'unsigned char *' to the union DBKey.
 * @param key Key to be casted
 * @param len Key length, if 0 the length is calculated.
 * @return The key as a DBKey struct
 * @public
 */
struct DBKey_s (*str2key) (const char *key, size_t len);

/**
 * Manual cast from 'int64' to the union DBKey.
 * @param key Key to be casted
 * @return The key as a DBKey struct
 * @public
 */
struct DBKey_s (*i642key) (int64 key);

/**
 * Manual cast from 'uint64' to the union DBKey.
 * @param key Key to be casted
 * @return The key as a DBKey struct
 * @public
 */
struct DBKey_s (*ui642key) (uint64 key);

/**
 * Manual cast from 'int' to the struct DBData.
 * @param data Data to be casted
 * @return The data as a DBData struct
 * @public
 */
struct DBData (*i2data) (int data);

/**
 * Manual cast from 'unsigned int' to the struct DBData.
 * @param data Data to be casted
 * @return The data as a DBData struct
 * @public
 */
struct DBData (*ui2data) (unsigned int data);

/**
 * Manual cast from 'void *' to the struct DBData.
 * @param data Data to be casted
 * @return The data as a DBData struct
 * @public
 */
struct DBData (*ptr2data) (void *data);

/**
 * Gets int type data from struct DBData.
 * If data is not int type, returns 0.
 * @param data Data
 * @return Integer value of the data.
 * @public
 */
int (*data2i) (struct DBData *data);

/**
 * Gets unsigned int type data from struct DBData.
 * If data is not unsigned int type, returns 0.
 * @param data Data
 * @return Unsigned int value of the data.
 * @public
 */
unsigned int (*data2ui) (struct DBData *data);

/**
 * Gets void* type data from struct DBData.
 * If data is not void* type, returns NULL.
 * @param data Data
 * @return Void* value of the data.
 * @public
 */
void* (*data2ptr) (struct DBData *data);

/**
 * Initialize the database system.
 * @public
 * @see #db_final(void)
 */
void (*init) (void);

/**
 * Finalize the database system.
 * Frees the memory used by the block reusage system.
 * @public
 * @see #db_init(void)
 */
void (*final) (void);

/**
 * Sets all stat data to zero
 *
 * Only has effect when DB_ENABLE_STATS is active.
 **/
void (*clear_stats)(void);
};

// Link DB System - From jAthena
struct linkdb_node {
	struct linkdb_node *next;
	struct linkdb_node *prev;
	void               *key;
	void               *data;
};

/**
 * Function to be applied to an item when calling linkdb_foreach
 *
 * @see linkdb_vforeach
 * @see linkdb_foreach
 * @retval 0 Keep item
 * @retval 1 Remove item
 **/
typedef int (*LinkDBFunc)(void *key, void *data, va_list args);

#ifdef HERCULES_CORE
void  linkdb_insert  (struct linkdb_node** head, void *key, void* data); // Doesn't take into account duplicate keys
void  linkdb_replace (struct linkdb_node** head, void *key, void* data); // Takes into account duplicate keys
void* linkdb_search  (struct linkdb_node** head, void *key);
void* linkdb_erase   (struct linkdb_node** head, void *key);
void  linkdb_final   (struct linkdb_node** head);
void  linkdb_vforeach(struct linkdb_node** head, LinkDBFunc func, va_list ap);
void  linkdb_foreach (struct linkdb_node** head, LinkDBFunc func, ...);

void db_defaults(void);
#endif // HERCULES_CORE

HPShared struct db_interface *DB;


/*****************************************************************************
 *  (3) Section with help macros.                                            *
 *    a. Array Helper Macros.                                                *
 *    b. Vector library.                                                     *
 *    c. Binary heap library.                                                *
 *    d. Queue (FIFO).                                                       *
 *    e. Index map array.                                                    *
 *****************************************************************************/


/*****************************************************************************
 *  (3a) Array Helper Macros.                                                *
 *  ARR_FIND      - Finds an entry in an array.                              *
 *  ARR_MOVE      - Moves an entry of the array.                             *
 *  ARR_MOVERIGHT - Moves an entry of the array to the right.                *
 *  ARR_MOVELEFT  - Moves an entry of the array to the left.                 *
 *****************************************************************************/

/**
 * Finds an entry in an array.
 *
 * @code
 *    ARR_FIND(0, size, i, list[i] == target);
 * @endcode
 *
 * To differentiate between the found and not found cases, the caller code can
 * compare _end and _var after this macro returns.
 *
 * @param _start Starting index (ex: 0).
 * @param _end   End index (ex: size of the array).
 * @param _var   Index variable.
 * @param _cmp   Search expression (should return true when the target entry is found).
 */
#define ARR_FIND(_start, _end, _var, _cmp) \
	do { \
		for ((_var) = (_start); (_var) < (_end); ++(_var)) \
			if (_cmp) \
				break; \
	} while(false)

/**
 * Moves an entry of the array.
 *
 * @code
 *    ARR_MOVE(i, 0, list, int); // move index i to index 0
 * @endcode
 *
 * @remark
 *    Use ARR_MOVERIGHT/ARR_MOVELEFT if _from and _to are direct numbers.
 *
 * @param _from Initial index of the entry.
 * @param _to   Target index of the entry.
 * @param _arr  Array.
 * @param _type Type of entry.
 */
#define ARR_MOVE(_from, _to, _arr, _type) \
	do { \
		if ((_from) != (_to)) { \
			_type _backup_; \
			memmove(&_backup_, (_arr)+(_from), sizeof(_type)); \
			if ((_from) < (_to)) \
				memmove((_arr)+(_from), (_arr)+(_from)+1, ((_to)-(_from))*sizeof(_type)); \
			else if ((_from) > (_to)) \
				memmove((_arr)+(_to)+1, (_arr)+(_to), ((_from)-(_to))*sizeof(_type)); \
			memmove((_arr)+(_to), &_backup_, sizeof(_type)); \
		} \
	} while(false)

/**
 * Moves an entry of the array to the right.
 *
 * @code
 *    ARR_MOVERIGHT(1, 4, list, int); // move index 1 to index 4
 * @endcode
 *
 * @param _from Initial index of the entry.
 * @param _to   Target index of the entry.
 * @param _arr  Array.
 * @param _type Type of entry.
 */
#define ARR_MOVERIGHT(_from, _to, _arr, _type) \
	do { \
		_type _backup_; \
		memmove(&_backup_, (_arr)+(_from), sizeof(_type)); \
		memmove((_arr)+(_from), (_arr)+(_from)+1, ((_to)-(_from))*sizeof(_type)); \
		memmove((_arr)+(_to), &_backup_, sizeof(_type)); \
	} while(false)

/**
 * Moves an entry of the array to the left.
 *
 * @code
 *    ARR_MOVELEFT(3, 0, list, int); // move index 3 to index 0
 * @endcode
 *
 * @param _from Initial index of the entry.
 * @param _end  Target index of the entry.
 * @param _arr  Array.
 * @param _type Type of entry.
 */
#define ARR_MOVELEFT(_from, _to, _arr, _type) \
	do { \
		_type _backup_; \
		memmove(&_backup_, (_arr)+(_from), sizeof(_type)); \
		memmove((_arr)+(_to)+1, (_arr)+(_to), ((_from)-(_to))*sizeof(_type)); \
		memmove((_arr)+(_to), &_backup_, sizeof(_type)); \
	} while(false)


/******************************************************************************\
 *  (3b) Vector library (dynamic array).                                       *
 *  VECTOR_DECL               - Declares an anonymous vector struct.           *
 *  VECTOR_STRUCT_DECL        - Declares a named vector struct.                *
 *  VECTOR_STATIC_INITIALIZER - Vector static initializer.                     *
 *  VECTOR_VAR                - Declares and initializes an anonymous variable.*
 *  VECTOR_STRUCT_VAR         - Declares and initializes a named variable.     *
 *  VECTOR_INIT               - Initializes a vector.                          *
 *  VECTOR_DATA               - Returns the internal array of values.          *
 *  VECTOR_LENGTH             - Returns the length of the vector.              *
 *  VECTOR_CAPACITY           - Returns the capacity of the vector.            *
 *  VECTOR_INDEX              - Returns the value at the target index.         *
 *  VECTOR_FIRST              - Returns the first value of the vector.         *
 *  VECTOR_LAST               - Returns the last value of the vector.          *
 *  VECTOR_RESIZE_*           - Resizes the vector.                            *
 *  VECTOR_ENSURE_*           - Ensures that there are enough empty positions. *
 *  VECTOR_INSERTZEROED       - Inserts a zeroed value in the target index.    *
 *  VECTOR_INSERT             - Assigns value to target index.                 *
 *  VECTOR_INSERTCOPY         - Copies value to target index.                  *
 *  VECTOR_INSERTARRAY        - Inserts the values of the array.               *
 *  VECTOR_PUSHZEROED         - Appends a zeroed value.                        *
 *  VECTOR_PUSH               - Appends a value.                               *
 *  VECTOR_PUSHCOPY           - Copies a value to the end of the vector.       *
 *  VECTOR_PUSHARRAY          - Appends the values of the array.               *
 *  VECTOR_POPN               - Pops the last N values and returns the last.   *
 *  VECTOR_ERASE              - Removes the target index from the vector.      *
 *  VECTOR_ERASEN             - Removes N values from the target index.        *
 *  VECTOR_TRUNCATE           - Removes all values from the vector.            *
 *  VECTOR_CLEAR_*            - Clears the vector, freeing allocated data.     *
 *  VECTOR_PUSHCOPY_ENSURE_*  - VECTOR_ENSURE + VECTOR_PUSHCOPY.               *
 *  VECTOR_INIT_CAPACITY_*    - Initializes a vector with provided capacity.   *
 *******************************************************************************/

/**
 * Vector library based on defines (dynamic array).
 *
 * @remark
 *    This library uses the internal memory manager
 *     *_SHARED uses shared memory allocation
 *     *_LOCAL  uses local memory allocation
 *    The default usage uses shared memory allocation
 * @see VECTOR_RESIZE_
 * @see VECTOR_ENSURE_
 * @see VECTOR_CLEAR_
 * @see VECTOR_PUSHCOPY_ENSURE_
 * @see VECTOR_INIT_CAPACITY_
 **/

/**
 * Declares an anonymous vector struct.
 *
 * @param _type Type of data to be contained.
 */
#define VECTOR_DECL(_type) \
	struct { \
		int _max_; \
		int _len_; \
		_type *_data_; \
	}

/**
 * Declares a named vector struct.
 *
 * @param _name Structure name.
 * @param _type Type of data to be contained.
 */
#define VECTOR_STRUCT_DECL(_name, _type) \
	struct _name { \
		int _max_; \
		int _len_; \
		_type *_data_; \
	}

/**
 * Vector static initializer.
 **/
#define VECTOR_STATIC_INITIALIZER {0, 0, NULL}

/**
 * Declares and initializes an anonymous vector variable.
 *
 * @param _type Type of data to be contained.
 * @param _var  Variable name.
 */
#define VECTOR_VAR(_type, _var) \
	VECTOR_DECL(_type) _var = VECTOR_STATIC_INITIALIZER

/**
 * Declares and initializes a named vector variable.
 *
 * @param _name Structure name.
 * @param _var  Variable name.
 */
#define VECTOR_STRUCT_VAR(_name, _var) \
	struct _name _var = VECTOR_STATIC_INITIALIZER

/**
 * Initializes a vector.
 *
 * @param _vec Vector.
 */
#define VECTOR_INIT(_vec) \
	do { \
		VECTOR_DATA(_vec) = NULL; \
		VECTOR_CAPACITY(_vec) = 0; \
		VECTOR_LENGTH(_vec) = 0; \
	} while(false)

/**
 * Returns the internal array of values.
 *
 * @param _vec Vector.
 * @return Internal array of values.
 */
#define VECTOR_DATA(_vec) \
	( (_vec)._data_ )

/**
 * Returns the length of the vector (number of elements in use).
 *
 * @param _vec Vector
 * @return Length
 */
#define VECTOR_LENGTH(_vec) \
	( (_vec)._len_ )

/**
 * Returns the capacity of the vector (number of elements allocated).
 *
 * @param _vec Vector.
 * @return Capacity.
 */
#define VECTOR_CAPACITY(_vec) \
	( (_vec)._max_ )

/**
 * Returns the value at the target index.
 *
 * Assumes the index exists.
 *
 * @param _vec Vector.
 * @param _idx Index.
 * @return Value.
 */
#define VECTOR_INDEX(_vec, _idx) \
	( VECTOR_DATA(_vec)[_idx] )

/**
 * Returns the first value of the vector.
 *
 * Assumes the array is not empty.
 *
 * @param _vec Vector.
 * @return First value.
 */
#define VECTOR_FIRST(_vec) \
	( VECTOR_INDEX(_vec, 0) )

/**
 * Returns the last value of the vector.
 *
 * Assumes the array is not empty.
 *
 * @param _vec Vector.
 * @return Last value.
 */
#define VECTOR_LAST(_vec) \
	( VECTOR_INDEX(_vec, VECTOR_LENGTH(_vec)-1) )

/**
 * Resizes the vector
 *
 * Excess values are discarded.
 *
 * @param _vec Vector.
 * @param _n   New size.
 * @param _ma  Malloc function.
 * @param _re  Realloc function.
 * @param _fr  Free function.
 * @param _ca  Calloc function.
 * @param _zero Should the new data be zeroed?
 */
#define VECTOR_RESIZE_SUB(_vec, _n, _ma, _re, _fr, _ca, _zero) \
	do { \
		if ((_n) > VECTOR_CAPACITY(_vec)) { \
			/* increase size */ \
			if (VECTOR_CAPACITY(_vec) == 0) { \
				/* allocate new */ \
				if ((_zero)) \
					VECTOR_DATA(_vec) = _ca((_n), sizeof(VECTOR_FIRST(_vec)));\
				else \
					VECTOR_DATA(_vec) = _ma((_n)*sizeof(VECTOR_FIRST(_vec))); \
			} else { \
				VECTOR_DATA(_vec) = _re(VECTOR_DATA(_vec), (_n)*sizeof(VECTOR_FIRST(_vec))); /* reallocate */ \
				if((_zero))\
					memset(VECTOR_DATA(_vec)+VECTOR_LENGTH(_vec), 0, (VECTOR_CAPACITY(_vec)-VECTOR_LENGTH(_vec))*sizeof(VECTOR_FIRST(_vec))); /* clear new data */ \
			} \
			VECTOR_CAPACITY(_vec) = (_n); /* update capacity */ \
		} else if ((_n) == 0 && VECTOR_CAPACITY(_vec) > 0) { \
			/* clear vector */ \
			_fr(VECTOR_DATA(_vec)); VECTOR_DATA(_vec) = NULL; /* free data */ \
			VECTOR_CAPACITY(_vec) = 0; /* clear capacity */ \
			VECTOR_LENGTH(_vec) = 0; /* clear length */ \
		} else if ((_n) < VECTOR_CAPACITY(_vec)) { \
			/* reduce size */ \
			VECTOR_DATA(_vec) = _re(VECTOR_DATA(_vec), (_n)*sizeof(VECTOR_FIRST(_vec))); /* reallocate */ \
			VECTOR_CAPACITY(_vec) = (_n); /* update capacity */ \
			if ((_n) - VECTOR_LENGTH(_vec) > 0) \
				VECTOR_LENGTH(_vec) = (_n); /* update length */ \
		} \
	} while(false)

/**
 * Resizes the vector.
 *
 * Excess values are discarded, new positions are zeroed.
 * _SHARED Uses shared memory allocation
 * _LOCAL  Uses local memory allocation
 *
 * @param _vec  Vector.
 * @param _n    New size.
 * @param _zero Should the new data be zeroed?
 * @see VECTOR_RESIZE_SUB
 */
#define VECTOR_RESIZE_SHARED(_vec, _n, _zero) VECTOR_RESIZE_SUB(_vec, _n, aMalloc, aRealloc, aFree, aCalloc, _zero)
#define VECTOR_RESIZE_LOCAL(_vec, _n, _zero) VECTOR_RESIZE_SUB(_vec, _n, alMalloc, alRealloc, alFree, alCalloc, _zero)
#define VECTOR_RESIZE(_vec, _n) VECTOR_RESIZE_SHARED(_vec, _n, true)

/**
 * Ensures that the array has the target number of empty positions.
 *
 * Increases the capacity in counts of _step.
 *
 * @param _vec  Vector.
 * @param _n    Desired empty positions.
 * @param _step Increase.
 */
#define VECTOR_ENSURE_SUB(_vec, _n, _step, _mem) \
	do { \
		int _newcapacity_ = VECTOR_CAPACITY(_vec); \
		while ((_n) + VECTOR_LENGTH(_vec) > _newcapacity_) \
			_newcapacity_ += (_step); \
		if (_newcapacity_ > VECTOR_CAPACITY(_vec)) \
			VECTOR_RESIZE##_mem(_vec, _newcapacity_, true); \
	} while(false)

/**
 * Ensures that the array has the target number of empty positions.
 *
 * Increases the capacity in counts of _step.
 * _SHARED Uses shared memory allocation
 * _LOCAL  Uses local memory allocation
 *
 * @param _vec  Vector.
 * @param _n    Desired empty positions.
 * @param _step Increase.
 * @see VECTOR_ENSURE_SUB
 */
#define VECTOR_ENSURE(_vec, _n, _step) VECTOR_ENSURE_SUB(_vec, _n, _step, _SHARED)
#define VECTOR_ENSURE_SHARED(_vec, _n, _step) VECTOR_ENSURE_SUB(_vec, _n, _step, _SHARED)
#define VECTOR_ENSURE_LOCAL(_vec, _n, _step) VECTOR_ENSURE_SUB(_vec, _n, _step, _LOCAL)

/**
 * Inserts a zeroed value in the target index.
 *
 * Assumes the index is valid and there is enough capacity.
 *
 * @param _vec Vector.
 * @param _idx Index.
 */
#define VECTOR_INSERTZEROED(_vec, _idx) \
	do { \
		if ((_idx) < VECTOR_LENGTH(_vec)) /* move data */ \
			memmove(&VECTOR_INDEX(_vec, (_idx)+1), &VECTOR_INDEX(_vec, _idx), (VECTOR_LENGTH(_vec)-(_idx))*sizeof(VECTOR_FIRST(_vec))); \
		memset(&VECTOR_INDEX(_vec, _idx), 0, sizeof(VECTOR_INDEX(_vec, _idx))); /* set zeroed value */ \
		++VECTOR_LENGTH(_vec); /* increase length */ \
	} while(false)

/**
 * Inserts a value in the target index (using the '=' operator).
 *
 * Assumes the index is valid and there is enough capacity.
 *
 * @param _vec Vector.
 * @param _idx Index.
 * @param _val Value.
 */
#define VECTOR_INSERT(_vec, _idx, _val) \
	do { \
		if ((_idx) < VECTOR_LENGTH(_vec)) /* move data */ \
			memmove(&VECTOR_INDEX(_vec, (_idx)+1), &VECTOR_INDEX(_vec, _idx), (VECTOR_LENGTH(_vec)-(_idx))*sizeof(VECTOR_FIRST(_vec))); \
		VECTOR_INDEX(_vec, _idx) = (_val); /* set value */ \
		++VECTOR_LENGTH(_vec); /* increase length */ \
	} while(false)

/**
 * Inserts a value in the target index (using memcpy).
 *
 * Assumes the index is valid and there is enough capacity.
 *
 * @param _vec Vector.
 * @param _idx Index.
 * @param _val Value.
 */
#define VECTOR_INSERTCOPY(_vec, _idx, _val) \
	VECTOR_INSERTARRAY(_vec, _idx, &(_val), 1)

/**
 * Inserts the values of the array in the target index (using memcpy).
 *
 * Assumes the index is valid and there is enough capacity.
 *
 * @param _vec  Vector.
 * @param _idx  Index.
 * @param _pval Array of values.
 * @param _n    Number of values.
 */
#define VECTOR_INSERTARRAY(_vec, _idx, _pval, _n) \
	do { \
		if ((_idx) < VECTOR_LENGTH(_vec)) /* move data */ \
			memmove(&VECTOR_INDEX(_vec, (_idx)+(_n)), &VECTOR_INDEX(_vec, _idx), (VECTOR_LENGTH(_vec)-(_idx))*sizeof(VECTOR_FIRST(_vec))); \
		memcpy(&VECTOR_INDEX(_vec, _idx), (_pval), (_n)*sizeof(VECTOR_FIRST(_vec))); /* set values */ \
		VECTOR_LENGTH(_vec) += (_n); /* increase length */ \
	} while(false)

/**
 * Inserts a zeroed value in the end of the vector.
 *
 * Assumes there is enough capacity.
 *
 * @param _vec Vector.
 */
#define VECTOR_PUSHZEROED(_vec) \
	do { \
		memset(&VECTOR_INDEX(_vec, VECTOR_LENGTH(_vec)), 0, sizeof(VECTOR_INDEX(_vec, VECTOR_LENGTH(_vec)))); /* set zeroed value */ \
		++VECTOR_LENGTH(_vec); /* increase length */ \
	} while(false)

/**
 * Appends a value at the end of the vector (using the '=' operator).
 *
 * Assumes there is enough capacity.
 *
 * @param _vec Vector.
 * @param _val Value.
 */
#define VECTOR_PUSH(_vec, _val) \
	do { \
		VECTOR_INDEX(_vec, VECTOR_LENGTH(_vec)) = (_val); /* set value */ \
		++VECTOR_LENGTH(_vec); /* increase length */ \
	}while(false)

/**
 * Appends a value at the end of the vector (using memcpy).
 *
 * Assumes there is enough capacity.
 *
 * @param _vec Vector.
 * @param _val Value.
 */
#define VECTOR_PUSHCOPY(_vec, _val) \
	VECTOR_PUSHARRAY(_vec, &(_val), 1)

/**
 * Appends the values of the array at the end of the vector (using memcpy).
 *
 * Assumes there is enough capacity.
 *
 * @param _vec  Vector.
 * @param _pval Array of values.
 * @param _n    Number of values.
 */
#define VECTOR_PUSHARRAY(_vec, _pval, _n) \
	do { \
		memcpy(&VECTOR_INDEX(_vec, VECTOR_LENGTH(_vec)), (_pval), (_n)*sizeof(VECTOR_FIRST(_vec))); /* set values */ \
		VECTOR_LENGTH(_vec) += (_n); /* increase length */ \
	} while(false)

/**
 * Removes and returns the last value of the vector.
 *
 * Assumes the array is not empty.
 *
 * @param _vec Vector.
 * @return Removed value.
 */
#define VECTOR_POP(_vec) \
	( VECTOR_INDEX(_vec, --VECTOR_LENGTH(_vec)) )

/**
 * Removes the last N values of the vector and returns the value of the last pop.
 *
 * Assumes there are enough values.
 *
 * @param _vec Vector.
 * @param _n   Number of pops.
 * @return Last removed value.
 */
#define VECTOR_POPN(_vec, _n) \
	( VECTOR_INDEX(_vec, (VECTOR_LENGTH(_vec) -= (_n))) )

/**
 * Removes the target index from the vector.
 *
 * Assumes the index is valid and there are enough values.
 *
 * @param _vec Vector.
 * @param _idx Index.
 */
#define VECTOR_ERASE(_vec, _idx) \
	VECTOR_ERASEN(_vec, _idx, 1)

/**
 * Removes N values from the target index of the vector.
 *
 * Assumes the index is valid and there are enough values.
 *
 * @param _vec Vector.
 * @param _idx Index.
 * @param _n   Number of values to remove.
 */
#define VECTOR_ERASEN(_vec, _idx, _n) \
	do { \
		if ((_idx) < VECTOR_LENGTH(_vec)-(_n) ) /* move data */ \
			memmove(&VECTOR_INDEX(_vec, _idx), &VECTOR_INDEX(_vec, (_idx)+(_n)), (VECTOR_LENGTH(_vec)-((_idx)+(_n)))*sizeof(VECTOR_FIRST(_vec))); \
		VECTOR_LENGTH(_vec) -= (_n); /* decrease length */ \
	} while(false)

/**
 * Removes all values from the vector.
 *
 * Does not free the allocated data.
 */
#define VECTOR_TRUNCATE(_vec) \
	do { \
		VECTOR_LENGTH(_vec) = 0; \
	} while (false)

/**
 * Clears the vector, freeing allocated data.
 *
 * @param _vec Vector.
 * @param _fr Free.
 */
#define VECTOR_CLEAR_SUB(_vec, _fr) \
	do { \
		if (VECTOR_CAPACITY(_vec) > 0) { \
			_fr(VECTOR_DATA(_vec)); VECTOR_DATA(_vec) = NULL; /* clear allocated array */ \
			VECTOR_CAPACITY(_vec) = 0; /* clear capacity */ \
			VECTOR_LENGTH(_vec) = 0; /* clear length */ \
		} \
	} while(false)

/**
 * Clears the vector, freeing allocated data.
 * _SHARED Uses shared memory allocation
 * _LOCAL  Uses local memory allocation
 *
 * @param _vec Vector.
 * @see VECTOR_CLEAR_SUB
 */
#define VECTOR_CLEAR(_vec) VECTOR_CLEAR_SUB(_vec, aFree)
#define VECTOR_CLEAR_SHARED(_vec) VECTOR_CLEAR_SUB(_vec, aFree)
#define VECTOR_CLEAR_LOCAL(_vec) VECTOR_CLEAR_SUB(_vec, alFree)

/**
 * Ensures that there is enough capacity and then appends a value at
 * the end of the vector using VECTOR_PUSHCOPY.
 * _SHARED Uses shared memory allocation
 * _LOCAL  Uses local memory allocation
 *
 * @param _vec Vector.
 * @param _val Value.
 * @param _step Increase factor.
 */
#define VECTOR_PUSHCOPY_ENSURE_SUB(_vec, _val, _step, _mem) \
	do { \
		VECTOR_ENSURE##_mem(_vec, 1, _step); \
		VECTOR_PUSHCOPY(_vec, _val); \
	} while(false)
#define VECTOR_PUSHCOPY_ENSURE(_vec, _val, _step) \
	VECTOR_PUSHCOPY_ENSURE_SUB(_vec, _val, _step, _SHARED)
#define VECTOR_PUSHCOPY_ENSURE_SHARED(_vec, _val, _step) \
	VECTOR_PUSHCOPY_ENSURE_SUB(_vec, _val, _step, _SHARED)
#define VECTOR_PUSHCOPY_ENSURE_LOCAL(_vec, _val, _step) \
	VECTOR_PUSHCOPY_ENSURE_SUB(_vec, _val, _step, _LOCAL)

/**
 * Initializes a vector with provided capacity
 * _SHARED Uses shared memory allocation
 * _LOCAL  Uses local memory allocation
 *
 * @param _vec Vector.
 * @param _n Initial capacity.
 **/
#define VECTOR_INIT_CAPACITY_SUB(_vec, _n, _mem) \
	do { \
		VECTOR_INIT(_vec); \
		VECTOR_RESIZE##_mem(_vec, _n, true); \
	} while(false)
#define VECTOR_INIT_CAPACITY(_vec, _n) VECTOR_INIT_CAPACITY_SUB(_vec, _n, _SHARED)
#define VECTOR_INIT_CAPACITY_SHARED(_vec, _n) VECTOR_INIT_CAPACITY_SUB(_vec, _n, _SHARED)
#define VECTOR_INIT_CAPACITY_LOCAL(_vec, _n) VECTOR_INIT_CAPACITY_SUB(_vec, _n, _LOCAL)


/******************************************************************************\
 *  (3c) Binary heap library.                                                 *
 * BHEAP_DECL        - Declares an anonymous binary heap struct.              *
 * BHEAP_STRUCT_DECL - Declares a named binary heap struct.                   *
 * BHEAP_VAR         - Declares and initializes an anonymous variable.        *
 * BHEAP_STRUCT_VAR  - Declares and initializes a named variable. .           *
 * BHEAP_INIT        - Initializes a heap.                                    *
 * BHEAP_DATA        - Returns the internal array of values.                  *
 * BHEAP_LENGTH      - Returns the length of the heap.                        *
 * BHEAP_CAPACITY    - Returns the capacity of the heap.                      *
 * BHEAP_ENSURE      - Ensures that the heap has the required empty positions.*
 * BHEAP_PEEK        - Returns the top value of the heap.                     *
 * BHEAP_PUSH        - Inserts a value in the heap.                           *
 * BHEAP_PUSH2       - Variant of BHEAP_PUSH used by A* implementation.       *
 * BHEAP_POP         - Removes the top value of the heap.                     *
 * BHEAP_POP2        - Variant of BHEAP_POP used by A* implementation.        *
 * BHEAP_POPINDEX    - Removes the target value of the heap.                  *
 * BHEAP_SIFTDOWN    - Follow path up towards the root, swapping nodes.       *
 * BHEAP_SIFTUP      - Repeatedly swap the smaller child with parent.         *
 * BHEAP_UPDATE      - Restores a heap.                                       *
 * BHEAP_CLEAR       - Clears the binary heap, freeing allocated data.        *
 * BHEAP_MINTOPCMP   - Generic comparator for a min-heap.                     *
 * BHEAP_MAXTOPCMP   - Generic comparator for a max-heap.                     *
 ******************************************************************************/

/**
 * Binary heap library based on defines.
 *
 * Uses the VECTOR defines above.
 * Uses aMalloc, aRealloc, aFree.
 *
 * @warning
 *    BHEAP implementation details affect behaviour of A* pathfinding.
 */

/**
 * Declares an anonymous binary heap struct.
 *
 * @param _type Type of data.
 */
#define BHEAP_DECL(_type) \
	VECTOR_DECL(_type)

/**
 * Declares a named binary heap struct.
 *
 * @param _name Structure name.
 * @param _type Type of data.
 */
#define BHEAP_STRUCT_DECL(_name, _type) \
	VECTOR_STRUCT_DECL(_name, _type)

/**
 * Declares and initializes an anonymous binary heap variable.
 *
 * @param _type Type of data.
 * @param _var  Variable name.
 */
#define BHEAP_VAR(_type, _var) \
	VECTOR_VAR(_type, _var)

/**
 * Declares and initializes a named binary heap variable.
 *
 * @param _name Structure name.
 * @param _var  Variable name.
 */
#define BHEAP_STRUCT_VAR(_name, _var) \
	VECTOR_STRUCT_VAR(_name, _var)

/**
 * Initializes a heap.
 *
 * @param _heap Binary heap.
 */
#define BHEAP_INIT(_heap) \
	VECTOR_INIT(_heap)

/**
 * Returns the internal array of values.
 *
 * @param _heap Binary heap.
 * @return Internal array of values.
 */
#define BHEAP_DATA(_heap) \
	VECTOR_DATA(_heap)

/**
 * Returns the length of the heap.
 *
 * @param _heap Binary heap.
 * @return Length.
 */
#define BHEAP_LENGTH(_heap) \
	VECTOR_LENGTH(_heap)

/**
 * Returns the capacity of the heap.
 *
 * @param _heap Binary heap.
 * @return Capacity.
 */
#define BHEAP_CAPACITY(_heap) \
	VECTOR_CAPACITY(_heap)

/**
 * Ensures that the heap has the target number of empty positions.
 *
 * Increases the capacity in counts of _step.
 *
 * @param _heap Binary heap.
 * @param _n    Required empty positions.
 * @param _step Increase.
 */
#define BHEAP_ENSURE(_heap, _n, _step) \
	VECTOR_ENSURE(_heap, _n, _step)

/**
 * Returns the top value of the heap.
 *
 * Assumes the heap is not empty.
 *
 * @param _heap Binary heap.
 * @return Value at the top.
 */
#define BHEAP_PEEK(_heap) \
	VECTOR_INDEX(_heap, 0)

/**
 * Inserts a value in the heap (using the '=' operator).
 *
 * Assumes there is enough capacity.
 *
 * The comparator takes two values as arguments, returns:
 *   - negative if the first value is on the top
 *   - positive if the second value is on the top
 *   - 0 if they are equal
 *
 * @param _heap   Binary heap.
 * @param _val    Value.
 * @param _topcmp Comparator.
 * @param _swp    Swapper.
 */
#define BHEAP_PUSH(_heap, _val, _topcmp, _swp) \
	do { \
		int _i_ = VECTOR_LENGTH(_heap); \
		VECTOR_PUSH(_heap, _val); /* insert at end */ \
		while (_i_ > 0) { \
			/* restore heap property in parents */ \
			int _parent_ = (_i_-1)/2; \
			if (_topcmp(VECTOR_INDEX(_heap, _parent_), VECTOR_INDEX(_heap, _i_)) < 0) \
				break; /* done */ \
			_swp(VECTOR_INDEX(_heap, _parent_), VECTOR_INDEX(_heap, _i_)); \
			_i_ = _parent_; \
		} \
	} while(false)

/**
 * Variant of BHEAP_PUSH used by A* implementation, matching client bheap.
 *
 * @see BHEAP_PUSH.
 *
 * @param _heap   Binary heap.
 * @param _val    Value.
 * @param _topcmp Comparator.
 * @param _swp    Swapper.
 */
#define BHEAP_PUSH2(_heap, _val, _topcmp, _swp) \
	do { \
		int _i_ = VECTOR_LENGTH(_heap); \
		VECTOR_PUSH(_heap, _val); /* insert at end */ \
		BHEAP_SIFTDOWN(_heap, 0, _i_, _topcmp, _swp); \
	} while(false)

/**
 * Removes the top value of the heap (using the '=' operator).
 *
 * Assumes the heap is not empty.
 *
 * The comparator takes two values as arguments, returns:
 *   - negative if the first value is on the top
 *   - positive if the second value is on the top
 *   - 0 if they are equal
 *
 * @param _heap   Binary heap.
 * @param _topcmp Comparator.
 * @param _swp Swapper.
 */
#define BHEAP_POP(_heap, _topcmp, _swp) \
	BHEAP_POPINDEX(_heap, 0, _topcmp, _swp)

/**
 * Variant of BHEAP_POP used by A* implementation, matching client bheap.
 *
 * @see BHEAP_POP.
 *
 * @param _heap   Binary heap.
 * @param _topcmp Comparator.
 * @param _swp    Swapper.
 */
#define BHEAP_POP2(_heap, _topcmp, _swp) \
	do { \
		VECTOR_INDEX(_heap, 0) = VECTOR_POP(_heap); /* put last at index */ \
		if (VECTOR_LENGTH(_heap) == 0) /* removed last, nothing to do */ \
			break; \
		BHEAP_SIFTUP(_heap, 0, _topcmp, _swp); \
	} while(false)

/**
 * Removes the target value of the heap (using the '=' operator).
 *
 * Assumes the index exists.
 *
 * The comparator takes two values as arguments, returns:
 *   - negative if the first value is on the top
 *   - positive if the second value is on the top
 *   - 0 if they are equal
 *
 * @param _heap   Binary heap.
 * @param _idx    Index.
 * @param _topcmp Comparator.
 * @param _swp    Swapper.
 */
#define BHEAP_POPINDEX(_heap, _idx, _topcmp, _swp) \
	do { \
		int _i_ = _idx; \
		VECTOR_INDEX(_heap, _idx) = VECTOR_POP(_heap); /* put last at index */ \
		if (_i_ >= VECTOR_LENGTH(_heap)) /* removed last, nothing to do */ \
			break; \
		while (_i_ > 0) { \
			/* restore heap property in parents */ \
			int _parent_ = (_i_-1)/2; \
			if (_topcmp(VECTOR_INDEX(_heap, _parent_), VECTOR_INDEX(_heap, _i_)) < 0) \
				break; /* done */ \
			_swp(VECTOR_INDEX(_heap, _parent_), VECTOR_INDEX(_heap, _i_)); \
			_i_ = _parent_; \
		} \
		while (_i_ < VECTOR_LENGTH(_heap)) { \
			/* restore heap property in children */ \
			int _lchild_ = _i_*2 + 1; \
			int _rchild_ = _i_*2 + 2; \
			if ((_lchild_ >= VECTOR_LENGTH(_heap) || _topcmp(VECTOR_INDEX(_heap, _i_), VECTOR_INDEX(_heap, _lchild_)) <= 0) \
			 && (_rchild_ >= VECTOR_LENGTH(_heap) || _topcmp(VECTOR_INDEX(_heap, _i_), VECTOR_INDEX(_heap, _rchild_)) <= 0)) { \
				break; /* done */ \
			} else if (_rchild_ >= VECTOR_LENGTH(_heap) || _topcmp(VECTOR_INDEX(_heap, _lchild_), VECTOR_INDEX(_heap, _rchild_)) <= 0) { \
				/* left child */ \
				_swp(VECTOR_INDEX(_heap, _i_), VECTOR_INDEX(_heap, _lchild_)); \
				_i_ = _lchild_; \
			} else { \
				/* right child */ \
				_swp(VECTOR_INDEX(_heap, _i_), VECTOR_INDEX(_heap, _rchild_)); \
				_i_ = _rchild_; \
			} \
		} \
	} while(false)

/**
 * Follow path up towards (but not all the way to) the root, swapping nodes
 * until finding a place where the new item that was placed at _idx fits.
 *
 * Only goes as high as _startidx (usually 0).
 *
 * @param _heap     Binary heap.
 * @param _startidx Index of an ancestor of _idx.
 * @param _idx      Index of an inserted element.
 * @param _topcmp   Comparator.
 * @param _swp      Swapper.
 */
#define BHEAP_SIFTDOWN(_heap, _startidx, _idx, _topcmp, _swp) \
	do { \
		int _i2_ = _idx; \
		while (_i2_ > _startidx) { \
			/* restore heap property in parents */ \
			int _parent_ = (_i2_-1)/2; \
			if (_topcmp(VECTOR_INDEX(_heap, _parent_), VECTOR_INDEX(_heap, _i2_)) <= 0) \
				break; /* done */ \
			_swp(VECTOR_INDEX(_heap, _parent_), VECTOR_INDEX(_heap, _i2_)); \
			_i2_ = _parent_; \
		} \
	} while(false)

/**
 * Repeatedly swap the smaller child with parent, after placing a new item at _idx.
 *
 * @param _heap   Binary heap.
 * @param _idx    Index of an inserted element.
 * @param _topcmp Comparator.
 * @param _swp    Swapper.
 */
#define BHEAP_SIFTUP(_heap, _idx, _topcmp, _swp) \
	do { \
		int _i_ = _idx; \
		int _lchild_ = _i_*2 + 1; \
		while (_lchild_ < VECTOR_LENGTH(_heap)) { \
			/* restore heap property in children */ \
			int _rchild_ = _i_*2 + 2; \
			if (_rchild_ >= VECTOR_LENGTH(_heap) || _topcmp(VECTOR_INDEX(_heap, _lchild_), VECTOR_INDEX(_heap, _rchild_)) < 0) { \
				/* left child */ \
				_swp(VECTOR_INDEX(_heap, _i_), VECTOR_INDEX(_heap, _lchild_)); \
				_i_ = _lchild_; \
			} else { \
				/* right child */ \
				_swp(VECTOR_INDEX(_heap, _i_), VECTOR_INDEX(_heap, _rchild_)); \
				_i_ = _rchild_; \
			} \
			_lchild_ = _i_*2 + 1; \
		} \
		BHEAP_SIFTDOWN(_heap, _idx, _i_, _topcmp, _swp); \
	} while(false)

/**
 * Restores a heap (after modifying the item at _idx).
 *
 * @param _heap   Binary heap.
 * @param _idx    Index.
 * @param _topcmp Comparator.
 * @param _swp    Swapper.
 */
#define BHEAP_UPDATE(_heap, _idx, _topcmp, _swp) \
	do { \
		BHEAP_SIFTDOWN(_heap, 0, _idx, _topcmp, _swp); \
		BHEAP_SIFTUP(_heap, _idx, _topcmp, _swp); \
	} while(false)

/**
 * Clears the binary heap, freeing allocated data.
 *
 * @param _heap Binary heap.
 */
#define BHEAP_CLEAR(_heap) \
	VECTOR_CLEAR(_heap)

/**
 * Generic comparator for a min-heap (minimum value at top).
 *
 * Returns -1 if v1 is smaller, 1 if v2 is smaller, 0 if equal.
 *
 * @warning
 *    Arguments may be evaluted more than once.
 *
 * @param v1 First value.
 * @param v2 Second value.
 * @return negative if v1 is top, positive if v2 is top, 0 if equal.
 */
#define BHEAP_MINTOPCMP(v1, v2) \
	( (v1) == (v2) ? 0 : (v1) < (v2) ? -1 : 1 )

/**
 * Generic comparator for a max-heap (maximum value at top).
 *
 * Returns -1 if v1 is bigger, 1 if v2 is bigger, 0 if equal.
 *
 * @warning
 *    Arguments may be evaluted more than once.
 *
 * @param v1 First value.
 * @param v2 Second value.
 * @return negative if v1 is top, positive if v2 is top, 0 if equal.
 */
#define BHEAP_MAXTOPCMP(v1, v2) \
	( (v1) == (v2) ? 0 : (v1) > (v2) ? -1 : 1 )


/******************************************************************************\
 *  (3d) Queue (FIFO) library.                                                *
 * QUEUE_DECL               - Declares an anonymous queue struct.             *
 * QUEUE_STRUCT_DECL        - Declares a named queue struct.                  *
 * QUEUE_STATIC_INITIALIZER - Queue static initializer.                       *
 * QUEUE_VAR                - Declares and initializes an anonymous variable. *
 * QUEUE_STRUCT_VAR         - Declares and initializes a named variable.      *
 * QUEUE_VECTOR             - Returns pointer of vector data.                 *
 * QUEUE_CAPACITY           - Returns current queue capacity.                 *
 * QUEUE_LENGTH             - Returns number of active elements of a queue.   *
 * QUEUE_INDEX              - Returns the value at the target index.          *
 * QUEUE_BACK               - Returns the back of the queue.                  *
 * QUEUE_FRONT              - Returns the front of the queue (older value).   *
 * QUEUE_DYNAMIC_INITIALIZER- Queue dynamic initializer.                      *
 * QUEUE_DEQUEUE            - Dequeues a value (from the front).              *
 * QUEUE_GROW               - Grows queue.                                    *
 * QUEUE_INSERT_EQUAL       - Inserts value into queue, assignment.           *
 * QUEUE_INSERT_COPY        - Inserts value into queue, memory copy.          *
 * QUEUE_ENQUEUE_*          - Enqueues a value, grows queue if necessary.     *
 * QUEUE_TRUNCATE           - Removes all values from queue.                  *
 * QUEUE_CLEAR_*            - Clears the queue, freeing allocated data.       *
 * QUEUE_INIT_CAPACITY_*    - Initializes queue with provided capacity.       *
 ******************************************************************************/

/**
 * Queue (FIFO) library based on macros.
 *
 * @remark
 *    This library uses the internal memory manager (via VECTOR)
 *     *_SHARED uses shared memory allocation
 *     *_LOCAL  uses local memory allocation
 *    The default usage uses shared memory allocation
 *
 * The memory used by this structure is contiguous and grows dynamically
 * Dequeue is O(1), and if there's still memory remaining enqueue is O(1)
 **/

/**
 * Declares an anonymous queue struct.
 *
 * @param _type Type of data to be contained.
 */
#define QUEUE_DECL(_type)          \
	struct {                       \
		VECTOR_DECL(_type) _data_; \
		int _back_;                \
		int _front_;               \
	}

/**
 * Declares a named queue struct.
 *
 * @param _name Structure name.
 * @param _type Type of data to be contained.
 */
#define QUEUE_STRUCT_DECL(_name, _type) \
	struct _name {                      \
		VECTOR_DECL(_type) _data_;      \
		int _back_;                     \
		int _front_;                    \
	}

#define QUEUE_DEFAULT_BACK -1
#define QUEUE_DEFAULT_FRONT 0
/**
 * Queue static initializer.
 **/
#define QUEUE_STATIC_INITIALIZER {VECTOR_STATIC_INITIALIZER, QUEUE_DEFAULT_BACK, QUEUE_DEFAULT_FRONT}

/**
 * Declares and initializes an anonymous queue variable.
 *
 * @param _type Type of data to be contained.
 * @param _var  Variable name.
 */
#define QUEUE_VAR(_type, _var) \
	QUEUE_DECL(_type) _var = QUEUE_STATIC_INITIALIZER

/**
 * Declares and initializes a named queue variable.
 *
 * @param _name Structure name.
 * @param _var  Variable name.
 */
#define QUEUE_STRUCT_VAR(_name, _var) \
	struct _name _var = QUEUE_STATIC_INITIALIZER

/**
 * Returns pointer of vector data.
 *
 * @param _que Queue.
 * @return Pointer of vector data.
 **/
#define QUEUE_VECTOR(_que)      ((_que)._data_)

/**
 * Returns current queue capacity.
 *
 * @param _que Queue.
 * @return Current queue capacity
 **/
#define QUEUE_CAPACITY(_que)    VECTOR_CAPACITY(QUEUE_VECTOR(_que))

/**
 * Returns number of active elements of a queue.
 *
 * @param _que Queue.
 * @return Current queue length
 **/
#define QUEUE_LENGTH(_que)      VECTOR_LENGTH(QUEUE_VECTOR(_que))

/**
 * Returns the value at the target index.
 *
 * @param _que Queue.
 * @param _idx Index.
 * @return Value.
 **/
#define QUEUE_INDEX(_que, _idx) (VECTOR_INDEX(QUEUE_VECTOR(_que), _idx))

/**
 * Returns the back of the queue (last inserted value).
 *
 * @param _que Queue.
 * @return Value.
 **/
#define QUEUE_BACK(_que)        (QUEUE_INDEX((_que), (_que)._back_))

/**
 * Returns the front of the queue (older value).
 *
 * @param _que Queue.
 * @return Value.
 **/
#define QUEUE_FRONT(_que)       (QUEUE_INDEX((_que), (_que)._front_))

/**
 * Queue dynamic initializer.
 **/
 #define QUEUE_DYNAMIC_INITIALIZER(_que)      \
	do {                                      \
		VECTOR_INIT(QUEUE_VECTOR(_que));      \
		(_que)._back_ = QUEUE_DEFAULT_BACK;   \
		(_que)._front_ = QUEUE_DEFAULT_FRONT; \
	} while(false)

/**
 * Dequeues a value (from the front).
 *
 * @param _que Queue
 **/
#define QUEUE_DEQUEUE(_que)                                       \
	do {                                                          \
		if(!QUEUE_LENGTH(_que))                                   \
			break;                                                \
		(_que)._front_ = ((_que)._front_+1)%QUEUE_CAPACITY(_que); \
		QUEUE_LENGTH(_que) -= 1;                                  \
	} while(false)

/**
 * Grows queue.
 *
 * @param _que Queue
 * @param _step Growth factor
 * @param _mem Memory manager type
 **/
#define QUEUE_GROW(_que, _step, _mem)                                                \
	do {                                                                             \
		int _old_size_ = (QUEUE_CAPACITY(_que))?QUEUE_CAPACITY(_que):1;              \
		VECTOR_RESIZE##_mem(QUEUE_VECTOR(_que), _old_size_*(_step), false);          \
		if((_que)._front_ > (_que)._back_ && (_que)._back_ != QUEUE_DEFAULT_BACK) {  \
			/* _back_ was wrapped, reposition in new vector */                       \
			memcpy(&QUEUE_INDEX(_que, _old_size_),                                   \
			       &QUEUE_INDEX(_que, 0),                                            \
			       sizeof(QUEUE_INDEX(_que, 0))*(_que)._front_);                     \
			(_que)._back_ += _old_size_;                                             \
		}                                                                            \
	} while(false)

/**
 * Inserts value into queue, assignment (internal)
 *
 * @param _que Queue
 * @param _idx Index inside vector
 * @param _var Variable to be inserted
 **/
#define QUEUE_INSERT_EQUAL(_que, _idx, _var) QUEUE_INDEX((_que), (_idx)) = (_var)

/**
 * Inserts value into queue, memory copy (internal)
 *
 * @param _que Queue
 * @param _idx Index inside vector
 * @param _var Variable to be inserted
 **/
#define QUEUE_INSERT_COPY(_que, _idx, _var)                  \
	do {                                                     \
		memcpy(&QUEUE_INDEX((_que), (_idx)),                 \
		&(_var), sizeof(VECTOR_FIRST(QUEUE_VECTOR(_que))));  \
	} while(0)

/**
 * Enqueues a value, grows queue if necessary.
 *
 * @param _que Queue
 * @param _var Variable to be inserted
 * @param _mem Memory management type
 * @param _type _EQUAL (assignment) or _COPY (copy)
 **/
#define QUEUE_ENQUEUE_SUB(_que, _var, _step, _mem, _type)                    \
	do {                                                                     \
		if(QUEUE_LENGTH(_que)+1 >= QUEUE_CAPACITY(_que))                     \
			QUEUE_GROW(_que, _step, _mem);                                   \
		(_que)._back_ = ((_que)._back_+1)%QUEUE_CAPACITY(_que);              \
		QUEUE_INSERT##_type(_que, (_que)._back_, _var);                      \
		QUEUE_LENGTH(_que) += 1;                                             \
	} while(false)
#define QUEUE_ENQUEUE(_que, _var, _step)             QUEUE_ENQUEUE_SUB(_que, _var, _step, _SHARED, _EQUAL)
#define QUEUE_ENQUEUE_SHARED(_que, _var, _step)      QUEUE_ENQUEUE(_que, _var, _step)
#define QUEUE_ENQUEUE_LOCAL(_que, _var, _step)       QUEUE_ENQUEUE_SUB(_que, _var, _step, _LOCAL, _EQUAL)
#define QUEUE_ENQUEUE_COPY(_que, _var, _step)        QUEUE_ENQUEUE_SUB(_que, _var, _step, _SHARED, _COPY)
#define QUEUE_ENQUEUE_COPY_SHARED(_que, _var, _step) QUEUE_ENQUEUE_COPY(_que, _var, _step)
#define QUEUE_ENQUEUE_COPY_LOCAL(_que, _var, _step)  QUEUE_ENQUEUE_SUB(_que, _var, _step, _LOCAL, _COPY)

/**
 * Removes all values from queue.
 *
 * Does not free the allocated data.
 **/
#define QUEUE_TRUNCATE(_que)                  \
	do {                                      \
		VECTOR_TRUNCATE(QUEUE_VECTOR(_que));  \
		(_que)._front_ = QUEUE_DEFAULT_FRONT; \
		(_que)._back_ =  QUEUE_DEFAULT_BACK;  \
	} while(false)

/**
 * Clears the queue, freeing allocated data.
 *
 * @param _que Queue.
 * @param _fr Free.
 */
#define QUEUE_CLEAR_SUB(_que, _mem)             \
	do {                                        \
		QUEUE_TRUNCATE(_que);                   \
		VECTOR_CLEAR##_mem(QUEUE_VECTOR(_que)); \
	} while(false)
#define QUEUE_CLEAR(_que) QUEUE_CLEAR_SUB(_que, _SHARED)
#define QUEUE_CLEAR_SHARED(_que) QUEUE_CLEAR(_que)
#define QUEUE_CLEAR_LOCAL(_que) QUEUE_CLEAR_SUB(_que, _LOCAL)

/**
 * Initializes queue with provided capacity.
 *
 * @param _que Queue
 * @param _n Number of elements
 * @param _mem Memory manager type
 **/
#define QUEUE_INIT_CAPACITY_SUB(_que, _n, _mem)             \
	do {                                                    \
		QUEUE_DYNAMIC_INITIALIZER(_que);                    \
		VECTOR_INIT_CAPACITY##_mem(QUEUE_VECTOR(_que), _n); \
	} while(false)
#define QUEUE_INIT_CAPACITY(_que, _n) QUEUE_INIT_CAPACITY_SUB(_que, _n, _SHARED)
#define QUEUE_INIT_CAPACITY_SHARED(_que, _n) QUEUE_INIT_CAPACITY(_que, _n)
#define QUEUE_INIT_CAPACITY_LOCAL(_que, _n) QUEUE_INIT_CAPACITY_SUB(_que, _n, _LOCAL)


/******************************************************************************\
 *  (3e) Index map array.                                                     *
 * INDEX_MAP_DECL                - Declares an anonymous index map.           *
 * INDEX_MAP_STRUCT_DECL         - Declares an named index map struct         *
 * INDEX_MAP_STATIC_INITIALIZER  - Static initializer.                        *
 * INDEX_MAP_CREATE              - Sets up a new index map.                   *
 * INDEX_MAP_DESTROY             - Destroys an index map.                     *
 * INDEX_MAP_REMOVE              - Removes entry from index map.              *
 * INDEX_MAP_ADD                 - Adds entry, grows map if necessary.        *
 * INDEX_MAP_LENGTH              - Length of entry array.                     *
 * INDEX_MAP_EMPTY               - Next empty index.                          *
 * INDEX_MAP_ITER_DECL           - Declares an iterator.                      *
 * INDEX_MAP_ITER                - Creates a new iterator.                    *
 * INDEX_MAP_ITER_FREE           - Frees an iterator.                         *
 * INDEX_MAP_NEXT                - Returns next used index.                   *
 * INDEX_MAP_COUNT               - Number of valid entries.                   *
 * INDEX_MAP_INDEX               - Returns object.                            *
 ******************************************************************************/

/**
 * Index map array
 *
 * Declares a pointer array and a free index bitmap
 * Grows quadratically (always in multiples of 32)
 **/

/**
 * Declares an anonymous index map.
 *
 * @param _type Type of data to be contained.
 **/
#define INDEX_MAP_DECL(_type)            \
	struct {                             \
		_type **_data_;                  \
		uint32_t *_free_index_;          \
		int32_t _free_index_length_;     \
		int32_t _count_;                 \
		enum memory_type _mt_;           \
	}
/**
 * Declares an named index map struct.
 *
 * @param _name Structure name.
 * @param _type Type of data to be contained.
 **/
#define INDEX_MAP_STRUCT_DECL(_name, _type) \
	struct _name {                          \
		_type **_data_;                     \
		uint32_t *_free_index_;             \
		int32_t _free_index_length_;        \
		int32_t _count_;                    \
		enum memory_type _mt_;              \
	}

/**
 * Static initializer.
 **/
#define INDEX_MAP_STATIC_INITIALIZER(_mem) {NULL, NULL, 0, 0, (_mem)}

/**
 * Sets up a new index map.
 *
 * @param _im  Index map object
 * @param _sz  Initial size (this is multiplied by 32 internally)
 * @param _mem Memory allocation type
 **/
#define INDEX_MAP_CREATE(_im, _sz, _mem)                                           \
	do {                                                                           \
		(_im)._mt_ = (_mem);                                                       \
		(_im)._data_ = amCalloc((_sz)*32,                                          \
								sizeof(*(_im)._data_), (_im)._mt_);                \
		(_im)._free_index_ = amMalloc(sizeof(*(_im)._free_index_)*(_sz),           \
									(_im)._mt_);                                   \
		(_im)._free_index_length_ = (_sz);                                         \
		memset((_im)._free_index_, UINT32_MAX, sizeof(*(_im)._free_index_)*(_sz)); \
		(_im)._count_ = 0;                                                         \
	} while(false)
		
/**
 * Destroys an index map.
 *
 * @param _im  Index map object
 **/
#define INDEX_MAP_DESTROY(_im)                   \
	do {                                         \
		amFree((_im)._data_, (_im)._mt_);        \
		amFree((_im)._free_index_, (_im)._mt_);  \
		(_im)._data_ = NULL;                     \
		(_im)._free_index_ = NULL;               \
		(_im)._free_index_length_ = 0;           \
		(_im)._count_ = 0;                       \
	} while(false)

/**
 * Removes entry from index map.
 *
 * @param _im  Index map object
 * @param _pos Position of object in array
 **/
#define INDEX_MAP_REMOVE(_im, _pos)                     \
	do {                                                \
		(_im)._data_[(_pos)] = NULL;                    \
		BIT_SET((_im)._free_index_[(_pos)/32], (_pos)); \
		(_im)._count_ = (_im)._count_-1;                \
	} while(false)

/**
 * Adds entry to index map, grows if necessary.
 * Growth is always quadratic
 *
 * @param _im        Index map object
 * @param _val       Pointer to data.
 * @param _new_index [OUT] An uint32_t integer, this is set to last added index.
 **/
#define INDEX_MAP_ADD(_im, _val, _new_index)                                   \
	do {                                                                       \
		uint32_t _empty_index;                                                 \
		_empty_index = find_first_set_array((_im)._free_index_,                \
											(_im)._free_index_length_, true);  \
		if(_empty_index == -1) {                                               \
			/* Grow lists */                                                   \
			uint32_t _new_length;                                              \
			(_im)._free_index_length_++;                                       \
			_new_length = (_im)._free_index_length_*32;                        \
			amReallocz((_im)._data_,                                           \
						_new_length*sizeof(*(_im)._data_), (_im)._mt_);        \
			amRealloc((_im)._free_index_,                                      \
						(_im)._free_index_length_*sizeof(*(_im)._free_index_), \
						(_im)._mt_);                                           \
			(_im)._free_index_[(_im)._free_index_length_-1] = UINT32_MAX;      \
			BIT_CLEAR((_im)._free_index_[(_im)._free_index_length_-1], 31);    \
		}                                                                      \
		(_im)._data_[_empty_index] = (_val);                                   \
		(_new_index) = _empty_index;                                           \
		(_im)._count_ = (_im)._count_+1;                                       \
	} while(false)

/**
 * Finds next empty index and clears it for use.
 *
 * @param _im Index map object
 * @return Next empty index
 * @retval -1 All entries occupied
 **/
#define INDEX_MAP_EMPTY(_im) (find_first_set_array((_im)._free_index_, (_im)._free_index_length_, true))

/**
 * Declares an iterator.
 **/
#define INDEX_MAP_ITER_DECL(_name) uint32 *(_name) = NULL

/**
 * Creates a new iterator for the provided index map object
 *
 * @param _im Index map object
 * @param _name Name of the iterator variable
 * @remarks After an iterator is created the index map must not be changed,
 * otherwise the iterator becomes invalid
 * @remarks This iterator should be freed by calling INDEX_MAP_ITER_FREE
 **/
#define INDEX_MAP_ITER(_im, _name)                               \
	do {                                                         \
		size_t len = sizeof(uint32)*(_im)._free_index_length_;   \
		(_name) = aMalloc(len);                                  \
		for(int _i = 0; _i < (_im)._free_index_length_; _i++)    \
			(_name)[_i] = ~((_im)._free_index_[_i]);             \
	} while(false)

/**
 * Frees an iterator
 **/
#define INDEX_MAP_ITER_FREE(_iter) aFree(_iter)

/**
 * Finds next occupied index.
 *
 * @param _im  Index map object
 * @param _id  Current index
 * @return Next valid index
 * @retval -1 No next occupied index
 **/
#define INDEX_MAP_NEXT(_im, _iter) (find_first_set_array((_iter), (_im)._free_index_length_, true))

/**
 * Number of valid entries.
 *
 * @param _im  Index map object
 **/
#define INDEX_MAP_COUNT(_im) ((_im)._count_)

/**
 * Length of entry array.
 *
 * @param _im  Index map object
 **/
#define INDEX_MAP_LENGTH(_im) ((_im)._free_index_length_*32)

/**
 * Returns object.
 *
 * @param _im  Index map object
 **/
#define INDEX_MAP_INDEX(_im, _idx) ((_im)._data_[(_idx)])

#endif /* COMMON_DB_H */
