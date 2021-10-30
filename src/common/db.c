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
 *  This file is separated in six sections:
 *  (1) Private enums, structures, defines and global variables
 *  (2) Private functions
 *  (3) Protected functions used internally
 *  (4) Protected functions used in the interface of the database
 *  (5) Public functions
 *  (6) Linkdb system (doubly-linked list wrapper)
 *
 *  The databases are hash tables with balanced trees (RED-BLACK) to handle
 *  any collisions instead of chaining. With the latter the worst
 *  case in search is <code>O(n)</code> while with the former it's
 *  <code>O(lg(n))</code>.
 *  With this approach the total number of buckets (<code>HASH_SIZE</code>),
 *  can be smaller because collisions are not as damaging to the basic
 *  properties of the table.
 *
 *
 *  <B>Properties of the RED-BLACK trees being used:</B>
 *  1. The value of any node is greater than the value of its left child and
 *     less than the value of its right child.
 *  2. Every node is colored either RED or BLACK.
 *  3. Every red node that is not a leaf has only black children.
 *  4. Every path from the root to a leaf contains the same number of black
 *     nodes.
 *  5. The root node is black.
 *  An <code>n</code> node in a RED-BLACK tree has the property that its
 *  height is <code>O(lg(n))</code>.
 *  Another important property is that after adding a node to a RED-BLACK
 *  tree, the tree can be readjusted in <code>O(lg(n))</code> time.
 *  Similarly, after deleting a node from a RED-BLACK tree, the tree can be
 *  readjusted in <code>O(lg(n))</code> time.
 *  {@link http://www.cs.mcgill.ca/~cs251/OldCourses/1997/topic18/}
 *
 *  <B>How to add new database types:</B>
 *  1. Add the identifier of the new database type to the enum DBType
 *  2. If not already there, add the data type of the key to the union DBKey and struct DBKey_s
 *  3. If the key can be considered NULL, update the function db_is_key_null
 *  4. If the key can be duplicated, update the functions db_dup_key and
 *     db_dup_key_free
 *  5. Create a comparator and update the function db_default_cmp
 *  6. Create a hasher and update the function db_default_hash
 *  7. If the new database type requires or does not support some options,
 *     update the function db_fix_options
 *
 *  <B>About multi-threading:</B>
 *  Currently the database system supports multi-threaded applications, all global
 *  database states are protected automatically by mutexes. The responsability of
 *  ensuring the synchronization policy of a new database is of the one that
 *  allocated it.
 *
 *  TODO:
 *  - create test cases to test the database system thoroughly
 *  - create custom database allocator
 *  - change the structure of the database to T-Trees
 *  - create a db that organizes itself by splaying
 *
 *  HISTORY:
 *    2021/08    - Multi-thread support + new hash functions [Panikon/Hercules]
 *               - Dynamic bucket count with rehashing and load factor
 *    2013/08/25 - Added int64/uint64 support for keys [Ind/Hercules]
 *    2013/04/27 - Added ERS to speed up iterator memory allocation [Ind/Hercules]
 *    2012/03/09 - Added enum for data types (int, uint, void*)
 *    2008/02/19 - Fixed db_obj_get not handling deleted entries correctly.
 *    2007/11/09 - Added an iterator to the database.
 *    2006/12/21 - Added 1-node cache to the database.
 *    2.1 (Athena build #???#) - Portability fix
 *      - Fixed the portability of casting to union and added the functions
 *        ensure and clear to the database.
 *    2.0 (Athena build 4859) - Transition version
 *      - Almost everything recoded with a strategy similar to objects,
 *        database structure is maintained.
 *    1.0 (up to Athena build 4706)
 *      - Previous database system.
 *
 * @version 2006/12/21
 * @author Athena Dev team
 * @encoding US-ASCII
 * @see #db.h
\*****************************************************************************/

#define HERCULES_CORE

#include "db.h"

#include "common/ers.h"
#include "common/memmgr.h"
#include "common/mmo.h"
#include "common/nullpo.h"
#include "common/showmsg.h"
#include "common/strlib.h"
#include "common/rwlock.h"
#include "common/mutex.h"
#include "common/utils.h"
#include "common/atomic.h"
#include "common/rwlock.h"
#include "common/thread.h"

#include <stdio.h>
#include <stdlib.h>

static struct db_interface DB_s;
struct db_interface *DB;

/*****************************************************************************
 *  (1) Private enums, structures, defines and global variables of the       *
 *      database system.                                                     *
 *  DB_ENABLE_STATS         - Define to enable database statistics.          *
 *  DB_ENABLE_PRIVATE_STATS - Define to enable private database statistics.  *
 *  DB_USE_HASH_MURMUR2     - Define to enable murmur hash.                  *
 *  enum DBNodeColor        - Enumeration of colors of the nodes.            *
 *  struct DBNode           - Structure of a node in RED-BLACK trees.        *
 *  struct db_free          - Structure that holds a deleted node to be freed*
 *  struct DBMap_impl       - Structure of the database.                     *
 *  stats                   - Statistics about the database system.          *
 *****************************************************************************/

/**
 * If defined statistics about database nodes, database creating/destruction
 * and function usage are kept and displayed when finalizing the database
 * system.
 * WARNING: When defined everytime an operation is performed the global stat
 * table is updated. If there are no threads the overhead cost isn't prohibitive
 * but with multi-threading there could be data races.
 * @private
 * @see #DBStats
 * @see #stats
 * @see #db_final(void)
 */
//#define DB_ENABLE_STATS

/**
 * If defined statistics about database collision / bucket peak / rehash
 * count are saved internally in each database.
 * @private
 * @see #DBStats
 * @see #stats
 * @see #db_final(void)
 */
//#define DB_ENABLE_PRIVATE_STATS

/**
 * When defined changes the default hashing function for DB_STRING and DB_ISTRING
 * databases from athena_hash to murmur2_hash.
 * There are performance and collision differences, usually murmur2 outperforms
 * the default function. Even if this is set it's still possible to fine-tune each
 * database by calling set_hash and changing other parameters such as load factor
 * and the initial bucket size.
 * @see db_default_hash
 * @see test_db
 **/
#define DB_USE_HASH_MURMUR2

/**
 * The color of individual nodes.
 * @private
 * @see struct DBNode
 */
enum DBNodeColor {
	RED,
	BLACK,
};

/**
 * A node in a RED-BLACK tree of the database.
 * @param parent Parent node
 * @param left Left child node
 * @param right Right child node
 * @param key Key of this database entry
 * @param data Data of this database entry
 * @param deleted If the node is deleted
 * @param color Color of the node
 * @param reference_counter Number of instances of this node
 * @param waiting_deletion  Delete node when reference_counter reaches 0
 * @private
 * @see struct DBMap_impl#ht
 */
struct DBNode {
	// Tree structure
	struct DBNode *parent;
	struct DBNode *left;
	struct DBNode *right;
	// Node data
	struct DBKey_s key;
	struct DBData data;
	// Other
	enum DBNodeColor color;
	unsigned deleted : 1;

	unsigned int reference_counter;
	bool waiting_deletion;
};

/**
 * Structure that holds a deleted node.
 * @param node Deleted node
 * @param root Address to the root of the tree
 * @private
 * @see struct DBMap_impl#free_list
 */
struct db_free {
	struct DBNode *node;
	struct DBNode **root;
};

/**
 * Complete database structure.
 * @param vtable Interface of the database
 * @param alloc_file File where the database was allocated
 * @param alloc_line Line in the file where the database was allocated
 * @param lock Internal database lock
 * @param lock_tid TID if db is write locked, otherwise -1
 * @param garbage_collection Internal garbage collection so we don't spam free calls
 * @param nodes Manager of reusable tree nodes
 * @param cache Last accessed node (atomically accessed)
 * @param cmp Comparator of the database
 * @param hash Hasher of the database
 * @param release Releaser of the database
 * @param ht Hashtable of RED-BLACK trees (bucket list)
 * @param type Type of the database
 * @param options Options of the database
 * @param item_count Number of items in the database
 * @param maxlen Maximum length of strings in DB_STRING and DB_ISTRING databases
 * @param global_lock Global lock of the database (atomically accessed)
 * @param bucket_count Current size of ht
 * @param load_factor The ratio of item_count and bucket_count that triggers a capacity increase
 * @private
 * @see #db_alloc()
 */
struct DBMap_impl {
	/**
	 * Database interface
	 * Must always be the first item of this struct, otherwise casts to struct DBIterator_impl
	 * will fail, @see dbit_obj_first for an example on how this is being used.
	 **/
	struct DBMap vtable;
	// File and line of allocation
	const char *alloc_file;
	int alloc_line;

	struct rwlock_data *lock;
	int lock_tid;
	/**
	 * Internal garbage collection
	 * @param free_list Array of deleted nodes to be freed
	 * @param free_count Number of deleted nodes in free_list
	 * @param free_max Current maximum capacity of free_list
	 * @param free_lock Number of instances currently using the database, when
	 *                  reaches 0 all nodes in the free_list are freed from
	 *                  db->nodes (atomically accessed)
	 * @see db_free_lock
	 * @see db_free_unlock
	 **/
	struct {
		struct db_free *free_list;
		unsigned int free_count;
		unsigned int free_max;
		unsigned int free_lock;
	} garbage_collection;

	// Hash table implementation
	ERS *nodes;
	struct DBNode **ht;
	struct DBNode *cache;
	float load_factor;
	uint32 item_count;
	uint32 bucket_count;
	unsigned short maxlen;
	// Private functions
	DBComparator cmp;
	DBHasher hash;
	DBReleaser release;
	// Database flags
	enum DBType type;
	enum DBOptions options;

#ifdef DB_ENABLE_PRIVATE_STATS
	struct s_private_stats {
		uint32_t collision;
		uint32_t bucket_peak;
		uint32_t rehash;
	} stats;
#endif
};

#ifdef DB_ENABLE_PRIVATE_STATS
#define DB_COUNTSTAT_PRIVATE(db,token)        \
	do {                                      \
		if (((db)->stats.token) != UINT32_MAX)\
			++((db)->stats.token);           \
	} while(0)
#else
#define DB_COUNTSTAT_PRIVATE(db, token) (void)0
#endif

/**
 * Complete iterator structure.
 * @param vtable Interface of the iterator
 * @param db Parent database
 * @param ht_index Current index of the hashtable
 * @param node Current node
 * @private
 * @see struct DBIterator
 * @see struct DBMap_impl
 * @see struct DBNode
 */
struct DBIterator_impl {
	// Iterator interface
	struct DBIterator vtable;
	struct DBMap_impl *db;
	int ht_index;
	struct DBNode *node;
};

#if defined(DB_ENABLE_STATS)
/**
 * DB stats mutex
 **/
static struct mutex_data *db_stats_mutex = NULL;

/**
 * Structure with what is counted when the database statistics are enabled.
 * @private
 * @see #DB_ENABLE_STATS
 * @see #stats
 */
static struct db_stats {
	// Node alloc/free
	uint32 db_node_alloc;
	uint32 db_node_free;
	// Database creating/destruction counters
	uint32 db_int_alloc;
	uint32 db_uint_alloc;
	uint32 db_string_alloc;
	uint32 db_istring_alloc;
	uint32 db_int64_alloc;
	uint32 db_uint64_alloc;
	uint32 db_int_destroy;
	uint32 db_uint_destroy;
	uint32 db_string_destroy;
	uint32 db_istring_destroy;
	uint32 db_int64_destroy;
	uint32 db_uint64_destroy;
	// Function usage counters
	uint32 db_rotate_left;
	uint32 db_rotate_right;
	uint32 db_rebalance;
	uint32 db_rebalance_erase;
	uint32 db_is_key_null;
	uint32 db_dup_key;
	uint32 db_dup_key_free;
	uint32 db_free_add;
	uint32 db_free_remove;
	uint32 db_free_lock;
	uint32 db_free_unlock;
	uint32 db_int_cmp;
	uint32 db_uint_cmp;
	uint32 db_string_cmp;
	uint32 db_istring_cmp;
	uint32 db_int64_cmp;
	uint32 db_uint64_cmp;
	uint32 db_int_hash;
	uint32 db_uint_hash;
	uint32 db_string_hash;
	uint32 db_istring_hash;
	uint32 db_int64_hash;
	uint32 db_uint64_hash;
	uint32 db_release_nothing;
	uint32 db_release_key;
	uint32 db_release_data;
	uint32 db_release_both;
	uint32 dbit_first;
	uint32 dbit_last;
	uint32 dbit_next;
	uint32 dbit_prev;
	uint32 dbit_exists;
	uint32 dbit_remove;
	uint32 dbit_destroy;
	uint32 db_iterator;
	uint32 db_exists;
	uint32 db_get;
	uint32 db_getall;
	uint32 db_vgetall;
	uint32 db_ensure;
	uint32 db_vensure;
	uint32 db_put;
	uint32 db_remove;
	uint32 db_foreach;
	uint32 db_vforeach;
	uint32 db_clear;
	uint32 db_vclear;
	uint32 db_destroy;
	uint32 db_vdestroy;
	uint32 db_size;
	uint32 db_type;
	uint32 db_options;
	uint32 db_fix_options;
	uint32 db_default_cmp;
	uint32 db_default_hash;
	uint32 db_default_release;
	uint32 db_custom_release;
	uint32 db_alloc;
	uint32 db_i2key;
	uint32 db_ui2key;
	uint32 db_str2key;
	uint32 db_i642key;
	uint32 db_ui642key;
	uint32 db_i2data;
	uint32 db_ui2data;
	uint32 db_ptr2data;
	uint32 db_data2i;
	uint32 db_data2ui;
	uint32 db_data2ptr;
	uint32 db_init;
	uint32 db_final;
	uint32 db_rehash;
	// Collision stats
	uint32 db_int_collision;
	uint32 db_uint_collision;
	uint32 db_string_collision;
	uint32 db_istring_collision;
	uint32 db_int64_collision;
	uint32 db_uint64_collision;
	uint32 db_int_bucket_peak; 
	uint32 db_uint_bucket_peak;
	uint32 db_string_bucket_peak;
	uint32 db_istring_bucket_peak;
	uint32 db_int64_bucket_peak;
	uint32 db_uint64_bucket_peak;
} stats = { 0 };
#define DB_COUNTSTAT(token)                 \
	do {                                    \
		mutex->lock(db_stats_mutex);        \
		if ((stats.token) != UINT32_MAX)    \
			++(stats.token);                \
		mutex->unlock(db_stats_mutex);      \
	} while(0)
#define DB_GREATERTHAN_COUNT(v, token)                         \
	do {                                                       \
		mutex->lock(db_stats_mutex);                           \
		if((v) > (stats.token) && (stats.token) != UINT32_MAX) \
			++(stats.token);                                   \
		mutex->unlock(db_stats_mutex);                         \
	} while(0)

#define DB_COUNTSTAT_SWITCH(t, partial_token)                                \
	do {                                                                     \
		switch ((t)) {                                                       \
			case DB_INT:     DB_COUNTSTAT(db_int_##partial_token);    break; \
			case DB_UINT:    DB_COUNTSTAT(db_uint_##partial_token);   break; \
			case DB_STRING:  DB_COUNTSTAT(db_string_##partial_token); break; \
			case DB_ISTRING: DB_COUNTSTAT(db_istring_##partial_token);break; \
			case DB_INT64:   DB_COUNTSTAT(db_int64_##partial_token);  break; \
			case DB_UINT64:  DB_COUNTSTAT(db_uint64_##partial_token); break; \
		}                                                                    \
	} while(false)
#define DB_GREATERTHAN_SWITCH(t, v, partial_token)                                        \
	do {                                                                                  \
		switch ((t)) {                                                                    \
			case DB_INT:     DB_GREATERTHAN_COUNT((v), db_int_##partial_token);    break; \
			case DB_UINT:    DB_GREATERTHAN_COUNT((v), db_uint_##partial_token);   break; \
			case DB_STRING:  DB_GREATERTHAN_COUNT((v), db_string_##partial_token); break; \
			case DB_ISTRING: DB_GREATERTHAN_COUNT((v), db_istring_##partial_token);break; \
			case DB_INT64:   DB_GREATERTHAN_COUNT((v), db_int64_##partial_token);  break; \
			case DB_UINT64:  DB_GREATERTHAN_COUNT((v), db_uint64_##partial_token); break; \
		}                                                                                 \
	} while(false)

#else /* !defined(DB_ENABLE_STATS) */
#define DB_COUNTSTAT(token) (void)0
#define DB_GREATERTHAN_COUNT(v, token) (void)0
#define DB_COUNTSTAT_SWITCH(d, partial_token) (void)0
#define DB_GREATERTHAN_SWITCH(d, v, partial_token) (void)0
#endif /* !defined(DB_ENABLE_STATS) */

/* [Ind/Hercules] */
static struct eri *db_iterator_ers;
static struct eri *db_alloc_ers;
static struct ers_collection_t *db_ers_collection = NULL;

/*****************************************************************************\
 *  (2) Section of private functions used by the database system.            *
 *  db_rotate_left     - Rotate a tree node to the left.                     *
 *  db_rotate_right    - Rotate a tree node to the right.                    *
 *  db_rebalance       - Rebalance the tree.                                 *
 *  db_rebalance_erase - Rebalance the tree after a BLACK node was erased.   *
 *  db_is_key_null     - Returns not 0 if the key is considered NULL.        *
 *  db_dup_key         - Duplicate a key for internal use.                   *
 *  db_dup_key_free    - Free the duplicated key.                            *
 *  db_free_add        - Add a node to the free_list of a database.          *
 *  db_free_remove     - Remove a node from the free_list of a database.     *
 *  db_free_lock       - Increment the free_lock of a database.              *
 *  db_free_unlock     - Decrement the free_lock of a database.              *
 *         If it was the last lock, frees the nodes in free_list.            *
 *         NOTE: Keeps the database trees balanced.                          *
\*****************************************************************************/

/**
 * Rotate a node to the left.
 * @param node Node to be rotated
 * @param root Pointer to the root of the tree
 * @private
 * @see #db_rebalance()
 * @see #db_rebalance_erase()
 */
static void db_rotate_left(struct DBNode *node, struct DBNode **root)
{
	struct DBNode *y = node->right;

	DB_COUNTSTAT(db_rotate_left);
	// put the left of y at the right of node
	node->right = y->left;
	if (y->left)
		y->left->parent = node;
	y->parent = node->parent;
	// link y and node's parent
	if (node == *root) {
		*root = y; // node was root
	} else if (node == node->parent->left) {
		node->parent->left = y; // node was at the left
	} else {
		node->parent->right = y; // node was at the right
	}
	// put node at the left of y
	y->left = node;
	node->parent = y;
}

/**
 * Rotate a node to the right
 * @param node Node to be rotated
 * @param root Pointer to the root of the tree
 * @private
 * @see #db_rebalance()
 * @see #db_rebalance_erase()
 * @writelock
 */
static void db_rotate_right(struct DBNode *node, struct DBNode **root)
{
	struct DBNode *y = node->left;

	DB_COUNTSTAT(db_rotate_right);
	// put the right of y at the left of node
	node->left = y->right;
	if (y->right != 0)
		y->right->parent = node;
	y->parent = node->parent;
	// link y and node's parent
	if (node == *root) {
		*root = y; // node was root
	} else if (node == node->parent->right) {
		node->parent->right = y; // node was at the right
	} else {
		node->parent->left = y; // node was at the left
	}
	// put node at the right of y
	y->right = node;
	node->parent = y;
}

/**
 * Rebalance the RED-BLACK tree.
 * Called when the node and it's parent are both RED.
 * @param node Node to be rebalanced
 * @param root Pointer to the root of the tree
 * @private
 * @see #db_rotate_left()
 * @see #db_rotate_right()
 * @see #db_obj_put()
 * @writelock
 */
static void db_rebalance(struct DBNode *node, struct DBNode **root)
{
	struct DBNode *y;

	DB_COUNTSTAT(db_rebalance);
	// Restore the RED-BLACK properties
	node->color = RED;
	while (node != *root && node->parent->color == RED) {
		if (node->parent == node->parent->parent->left) {
			// If node's parent is a left, y is node's right 'uncle'
			y = node->parent->parent->right;
			if (y && y->color == RED) { // case 1
				// change the colors and move up the tree
				node->parent->color = BLACK;
				y->color = BLACK;
				node->parent->parent->color = RED;
				node = node->parent->parent;
			} else {
				if (node == node->parent->right) { // case 2
					// move up and rotate
					node = node->parent;
					db_rotate_left(node, root);
				}
				// case 3
				node->parent->color = BLACK;
				node->parent->parent->color = RED;
				db_rotate_right(node->parent->parent, root);
			}
		} else {
			// If node's parent is a right, y is node's left 'uncle'
			y = node->parent->parent->left;
			if (y && y->color == RED) { // case 1
				// change the colors and move up the tree
				node->parent->color = BLACK;
				y->color = BLACK;
				node->parent->parent->color = RED;
				node = node->parent->parent;
			} else {
				if (node == node->parent->left) { // case 2
					// move up and rotate
					node = node->parent;
					db_rotate_right(node, root);
				}
				// case 3
				node->parent->color = BLACK;
				node->parent->parent->color = RED;
				db_rotate_left(node->parent->parent, root);
			}
		}
	}
	(*root)->color = BLACK; // the root can and should always be black
}

/**
 * Erase a node from the RED-BLACK tree, keeping the tree balanced.
 * @param node Node to be erased from the tree
 * @param root Root of the tree
 * @private
 * @see #db_rotate_left()
 * @see #db_rotate_right()
 * @see #db_free_unlock()
 * @writelock
 */
static void db_rebalance_erase(struct DBNode *node, struct DBNode **root)
{
	struct DBNode *y = node;
	struct DBNode *x = NULL;
	struct DBNode *x_parent = NULL;

	DB_COUNTSTAT(db_rebalance_erase);
	// Select where to change the tree
	if (y->left == NULL) { // no left
		x = y->right;
	} else if (y->right == NULL) { // no right
		x = y->left;
	} else { // both exist, go to the leftmost node of the right sub-tree
		y = y->right;
		while (y->left != NULL)
			y = y->left;
		x = y->right;
	}

	// Remove the node from the tree
	if (y != node) { // both child existed
		// put the left of 'node' in the left of 'y'
		node->left->parent = y;
		y->left = node->left;

		// 'y' is not the direct child of 'node'
		if (y != node->right) {
			// put 'x' in the old position of 'y'
			x_parent = y->parent;
			if (x) x->parent = y->parent;
			y->parent->left = x;
			// put the right of 'node' in 'y'
			y->right = node->right;
			node->right->parent = y;
			// 'y' is a direct child of 'node'
		} else {
			x_parent = y;
		}

		// link 'y' and the parent of 'node'
		if (*root == node) {
			*root = y; // 'node' was the root
		} else if (node->parent->left == node) {
			node->parent->left = y; // 'node' was at the left
		} else {
			node->parent->right = y; // 'node' was at the right
		}
		y->parent = node->parent;
		// switch colors
		{
			enum DBNodeColor tmp = y->color;
			y->color = node->color;
			node->color = tmp;
		}
		y = node;
	} else { // one child did not exist
		// put x in node's position
		x_parent = y->parent;
		if (x) x->parent = y->parent;
		// link x and node's parent
		if (*root == node) {
			*root = x; // node was the root
		} else if (node->parent->left == node) {
			node->parent->left = x; // node was at the left
		} else {
			node->parent->right = x;  // node was at the right
		}
	}

	// Restore the RED-BLACK properties
	if (y->color != RED) {
		while (x != *root && (x == NULL || x->color == BLACK)) {
			struct DBNode *w;
			if (x == x_parent->left) {
				w = x_parent->right;
				if (w->color == RED) {
					w->color = BLACK;
					x_parent->color = RED;
					db_rotate_left(x_parent, root);
					w = x_parent->right;
				}
				if ((w->left == NULL || w->left->color == BLACK) &&
					(w->right == NULL || w->right->color == BLACK)) {
					w->color = RED;
					x = x_parent;
					x_parent = x_parent->parent;
				} else {
					if (w->right == NULL || w->right->color == BLACK) {
						if (w->left) w->left->color = BLACK;
						w->color = RED;
						db_rotate_right(w, root);
						w = x_parent->right;
					}
					w->color = x_parent->color;
					x_parent->color = BLACK;
					if (w->right) w->right->color = BLACK;
					db_rotate_left(x_parent, root);
					break;
				}
			} else {
				w = x_parent->left;
				if (w->color == RED) {
					w->color = BLACK;
					x_parent->color = RED;
					db_rotate_right(x_parent, root);
					w = x_parent->left;
				}
				if ((w->right == NULL || w->right->color == BLACK) &&
					(w->left == NULL || w->left->color == BLACK)) {
					w->color = RED;
					x = x_parent;
					x_parent = x_parent->parent;
				} else {
					if (w->left == NULL || w->left->color == BLACK) {
						if (w->right) w->right->color = BLACK;
						w->color = RED;
						db_rotate_left(w, root);
						w = x_parent->left;
					}
					w->color = x_parent->color;
					x_parent->color = BLACK;
					if (w->left) w->left->color = BLACK;
					db_rotate_right(x_parent, root);
					break;
				}
			}
		}
		if (x) x->color = BLACK;
	}
}

/**
 * Returns true if the key is considered to be NULL.
 * @param type Type of database
 * @param key Key being tested
 * @return true if the key is considered to be NULL
 * @private
 * @see #db_obj_get()
 * @see #db_obj_put()
 * @see #db_obj_remove()
 */
static bool db_is_key_null(enum DBType type, const struct DBKey_s *key)
{
	DB_COUNTSTAT(db_is_key_null);
	switch (type) {
		case DB_STRING:
		case DB_ISTRING:
			return (key->u.str == NULL);

		case DB_INT:
		case DB_UINT:
		case DB_INT64:
		case DB_UINT64:
		default: // Not a pointer
			return false;
	}
}

/**
 * Duplicate the key used in the database.
 * @param db Database the key is being used in
 * @param key Key to be duplicated
 * @param Duplicated key
 * @private
 * @see #db_free_add()
 * @see #db_free_remove()
 * @see #db_obj_put()
 * @see #db_dup_key_free()
 */
static struct DBKey_s db_dup_key(struct DBMap_impl *db, const struct DBKey_s *key)
{
	DB_COUNTSTAT(db_dup_key);
	struct DBKey_s new_key;

	switch (db->type) {
		case DB_STRING:
		case DB_ISTRING:
		{
			new_key.len = key->len;
			new_key.u.mutstr = aMalloc(key->len);
			memcpy(new_key.u.mutstr, key->u.str, key->len);
			return new_key;
		}

		case DB_INT:
		case DB_UINT:
		case DB_INT64:
		case DB_UINT64:
		default:
			new_key.len = key->len;
			new_key.u = key->u;
			return new_key;
	}
}

/**
 * Free a key duplicated by db_dup_key.
 * @param db Database the key is being used in
 * @param key Key to be freed
 * @private
 * @see #db_dup_key()
 */
static void db_dup_key_free(struct DBMap_impl *db, struct DBKey_s *key)
{
	DB_COUNTSTAT(db_dup_key_free);
	switch (db->type) {
		case DB_STRING:
		case DB_ISTRING:
			aFree(key->u.mutstr);
			return;

		case DB_INT:
		case DB_UINT:
		case DB_INT64:
		case DB_UINT64:
		default:
			return;
	}
}

/**
 * Add a node to the free_list of the database.
 * Marks the node as deleted.
 * If the key isn't duplicated, the key is duplicated and released.
 * @param db Target database
 * @param root Root of the tree from the node
 * @param node Target node
 * @private
 * @see #struct db_free
 * @see struct DBMap_impl#free_list
 * @see struct DBMap_impl#free_count
 * @see struct DBMap_impl#free_max
 * @see #db_obj_remove()
 * @see #db_free_remove()
 * @writelock
 */
static void db_free_add(struct DBMap_impl *db, struct DBNode *node, struct DBNode **root)
{
	DB_COUNTSTAT(db_free_add);
	if (db->garbage_collection.free_lock == (unsigned int)~0) {
		ShowFatalError("db_free_add: free_lock overflow\n"
				"Database allocated at %s:%d\n",
				db->alloc_file, db->alloc_line);
		exit(EXIT_FAILURE);
	}
	if (!(db->options&DB_OPT_DUP_KEY)) { // Make sure we have a key until the node is freed
		struct DBKey_s old_key;
		old_key = node->key; // shallow copy
		node->key = db_dup_key(db, &node->key);
		db->release(&old_key, node->data, DB_RELEASE_KEY);
	}
	if (db->garbage_collection.free_count == db->garbage_collection.free_max) { // No more space, expand free_list
		db->garbage_collection.free_max = (db->garbage_collection.free_max<<2) +3; // = db->free_max*4 +3
		if (db->garbage_collection.free_max <= db->garbage_collection.free_count) {
			if (db->garbage_collection.free_count == (unsigned int)~0) {
				ShowFatalError("db_free_add: free_count overflow\n"
						"Database allocated at %s:%d\n",
						db->alloc_file, db->alloc_line);
				exit(EXIT_FAILURE);
			}
			db->garbage_collection.free_max = (unsigned int)~0;
		}
		RECREATE(db->garbage_collection.free_list, struct db_free,
			db->garbage_collection.free_max);
	}
	node->deleted = 1;
	db->garbage_collection.free_list[db->garbage_collection.free_count].node = node;
	db->garbage_collection.free_list[db->garbage_collection.free_count].root = root;
	db->garbage_collection.free_count++;
	db->item_count--;
}

/**
 * Remove a node from the free_list of the database.
 * Marks the node as not deleted.
 * NOTE: Frees the duplicated key of the node.
 * @param db Target database
 * @param node Node being removed from free_list
 * @private
 * @see #struct db_free
 * @see struct DBMap_impl#free_list
 * @see struct DBMap_impl#free_count
 * @see #db_obj_put()
 * @see #db_free_add()
 * @writelock
 */
static void db_free_remove(struct DBMap_impl *db, struct DBNode *node)
{
	unsigned int i;

	DB_COUNTSTAT(db_free_remove);
	for (i = 0; i < db->garbage_collection.free_count; i++) {
		if (db->garbage_collection.free_list[i].node == node) {
			if (i < db->garbage_collection.free_count -1) // copy the last item to where the removed one was
				memcpy(&db->garbage_collection.free_list[i],
				       &db->garbage_collection.free_list[db->garbage_collection.free_count -1],
				       sizeof(struct db_free));
			db_dup_key_free(db, &node->key);
			break;
		}
	}
	node->deleted = 0;
	if (i == db->garbage_collection.free_count) {
		ShowWarning("db_free_remove: node was not found - database allocated at %s:%d\n",
			db->alloc_file, db->alloc_line);
	} else {
		db->garbage_collection.free_count--;
	}
	db->item_count++;
}

/**
 * Checks And Switches current acquired lock to WRITE_LOCK.
 * Doesn't perform any operations if the the currently acquired lock
 * is already a WRITE_LOCK.
 *
 * @return Returns true if the lock was switched
 **/
static bool db_lock_cas(struct DBMap_impl *db)
{
	if(!db->lock)
		return false;

	bool is_writer = (db->lock_tid == thread->get_tid());
	if(!is_writer) {
		rwlock->read_unlock(db->lock);
		rwlock->write_lock(db->lock);
		db->lock_tid = thread->get_tid();
		return true;
	}
	return false;
}

/**
 * Reacquires read lock if `reacquire` is true
 **/
static void db_lock_reacquire(struct DBMap_impl *db, bool reacquire)
{
	if(!reacquire || !db->lock)
		return;

	db->lock_tid = -1;
	rwlock->write_unlock(db->lock);
	rwlock->read_lock(db->lock);
}

/**
 * Increment the free_lock of the database.
 * Acquires db->lock.
 * @param db   Target database
 * @param type Type of lock to be used in most operations, operations that need
 *             more privileges will automatically acquire and release the write lock.
 * @private
 * @see struct DBMap_impl#free_lock
 * @see #db_unlock()
 */
static void db_free_lock(struct DBMap_impl *db, enum lock_type type)
{
	DB_COUNTSTAT(db_free_lock);
	if(db->garbage_collection.free_lock == (unsigned int)~0) {
		ShowFatalError("db_free_lock: free_lock overflow\n"
				"Database allocated at %s:%d\n",
				db->alloc_file, db->alloc_line);
		exit(EXIT_FAILURE);
	}
	if(db->lock) {
		if(type == READ_LOCK)
			rwlock->read_lock(db->lock);
		else {
			rwlock->write_lock(db->lock);
			Assert(db->lock_tid == -1);
			db->lock_tid = thread->get_tid();
		}
	}
	InterlockedIncrement(&db->garbage_collection.free_lock);
}

/**
 * Decrement the free_lock of the database.
 * If it was the last lock, frees the nodes in the free_list of this database.
 * Keeps the tree balanced.
 * NOTE: Frees the duplicated keys of the nodes
 * @param db Target database
 * @private
 * @see struct DBMap_impl#free_lock
 * @see #db_free_dbn()
 * @see #db_lock()
 * @lock
 */
static void db_free_unlock(struct DBMap_impl *db)
{
	unsigned int i;
	unsigned int free_lock_tmp;

	DB_COUNTSTAT(db_free_unlock);
	free_lock_tmp = InterlockedDecrement(&db->garbage_collection.free_lock);
	if (free_lock_tmp == UINT32_MAX) {
		ShowFatalError("db_free_unlock: free_lock underflow\n"
				"Database allocated at %s:%d\n",
				db->alloc_file, db->alloc_line);
		exit(EXIT_FAILURE);
	}
	if (free_lock_tmp)
		goto unlock_return; // Not last lock

	if (!db->garbage_collection.free_count)
		goto unlock_return; // No operation

	// Switch lock in use only if we have the read lock
	bool reacquire = db_lock_cas(db);

	rwlock->read_lock(db->nodes->collection_lock);
	mutex->lock(db->nodes->cache_mutex);
	for (i = 0; i < db->garbage_collection.free_count ; i++) {
		db_rebalance_erase(db->garbage_collection.free_list[i].node,
		                   db->garbage_collection.free_list[i].root);
		db_dup_key_free(db, &db->garbage_collection.free_list[i].node->key);
		DB_COUNTSTAT(db_node_free);
		ers_free(db->nodes, db->garbage_collection.free_list[i].node);
	}
	mutex->unlock(db->nodes->cache_mutex);
	rwlock->read_unlock(db->nodes->collection_lock);

	db->garbage_collection.free_count = 0;
	if(db->lock) {
		rwlock->write_unlock(db->lock);
		db->lock_tid = -1;
	}
	return;

unlock_return:
	{
		if(!db->lock)
			return;
		bool is_writer = (db->lock_tid == thread->get_tid());
		if(is_writer) {
			db->lock_tid = -1;
			rwlock->write_unlock(db->lock);
		} else
			rwlock->read_unlock(db->lock);
		return;
	}
}

/**
 * Verifies whether the database cache was hit.
 *
 * @return Cached node (when hit), otherwise NULL
 * @readlock
 **/
static struct DBNode *db_cache_is_hit(struct DBMap_impl *db, const struct DBKey_s *key)
{
	struct DBNode *tmp_cache = db->cache;
	if(tmp_cache && db->cmp(key, &tmp_cache->key) == 0) {
#if defined(DEBUG)
		if(tmp_cache->deleted) {
			ShowDebug("db_cache_is_hit: Cache contains a deleted node. Please report this!!!\n");
			return NULL;
		}
#endif
		return tmp_cache; // cache hit
	}
	return NULL;
}


/**
 * Performs recursive iteration of a DBNode tree, adding all items into the
 * provided database and then freeing the node.
 *
 * @param db Target Database.
 * @param node Node.
 * Acquires collection_lock (read) and cache_mutex
 * @private
 * @writelock
 **/
static void db_rehash_node(struct DBMap_impl *db, struct DBNode *node)
{
	struct DBMap *self = (struct DBMap *)db;
	self->put(self, node->key, node->data, NULL);

	if(node->left)
		db_rehash_node(db, node->left);
	if(node->right)
		db_rehash_node(db, node->right);

	/**
	 * The node is freed here instead of being put in a list to be freed
	 * later because otherwise the memory usage of this DBMap would double
	 * while a rehash operation was being done. Also even after freeing all
	 * the memory would continue to be allocated in the ERS.
	 **/
	rwlock->read_lock(db->nodes->collection_lock);
	mutex->lock(db->nodes->cache_mutex);
	ers_free(db->nodes, node);
	rwlock->read_unlock(db->nodes->collection_lock);
	mutex->unlock(db->nodes->cache_mutex);
}

/**
 * Reallocates <code>ht</code> with <code>new_count</code> entries and recalculates
 * all hashes in order to populate the new memory.
 * This operation is extremely expensive and should only be triggered after the
 * <code>entry_count</code> superseeds the <code>load_factor</code> threshold.
 * @param db        Target Database.
 * @param new_count New number of entries.
 * @private
 * @writelock
 **/
static bool db_rehash(struct DBMap_impl *db, size_t new_count)
{
	static bool done = false;

	DB_COUNTSTAT(db_rehash);
	DB_COUNTSTAT_PRIVATE(db, rehash);
	// Save previous state
	size_t previous_count = db->bucket_count;
	struct DBNode **ht_old = db->ht;
	enum DBOptions options = db->options;
	// Reset state
	db->ht = aCalloc(new_count, sizeof(*db->ht));
	db->bucket_count = new_count;
	db->item_count = 0;
	InterlockedExchangePointer(&db->cache, NULL);
	// Don't try to copy keys (if DB_OPT_DUP_KEY is already set they were
	// already duplicated)
	db->options &= ~DB_OPT_DUP_KEY;

	struct DBNode *node = NULL;
	/**
	 * collection_lock and cache_mutex can't be acquired before calling
	 * db_rehash_node because obj_put and rehash_node both acquire those
	 * locks.
	 * This makes this operation more expensive because there are several
	 * lock acquirals (at least two per iteration).
	 **/
	for(size_t i = 0; i < previous_count; i++) {
		node = ht_old[i];
		if(node)
			db_rehash_node(db, node);
	}

	db->options = options;
	aFree(ht_old);
	return true;
}

/**
 * Adds new entry at the next valid position.
 * This function should be called after failure to find a node.
 *
 * @param db Target database
 * @param hash Calculated hash for key via <code>db->hash%db->bucket_count</code>
 * @param c Last valid comparison <code>db->cmp</code>
 * @param parent This entry's parent
 * @return pointer to new node
 * @retval NULL Failed to create node
 * @remarks db must be locked via <code>db_free_lock</code>
 * @see db_obj_vensure
 * @see db_obj_put
 * @private
 * @writelock
 **/
struct DBNode *db_node_create(struct DBMap_impl *db, unsigned int hash, int c, struct DBNode *parent)
{
	struct DBNode *node;

	if (db->item_count == UINT32_MAX) {
		ShowError("db_obj_create: item_count overflow, aborting item insertion.\n"
				"Database allocated at %s:%d",
				db->alloc_file, db->alloc_line);
		return NULL;
	}

	DB_COUNTSTAT(db_node_alloc);

	rwlock->read_lock(db->nodes->collection_lock);
	mutex->lock(db->nodes->cache_mutex);
	node = ers_alloc(db->nodes);
	mutex->unlock(db->nodes->cache_mutex);
	rwlock->read_unlock(db->nodes->collection_lock);

	node->left = NULL;
	node->right = NULL;
	node->deleted = 0;
	db->item_count++;
	if (c == 0) { // hash entry is empty
		node->color = BLACK;
		node->parent = NULL;
		db->ht[hash] = node;
	} else {
		node->color = RED;
		if (c < 0) { // put at the left
			parent->left = node;
			node->parent = parent;
		} else { // put at the right
			parent->right = node;
			node->parent = parent;
		}
		if (parent->color == RED) // two consecutive RED nodes, must rebalance
			db_rebalance(node, &db->ht[hash]);
	}

	return node;
}

/**
 * Puts key and data in provided node
 *
 * @param db Target database
 * @param node Node to be filled
 * @param key Key that identifies the data
 * @param data Data to be put in the database
 * @writelock
 **/
void db_node_fill(struct DBMap_impl *db, struct DBNode *node, struct DBKey_s *key, struct DBData data)
{
	if (db->options&DB_OPT_DUP_KEY) {
		node->key = db_dup_key(db, key);
		if (db->options&DB_OPT_RELEASE_KEY)
			db->release(key, node->data, DB_RELEASE_KEY);
	} else {
		memcpy(&node->key, key, sizeof(*key));
	}
	node->data = data;
	if(!(db->load_factor == 0.f || db->options&DB_OPT_DISABLE_GROWTH)) {
		if((db->item_count/db->bucket_count) >= db->load_factor)
			db_rehash(db, 2*db->bucket_count + 1);
	}
}

/**
 * Gets the node of the entry identified by the key.
 * @param db         Target database
 * @param key        Key that identifies the entry
 * @param out_root   Root node (NULL when cache hit) [can be NULL]
 * @param out_node   Obtained node (NULL when no node)
 * @param ensure     If no node is found a new node is created (upon creation CAS lock)
 * @param caller Name of the function that called (for debug purposes)
 * @retval 0 Error in operation
 * @retval 1 Found node (cache hit)
 * @retval 2 Created node (lock was not switched)
 * @retval 3 Created node (lock was switched)
 * @retval 4 No errors (check *node)
 * @private
 * @writelock (ensure true)
 * @readlock  (ensure false)
 */
static int db_node_get(struct DBMap_impl *db, const struct DBKey_s *key,
	struct DBNode ***out_root, struct DBNode **out_node, bool ensure,
	const char *caller
) {
	struct DBNode *node = NULL;
	struct DBNode *parent = NULL;
	unsigned int hash;
	int c = 0;
	bool found = false;

	if(out_root)
		*out_root = NULL;
	*out_node = NULL;

	nullpo_retr(0, db);
	if(!db) {
		Assert_report(!db && "No database to get node!");
		return 0;
	}
	if(!(db->options&DB_OPT_ALLOW_NULL_KEY) && db_is_key_null(db->type, key)) {
		ShowError("db_node_get(%s): Attempted to retrieve not allowed NULL key for db\n"
			"\tAllocated at %s:%d\n", caller, db->alloc_file, db->alloc_line);
		Assert_report(!(db->options&DB_OPT_ALLOW_NULL_KEY) && db_is_key_null(db->type, key));
		return 0;
	}

	if((node = db_cache_is_hit(db, key))) {
		*out_node = node;
		return 1;
	}

	hash = db->hash(key)%db->bucket_count;
	node = db->ht[hash];
	if(out_root)
		*out_root = &db->ht[hash];
#if defined(DB_ENABLE_STATS) || defined(DB_ENABLE_PRIVATE_STATS)
	// Only try to calculate when possible insertion incoming
	if(ensure && db->ht[hash] && db->cmp(&key, &db->ht[hash]->key)
		&& !db->ht[hash]->deleted
	) {
		DB_COUNTSTAT_SWITCH(db->type, collision);
		DB_COUNTSTAT_PRIVATE(db, collision);
	}
	int bucket_fill = 0;
#endif
	while(node) {
		c = db->cmp(key, &node->key);
		if(c == 0) {
			if(!(node->deleted))
				InterlockedExchangePointer(&db->cache, node);
			break;
		}
		parent = node;
		if(c < 0)
			node = node->left;
		else
			node = node->right;
#if defined(DB_ENABLE_STATS) || defined(DB_ENABLE_PRIVATE_STATS)
		// Only try to calculate when possible insertion incoming
		if(ensure) {
			bucket_fill++;
			DB_GREATERTHAN_SWITCH(db->type, bucket_fill, bucket_peak);
			if(bucket_fill > db->stats.bucket_peak)
				db->stats.bucket_peak = bucket_fill;
		}
#endif
	}

	// Create node if necessary
	if(ensure && !node) {
		bool reacquire = db_lock_cas(db);
		node = db_node_create(db, hash, c, parent);
		if(!node) {
			ShowError("db_node_get(%s): Failed to create node for db allocated at %s:%d\n",
				caller, db->alloc_file, db->alloc_line);
			db_lock_reacquire(db, reacquire);
			return 0;
		}
		InterlockedExchangePointer(&db->cache, node);
		*out_node = node;
		return (reacquire)?3/*lock switched*/:2;
	}

	*out_node = node;
	return 4;
}

/******************************************************************************\
 *  (3) Section of protected functions used internally.                        *
 *  NOTE: the protected functions used in the database interface are in the    *
 *           next section.                                                     *
 *  db_int_cmp              - Default comparator for DB_INT databases.         *
 *  db_uint_cmp             - Default comparator for DB_UINT databases.        *
 *  db_string_cmp           - Default comparator for DB_STRING databases.      *
 *  db_istring_cmp          - Default comparator for DB_ISTRING databases.     *
 *  db_int64_cmp            - Default comparator for DB_INT64 databases.       *
 *  db_uint64_cmp           - Default comparator for DB_UINT64 databases.      *
 *  db_int_hash             - Default hasher for DB_INT databases.             *
 *  db_uint_hash            - Default hasher for DB_UINT databases.            *
 *  db_hash_murmur2         - Murmur2 32 hash function (not DBHasher).         *
 *  db_string_hash_murmur2  - Murmur2 32 hasher for DB_STRING databases.       *
 *  db_istring_hash_murmur2 - Murmur2 32 hasher for DB_ISTRING databases.      *
 *  db_string_hash_athena   - Athena hasher for DB_STRING databases.           *
 *  db_istring_hash_athena  - Athena hasher for DB_ISTRING databases.          *
 *  db_string_hash          - Default hasher for DB_STRING databases.          *
 *  db_istring_hash         - Default hasher for DB_ISTRING databases.         *
 *  db_int64_hash           - Default hasher for DB_INT64 databases.           *
 *  db_uint64_hash          - Default hasher for DB_UINT64 databases.          *
 *  db_release_nothing      - Releaser that releases nothing.                  *
 *  db_release_key          - Releaser that only releases the key.             *
 *  db_release_data         - Releaser that only releases the data.            *
 *  db_release_both         - Releaser that releases key and data.             *
\*******************************************************************************/

/**
 * Default comparator for DB_INT databases.
 * Compares key1 to key2.
 * Return 0 if equal, negative if lower and positive if higher.
 * @param key1 Key to be compared
 * @param key2 Key being compared to
 * @return 0 if equal, negative if lower and positive if higher
 * @see enum DBType#DB_INT
 * @see #DBComparator
 * @see #db_default_cmp()
 */
static int db_int_cmp(const struct DBKey_s *key1, const struct DBKey_s *key2)
{
	DB_COUNTSTAT(db_int_cmp);
	if (key1->u.i < key2->u.i) return -1;
	if (key1->u.i > key2->u.i) return 1;
	return 0;
}

/**
 * Default comparator for DB_UINT databases.
 * Compares key1 to key2.
 * Return 0 if equal, negative if lower and positive if higher.
 * @param key1 Key to be compared
 * @param key2 Key being compared to
 * @return 0 if equal, negative if lower and positive if higher
 * @see enum DBType#DB_UINT
 * @see #DBComparator
 * @see #db_default_cmp()
 */
static int db_uint_cmp(const struct DBKey_s *key1, const struct DBKey_s *key2)
{
	DB_COUNTSTAT(db_uint_cmp);
	if (key1->u.ui < key2->u.ui) return -1;
	if (key1->u.ui > key2->u.ui) return 1;
	return 0;
}

/**
 * Default comparator for DB_STRING databases.
 * Compares key1 to key2.
 * Return 0 if equal, negative if lower and positive if higher.
 * @param key1 Key to be compared
 * @param key2 Key being compared to
 * @return 0 if equal, negative if lower and positive if higher
 * @see enum DBType#DB_STRING
 * @see #DBComparator
 * @see #db_default_cmp()
 */
static int db_string_cmp(const struct DBKey_s *key1, const struct DBKey_s *key2)
{
	DB_COUNTSTAT(db_string_cmp);
	if(key1->len != key2->len)
		return key1->len - key2->len;
	return strncmp(key1->u.str, key2->u.str, key1->len); // Same length
}

/**
 * Default comparator for DB_ISTRING databases.
 * Compares key1 to key2 case insensitively.
 * Return 0 if equal, negative if lower and positive if higher.
 * @param key1 Key to be compared
 * @param key2 Key being compared to
 * @return 0 if equal, negative if lower and positive if higher
 * @see enum DBType#DB_ISTRING
 * @see #DBComparator
 * @see #db_default_cmp()
 */
static int db_istring_cmp(const struct DBKey_s *key1, const struct DBKey_s *key2)
{
	DB_COUNTSTAT(db_istring_cmp);
	if(key1->len != key2->len)
		return key1->len - key2->len;
	return strncasecmp(key1->u.str, key2->u.str, key1->len); // Same length
}

/**
 * Default comparator for DB_INT64 databases.
 * Compares key1 to key2.
 * Return 0 if equal, negative if lower and positive if higher.
 * @param key1 Key to be compared
 * @param key2 Key being compared to
 * @return 0 if equal, negative if lower and positive if higher
 * @see enum DBType#DB_INT64
 * @see #DBComparator
 * @see #db_default_cmp()
 */
static int db_int64_cmp(const struct DBKey_s *key1, const struct DBKey_s *key2)
{
	DB_COUNTSTAT(db_int64_cmp);
	if (key1->u.i64 < key2->u.i64) return -1;
	if (key1->u.i64 > key2->u.i64) return 1;
	return 0;
}

/**
 * Default comparator for DB_UINT64 databases.
 * Compares key1 to key2.
 * Return 0 if equal, negative if lower and positive if higher.
 * @param key1 Key to be compared
 * @param key2 Key being compared to
 * @return 0 if equal, negative if lower and positive if higher
 * @see enum DBType#DB_UINT64
 * @see #DBComparator
 * @see #db_default_cmp()
 */
static int db_uint64_cmp(const struct DBKey_s *key1, const struct DBKey_s *key2)
{
	DB_COUNTSTAT(db_uint64_cmp);
	if (key1->u.ui64 < key2->u.ui64) return -1;
	if (key1->u.ui64 > key2->u.ui64) return 1;
	return 0;
}


/**
 * Default hasher for DB_INT databases.
 * Returns the value of the key as an unsigned int.
 * @param key Key to be hashed
 * @return hash of the key
 * @see enum DBType#DB_INT
 * @see #DBHasher
 * @see #db_default_hash()
 */
static uint64 db_int_hash(const struct DBKey_s *key)
{
	DB_COUNTSTAT(db_int_hash);
	return key->u.i;
}

/**
 * Default hasher for DB_UINT databases.
 * Just returns the value of the key.
 * @param key Key to be hashed
 * @return hash of the key
 * @see enum DBType#DB_UINT
 * @see #DBHasher
 * @see #db_default_hash()
 */
static uint64 db_uint_hash(const struct DBKey_s *key)
{
	DB_COUNTSTAT(db_uint_hash);
	return key->u.ui;
}

/**
 * MurmurHash2
 * Character hashing function.
 * @param key Key to be hashed
 * @param len Key length
 * @return hash of the key
 * @see #DBHasher
 * @see #db_default_hash()
 * @author Austin Appleby (public domain)
 * @see github.com/aappleby/smhasher
 * @remarks This function is called by DBHasher functions and otherwise shouldn't
 * be called directly, this is the reason that it doesn't use a "standard"
 * DBHasher signature (see db_istring_hash_murmur2)
 **/
uint64 db_hash_murmur2(const char *key, int16_t len)
{
	DB_COUNTSTAT(db_string_hash);
	// 'm' and 'r' are mixing constants generated offline.
	// They're not really 'magic', they just happen to work well.
	const uint32_t m = 0x5bd1e995;
	const int r = 24;

	// Initialize the hash to a 'random' value
	uint32_t h = 1234 ^ len;
	int16_t maxlen = len;

	// Mix 4 bytes at a time into the hash
	const unsigned char * data = key;

	while(maxlen >= 4) {
		uint32_t k = *(uint32_t*)data;

		k *= m;
		k ^= k >> r;
		k *= m;

		h *= m;
		h ^= k;

		data += 4;
		maxlen -= 4;
	}

	// Handle the last few bytes of the input array
	switch(maxlen) {
		case 3: h ^= data[2] << 16;
		case 2: h ^= data[1] << 8;
		case 1: h ^= data[0];
			h *= m;
	}

	// Do a few final mixes of the hash to ensure the last few
	// bytes are well-incorporated.
	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	return h;
}

/**
 * MurmurHash2
 * String hashing function for DB_STRING databases
 * @param key Key to be hashed
 * @return hash of the key
 * @see enum DBType#DB_STRING
 * @see #DBHasher
 * @see #db_default_hash()
 **/
uint64 db_string_hash_murmur2(const struct DBKey_s *key) {
	return db_hash_murmur2(key->u.str, key->len);
}

/**
 * MurmurHash2
 * String hashing function for DB_ISTRING databases
 * @param key Key to be hashed
 * @return hash of the key
 * @see enum DBType#DB_STRING
 * @see #DBHasher
 * @see #db_default_hash()
 **/
uint64 db_istring_hash_murmur2(const struct DBKey_s *key)
{
	CREATE_BUFFER(k, char, key->len);
	for( ; *k; ++k)
		*k = TOLOWER(*k);
	uint64_t hash = db_hash_murmur2(k, key->len);
	DELETE_BUFFER(k);
	return hash;
}

/**
 * Athena hash implementation for DB_STRING databases.
 * @param key Key to be hashed
 * @return hash of the key
 * @see enum DBType#DB_STRING
 * @see #DBHasher
 * @see #db_default_hash()
 */
static uint64 db_string_hash_athena(const struct DBKey_s *key)
{
	const char *k = key->u.str;
	unsigned int hash = 0;
	unsigned short i;

	DB_COUNTSTAT(db_string_hash);

	for (i = 0; *k; ++i) {
		hash = (hash*33 + ((unsigned char)*k))^(hash>>24);
		k++;
		if (i == key->len)
			break;
	}

	return (uint64)hash;
}

/**
 * Athena hash implementation for DB_ISTRING databases.
 * @param key Key to be hashed
 * @return hash of the key
 * @see enum DBType#DB_ISTRING
 * @see #db_default_hash()
 */
static uint64 db_istring_hash_athena(const struct DBKey_s *key)
{
	const char *k = key->u.str;
	unsigned int hash = 0;
	unsigned short i;

	DB_COUNTSTAT(db_istring_hash);

	for (i = 0; *k; i++) {
		hash = (hash*33 + ((unsigned char)TOLOWER(*k)))^(hash>>24);
		k++;
		if (i == key->len)
			break;
	}

	return (uint64)hash;
}

/**
 * Default hasher for DB_INT64 databases.
 * Returns the value of the key as an unsigned int.
 * @param key Key to be hashed
 * @return hash of the key
 * @see enum DBType#DB_INT64
 * @see #DBHasher
 * @see #db_default_hash()
 */
static uint64 db_int64_hash(const struct DBKey_s *key)
{
	DB_COUNTSTAT(db_int64_hash);
	return key->u.i64;
}

/**
 * Default hasher for DB_UINT64 databases.
 * Just returns the value of the key.
 * @param key Key to be hashed
 * @return hash of the key
 * @see enum DBType#DB_UINT64
 * @see #DBHasher
 * @see #db_default_hash()
 */
static uint64 db_uint64_hash(const struct DBKey_s *key)
{
	DB_COUNTSTAT(db_uint64_hash);
	return key->u.i64;
}

/**
 * Releaser that releases nothing.
 * @param key Key of the database entry
 * @param data Data of the database entry
 * @param which What is being requested to be released
 * @protected
 * @see #DBReleaser
 * @see #db_default_releaser()
 */
static void db_release_nothing(struct DBKey_s *key, struct DBData data, enum DBReleaseOption which)
{
	(void)key;(void)data;(void)which;//not used
	DB_COUNTSTAT(db_release_nothing);
}

/**
 * Releaser that only releases the key.
 * @param key Key of the database entry
 * @param data Data of the database entry
 * @param which What is being requested to be released
 * @protected
 * @see #DBReleaser
 * @see #db_default_release()
 */
static void db_release_key(struct DBKey_s *key, struct DBData data, enum DBReleaseOption which)
{
	(void)data;//not used
	DB_COUNTSTAT(db_release_key);
	if (which&DB_RELEASE_KEY)
		aFree(key->u.mutstr); // FIXME: Ensure this is the right db type.
}

/**
 * Releaser that only releases the data.
 * @param key Key of the database entry
 * @param data Data of the database entry
 * @param which What is being requested to be released
 * @protected
 * @see struct DBData
 * @see enum DBReleaseOption
 * @see #DBReleaser
 * @see #db_default_release()
 */
static void db_release_data(struct DBKey_s *key, struct DBData data, enum DBReleaseOption which)
{
	(void)key;//not used
	DB_COUNTSTAT(db_release_data);
	if (which&DB_RELEASE_DATA && data.type == DB_DATA_PTR) {
		aFree(data.u.ptr);
		data.u.ptr = NULL;
	}
}

/**
 * Releaser that releases both key and data.
 * @param key Key of the database entry
 * @param data Data of the database entry
 * @param which What is being requested to be released
 * @protected
 * @see struct DBKey_s
 * @see struct DBData
 * @see enum DBReleaseOption
 * @see #DBReleaser
 * @see #db_default_release()
 */
static void db_release_both(struct DBKey_s *key, struct DBData data, enum DBReleaseOption which)
{
	DB_COUNTSTAT(db_release_both);
	if (which&DB_RELEASE_KEY)
		aFree(key->u.mutstr); // FIXME: Ensure this is the right db type.
	if (which&DB_RELEASE_DATA && data.type == DB_DATA_PTR) {
		aFree(data.u.ptr);
		data.u.ptr = NULL;
	}
}

/*****************************************************************************\
 *  (4) Section with protected functions used in the interface of the        *
 *  database and interface of the iterator. Before calling any of these      *
 *  functions the db should be locked.                                       *
 *  dbit_obj_first   - Fetches the first entry from the database.            *
 *  dbit_obj_last    - Fetches the last entry from the database.             *
 *  dbit_obj_next    - Fetches the next entry from the database.             *
 *  dbit_obj_prev    - Fetches the previous entry from the database.         *
 *  dbit_obj_exists  - Returns true if the current entry exists.             *
 *  dbit_obj_remove  - Remove the current entry from the database.           *
 *  dbit_obj_destroy - Destroys the iterator, unlocking the database and     *
 *           freeing used memory.                                            *
 *  db_obj_iterator - Return a new database iterator.                        *
 *  db_set_release  - Sets a new release function.                           *
 *  db_set_hash     - Sets a new hash function.                              *
 *  db_obj_exists   - Checks if an entry exists.                             *
 *  db_obj_get      - Get the data identified by the key.                    *
 *  db_obj_vgetall  - Get the data of the matched entries.                   *
 *  db_obj_getall   - Get the data of the matched entries.                   *
 *  db_obj_vensure  - Get the data identified by the key, creating if it     *
 *           doesn't exist yet.                                              *
 *  db_obj_ensure   - Get the data identified by the key, creating if it     *
 *           doesn't exist yet.                                              *
 *  db_obj_put      - Put data identified by the key in the database.        *
 *  db_obj_remove   - Remove an entry from the database.                     *
 *  db_obj_vforeach - Apply a function to every entry in the database.       *
 *  db_obj_foreach  - Apply a function to every entry in the database.       *
 *  db_obj_vclear   - Remove all entries from the database.                  *
 *  db_obj_clear    - Remove all entries from the database.                  *
 *  db_obj_vdestroy - Destroy the database, freeing all the used memory.     *
 *  db_obj_destroy  - Destroy the database, freeing all the used memory.     *
 *  db_obj_size     - Return the size of the database.                       *
 *  db_obj_type     - Return the type of the database.                       *
 *  db_obj_options  - Return the options of the database.                    *
 *  db_obj_lock     - Lock database to read.                                 *
 *  db_obj_unlock   - Unlocks database.                                      *
\*****************************************************************************/

/**
 * Fetches the first entry in the database.
 * Returns the data of the entry.
 * Puts the key in out_key, if out_key is not NULL.
 * @param self Iterator
 * @param out_key Key of the entry
 * @return Data of the entry
 * @protected
 * @see struct DBIterator#first()
 * @readlock
 */
static struct DBData *dbit_obj_first(struct DBIterator *self, struct DBKey_s *out_key)
{
	struct DBIterator_impl *it = (struct DBIterator_impl *)self;

	DB_COUNTSTAT(dbit_first);
	// position before the first entry
	it->ht_index = -1;
	it->node = NULL;
	// get next entry
	return self->next(self, out_key);
}

/**
 * Fetches the last entry in the database.
 * Returns the data of the entry.
 * Puts the key in out_key, if out_key is not NULL.
 * @param self Iterator
 * @param out_key Key of the entry
 * @return Data of the entry
 * @protected
 * @see struct DBIterator#last()
 * @readlock
 */
static struct DBData *dbit_obj_last(struct DBIterator *self, struct DBKey_s *out_key)
{
	struct DBIterator_impl *it = (struct DBIterator_impl *)self;

	DB_COUNTSTAT(dbit_last);
	// position after the last entry
	it->ht_index = it->db->bucket_count;
	it->node = NULL;
	// get previous entry
	return self->prev(self, out_key);
}

/**
 * Fetches the next entry in the database.
 * Returns the data of the entry.
 * Puts the key in out_key, if out_key is not NULL.
 * @param self Iterator
 * @param out_key Key of the entry
 * @return Data of the entry
 * @protected
 * @see struct DBIterator#next()
 * @readlock
 */
static struct DBData *dbit_obj_next(struct DBIterator *self, struct DBKey_s *out_key)
{
	struct DBIterator_impl *it = (struct DBIterator_impl *)self;
	struct DBNode *node;
	struct DBNode *parent;
	struct DBNode fake;

	DB_COUNTSTAT(dbit_next);
	if( it->ht_index < 0 )
	{// get first node
		it->ht_index = 0;
		it->node = NULL;
	}
	node = it->node;
	memset(&fake, 0, sizeof(fake));
	for( ; it->ht_index < it->db->bucket_count; ++(it->ht_index) )
	{
		// Iterate in the order: left tree, current node, right tree
		if( node == NULL )
		{// prepare initial node of this hash
			node = it->db->ht[it->ht_index];
			if( node == NULL )
				continue;// next hash
			fake.right = node;
			node = &fake;
		}

		while( node )
		{// next node
			if( node->right )
			{// continue in the right subtree
				node = node->right;
				while( node->left )
					node = node->left;// get leftmost node
			}
			else
			{// continue to the next parent (recursive)
				parent = node->parent;
				while( parent )
				{
					if( parent->right != node )
						break;
					node = parent;
					parent = node->parent;
				}
				if( parent == NULL )
				{// next hash
					node = NULL;
					break;
				}
				node = parent;
			}

			if( !node->deleted )
			{// found next entry
				it->node = node;
				if( out_key )
					memcpy(out_key, &node->key, sizeof(*out_key));
				return &node->data;
			}
		}
	}
	it->node = NULL;
	return NULL;// not found
}

/**
 * Fetches the previous entry in the database.
 * Returns the data of the entry.
 * Puts the key in out_key, if out_key is not NULL.
 * @param self Iterator
 * @param out_key Key of the entry
 * @return Data of the entry
 * @protected
 * @see struct DBIterator#prev()
 * @readlock
 */
static struct DBData *dbit_obj_prev(struct DBIterator *self, struct DBKey_s *out_key)
{
	struct DBIterator_impl *it = (struct DBIterator_impl *)self;
	struct DBNode *node;
	struct DBNode *parent;
	struct DBNode fake;

	DB_COUNTSTAT(dbit_prev);
	if( it->ht_index >= it->db->bucket_count )
	{// get last node
		it->ht_index = it->db->bucket_count-1;
		it->node = NULL;
	}
	node = it->node;
	memset(&fake, 0, sizeof(fake));
	for( ; it->ht_index >= 0; --(it->ht_index) )
	{
		// Iterate in the order: right tree, current node, left tree
		if( node == NULL )
		{// prepare initial node of this hash
			node = it->db->ht[it->ht_index];
			if( node == NULL )
				continue;// next hash
			fake.left = node;
			node = &fake;
		}

		while( node )
		{// next node
			if( node->left )
			{// continue in the left subtree
				node = node->left;
				while( node->right )
					node = node->right;// get rightmost node
			}
			else
			{// continue to the next parent (recursive)
				parent = node->parent;
				while( parent )
				{
					if( parent->left != node )
						break;
					node = parent;
					parent = node->parent;
				}
				if( parent == NULL )
				{// next hash
					node = NULL;
					break;
				}
				node = parent;
			}

			if( !node->deleted )
			{// found previous entry
				it->node = node;
				if( out_key )
					memcpy(out_key, &node->key, sizeof(*out_key));
				return &node->data;
			}
		}
	}
	it->node = NULL;
	return NULL;// not found
}

/**
 * Returns true if the fetched entry exists.
 * The databases entries might have NULL data, so use this to to test if
 * the iterator is done.
 * @param self Iterator
 * @return true if the entry exists
 * @protected
 * @see struct DBIterator#exists()
 * @readlock
 */
static bool dbit_obj_exists(struct DBIterator *self)
{
	struct DBIterator_impl *it = (struct DBIterator_impl *)self;

	DB_COUNTSTAT(dbit_exists);
	return (it->node && !it->node->deleted);
}

/**
 * Removes the current entry from the database.
 *
 * NOTE: struct DBIterator#exists() will return false until another entry is
 * fetched.
 *
 * Puts data of the removed entry in out_data, if out_data is not NULL (unless data has been released)
 * @param self Iterator
 * @param out_data Data of the removed entry.
 * @return 1 if entry was removed, 0 otherwise
 * @protected
 * @see struct DBMap#remove()
 * @see struct DBIterator#remove()
 * @writelock
 */
static int dbit_obj_remove(struct DBIterator *self, struct DBData *out_data)
{
	struct DBIterator_impl *it = (struct DBIterator_impl *)self;
	struct DBNode *node;
	int retval = 0;

	DB_COUNTSTAT(dbit_remove);
	node = it->node;
	if( node && !node->deleted )
	{
		struct DBMap_impl *db = it->db;
		bool reacquire = db_lock_cas(db);
		InterlockedExchangePointer(&db->cache, NULL);
		db->release(&node->key, node->data, DB_RELEASE_DATA);
		if( out_data )
			memcpy(out_data, &node->data, sizeof(struct DBData));
		retval = 1;
		db_free_add(db, node, &db->ht[it->ht_index]);
		db_lock_reacquire(db, reacquire);
	}
	return retval;
}

/**
 * Destroys this iterator and unlocks the database.
 * @param self Iterator
 * @protected
 * @readlock
 */
static void dbit_obj_destroy(struct DBIterator *self)
{
	struct DBIterator_impl *it = (struct DBIterator_impl *)self;

	DB_COUNTSTAT(dbit_destroy);
	// free iterator
	rwlock->read_lock(db_iterator_ers->collection_lock);

	mutex->lock(db_iterator_ers->cache_mutex);
	ers_free(db_iterator_ers,self);
	mutex->unlock(db_iterator_ers->cache_mutex);

	rwlock->read_unlock(db_iterator_ers->collection_lock);
}

/**
 * Returns a new iterator for this database.
 * The iterator keeps the database locked until it is destroyed.
 * The database will keep functioning normally but will only free internal
 * memory when unlocked, so destroy the iterator as soon as possible.
 * @param self Database
 * @return New iterator
 * @protected
 * @readlock
 */
static struct DBIterator *db_obj_iterator(struct DBMap *self)
{
	struct DBMap_impl *db = (struct DBMap_impl *)self;
	struct DBIterator_impl *it;

	DB_COUNTSTAT(db_iterator);

	rwlock->read_lock(db_iterator_ers->collection_lock);

	mutex->lock(db_iterator_ers->cache_mutex);
	it = ers_alloc(db_iterator_ers);
	mutex->unlock(db_iterator_ers->cache_mutex);

	rwlock->read_unlock(db_iterator_ers->collection_lock);

	/* Interface of the iterator **/
	it->vtable.first   = dbit_obj_first;
	it->vtable.last    = dbit_obj_last;
	it->vtable.next    = dbit_obj_next;
	it->vtable.prev    = dbit_obj_prev;
	it->vtable.exists  = dbit_obj_exists;
	it->vtable.remove  = dbit_obj_remove;
	it->vtable.destroy = dbit_obj_destroy;
	/* Initial state (before the first entry) */
	it->db = db;
	it->ht_index = -1;
	it->node = NULL;

	return &it->vtable;
}

/**
 * Sets a new releasal function for provided table
 * @writelock
 **/
void db_set_release(struct DBMap *self, DBReleaser new_release)
{
	struct DBMap_impl *db = (struct DBMap_impl *)self;
	bool reacquire = db_lock_cas(db);
	db->release = new_release;
	db_lock_reacquire(db, reacquire);
}

/**
 * Sets a new hashing function for provided table
 * @return False if there are already any entries in the table.
 * @writelock
 **/
static bool db_set_hash(struct DBMap *self, DBHasher new_hash)
{
	struct DBMap_impl *db = (struct DBMap_impl *)self;
	if(db->item_count) {
		ShowWarning("db_set_hash: Attempted to change hashing function for db allocated at %s:%d\n",
			db->alloc_file, db->alloc_line);
		return false;
	}
	bool reacquire = db_lock_cas(db);
	db->hash = new_hash;
	db_lock_reacquire(db, reacquire);
	return true;
}

/**
 * Returns true if the entry exists.
 * @param self Interface of the database
 * @param key Key that identifies the entry
 * @return true is the entry exists
 * @protected
 * @see struct DBMap#exists()
 * @readlock
 */
static bool db_obj_exists(struct DBMap *self, const struct DBKey_s key)
{
	struct DBMap_impl *db = (struct DBMap_impl *)self;
	struct DBNode *node = NULL;

	DB_COUNTSTAT(db_exists);
	if(!db_node_get(db, &key, NULL, &node, false, "db_obj_exists"))
		return false;

	return (node != NULL);
}

/**
 * Get the data of the entry identified by the key.
 * @param self Interface of the database
 * @param key Key that identifies the entry
 * @return Data of the entry or NULL if not found
 * @protected
 * @see struct DBMap#get()
 * @readlock
 */
static struct DBData *db_obj_get(struct DBMap *self, const struct DBKey_s key)
{
	struct DBMap_impl *db = (struct DBMap_impl *)self;
	struct DBNode *node = NULL;
	struct DBData *data = NULL;

	DB_COUNTSTAT(db_get);
	if(!db_node_get(db, &key, NULL, &node, false, "db_obj_get"))
		return NULL;

	return (node)?&node->data:NULL;
}

/**
 * Get the data of the entries matched by <code>match</code>.
 * It puts a maximum of <code>max</code> entries into <code>buf</code>.
 * If <code>buf</code> is NULL, it only counts the matches.
 * Returns the number of entries that matched.
 * NOTE: if the value returned is greater than <code>max</code>, only the
 * first <code>max</code> entries found are put into the buffer.
 * @param self Interface of the database
 * @param buf Buffer to put the data of the matched entries
 * @param max Maximum number of data entries to be put into buf
 * @param match Function that matches the database entries
 * @param ... Extra arguments for match
 * @return The number of entries that matched
 * @protected
 * @see struct DBMap#vgetall()
 * @readlock
 */
static unsigned int db_obj_vgetall(struct DBMap *self, struct DBData **buf, unsigned int max, DBMatcher match, va_list args)
{
	struct DBMap_impl *db = (struct DBMap_impl *)self;
	unsigned int i;
	struct DBNode *node;
	struct DBNode *parent;
	unsigned int ret = 0;

	DB_COUNTSTAT(db_vgetall);
	nullpo_retr(0, db);
	nullpo_retr(0, match);

	for (i = 0; i < db->bucket_count; i++) {
		// Match in the order: current node, left tree, right tree
		node = db->ht[i];
		while (node) {

			if (!(node->deleted)) {
				va_list argscopy;
				va_copy(argscopy, args);
				if (match(&node->key, node->data, argscopy) == 0) {
					if (buf && ret < max)
						buf[ret] = &node->data;
					ret++;
				}
				va_end(argscopy);
			}

			if (node->left) {
				node = node->left;
				continue;
			}

			if (node->right) {
				node = node->right;
				continue;
			}

			while (node) {
				parent = node->parent;
				if (parent && parent->right && parent->left == node) {
					node = parent->right;
					break;
				}
				node = parent;
			}

		}
	}
	return ret;
}

/**
 * Just calls struct DBMap#vgetall().
 *
 * Get the data of the entries matched by <code>match</code>.
 * It puts a maximum of <code>max</code> entries into <code>buf</code>.
 * If <code>buf</code> is NULL, it only counts the matches.
 * Returns the number of entries that matched.
 * NOTE: if the value returned is greater than <code>max</code>, only the
 * first <code>max</code> entries found are put into the buffer.
 * @param self Interface of the database
 * @param buf Buffer to put the data of the matched entries
 * @param max Maximum number of data entries to be put into buf
 * @param match Function that matches the database entries
 * @param ... Extra arguments for match
 * @return The number of entries that matched
 * @protected
 * @see struct DBMap#vgetall()
 * @see struct DBMap#getall()
 * @readlock
 */
static unsigned int db_obj_getall(struct DBMap *self, struct DBData **buf, unsigned int max, DBMatcher match, ...)
{
	va_list args;
	unsigned int ret;

	DB_COUNTSTAT(db_getall);
	nullpo_retr(0, self);

	va_start(args, match);
	ret = self->vgetall(self, buf, max, match, args);
	va_end(args);
	return ret;
}

/**
 * Gets the data of the entry identified by the key.
 * If the entry does not exist, an entry is added with the data returned by
 * <code>create</code>.
 * @param self Interface of the database
 * @param key Key that identifies the entry
 * @param create Function used to create the data if the entry doesn't exist
 * @param args Extra arguments for create
 * @return Data of the entry
 * @protected
 * @see struct DBMap#vensure()
 * @writelock
 */
static struct DBData *db_obj_vensure(struct DBMap *self, struct DBKey_s key, DBCreateData create, va_list args)
{
	struct DBMap_impl *db = (struct DBMap_impl *)self;
	struct DBNode *node = NULL;

	DB_COUNTSTAT(db_vensure);
	nullpo_retr(NULL, db);
	if(create == NULL) {
		ShowError("db_ensure: Create function is NULL for db allocated at %s:%d\n",
			db->alloc_file, db->alloc_line);
		return NULL; // nullpo candidate
	}

	int retval = db_node_get(db, &key, NULL, &node, true, "db_obj_vensure");
	switch(retval) {
		case 0: // Failed to find because there was an error
			return NULL;
		case 1: // Cache hit
		case 4: // Node found
			Assert(node); // Always true db_node_get has `ensure` set to true
			return &node->data;
		case 2: // Created node (lock was not switched)
		case 3: // Created node (lock was switched)
		{
			va_list argscopy;
			va_copy(argscopy, args);
			db_node_fill(db, node, &key, create(&key, argscopy));
			va_end(argscopy);
			db_lock_reacquire(db, (retval == 3)/*lock was switched*/);
			return &node->data;
		}
		default:
			ShowError("db_ensure: Unknown get_node (%d) for db allocated at %s:%d\n",
				retval, db->alloc_file, db->alloc_line);
			return NULL;
	}
	return NULL;
}

/**
 * Just calls struct DBMap#vensure().
 *
 * Get the data of the entry identified by the key.
 * If the entry does not exist, an entry is added with the data returned by
 * <code>create</code>.
 * @param self Interface of the database
 * @param key Key that identifies the entry
 * @param create Function used to create the data if the entry doesn't exist
 * @param ... Extra arguments for create
 * @return Data of the entry
 * @protected
 * @see struct DBMap#vensure()
 * @see struct DBMap#ensure()
 * @writelock
 */
static struct DBData *db_obj_ensure(struct DBMap *self, struct DBKey_s key, DBCreateData create, ...)
{
	va_list args;
	struct DBData *ret = NULL;

	DB_COUNTSTAT(db_ensure);
	if (self == NULL) return NULL; // nullpo candidate

	va_start(args, create);
	ret = self->vensure(self, key, create, args);
	va_end(args);
	return ret;
}

/**
 * Put the data identified by the key in the database.
 * Puts the previous data in out_data, if out_data is not NULL. (unless data has been released)
 * NOTE: Uses the new key, the old one is released.
 * @param self Interface of the database
 * @param key Key that identifies the data
 * @param data Data to be put in the database
 * @param out_data Previous data if the entry exists
 * @return 1 if if the entry already exists, 0 otherwise
 * @protected
 * @see #db_malloc_dbn(void)
 * @see struct DBMap#put()
 * @writelock
 */
static int db_obj_put(struct DBMap *self, struct DBKey_s key, struct DBData data, struct DBData *out_data)
{
	struct DBMap_impl *db = (struct DBMap_impl *)self;
	struct DBNode *node = NULL;

	DB_COUNTSTAT(db_put);
	nullpo_retr(0, db);
	if(!(db->options&DB_OPT_ALLOW_NULL_KEY) && db_is_key_null(db->type, &key)) {
		ShowError("db_put: Attempted to use non-allowed NULL key for db allocated at %s:%d\n",
			db->alloc_file, db->alloc_line);
		return 0; // nullpo candidate
	}
	if(!(db->options&DB_OPT_ALLOW_NULL_DATA) && (data.type == DB_DATA_PTR && data.u.ptr == NULL)) {
		ShowError("db_put: Attempted to use non-allowed NULL data for db allocated at %s:%d\n",
			db->alloc_file, db->alloc_line);
		return 0; // nullpo candidate
	}
	if((db->type == DB_STRING || db->type == DB_ISTRING) && !key.len) {
		ShowWarning("db_put: Attempted to store key (%s) with no length for "
			"db allocated at %s:%d\n Calculating length.",
			key.u.str, db->alloc_file, db->alloc_line);
		size_t key_len = strlen(key.u.str);
		key.len = (int16_t)cap_value(key_len, 0, INT16_MAX);
	}
	if(key.len > db->maxlen) {
		ShowWarning("db_put: Attempted to store key with len (%d) greater than "
			"maxlen (%d) for db allocated at %s:%d\n Truncating key.",
			key.len, db->maxlen, db->alloc_file, db->alloc_line);
		key.len = db->maxlen;
	}

	int retval = db_node_get(db, &key, NULL, &node, true, "db_obj_put");
	if(retval == 0 || !node) // node should be always set db_node_get `ensure` is true
		return 0;

	// Node already in database, release
	if(retval != 2 && retval != 3) {
		if(node->deleted) {
			db_free_remove(db, node);
		} else {
			db->release(&node->key, node->data, DB_RELEASE_BOTH);
			if(out_data)
				memcpy(out_data, &node->data, sizeof(*out_data));
		}
	}
	Assert(!db->lock || (db->lock && db->lock_tid != -1));
	db_node_fill(db, node, &key, data);
	db_lock_reacquire(db, (retval == 3)/*lock was switched*/);
	return (retval == 2 || retval == 3)?0:1/*entry already exists*/;
}

/**
 * Remove an entry from the database.
 * Puts the previous data in out_data, if out_data is not NULL. (unless data has been released)
 * NOTE: The key (of the database) is released in #db_free_add().
 * @param self Interface of the database
 * @param key Key that identifies the entry
 * @param out_data Previous data if the entry exists
 * @return 1 if if the entry already exists, 0 otherwise
 * @protected
 * @see #db_free_add()
 * @see struct DBMap#remove()
 * @writelock
 */
static int db_obj_remove(struct DBMap *self, const struct DBKey_s key, struct DBData *out_data)
{
	struct DBMap_impl *db = (struct DBMap_impl *)self;
	struct DBNode *node = NULL;
	struct DBNode **root = NULL;

	DB_COUNTSTAT(db_remove);
	nullpo_retr(0, db);

	int retval = db_node_get(db, &key, NULL, &node, false, "db_obj_remove");
	if(!retval || !node)
		return 0;
	Assert(retval != 2 && retval != 4); // Node can't be created on obj_remove

	bool reacquire = db_lock_cas(db);
	if(!(node->deleted)) {
		if(retval == 1) // Cache hit
			InterlockedExchangePointer(&db->cache, NULL);
		db->release(&node->key, node->data, DB_RELEASE_DATA);
		if(out_data)
			memcpy(out_data, &node->data, sizeof(*out_data));
		if(!root) // Got node from cache
			root = &db->ht[db->hash(&key)%db->bucket_count];
		db_free_add(db, node, root);
	}
	db_lock_reacquire(db, reacquire);
	return 1;
}

/**
 * Apply <code>func</code> to every entry in the database.
 * Returns the sum of values returned by func.
 * @param self Interface of the database
 * @param func Function to be applied
 * @param args Extra arguments for func
 * @return Sum of the values returned by func
 * @protected
 * @see struct DBMap#vforeach()
 * @writelock
 */
static int db_obj_vforeach(struct DBMap *self, DBApply func, va_list args)
{
	struct DBMap_impl *db = (struct DBMap_impl *)self;
	unsigned int i;
	int sum = 0;
	struct DBNode *node;
	struct DBNode *parent;

	DB_COUNTSTAT(db_vforeach);
	nullpo_retr(0, db);
	if(func == NULL) {
		ShowError("db_foreach: Passed function is NULL for db allocated at %s:%d\n",
			db->alloc_file, db->alloc_line);
		return 0; // nullpo candidate
	}

	bool reacquire = db_lock_cas(db);
	for (i = 0; i < db->bucket_count; i++) {
		// Apply func in the order: current node, left node, right node
		node = db->ht[i];
		while (node) {
			if (!(node->deleted)) {
				va_list argscopy;
				va_copy(argscopy, args);
				sum += func(&node->key, &node->data, argscopy);
				va_end(argscopy);
			}
			if (node->left) {
				node = node->left;
				continue;
			}
			if (node->right) {
				node = node->right;
				continue;
			}
			while (node) {
				parent = node->parent;
				if (parent && parent->right && parent->left == node) {
					node = parent->right;
					break;
				}
				node = parent;
			}
		}
	}
	db_lock_reacquire(db, reacquire);
	return sum;
}

/**
 * Just calls struct DBMap#vforeach().
 *
 * Apply <code>func</code> to every entry in the database.
 * Returns the sum of values returned by func.
 * @param self Interface of the database
 * @param func Function to be applied
 * @param ... Extra arguments for func
 * @return Sum of the values returned by func
 * @protected
 * @see struct DBMap#vforeach()
 * @see struct DBMap#foreach()
 * @writelock
 */
static int db_obj_foreach(struct DBMap *self, DBApply func, ...)
{
	va_list args;
	int ret;

	DB_COUNTSTAT(db_foreach);
	nullpo_retr(0, self);

	va_start(args, func);
	ret = self->vforeach(self, func, args);
	va_end(args);
	return ret;
}

/**
 * Removes all entries from the database.
 * Before deleting an entry, func is applied to it.
 * Releases the key and the data.
 * Returns the sum of values returned by func, if it exists.
 * @param self Interface of the database
 * @param func Function to be applied to every entry before deleting
 * @param args Extra arguments for func
 * @return Sum of values returned by func
 * @protected
 * @see struct DBMap#vclear()
 * @writelock
 */
static int db_obj_vclear(struct DBMap *self, DBApply func, va_list args)
{
	struct DBMap_impl *db = (struct DBMap_impl *)self;
	int sum = 0;
	unsigned int i;
	struct DBNode *node;
	struct DBNode *parent;

	DB_COUNTSTAT(db_vclear);
	nullpo_retr(0, db);

	bool reacquire = db_lock_cas(db);
	InterlockedExchangePointer(&db->cache, NULL);

	rwlock->read_lock(db->nodes->collection_lock);
	mutex->lock(db->nodes->cache_mutex);
	for (i = 0; i < db->bucket_count; i++) {
		// Apply the func and delete in the order: left tree, right tree, current node
		node = db->ht[i];
		db->ht[i] = NULL;
		while (node) {
			parent = node->parent;
			if (node->left) {
				node = node->left;
				continue;
			}
			if (node->right) {
				node = node->right;
				continue;
			}
			if (node->deleted) {
				db_dup_key_free(db, &node->key);
			} else {
				if (func)
				{
					va_list argscopy;
					va_copy(argscopy, args);
					sum += func(&node->key, &node->data, argscopy);
					va_end(argscopy);
				}
				db->release(&node->key, node->data, DB_RELEASE_BOTH);
				node->deleted = 1;
			}
			DB_COUNTSTAT(db_node_free);
			if (parent) {
				if (parent->left == node)
					parent->left = NULL;
				else
					parent->right = NULL;
			}
			ers_free(db->nodes, node);
			node = parent;
		}
		db->ht[i] = NULL;
	}
	mutex->unlock(db->nodes->cache_mutex);
	rwlock->read_unlock(db->nodes->collection_lock);

	db->garbage_collection.free_count = 0;
	db->item_count = 0;
	db_lock_reacquire(db, reacquire);
	return sum;
}

/**
 * Just calls struct DBMap#vclear().
 *
 * Removes all entries from the database.
 * Before deleting an entry, func is applied to it.
 * Releases the key and the data.
 * Returns the sum of values returned by func, if it exists.
 * NOTE: This locks the database globally. Any attempt to insert or remove
 * a database entry will give an error and be aborted (except for clearing).
 * @param self Interface of the database
 * @param func Function to be applied to every entry before deleting
 * @param ... Extra arguments for func
 * @return Sum of values returned by func
 * @protected
 * @see struct DBMap#vclear()
 * @see struct DBMap#clear()
 * @writelock
 */
static int db_obj_clear(struct DBMap *self, DBApply func, ...)
{
	va_list args;
	int ret;

	DB_COUNTSTAT(db_clear);
	nullpo_retr(0, self);

	va_start(args, func);
	ret = self->vclear(self, func, args);
	va_end(args);
	return ret;
}

/**
 * Finalize the database, freeing all the memory it uses.
 * Before deleting an entry, func is applied to it.
 * Returns the sum of values returned by func, if it exists.
 * NOTE: This locks the database globally. Any attempt to insert or remove
 * a database entry will give an error and be aborted (except for clearing).
 * @param self Interface of the database
 * @param func Function to be applied to every entry before deleting
 * @param args Extra arguments for func
 * @return Sum of values returned by func
 * @protected
 * @see struct DBMap#vdestroy()
 * @writelock
 * @remarks Unlocks database upon destruction.
 */
static int db_obj_vdestroy(struct DBMap *self, DBApply func, va_list args)
{
	struct DBMap_impl *db = (struct DBMap_impl *)self;
	int sum;

	DB_COUNTSTAT(db_vdestroy);
	nullpo_retr(0, db);

	db_lock_cas(db);
	int remaining_lock = InterlockedExchange(&db->garbage_collection.free_lock, 1);
	if(remaining_lock != 1) // The database must be locked so it can be destroyed
		ShowWarning("db_vdestroy: Database is still in use, %u lock(s) left. Continuing database destruction.\n"
				"Database allocated at %s:%d\n",
				remaining_lock-1, db->alloc_file, db->alloc_line);

	DB_COUNTSTAT_SWITCH(db->type, destroy);

	sum = self->vclear(self, func, args);
	aFree(db->garbage_collection.free_list);
	db->garbage_collection.free_list = NULL;
	db->garbage_collection.free_max = 0;

	db_free_unlock(db);
	if(db->lock)
		rwlock->destroy(db->lock);

	struct rwlock_data *collection_lock = db->nodes->collection_lock;
	rwlock->write_lock(collection_lock);
	ers_destroy(db->nodes);
	rwlock->write_unlock(collection_lock);

	rwlock->read_lock(db_alloc_ers->collection_lock);
	mutex->lock(db_alloc_ers->cache_mutex);
	ers_free(db_alloc_ers, db);
	mutex->unlock(db_alloc_ers->cache_mutex);
	rwlock->read_unlock(db_alloc_ers->collection_lock);
	aFree(db->ht);

	return sum;
}

/**
 * Just calls struct DBMap#db_vdestroy().
 * Finalize the database, feeing all the memory it uses.
 * Before deleting an entry, func is applied to it.
 * Releases the key and the data.
 * Returns the sum of values returned by func, if it exists.
 * NOTE: This locks the database globally. Any attempt to insert or remove
 * a database entry will give an error and be aborted.
 * @param self Database
 * @param func Function to be applied to every entry before deleting
 * @param ... Extra arguments for func
 * @return Sum of values returned by func
 * @protected
 * @see struct DBMap#vdestroy()
 * @see struct DBMap#destroy()
 * @writelock
 * @remarks Unlocks database upon destruction.
 */
static int db_obj_destroy(struct DBMap *self, DBApply func, ...)
{
	va_list args;
	int ret;

	DB_COUNTSTAT(db_destroy);
	nullpo_retr(0, self);

	va_start(args, func);
	ret = self->vdestroy(self, func, args);
	va_end(args);
	return ret;
}

/**
 * Return the size of the database (number of items in the database).
 * @param self Interface of the database
 * @return Size of the database
 * @protected
 * @see struct DBMap_impl#item_count
 * @see struct DBMap#size()
 * @readlock
 */
static unsigned int db_obj_size(struct DBMap *self)
{
	struct DBMap_impl *db = (struct DBMap_impl *)self;

	DB_COUNTSTAT(db_size);
	nullpo_retr(0, db);

	return db->item_count;
}

/**
 * Return the type of database.
 * @param self Interface of the database
 * @return Type of the database
 * @protected
 * @see struct DBMap_impl#type
 * @see struct DBMap#type()
 * @readlock
 */
static enum DBType db_obj_type(struct DBMap *self)
{
	struct DBMap_impl *db = (struct DBMap_impl *)self;

	DB_COUNTSTAT(db_type);
	nullpo_retr(DB_ERROR, db);

	return db->type;
}

/**
 * Return the options of the database.
 * @param self Interface of the database
 * @return Options of the database
 * @protected
 * @see struct DBMap_impl#options
 * @see struct DBMap#options()
 * @readlock
 */
static enum DBOptions db_obj_options(struct DBMap *self)
{
	struct DBMap_impl* db = (struct DBMap_impl *)self;

	DB_COUNTSTAT(db_options);
	nullpo_retr(DB_OPT_BASE, db);

	return db->options;
}

/**
 * Increments free lock of the database
 * @protected
 * @remarks All protected functions must be preceded by a lock call
 **/
static void db_obj_lock(struct DBMap *self, enum lock_type type)
{
	db_free_lock((struct DBMap_impl*)self, type);
}

/**
 * Decrements free lock of the database
 * @protected
 **/
static void db_obj_unlock(struct DBMap *self)
{
	db_free_unlock((struct DBMap_impl*)self);
}

/*****************************************************************************\
 *  (5) Section with public functions.
 *  db_fix_options     - Apply database type restrictions to the options.
 *  db_default_cmp     - Get the default comparator for a type of database.
 *  db_default_hash    - Get the default hasher for a type of database.
 *  db_default_release - Get the default releaser for a type of database with the specified options.
 *  db_custom_release  - Get a releaser that behaves a certain way.
 *  db_alloc           - Allocate a new database.
 *  db_i2key           - Creates a new key from `int`.
 *  db_ui2key          - Creates a new key from `unsigned int`.
 *  db_str2key         - Creates a new key from `unsigned char *`.
 *  db_i642key         - Creates a new key from `int64`.
 *  db_ui642key        - Creates a new key from `uin64`.
 *  db_i2data          - Creates a new key from `int` to `struct DBData`.
 *  db_ui2data         - Creates a new key from `unsigned int` to `struct DBData`.
 *  db_ptr2data        - Creates a new key from `void*` to `struct DBData`.
 *  db_data2i          - Gets `int` value from `struct DBData`.
 *  db_data2ui         - Gets `unsigned int` value from `struct DBData`.
 *  db_data2ptr        - Gets `void*` value from `struct DBData`.
 *  db_init            - Initializes the database system.
 *  db_final           - Finalizes the database system.
\*****************************************************************************/

/**
 * Returns the fixed options according to the database type.
 * Sets required options and unsets unsupported options.
 * For numeric databases DB_OPT_DUP_KEY and DB_OPT_RELEASE_KEY are unset.
 * @param type Type of the database
 * @param options Original options of the database
 * @return Fixed options of the database
 * @private
 * @see #db_default_release()
 * @see #db_alloc()
 */
static enum DBOptions db_fix_options(enum DBType type, enum DBOptions options)
{
	DB_COUNTSTAT(db_fix_options);
	switch (type) {
		case DB_INT:
		case DB_UINT:
		case DB_INT64:
		case DB_UINT64: // Numeric database, do nothing with the keys
			return (enum DBOptions)(options&~(DB_OPT_DUP_KEY|DB_OPT_RELEASE_KEY));

		default:
			ShowError("db_fix_options: Unknown database type %u with options %x\n", type, options);
			FALLTHROUGH
		case DB_STRING:
		case DB_ISTRING: // String databases, no fix required
			return options;
	}
}

/**
 * Returns the default comparator for the specified type of database.
 * @param type Type of database
 * @return Comparator for the type of database or NULL if unknown database
 * @public
 * @see #db_int_cmp()
 * @see #db_uint_cmp()
 * @see #db_string_cmp()
 * @see #db_istring_cmp()
 * @see #db_int64_cmp()
 * @see #db_uint64_cmp()
 */
static DBComparator db_default_cmp(enum DBType type)
{
	DB_COUNTSTAT(db_default_cmp);
	switch (type) {
		case DB_INT:     return &db_int_cmp;
		case DB_UINT:    return &db_uint_cmp;
		case DB_STRING:  return &db_string_cmp;
		case DB_ISTRING: return &db_istring_cmp;
		case DB_INT64:   return &db_int64_cmp;
		case DB_UINT64:  return &db_uint64_cmp;
		default:
			ShowError("db_default_cmp: Unknown database type %u\n", type);
			return NULL;
	}
}

/**
 * Returns the default hasher for the specified type of database.
 * @param type Type of database
 * @return Hasher of the type of database or NULL if unknown database
 * @public
 * @see #db_int_hash()
 * @see #db_uint_hash()
 * @see #db_string_hash()
 * @see #db_istring_hash()
 * @see #db_int64_hash()
 * @see #db_uint64_hash()
 */
static DBHasher db_default_hash(enum DBType type)
{
	DB_COUNTSTAT(db_default_hash);
	switch (type) {
		case DB_INT:     return &db_int_hash;
		case DB_UINT:    return &db_uint_hash;
#ifdef DB_USE_HASH_MURMUR2
		case DB_STRING:  return &db_string_hash_murmur2;
		case DB_ISTRING: return &db_istring_hash_murmur2;
#else
		case DB_STRING:  return &db_string_hash_athena;
		case DB_ISTRING: return &db_istring_hash_athena;
#endif
		case DB_INT64:   return &db_int64_hash;
		case DB_UINT64:  return &db_uint64_hash;
		default:
			ShowError("db_default_hash: Unknown database type %u\n", type);
			return NULL;
	}
}

/**
 * Returns the default releaser for the specified type of database with the
 * specified options.
 *
 * NOTE: the options are fixed with #db_fix_options() before choosing the
 * releaser.
 *
 * @param type Type of database
 * @param options Options of the database
 * @return Default releaser for the type of database with the specified options
 * @public
 * @see #db_release_nothing()
 * @see #db_release_key()
 * @see #db_release_data()
 * @see #db_release_both()
 * @see #db_custom_release()
 */
static DBReleaser db_default_release(enum DBType type, enum DBOptions options)
{
	DB_COUNTSTAT(db_default_release);
	options = DB->fix_options(type, options);
	if (options&DB_OPT_RELEASE_DATA) { // Release data, what about the key?
		if (options&(DB_OPT_DUP_KEY|DB_OPT_RELEASE_KEY))
			return &db_release_both; // Release both key and data
		return &db_release_data; // Only release data
	}
	if (options&(DB_OPT_DUP_KEY|DB_OPT_RELEASE_KEY))
		return &db_release_key; // Only release key
	return &db_release_nothing; // Release nothing
}

/**
 * Returns the releaser that releases the specified release options.
 * @param which Options that specified what the releaser releases
 * @return Releaser for the specified release options
 * @public
 * @see #db_release_nothing()
 * @see #db_release_key()
 * @see #db_release_data()
 * @see #db_release_both()
 * @see #db_default_release()
 */
static DBReleaser db_custom_release(enum DBReleaseOption which)
{
	DB_COUNTSTAT(db_custom_release);
	switch (which) {
		case DB_RELEASE_NOTHING: return &db_release_nothing;
		case DB_RELEASE_KEY:     return &db_release_key;
		case DB_RELEASE_DATA:    return &db_release_data;
		case DB_RELEASE_BOTH:    return &db_release_both;
		default:
			ShowError("db_custom_release: Unknown release options %u\n", which);
			return NULL;
	}
}

/**
 * Allocate a new database of the specified type.
 *
 * NOTE: the options are fixed by #db_fix_options() before creating the
 * database.
 *
 * @param file File where the database is being allocated
 * @param line Line of the file where the database is being allocated
 * @param type Type of database
 * @param options Options of the database
 * @param maxlen Maximum length of the string to be used as key in string
 *               databases. If 0, the maximum number of maxlen is used (64K).
 * @param initial_capacity Initial number of buckets, historically this has been
 *                         set to HASH_SIZE.
 * @param load_factor The ratio of item_count and bucket_count that triggers a
 *                    capacity increase. When DB_OPT_DISABLE_GROWTH is set this
 *                    number is ignored. If 0 ignored.
 * @return The interface of the database
 * @public
 * @see struct DBMap_impl
 * @see #db_fix_options()
 */
static struct DBMap *db_alloc(const char *file, const char *func, int line,
	enum DBType type, enum DBOptions options, unsigned short maxlen,
	uint32_t initial_capacity, float load_factor
) {
	struct DBMap_impl *db;
	char ers_name[50];

#ifdef DB_ENABLE_STATS
	DB_COUNTSTAT(db_alloc);
	DB_COUNTSTAT_SWITCH(type, alloc);
#endif /* DB_ENABLE_STATS */

	rwlock->read_lock(db_alloc_ers->collection_lock);

	mutex->lock(db_alloc_ers->cache_mutex);
	db = ers_alloc(db_alloc_ers);
	mutex->unlock(db_alloc_ers->cache_mutex);

	rwlock->read_unlock(db_alloc_ers->collection_lock);

	options = DB->fix_options(type, options);
	/* Interface of the database */
	db->vtable.iterator = db_obj_iterator;
	db->vtable.exists   = db_obj_exists;
	db->vtable.get      = db_obj_get;
	db->vtable.getall   = db_obj_getall;
	db->vtable.vgetall  = db_obj_vgetall;
	db->vtable.ensure   = db_obj_ensure;
	db->vtable.vensure  = db_obj_vensure;
	db->vtable.put      = db_obj_put;
	db->vtable.remove   = db_obj_remove;
	db->vtable.foreach  = db_obj_foreach;
	db->vtable.vforeach = db_obj_vforeach;
	db->vtable.clear    = db_obj_clear;
	db->vtable.vclear   = db_obj_vclear;
	db->vtable.destroy  = db_obj_destroy;
	db->vtable.vdestroy = db_obj_vdestroy;
	db->vtable.size     = db_obj_size;
	db->vtable.type     = db_obj_type;
	db->vtable.options  = db_obj_options;
	db->vtable.set_hash = db_set_hash;
	db->vtable.set_release = db_set_release;
	db->vtable.lock     = db_obj_lock;
	db->vtable.unlock   = db_obj_unlock;
	/* File and line of allocation */
	db->alloc_file = file;
	db->alloc_line = line;
	/* Garbage collection */
	db->garbage_collection.free_list = NULL;
	db->garbage_collection.free_count = 0;
	db->garbage_collection.free_max = 0;
	db->garbage_collection.free_lock = 0;
	/* Table implementation */
	db->load_factor = load_factor;
	db->bucket_count = initial_capacity;
	/* Other */
	snprintf(ers_name, 50, "db_alloc:nodes:%s:%s:%d",func,file,line);
	if(options&DB_OPT_DISABLE_LOCK)
		db->lock = NULL;
	else
		db->lock = rwlock->create();
	db->lock_tid = -1;

	rwlock->write_lock(ers_collection_lock(db_ers_collection));
	db->nodes = ers_new(db_ers_collection, sizeof(struct DBNode),
		ers_name,ERS_OPT_WAIT|ERS_OPT_FREE_NAME|ERS_OPT_CLEAN);
	rwlock->write_unlock(ers_collection_lock(db_ers_collection));

	db->cmp = DB->default_cmp(type);
	db->hash = DB->default_hash(type);
	db->release = DB->default_release(type, options);
	db->ht = aCalloc(initial_capacity, sizeof(*db->ht));

	db->cache = NULL;
	db->type = type;
	db->options = options;
	db->item_count = 0;
	db->maxlen = maxlen;

	if( db->maxlen == 0 && (type == DB_STRING || type == DB_ISTRING) )
		db->maxlen = UINT16_MAX;

	return &db->vtable;
}

/**
 * Creates a new key from 'int'.
 * @param key Key to be casted
 * @return The key as a DBKey struct
 * @public
 */
static struct DBKey_s db_i2key(int key)
{
	struct DBKey_s ret;

	DB_COUNTSTAT(db_i2key);
	ret.u.i = key;
	ret.len = sizeof(ret.u.i);
	return ret;
}

/**
 * Creates a new key from 'unsigned int'.
 * @param key Key to be casted
 * @return The key as a DBKey struct
 * @public
 */
static struct DBKey_s db_ui2key(unsigned int key)
{
	struct DBKey_s ret;

	DB_COUNTSTAT(db_ui2key);
	ret.u.ui = key;
	ret.len = sizeof(ret.u.ui);
	return ret;
}

/**
 * Creates a new key from 'const char *'.
 * @param key Key to be casted
 * @param len Key length, if 0 the length is calculated.
 * @return The key as a DBKey struct
 * @public
 */
static struct DBKey_s db_str2key(const char *key, size_t len)
{
	struct DBKey_s ret;
	size_t key_len;

	DB_COUNTSTAT(db_str2key);
	ret.u.str = key;
	key_len = (!len)?strlen(key):len;
	ret.len = (int16_t)cap_value(key_len, 0, INT16_MAX);

	return ret;
}

/**
 * Creates a new key from 'int64'.
 * @param key Key to be casted
 * @return The key as a DBKey struct
 * @public
 */
static struct DBKey_s db_i642key(int64 key)
{
	struct DBKey_s ret;

	DB_COUNTSTAT(db_i642key);
	ret.u.i64 = key;
	ret.len = sizeof(ret.u.i64);
	return ret;
}

/**
 * Creates a new key from 'uin64'.
 * @param key Key to be casted
 * @return The key as a DBKey struct
 * @public
 */
static struct DBKey_s db_ui642key(uint64 key)
{
	struct DBKey_s ret;

	DB_COUNTSTAT(db_ui642key);
	ret.u.ui64 = key;
	ret.len = sizeof(ret.u.ui64);
	return ret;
}

/**
 * Manual cast from 'int' to the struct DBData.
 * @param data Data to be casted
 * @return The data as a DBData struct
 * @public
 */
static struct DBData db_i2data(int data)
{
	struct DBData ret;

	DB_COUNTSTAT(db_i2data);
	ret.type = DB_DATA_INT;
	ret.u.i = data;
	return ret;
}

/**
 * Manual cast from 'unsigned int' to the struct DBData.
 * @param data Data to be casted
 * @return The data as a DBData struct
 * @public
 */
static struct DBData db_ui2data(unsigned int data)
{
	struct DBData ret;

	DB_COUNTSTAT(db_ui2data);
	ret.type = DB_DATA_UINT;
	ret.u.ui = data;
	return ret;
}

/**
 * Manual cast from 'void *' to the struct DBData.
 * @param data Data to be casted
 * @return The data as a DBData struct
 * @public
 */
static struct DBData db_ptr2data(void *data)
{
	struct DBData ret;

	DB_COUNTSTAT(db_ptr2data);
	ret.type = DB_DATA_PTR;
	ret.u.ptr = data;
	return ret;
}

/**
 * Gets int type data from struct DBData.
 * If data is not int type, returns 0.
 * @param data Data
 * @return Integer value of the data.
 * @public
 */
static int db_data2i(struct DBData *data)
{
	DB_COUNTSTAT(db_data2i);
	if (data && DB_DATA_INT == data->type)
		return data->u.i;
	return 0;
}

/**
 * Gets unsigned int type data from struct DBData.
 * If data is not unsigned int type, returns 0.
 * @param data Data
 * @return Unsigned int value of the data.
 * @public
 */
static unsigned int db_data2ui(struct DBData *data)
{
	DB_COUNTSTAT(db_data2ui);
	if (data && DB_DATA_UINT == data->type)
		return data->u.ui;
	return 0;
}

/**
 * Gets void* type data from struct DBData.
 * If data is not void* type, returns NULL.
 * @param data Data
 * @return Void* value of the data.
 * @public
 */
static void *db_data2ptr(struct DBData *data)
{
	DB_COUNTSTAT(db_data2ptr);
	if (data && DB_DATA_PTR == data->type)
		return data->u.ptr;
	return NULL;
}

/**
 * Sets all stat data to zero
 **/
static void db_clear_stats(void)
{
#ifdef DB_ENABLE_STATS
	memset(&stats, 0, sizeof(stats));
#endif
}

/**
 * Initializes the database system.
 *
 * @public
 * @see #db_final(void)
 */
static void db_init(void)
{
#ifdef DB_ENABLE_STATS
	db_stats_mutex = mutex->create();
	if(!db_stats_mutex) {
		ShowFatalError("db_init: Failed to setup stats mutex\n");
		exit(EXIT_FAILURE);
	}
#endif
	db_ers_collection = ers_collection_create(MEMORYTYPE_SHARED);
	if(!db_ers_collection) {
		ShowFatalError("db_init: Failed to setup ERS collection\n");
		exit(EXIT_FAILURE);
	}
	rwlock->write_lock(ers_collection_lock(db_ers_collection));

	db_iterator_ers = ers_new(db_ers_collection, sizeof(struct DBIterator_impl),
		"db.c::db_iterator_ers",ERS_OPT_CLEAN|ERS_OPT_FLEX_CHUNK);
	db_alloc_ers = ers_new(db_ers_collection, sizeof(struct DBMap_impl),
		"db.c::db_alloc_ers",ERS_OPT_CLEAN|ERS_OPT_FLEX_CHUNK);
	// Don't need to get cache_mutex because this is a new collection
	// and there's no one trying to access these caches
	ers_chunk_size(db_alloc_ers, 50);
	ers_chunk_size(db_iterator_ers, 10);

	rwlock->write_unlock(ers_collection_lock(db_ers_collection));

	DB_COUNTSTAT(db_init);
}

/**
 * Finalizes the database system.
 *
 * @remarks Acquires write db_ers_collection
 * @public
 * @see #db_init(void)
 */
static void db_final(void)
{
#ifdef DB_ENABLE_STATS
	DB_COUNTSTAT(db_final);
	mutex->destroy(db_stats_mutex);
	db_stats_mutex = NULL;
	ShowInfo(CL_WHITE"Database nodes"CL_RESET":\n"
			"allocated %u, freed %u\n",
			stats.db_node_alloc, stats.db_node_free);
	ShowMessage(CL_WHITE"Database types"CL_RESET":\n"
			"DB_INT     : allocated %10u, destroyed %10u\n"
			"DB_UINT    : allocated %10u, destroyed %10u\n"
			"DB_STRING  : allocated %10u, destroyed %10u\n"
			"DB_ISTRING : allocated %10u, destroyed %10u\n"
			"DB_INT64   : allocated %10u, destroyed %10u\n"
			"DB_UINT64  : allocated %10u, destroyed %10u\n",
			stats.db_int_alloc,     stats.db_int_destroy,
			stats.db_uint_alloc,    stats.db_uint_destroy,
			stats.db_string_alloc,  stats.db_string_destroy,
			stats.db_istring_alloc, stats.db_istring_destroy,
			stats.db_int64_alloc,   stats.db_int64_destroy,
			stats.db_uint64_alloc,  stats.db_uint64_destroy);
	ShowMessage(CL_WHITE"Key collision counters"CL_RESET":\n"
			"DB_INT     : count %10u, peak capacity %10u\n"
			"DB_UINT    : count %10u, peak capacity %10u\n"
			"DB_STRING  : count %10u, peak capacity %10u\n"
			"DB_ISTRING : count %10u, peak capacity %10u\n"
			"DB_INT64   : count %10u, peak capacity %10u\n"
			"DB_UINT64  : count %10u, peak capacity %10u\n",
			stats.db_int_collision,     stats.db_int_bucket_peak,
			stats.db_uint_collision,    stats.db_uint_bucket_peak,
			stats.db_string_collision,  stats.db_string_bucket_peak,
			stats.db_istring_collision, stats.db_istring_bucket_peak,
			stats.db_int64_collision,   stats.db_int64_bucket_peak,
			stats.db_uint64_collision,  stats.db_uint64_bucket_peak);

	ShowMessage(CL_WHITE"Database function counters"CL_RESET":\n"
			"db_rotate_left     %10u, db_rotate_right    %10u,\n"
			"db_rebalance       %10u, db_rebalance_erase %10u,\n"
			"db_is_key_null     %10u, db_rehash          %10u,\n"
			"db_dup_key         %10u, db_dup_key_free    %10u,\n"
			"db_free_add        %10u, db_free_remove     %10u,\n"
			"db_free_lock       %10u, db_free_unlock     %10u,\n"
			"db_int_cmp         %10u, db_uint_cmp        %10u,\n"
			"db_string_cmp      %10u, db_istring_cmp     %10u,\n"
			"db_int64_cmp       %10u, db_uint64_cmp      %10u,\n"
			"db_int_hash        %10u, db_uint_hash       %10u,\n"
			"db_string_hash     %10u, db_istring_hash    %10u,\n"
			"db_int64_hash      %10u, db_uint64_hash     %10u,\n"
			"db_release_nothing %10u, db_release_key     %10u,\n"
			"db_release_data    %10u, db_release_both    %10u,\n"
			"dbit_first         %10u, dbit_last          %10u,\n"
			"dbit_next          %10u, dbit_prev          %10u,\n"
			"dbit_exists        %10u, dbit_remove        %10u,\n"
			"dbit_destroy       %10u, db_iterator        %10u,\n"
			"db_exits           %10u, db_get             %10u,\n"
			"db_getall          %10u, db_vgetall         %10u,\n"
			"db_ensure          %10u, db_vensure         %10u,\n"
			"db_put             %10u, db_remove          %10u,\n"
			"db_foreach         %10u, db_vforeach        %10u,\n"
			"db_clear           %10u, db_vclear          %10u,\n"
			"db_destroy         %10u, db_vdestroy        %10u,\n"
			"db_size            %10u, db_type            %10u,\n"
			"db_options         %10u, db_fix_options     %10u,\n"
			"db_default_cmp     %10u, db_default_hash    %10u,\n"
			"db_default_release %10u, db_custom_release  %10u,\n"
			"db_alloc           %10u, db_i2key           %10u,\n"
			"db_ui2key          %10u, db_str2key         %10u,\n"
			"db_i642key         %10u, db_ui642key        %10u,\n"
			"db_i2data          %10u, db_ui2data         %10u,\n"
			"db_ptr2data        %10u, db_data2i          %10u,\n"
			"db_data2ui         %10u, db_data2ptr        %10u,\n"
			"db_init            %10u, db_final           %10u\n",
			stats.db_rotate_left,     stats.db_rotate_right,
			stats.db_rebalance,       stats.db_rebalance_erase,
			stats.db_is_key_null,     stats.db_rehash,
			stats.db_dup_key,         stats.db_dup_key_free,
			stats.db_free_add,        stats.db_free_remove,
			stats.db_free_lock,       stats.db_free_unlock,
			stats.db_int_cmp,         stats.db_uint_cmp,
			stats.db_string_cmp,      stats.db_istring_cmp,
			stats.db_int64_cmp,       stats.db_uint64_cmp,
			stats.db_int_hash,        stats.db_uint_hash,
			stats.db_string_hash,     stats.db_istring_hash,
			stats.db_int64_hash,      stats.db_uint64_hash,
			stats.db_release_nothing, stats.db_release_key,
			stats.db_release_data,    stats.db_release_both,
			stats.dbit_first,         stats.dbit_last,
			stats.dbit_next,          stats.dbit_prev,
			stats.dbit_exists,        stats.dbit_remove,
			stats.dbit_destroy,       stats.db_iterator,
			stats.db_exists,          stats.db_get,
			stats.db_getall,          stats.db_vgetall,
			stats.db_ensure,          stats.db_vensure,
			stats.db_put,             stats.db_remove,
			stats.db_foreach,         stats.db_vforeach,
			stats.db_clear,           stats.db_vclear,
			stats.db_destroy,         stats.db_vdestroy,
			stats.db_size,            stats.db_type,
			stats.db_options,         stats.db_fix_options,
			stats.db_default_cmp,     stats.db_default_hash,
			stats.db_default_release, stats.db_custom_release,
			stats.db_alloc,           stats.db_i2key,
			stats.db_ui2key,          stats.db_str2key,
			stats.db_i642key,         stats.db_ui642key,
			stats.db_i2data,          stats.db_ui2data,
			stats.db_ptr2data,        stats.db_data2i,
			stats.db_data2ui,         stats.db_data2ptr,
			stats.db_init,            stats.db_final);
#endif /* DB_ENABLE_STATS */


	assert(db_iterator_ers->collection_lock == db_alloc_ers->collection_lock);
	struct rwlock_data *collection_lock = db_iterator_ers->collection_lock;
	rwlock->write_lock(collection_lock);
	ers_destroy(db_iterator_ers);
	ers_destroy(db_alloc_ers);
	rwlock->write_unlock(collection_lock);

	ers_collection_destroy(db_ers_collection);
}


/*****************************************************************************\
 *  (6) Section with link DB (jAthena).                                      *
 *  Link DB is a doubly linked list wrapper.                                 *
 *                                                                           *
 *  linkdb_insert   - Inserts a new node into the list.                      *
 *  linkdb_vforeach - Iterator (va_arg).                                     *
 *  linkdb_foreach  - Iterator.                                              *
 *  linkdb_search   - Searches for a key.                                    *
 *  linkdb_erase    - Removes node                                           *
 *  linkdb_replace  - Inserts a new node (if key exists replaces node).      *
 *  linkdb_final    - Frees all nodes.                                       *
\*****************************************************************************/

/**
 * Inserts a node into the list, doesn't take key into account.
 * @param head Pointer to first item (the item can be NULL)
 * @param key  Key to be set
 * @param data Data
 **/
void linkdb_insert(struct linkdb_node **head, void *key, void *data)
{
	struct linkdb_node *node;
	nullpo_retv(head);
	node = (struct linkdb_node*)aMalloc( sizeof(struct linkdb_node) );
	if( *head == NULL ) {
		// first node
		*head      = node;
		node->prev = NULL;
		node->next = NULL;
	} else {
		// link nodes
		node->next    = *head;
		node->prev    = (*head)->prev;
		(*head)->prev = node;
		(*head)       = node;
	}
	node->key  = key;
	node->data = data;
}

/**
 * Iterates database applying <code>func</code>
 * @param head Pointer to first item (the item can be NULL)
 * @param func Function to be applyed
 * @param ap   Function arguments
 **/
void linkdb_vforeach(struct linkdb_node **head, LinkDBFunc func, va_list ap)
{
	struct linkdb_node *node;
	nullpo_retv(head);
	node = *head;
	while ( node ) {
		int ret;
		va_list argscopy;
		va_copy(argscopy, ap);
		ret = func(node->key, node->data, argscopy);
		va_end(argscopy);
		if(ret == 1) { // Remove item
			if(node->prev == NULL)
				*head = node->next;
			else
				node->prev->next = node->next;
			if(node->next)
				node->next->prev = node->prev;
			struct linkdb_node *node_next = node->next;
			aFree(node);
			node = node_next;
		} else
			node = node->next;
	}
}

/**
 * Iterates database applying <code>func</code>
 * @param head Pointer to first item (the item can be NULL)
 * @param func Function to be applyed
 * @param ...  Function arguments
 * @remarks Functions that alter a node must not be called from within the iterator.
 **/
void linkdb_foreach(struct linkdb_node **head, LinkDBFunc func, ...)
{
	va_list ap;
	va_start(ap, func);
	linkdb_vforeach(head, func, ap);
	va_end(ap);
}

/**
 * Searches db for key-value pair.
 * @param head Pointer to first item (the item can be NULL)
 * @param key  Key to be found
 * @return data
 * @retval NULL failed to find.
 **/
void* linkdb_search(struct linkdb_node **head, void *key)
{
	int n = 0;
	struct linkdb_node *node;
	nullpo_retr(NULL, head);
	node = *head;
	while( node ) {
		if( node->key == key ) {
			if( node->prev && n > 5 ) {
				//Moving the head in order to improve processing efficiency
				if(node->prev) node->prev->next = node->next;
				if(node->next) node->next->prev = node->prev;
				node->next = *head;
				node->prev = (*head)->prev;
				(*head)->prev = node;
				(*head)       = node;
			}
			return node->data;
		}
		node = node->next;
		n++;
	}
	return NULL;
}

/**
 * Removes key-value pair from database and returns value.
 * @param head Pointer to first item (the item can be NULL)
 * @param key  Key to be found
 * @return data
 * @retval NULL failed to find.
 **/
void* linkdb_erase(struct linkdb_node **head, void *key)
{
	struct linkdb_node *node;
	nullpo_retr(NULL, head);
	node = *head;
	while( node ) {
		if( node->key == key ) {
			void *data = node->data;
			if( node->prev == NULL )
				*head = node->next;
			else
				node->prev->next = node->next;
			if( node->next )
				node->next->prev = node->prev;
			aFree( node );
			return data;
		}
		node = node->next;
	}
	return NULL;
}

/**
 * Inserts a node into the list, takes key into account i.e. if there's
 * a key-value pair with this key it's only replaced.
 * @param head Pointer to first item (the item can be NULL)
 * @param key  Key to be set
 * @param data Data
 **/
void linkdb_replace(struct linkdb_node **head, void *key, void *data)
{
	int n = 0;
	struct linkdb_node *node;
	nullpo_retv(head);
	node = *head;
	while( node ) {
		if( node->key == key ) {
			if( node->prev && n > 5 ) {
				//Moving the head in order to improve processing efficiency
				if(node->prev) node->prev->next = node->next;
				if(node->next) node->next->prev = node->prev;
				node->next = *head;
				node->prev = (*head)->prev;
				(*head)->prev = node;
				(*head)       = node;
			}
			node->data = data;
			return ;
		}
		node = node->next;
		n++;
	}
	//Insert because it can not find
	linkdb_insert( head, key, data );
}

/**
 * Destroys database (frees all nodes).
 * @param head Pointer to first item (the item can be NULL)
 **/
void linkdb_final(struct linkdb_node **head)
{
	struct linkdb_node *node, *node2;
	nullpo_retv(head);
	node = *head;
	while( node ) {
		node2 = node->next;
		aFree( node );
		node = node2;
	}
	*head = NULL;
}

void db_defaults(void)
{
	DB = &DB_s;
	DB->alloc = db_alloc;
	DB->custom_release = db_custom_release;
	DB->data2i = db_data2i;
	DB->data2ptr = db_data2ptr;
	DB->data2ui = db_data2ui;
	DB->default_cmp = db_default_cmp;
	DB->default_hash = db_default_hash;
	DB->default_release = db_default_release;
	DB->final = db_final;
	DB->fix_options = db_fix_options;
	DB->i2data = db_i2data;
	DB->i2key = db_i2key;
	DB->init = db_init;
	DB->ptr2data = db_ptr2data;
	DB->str2key = db_str2key;
	DB->ui2data = db_ui2data;
	DB->ui2key = db_ui2key;
	DB->i642key = db_i642key;
	DB->ui642key = db_ui642key;
}
