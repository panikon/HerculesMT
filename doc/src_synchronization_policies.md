# Documentation for synchronization policies

#### Mark up tags

|     Tag        |  Usage
| :---           | ---
|**@lock**       | rwlock that's used by this method (usually this is used for ```struct``` and ```union``` to describe what lock guards the object)
|**@readlock**   | A read lock must be acquired
|**@writelock**  | A write lock must be acquired
|**@mutex**      | A mutex should be acquired

When more than a tag is described they must be listed in the expected order of acquiral.

#### Example
```C
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
	[...]

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

	[...]
```