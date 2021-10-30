/**
 * This file is part of Hercules.
 * http://herc.ws - http://github.com/HerculesWS/Hercules
 *
 * Copyright (C) 2021 Hercules Dev Team
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
#define HERCULES_CORE

#include "rwlock.h"

#include "common/cbasetypes.h"
#include "common/memmgr.h"
#include "common/nullpo.h"
#include "common/showmsg.h"
#include "common/mutex.h"
#include "common/thread.h"

#ifdef WIN32
#include "common/winapi.h"
#endif

// TODO: Unix portability

// Interface data
static struct rwlock_interface rwlock_s;
struct rwlock_interface *rwlock;

/**
 * Read-write lock data
 *
 * This lock is not fair, writers have priority over readers.
 * Multiple readers can have the lock simultaneously while only one writer.
 * 
 *
 * @see rwlock_create
 * @see rwlock_destroy
 **/
struct rwlock_data {
	SRWLOCK data;
};

/**
 * Unlocks read lock
 **/
static void rwlock_read_unlock(struct rwlock_data *lock) {
	nullpo_retv(lock);
	ReleaseSRWLockShared(&lock->data);
}

/**
 * Attempts to get read lock (doesn't block)
 *
 * @return Was read lock acquired?
 **/
static bool rwlock_read_trylock(struct rwlock_data *lock) {
	if(!TryAcquireSRWLockShared(&lock->data))
		return false;
	return true;
}

/**
 * Acquires read lock
 *
 * Read locks can be acquired recursively, but this is not good practice as
 * it can lead to deadlocks
 **/
static void rwlock_read_lock(struct rwlock_data *lock) {
	nullpo_retv(lock);

	AcquireSRWLockShared(&lock->data);
}

/**
 * Unlocks write lock
 **/
static void rwlock_write_unlock(struct rwlock_data *lock) {
	nullpo_retv(lock);

	ReleaseSRWLockExclusive(&lock->data);
}

/**
 * Attempts to get write lock (doesn't block)
 *
 * @return Was write lock acquired?
 **/
static bool rwlock_write_trylock(struct rwlock_data *lock) {
	if(!TryAcquireSRWLockExclusive(&lock->data))
		return false;

	return true;
}

/**
 * Acquires write lock
 **/
static void rwlock_write_lock(struct rwlock_data *lock) {
	nullpo_retv(lock);

	AcquireSRWLockExclusive(&lock->data);
}

/**
 * Destroys a read-write lock
 *
 * Only unlocked mutexes should be destroyed.
 * Illegal operations are undefined behavior and change depending on the
 * operating system
 * When MUTEX_DEBUG is set the mutex is not destroyed.
 * @see mutex_destroy_sub
 **/
static void rwlock_destroy(struct rwlock_data *lock) {
	nullpo_retv(lock);

	// A SRWLock is a pointer to a kernel keyed event, nothing is
	// allocated upon creation, so there's no need to release/delete it
	aFree(lock);
}

/**
 * Creates a new read-write lock
 *
 * Never fails.
 **/
static struct rwlock_data *rwlock_create(void) {
	struct rwlock_data *lock = aCalloc(1, sizeof(*lock));
	InitializeSRWLock(&lock->data);

	return lock;
}

/**
 * Interface base initialization.
 */
void rwlock_defaults(void) {
	rwlock = &rwlock_s;

	rwlock->read_unlock  = rwlock_read_unlock;
	rwlock->read_trylock = rwlock_read_trylock;
	rwlock->read_lock    = rwlock_read_lock;

	rwlock->write_unlock  = rwlock_write_unlock;
	rwlock->write_trylock = rwlock_write_trylock;
	rwlock->write_lock    = rwlock_write_lock;

	rwlock->destroy = rwlock_destroy;
	rwlock->create  = rwlock_create;
}
