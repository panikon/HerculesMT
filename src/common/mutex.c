/**
 * This file is part of Hercules.
 * http://herc.ws - http://github.com/HerculesWS/Hercules
 *
 * Copyright (C) 2012-2021 Hercules Dev Team
 * Copyright (C) rAthena Project (www.rathena.org)
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

#include "mutex.h"

#include "common/cbasetypes.h" // for WIN32
#include "common/memmgr.h"
#include "common/nullpo.h"
#include "common/showmsg.h"
#include "common/timer.h"

#ifdef WIN32
#include "common/winapi.h"
#ifdef MUTEX_DEBUG
#include "common/thread.h"
#endif
#else
#include <pthread.h>
#include <sys/time.h>
#include <string.h> // strerror
#endif

/** @file
 * Implementation of the mutex interface.
 */

static struct mutex_interface mutex_s;
struct mutex_interface *mutex;

#ifdef WIN32
/**
 * Define the internal type that Hercules' mutex uses
 *
 * SRWLocks are generally faster than CRITICAL_SECTIONs because
 * they don't use any standard kernel objects internally when waiting,
 * and mostly execute in user-space
 * There were also changes to the inner workings of CRITICAL_SECTIONs
 * starting in Windows 8, changing its performance
 * @link stackoverflow.com/q/52170665
 **/
#define MUTEX_USE_SRWLOCK
//#define MUTEX_USE_CRITICAL_SECTION
#endif

struct mutex_data {
#ifdef WIN32
#ifdef MUTEX_USE_CRITICAL_SECTION
	CRITICAL_SECTION hMutex;
#elif defined(MUTEX_USE_SRWLOCK)
	SRWLOCK hMutex;
#endif
#ifdef MUTEX_DEBUG
	CRITICAL_SECTION hMutex_debug;
	int owner_tid; // Current owner (if -1, not owned)
#endif
#else
	pthread_mutex_t hMutex;
#endif
};

struct cond_data {
#ifdef WIN32
	CONDITION_VARIABLE hCond;
#else
	pthread_cond_t hCond;
#endif
};

/* Mutex */

static struct mutex_data *mutex_create_sub(struct mutex_data *m)
{
	if (m == NULL) {
		ShowFatalError("mutex_create_sub: OOM while allocating %"PRIuS" bytes.\n", sizeof(struct mutex_data));
		return NULL;
	}

#ifdef WIN32
#ifdef MUTEX_USE_CRITICAL_SECTION
	InitializeCriticalSection(&m->hMutex);
#elif defined(MUTEX_USE_SRWLOCK)
	InitializeSRWLock(&m->hMutex);
#endif
#ifdef MUTEX_DEBUG
	InitializeCriticalSection(&m->hMutex_debug);
	m->owner_tid = -1;
#endif

#else
	int retval;
#ifdef MUTEX_DEBUG
	pthread_mutexattr_t attr;
	if(pthread_mutexattr_init(&attr) == -1) {
		ShowFatalError("mutex_create_sub: Failed to initialize mutex attribute\n");
		return NULL;
	}
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK); // Enable error checking
	retval = pthread_mutex_init(&m->hMutex, &attr);
#else
	retval = pthread_mutex_init(&m->hMutex, NULL);
#endif
	if(retval) {
		ShowFatalError("mutex_create_sub: Failed to create mutex (%d:%s)\n",
			retval, strerror(retval));
		return NULL;
	}
#endif

	return m;
}

/**
 * Creates a new mutex without using memory manager
 *
 * This function is used in order to initialize the shared memory mutex used in
 * the memory manager
 * @see memmgr_init
 *
 * @warning This function should not be used after memory management was started
 **/
static struct mutex_data *mutex_create_no_management(void) {
	return mutex_create_sub(iMalloc->rmalloc(sizeof(struct mutex_data)));
}

/// @copydoc mutex_interface::create()
static struct mutex_data *mutex_create(void)
{
	return mutex_create_sub(aMalloc(sizeof(struct mutex_data)));
}

/**
 * Destroys a mutex lock
 *
 * Only unlocked mutexes should be destroyed.
 * This function can only fail in debug mode, otherwise illegal
 * operations are undefined behavior and change depending on the
 * operating system
 *
 * @return Success of the operation
 **/
static bool mutex_destroy_sub(struct mutex_data *m)
{
	nullpo_retr(false, m);
#ifdef WIN32
#ifdef MUTEX_DEBUG
	bool failed = false;
	EnterCriticalSection(&m->hMutex_debug);
	if(m->owner_tid != -1) {
		// Only an unowned CRITICAL_SECTION can be deleted
		ShowDebug("mutex_destroy_sub: Trying to delete an owned critical section (TID %d, owner %d)\n",
			thread->get_tid(), m->owner_tid);
		ShowInfo("mutex_destroy_sub: Ignored previous operation\n");
		failed = true;
	}
	LeaveCriticalSection(&m->hMutex_debug);
	if(failed)
		return false;
	DeleteCriticalSection(&m->hMutex_debug);
#endif
#ifdef MUTEX_USE_CRITICAL_SECTION
	DeleteCriticalSection(&m->hMutex);
#elif defined(MUTEX_USE_SRWLOCK)
	// A SRWLock is a pointer to a kernel keyed event, nothing is
	// allocated upon creation, so there's no need to release/delete it
#endif
#else
	int retval = pthread_mutex_destroy(&m->hMutex);
	if(retval) {
		ShowError("mutex_destroy_sub: Failed to destroy mutex, (%d: %s)\n",
			ret, strerror(ret));
		ShowInfo("mutex_destroy_sub: Ignored previous operation\n");
		return false;
	}
#endif
	return true;
}

/**
 * Frees mutex created using mutex_create_no_management
 **/
static void mutex_destroy_no_management(struct mutex_data *m)
{
	if(mutex_destroy_sub(m))
		iMalloc->rfree(m);
}

/// @copydoc mutex_interface::destroy()
static void mutex_destroy(struct mutex_data *m)
{
	if(mutex_destroy_sub(m))
		aFree(m);
}

#if defined(WIN32) && defined(MUTEX_DEBUG)
/**
 * Can this thread try to acquire the provided mutex?
 *
 * This function is only implemented in WIN32 because pthread checks
 * internally when PTHREAD_MUTEX_ERRORCHECK is set
 * @retval true The current thread doesn't own the mutex
 * @retval false The current thread owns the mutex
 **/
bool mutex_can_lock(struct mutex_data *m) {
	bool retval = true;
	EnterCriticalSection(&m->hMutex_debug);
	if(m->owner_tid == thread->get_tid()) {
		ShowDebug("mutex_lock: Trying to re-enter a mutex (TID %d)\n",
			thread->get_tid());
		ShowInfo("mutex_lock: Ignored previous operation\n");
		retval = false;
	}
	LeaveCriticalSection(&m->hMutex_debug);
	return retval;
}
#endif

/// @copydoc mutex_interface::lock()
static void mutex_lock(struct mutex_data *m)
{
	nullpo_retv(m);
#ifdef WIN32
#ifdef MUTEX_DEBUG
	if(!mutex_can_lock(m))
		return;
#endif
#ifdef MUTEX_USE_CRITICAL_SECTION
	EnterCriticalSection(&m->hMutex);
#elif defined(MUTEX_USE_SRWLOCK)
	AcquireSRWLockExclusive(&m->hMutex);
#endif
#ifdef MUTEX_DEBUG
	EnterCriticalSection(&m->hMutex_debug);
	m->owner_tid = thread->get_tid();
	LeaveCriticalSection(&m->hMutex_debug);
#endif
#else
	int retval = pthread_mutex_lock(&m->hMutex);
	if(retval) {
		ShowError("mutex_lock: Failed to enter mutex, (%d: %s)\n",
			ret, strerror(ret));
		ShowInfo("mutex_lock: Ignored previous operation\n");
		return;
	}
#endif
}

/// @copydoc mutex_interface::trylock()
static bool mutex_trylock(struct mutex_data *m)
{
	nullpo_retr(false, m);
#ifdef WIN32
#ifdef MUTEX_DEBUG
	if(!mutex_can_lock(m))
		return true; // Already locked
#endif
#ifdef MUTEX_USE_CRITICAL_SECTION
	if(TryEnterCriticalSection(&m->hMutex) != FALSE)
		return true;
#elif defined(MUTEX_USE_SRWLOCK)
	if(TryAcquireSRWLockExclusive(&m->hMutex) != FALSE)
		return true;
#endif
#else
	if (pthread_mutex_trylock(&m->hMutex) == 0)
		return true;
#endif
	return false;
}

/// @copydoc mutex_interface::unlock()
static void mutex_unlock(struct mutex_data *m)
{
	nullpo_retv(m);
#ifdef WIN32
#ifdef MUTEX_DEBUG
	EnterCriticalSection(&m->hMutex_debug);
	m->owner_tid = -1;
	LeaveCriticalSection(&m->hMutex_debug);
#endif
#ifdef MUTEX_USE_CRITICAL_SECTION
	LeaveCriticalSection(&m->hMutex);
#elif defined(MUTEX_USE_SRWLOCK)
	ReleaseSRWLockExclusive(&m->hMutex);
#endif
#else
	pthread_mutex_unlock(&m->hMutex);
#endif
}

/* Conditional variable */

/// @copydoc mutex_interface::cond_create()
static struct cond_data *cond_create(void)
{
	struct cond_data *c = aMalloc(sizeof(struct cond_data)); // Never fails

#ifdef WIN32
	InitializeConditionVariable(&c->hCond);
#else
	int retval = pthread_cond_init(&c->hCond, NULL);
	if(retval)
		ShowError("cond_create: Failed to create condition (%d:%s)\n",
			retval, strerror(retval));
#endif

	return c;
}

/// @copydoc mutex_interface::cond_destroy()
static void cond_destroy(struct cond_data *c)
{
	nullpo_retv(c);
#ifdef WIN32
	// A CONDITION_VARIABLE is a pointer to a kernel keyed event, nothing is
	// allocated upon creation, so there's no need to release/delete it
#else
	pthread_cond_destroy(&c->hCond);
#endif

	aFree(c);
}

/// @copydoc mutex_interface::cond_wait()
static bool cond_wait(struct cond_data *c, struct mutex_data *m, sysint timeout_ticks)
{
	nullpo_retr(false, c);
	nullpo_retr(false, m);
	bool retval = true;

#ifdef WIN32
#ifdef MUTEX_USE_CRITICAL_SECTION
	retval = SleepConditionVariableCS(&c->hCond, &m->hMutex,
		(timeout_ticks < 0)?INFINITE:timeout_ticks);
#elif defined(MUTEX_USE_SRWLOCK)
	retval = SleepConditionVariableSRW(&c->hCond, &m->hMutex,
		(timeout_ticks < 0)?INFINITE:timeout_ticks, 0);
#endif
	if(!retval) {
		DWORD dw = GetLastError();
		if(dw != ERROR_TIMEOUT)
			ShowError("cond_wait: Failed to wait (error %ld)\n", dw);
	}
#else
	if (timeout_ticks < 0) {
		pthread_cond_wait(&c->hCond,  &m->hMutex);
	} else {
		struct timespec wtime;
		int64 exact_timeout = timer->gettick() + timeout_ticks;

		wtime.tv_sec = exact_timeout/1000;
		wtime.tv_nsec = (exact_timeout%1000)*1000000;

		retval = (pthread_cond_timedwait(&c->hCond,  &m->hMutex,  &wtime) == 0);
		if(!retval && errno != EAGAIN)
			ShowError("cond_wait: Failed to wait (errno %d)\n", errno);
	}
#endif
	return retval;
}

/// @copydoc mutex_interface::cond_signal()
static void cond_signal(struct cond_data *c)
{
	nullpo_retv(c);
#ifdef WIN32
	WakeConditionVariable(&c->hCond);
#else
	pthread_cond_signal(&c->hCond);
#endif
}

/// @copydoc mutex_interface::cond_broadcast()
static void cond_broadcast(struct cond_data *c)
{
	nullpo_retv(c);
#ifdef WIN32
	WakeAllConditionVariable(&c->hCond);
#else
	pthread_cond_broadcast(&c->hCond);
#endif
}

/**
 * Interface base initialization.
 */
void mutex_defaults(void)
{
	mutex = &mutex_s;
	mutex->create = mutex_create;
	mutex->destroy = mutex_destroy;
	mutex->create_no_management = mutex_create_no_management;
	mutex->destroy_no_management = mutex_destroy_no_management;
	mutex->lock = mutex_lock;
	mutex->trylock = mutex_trylock;
	mutex->unlock = mutex_unlock;

	mutex->cond_create = cond_create;
	mutex->cond_destroy = cond_destroy;
	mutex->cond_wait = cond_wait;
	mutex->cond_signal = cond_signal;
	mutex->cond_broadcast = cond_broadcast;
}
