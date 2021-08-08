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

struct mutex_data {
#ifdef WIN32
	CRITICAL_SECTION hMutex;
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
	HANDLE events[2];
	ra_align(8) volatile LONG nWaiters;
	CRITICAL_SECTION waiters_lock;
#define EVENT_COND_SIGNAL 0
#define EVENT_COND_BROADCAST 1
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
	InitializeCriticalSection(&m->hMutex);
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
 * Tries to destroy a mutex
 * @return bool success
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
		ShowDebug("mutex_destroy_sub: Trying to delete a owned critical section (TID %d, owner %d)\n",
			thread->get_tid(), m->owner_tid);
		ShowInfo("mutex_destroy_sub: Ignored previous operation\n");
		failed = true;
	}
	LeaveCriticalSection(&m->hMutex_debug);
	if(failed)
		return false;
	DeleteCriticalSection(&m->hMutex_debug);
#endif
	DeleteCriticalSection(&m->hMutex);
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
	EnterCriticalSection(&m->hMutex);
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
	if(TryEnterCriticalSection(&m->hMutex) != FALSE)
		return true;
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
	LeaveCriticalSection(&m->hMutex);
#else
	pthread_mutex_unlock(&m->hMutex);
#endif
}

/* Conditional variable */

/// @copydoc mutex_interface::cond_create()
static struct cond_data *cond_create(void)
{
	struct cond_data *c = aMalloc(sizeof(struct cond_data));
	if (c == NULL) {
		ShowFatalError("racond_create: OOM while allocating %"PRIuS" bytes\n", sizeof(struct cond_data));
		return NULL;
	}

#ifdef WIN32
	c->nWaiters = 0;
	c->events[EVENT_COND_SIGNAL]    = CreateEvent(NULL, FALSE, FALSE, NULL);
	c->events[EVENT_COND_BROADCAST] = CreateEvent(NULL, TRUE,  FALSE, NULL);
	InitializeCriticalSection( &c->waiters_lock );
#else
	pthread_cond_init(&c->hCond, NULL);
#endif

	return c;
}

/// @copydoc mutex_interface::cond_destroy()
static void cond_destroy(struct cond_data *c)
{
	nullpo_retv(c);
#ifdef WIN32
	CloseHandle(c->events[EVENT_COND_SIGNAL]);
	CloseHandle(c->events[EVENT_COND_BROADCAST]);
	DeleteCriticalSection(&c->waiters_lock);
#else
	pthread_cond_destroy(&c->hCond);
#endif

	aFree(c);
}

/// @copydoc mutex_interface::cond_wait()
static void cond_wait(struct cond_data *c, struct mutex_data *m, sysint timeout_ticks)
{
#ifdef WIN32
	register DWORD ms;
	int result;
	bool is_last = false;

	nullpo_retv(c);
	EnterCriticalSection(&c->waiters_lock);
	c->nWaiters++;
	LeaveCriticalSection(&c->waiters_lock);

	if (timeout_ticks < 0)
		ms = INFINITE;
	else
		ms = (timeout_ticks > MAXDWORD) ? (MAXDWORD - 1) : (DWORD)timeout_ticks;

	// we can release the mutex (m) here, cause win's
	// manual reset events maintain state when used with
	// SetEvent()
	mutex->unlock(m);

	result = WaitForMultipleObjects(2, c->events, FALSE, ms);

	EnterCriticalSection(&c->waiters_lock);
	c->nWaiters--;
	if ((result == WAIT_OBJECT_0 + EVENT_COND_BROADCAST) && (c->nWaiters == 0))
		is_last = true; // Broadcast called!
	LeaveCriticalSection(&c->waiters_lock);

	// we are the last waiter that has to be notified, or to stop waiting
	// so we have to do a manual reset
	if (is_last == true)
		ResetEvent( c->events[EVENT_COND_BROADCAST] );

	mutex->lock(m);

#else
	nullpo_retv(m);
	if (timeout_ticks < 0) {
		pthread_cond_wait(&c->hCond,  &m->hMutex);
	} else {
		struct timespec wtime;
		int64 exact_timeout = timer->gettick() + timeout_ticks;

		wtime.tv_sec = exact_timeout/1000;
		wtime.tv_nsec = (exact_timeout%1000)*1000000;

		pthread_cond_timedwait( &c->hCond,  &m->hMutex,  &wtime);
	}
#endif
}

/// @copydoc mutex_interface::cond_signal()
static void cond_signal(struct cond_data *c)
{
#ifdef WIN32
#	if 0
	bool has_waiters = false;
	nullpo_retv(c);
	EnterCriticalSection(&c->waiters_lock);
	if(c->nWaiters > 0)
		has_waiters = true;
	LeaveCriticalSection(&c->waiters_lock);

	if(has_waiters == true)
#	endif // 0
		SetEvent(c->events[EVENT_COND_SIGNAL]);
#else
	nullpo_retv(c);
	pthread_cond_signal(&c->hCond);
#endif
}

/// @copydoc mutex_interface::cond_broadcast()
static void cond_broadcast(struct cond_data *c)
{
#ifdef WIN32
#	if 0
	bool has_waiters = false;
	nullpo_retv(c);
	EnterCriticalSection(&c->waiters_lock);
	if(c->nWaiters > 0)
		has_waiters = true;
	LeaveCriticalSection(&c->waiters_lock);

	if(has_waiters == true)
#	endif // 0
		SetEvent(c->events[EVENT_COND_BROADCAST]);
#else
	nullpo_retv(c);
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
