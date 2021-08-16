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

#include "thread.h"

#include "common/cbasetypes.h"
#include "common/memmgr.h"
#include "common/showmsg.h"
#include "common/sysinfo.h" // sysinfo->getpagesize()
#include "common/utils.h" // cap_value
#include "common/nullpo.h"
#include "common/atomic.h"
#include "common/mutex.h"

#include "common/thread.h"

#ifdef WIN32
#	include "common/winapi.h"
#else
#	include <pthread.h>
#	include <sched.h>
#	include <signal.h>
#	include <stdlib.h>
#	include <string.h>
#	include <unistd.h>
#   include <errno.h>
#endif
#include <stdlib.h>

/** @file
 * Thread interface implementation.
 * @author Florian Wilkemeyer <fw@f-ws.de>
 */

static struct thread_interface thread_s;
struct thread_interface *thread;

/// The maximum amount of threads.
#define THREADS_MAX 130
/// Default thread stack size upon creation
#define THREAD_STACK_SIZE (1<<23) // 8MB

enum e_thread_status {
	THREADSTATUS_CLEAN = 0x0,   //< Thread ready to be setup
	THREADSTATUS_RESERVED,      //< Thread reserved for setup
	THREADSTATUS_RUN,           //< Thread running
};

struct thread_handle {
	unsigned int myID;
	/**
	 * Thread name
	 *
	 * In UNIX the name is hard limited to 16 characters including the terminating '\0'
	 * @see man7.org/linux/man-pages/man3/pthread_setname_np.3.html
	 **/
	char name[16];

	enum thread_priority prio;
	threadFunc proc;
	void *param;
	void *result;
	enum thread_status status;

	#ifdef WIN32
	HANDLE hThread;
	#else
	pthread_t hThread;
	#endif
};

// Subystem Code

/**
 * Thread list
 *
 * Threads that were created by our subsystem
 * l_threads[0] is the main thread
 *
 * @remark Only the thread that owns the id can change values
 * inside of it.
 **/
static struct thread_handle l_threads[THREADS_MAX];
static int32_t l_threads_count = 0;
static struct mutex_data *l_threads_mutex = NULL;

/**
 * Internal representation of thread id
 *
 * Represents the index of this thread in l_threads, is also
 * the same value as l_threads[g_thread_id].myID
 **/
static thread_local int g_thread_id = -1;

/**
 * Thread dynamic priority
 *
 * Wrapper of different thread priorities used when
 * converting thread_priority to the host system
 * @see thread_prio_init
 **/
static int thread_dynamic_priority[THREADPRIO_LAST] = {0};

/**
 * Sets up thread priority wrapper
 *
 * All the changes in priority usually are relative to the
 * current process priority, generally a THREADPRIO_HIGH thread on a normal
 * process will still have a lower priority than a thread of equivalent
 * value of a higher priority process
 **/
static void thread_prio_init(void)
{
#ifdef _WIN32
	/**
     * For more information on how each of the process _PRIORITY_CLASS
	 * affects the thread_priority
	 * @see docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadpriority
	 **/
	thread_dynamic_priority[THREADPRIO_IDLE]         = THREAD_PRIORITY_IDLE;
	thread_dynamic_priority[THREADPRIO_LOWEST]       = THREAD_PRIORITY_LOWEST;
	thread_dynamic_priority[THREADPRIO_LOW]          = THREAD_PRIORITY_BELOW_NORMAL;
	thread_dynamic_priority[THREADPRIO_NORMAL]       = THREAD_PRIORITY_NORMAL;
	thread_dynamic_priority[THREADPRIO_HIGH]         = THREAD_PRIORITY_ABOVE_NORMAL;
	thread_dynamic_priority[THREADPRIO_HIGHEST]      = THREAD_PRIORITY_HIGHEST;
	thread_dynamic_priority[THREADPRIO_TIMECRITICAL] = THREAD_PRIORITY_TIME_CRITICAL;
#else
	// TODO/FIXME this code is untested
	/** Linux
	 * Under normal scheduling policies (SCHED_OTHER, SCHED_IDLE, SCHED_BATCH)
	 * a thread can only have a static priority of 0. The default scheduling for
	 * a process is SCHED_OTHER. So instead of changing the actual priority we're
	 * changing the nice value.
	 * @see man7.org/linux/man-pages/man7/sched.7.html
	 *
	 * Under NPTL each thread has its own nice value (non conformant to POSIX.1),
	 * so it's possible to use it as a thread priority.
	 * @see man7.org/linux/man-pages/man7/pthreads.7.html
	 *
	 * Non-root users can not set nice < 0.
	 * @see man7.org/linux/man-pages/man2/nice.2.html
	 **/
	struct rlimit nice_limit;
	if(getrlimit(RLIMIT_NICE, &nice_limit)) {
		ShowError("thread_prio_init: Failed to get nice limit (errno %d)\n", errno);
		ShowWarning("thread_prio_init: defaulting all priorities to THREADPRIO_NORMAL\n");
		for(int i = 0; i < THREADPRIO_LAST; i++)
			thread_dynamic_priority[i] = 0;
		return;
	}
	int priority_maximum = 20 - nice_limit.rlim_cur;
	thread->dynamic_priority[THREADPRIO_NORMAL] = 0;
	if(priority_maximum == 0) { // We can't exceed normal priority
		thread_dynamic_priority[THREADPRIO_HIGH]         = 0;
		thread_dynamic_priority[THREADPRIO_HIGHEST]      = 0;
		thread_dynamic_priority[THREADPRIO_TIMECRITICAL] = 0;
	} else {
		int step = priority_maximum/3;
		thread_dynamic_priority[THREADPRIO_HIGH]
			= cap_value(priority_maximum+2*step, thread_dynamic_priority[THREADPRIO_HIGHEST], 0);
		thread_dynamic_priority[THREADPRIO_HIGHEST]
			= cap_value(priority_maximum+step, priority_maximum, 0);
		thread_dynamic_priority[THREADPRIO_TIMECRITICAL] = priority_maximum;
	}
	thread_dynamic_priority[THREADPRIO_IDLE]   = 20;
	thread_dynamic_priority[THREADPRIO_LOWEST] = 10;
	thread_dynamic_priority[THREADPRIO_LOW]    = 5;
#endif
}

/// @copydoc thread_interface::init()
static void thread_init(void)
{
	register int i;
	memset(&l_threads, 0x00, THREADS_MAX * sizeof(struct thread_handle));

	for (i = 0; i < THREADS_MAX; i++) {
		l_threads[i].myID = i;
	}

	// now lets init thread id 0, which represents the main thread
	g_thread_id = 0;
	l_threads[0].prio = THREADPRIO_NORMAL;
	l_threads[0].proc = (threadFunc)0xDEADCAFE;
	l_threads[0].proc = THREADSTATUS_RUN;
	l_threads_count = 1;

	thread_prio_init();
	l_threads_mutex = mutex->create();
	if(!l_threads_mutex) {
		ShowFatalError("thread_init: Failed to setup thread mutex!\n");
		exit(EXIT_FAILURE);
	}
}

/// @copydoc thread_interface::final()
static void thread_final(void)
{
	register int i;

	mutex->lock(l_threads_mutex);
	// Unterminated Threads Left?
	// Shouldn't happen ... Kill 'em all!
	for (i = 1; i < THREADS_MAX; i++) {
		if (l_threads[i].proc != NULL){
			ShowWarning("thread_final: unterminated Thread (tid %d, name '%s', entry_point %p)"
				"- forcing to terminate (kill)\n", i, l_threads[i].name, l_threads[i].proc);
			thread->destroy(&l_threads[i]);
		}
	}
	mutex->unlock(l_threads_mutex);
	mutex->destroy(l_threads_mutex);
}

/**
 * Gets called whenever a thread terminated.
 *
 * This can either be called from the main thread when one of the children
 * is terminated or from one of the children.
 * @param handle The terminated thread's handle.
 */
static void thread_terminated(struct thread_handle *handle)
{
	mutex->lock(l_threads_mutex);
	// Preserve handle->myID and handle->hThread, set everything else to its default value
	handle->param = NULL;
	handle->proc = NULL;
	handle->prio = THREADPRIO_NORMAL;
	handle->status = THREADSTATUS_CLEAN;
	handle->name[0] = '\0';
	mutex->unlock(l_threads_mutex);
	InterlockedDecrement(&l_threads_count);
}

#ifdef WIN32
static DWORD WINAPI thread_main_redirector(LPVOID p)
{
#else
static void *thread_main_redirector(void *p)
{
	sigset_t set; // on Posix Thread platforms
#endif
	struct thread_handle *self = p;

	// Update myID @ TLS to right id.
	g_thread_id = self->myID;
	thread->name_set(NULL);

#ifndef WIN32
	// When using posix threads
	// the threads inherits the Signal mask from the thread which spawned
	// this thread
	// so we've to block everything we don't care about.
	(void)sigemptyset(&set);
	(void)sigaddset(&set, SIGINT);
	(void)sigaddset(&set, SIGTERM);
	(void)sigaddset(&set, SIGPIPE);

	pthread_sigmask(SIG_BLOCK, &set, NULL);
#endif

	iMalloc->local_storage_init();
	self->result = self->proc(self->param);
	iMalloc->local_storage_final();
	ers_final(MEMORYTYPE_LOCAL);

#ifdef WIN32
	CloseHandle(self->hThread);
	self->hThread = NULL;
#endif
	thread_terminated(self);
#ifdef WIN32
	return (DWORD)self->result;
#else
	return self->result;
#endif
}

// API Level

/// @copydoc thread_interface::thread_count()
int thread_count(void) {
	return InterlockedExchangeAdd(&l_threads_count, 0);
}

/// @copydoc thread_interface::exit()
static void thread_exit(void *result)
{
	struct thread_handle *self = thread->self();
	self->result = result;
	thread_terminated(self);
#ifdef WIN32
	_endthreadex(0);
#else
	pthread_exit(NULL);
#endif
}

#if defined(WIN32)

#ifdef DEBUG
#pragma pack(push,8)
typedef struct tagTHREADNAME_INFO
{
	DWORD dwType; // Must be 0x1000.
	LPCSTR szName; // Pointer to name (in user addr space).
	DWORD dwThreadID; // Thread ID (-1=caller thread).
	DWORD dwFlags; // Reserved for future use, must be zero.
} THREADNAME_INFO;
#pragma pack(pop)
#endif

/**
 * SetThreadName
 * Sets thread name for the debugger
 *
 * @param dwThreadID System thread id
 * @param threadName New name (must be valid in user addr space)
 *
 * Used for setting the thread name when debugging in MSVC (windows' threads
 * don't have names)
 * @see docs.microsoft.com/en-us/visualstudio/debugger/how-to-set-a-thread-name-in-native-code
 **/
void SetThreadName(DWORD dwThreadID, const char *threadName)
{
#ifdef DEBUG
	THREADNAME_INFO info;
	info.dwType = 0x1000;
	info.szName = threadName;
	info.dwThreadID = dwThreadID;
	info.dwFlags = 0;
#pragma warning(push)
#pragma warning(disable: 6320 6322)
	__try{
		RaiseException(0x406D1388, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR*)&info);
	}
	__except (EXCEPTION_EXECUTE_HANDLER){
	}
#endif // DEBUG
}

#endif // WIN32

/// @copydoc thread_interface::name_get()
const char *thread_name_get(void)
{
	struct thread_handle *handle = thread->self();
	return handle->name;
}

/// @copydoc thread_interface::name_set()
void thread_name_set(const char *name)
{
	struct thread_handle *handle = thread->self();

	if(name) {
		if(handle->name)
			handle->name[0] = '\0';

		strncpy(handle->name, name, sizeof(handle->name));
		handle->name[sizeof(handle->name)-1] = '\0';
	}
#ifdef WIN32
	SetThreadName(GetCurrentThreadId(), handle->name);
#else
	// TODO: Test
	pthread_setname_np(handle->hThread, handle->name);
#endif
}

/// @copydoc thread_interface::create()
static struct thread_handle *thread_create(const char *name, threadFunc entry_point, void *param)
{
	return thread->create_opt(name, entry_point, param, THREAD_STACK_SIZE, THREADPRIO_NORMAL);
}

/// @copydoc thread_interface::create_opt()
static struct thread_handle *thread_create_opt(const char *name, threadFunc entry_point,
	void *param, size_t stack_size, enum thread_priority prio
) {
#ifndef WIN32
	pthread_attr_t attr;
#endif
	size_t tmp;
	int i;
	struct thread_handle *handle = NULL;

	// given stacksize aligned to systems pagesize?
	tmp = stack_size % sysinfo->getpagesize();
	if (tmp != 0)
		stack_size += tmp;

	// Get a free Thread Slot.
	mutex->lock(l_threads_mutex);
	for (i = 0; i < THREADS_MAX; i++) {
		if(l_threads[i].proc == NULL && l_threads[i].status == THREADSTATUS_CLEAN){
			handle = &l_threads[i];
			l_threads[i].status = THREADSTATUS_RESERVED;
			break;
		}
	}
	mutex->unlock(l_threads_mutex);

	if (handle == NULL) {
		ShowError("thread_create_opt: cannot create new thread (entry_point: %p)"
			"- no free thread slot found!\n", entry_point);
		return NULL;
	}

	handle->proc = entry_point;
	handle->param = param;
	strncpy(handle->name, name, sizeof(handle->name));
	handle->name[sizeof(handle->name)-1] = '\0';
	bool creation_success;

#ifdef WIN32
	/**
	 * docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
	 * CreateThread shouldn't be called by executables that call the CRT,
	 * _beginthreadex should be used instead. [Panikon]
	 * @see stackoverflow.com/a/331754 for a discussion on the subject
	 **/
	handle->hThread = (HANDLE)_beginthreadex(NULL, stack_size,
		thread_main_redirector, handle, 0, NULL);
	creation_success = (handle->hThread != NULL);
	if(!creation_success) {
		ShowError("thread_create_opt: failed to create new thread (entry_point: %p) "
			"error: %ld\n", GetLastError());
	}
#else
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, stack_size);

	int retval = pthread_create(&handle->hThread, &attr, thread_main_redirector, handle);
	creation_success = (retval != 0);
	pthread_attr_destroy(&attr);
	if(!creation_success) {
		ShowError("thread_create_opt: failed to create new thread (entry_point: %p) "
			"error: %d\n", retval);
	}
#endif
	if(!creation_success) {
		mutex->lock(l_threads_mutex);
		handle->proc = NULL;
		handle->param = NULL;
		handle->status = THREADSTATUS_CLEAN;
		mutex->unlock(l_threads_mutex);
	}

	// There's no need to do a context switch if the priority
	// won't be changed
	if(prio != THREADPRIO_NORMAL)
		thread->prio_set(handle,  prio);

	InterlockedIncrement(&l_threads_count);
	return handle;
}

/// @copydoc thread_interface::destroy()
static void thread_destroy(struct thread_handle *handle)
{
#ifdef WIN32
	if (TerminateThread(handle->hThread, 0) != FALSE) {
		CloseHandle(handle->hThread);
		thread_terminated(handle);
	}
#else
	if (pthread_cancel(handle->hThread) == 0) {
		// We have to join it, otherwise pthread wont re-cycle its internal resources assoc. with this thread.
		pthread_join(handle->hThread, NULL);

		// Tell our manager to release resources ;)
		thread_terminated(handle);
	}
#endif
}

static struct thread_handle *thread_self(void)
{
	struct thread_handle *handle = &l_threads[g_thread_id];

	if (handle->proc != NULL) // entry point set, so its used!
		return handle;

	return NULL;
}

/// @copydoc thread_interface::get_tid()
static int thread_get_tid(void)
{
	return g_thread_id;
}

/// @copydoc thread_interface::wait_multiple
static bool thread_wait_multiple(struct thread_handle *handle[], int count, void **out_exit_code)
{
	bool retval = true;
	int failed_ret_count = 0;
#ifdef WIN32
	for(int i = 0; i < count; i++) {
		/**
		 * WaitForSingleObject was chosen because even if a handle becomes invalid
		 * while waiting we can still recover and wait for the others in the list,
		 * and there are no hard limits to the number of objects we can wait without
		 * having to resort to creating another waiting thread.
		 **/
		DWORD wait_result = WaitForSingleObject(handle[i]->hThread, INFINITE);
		if(wait_result != WAIT_OBJECT_0) {
			DWORD error_code = GetLastError();
			if(error_code == ERROR_INVALID_HANDLE && handle[i]->status != THREADSTATUS_RUN)
				continue; // Thread probably already ended
			ShowError("thread_wait_multiple(%d/%d): "
				"Failed to wait for thread[%d] %s, wait_result %ld, error code %ld\n",
				i, count-1, handle[i]->myID, handle[i]->name, wait_result, GetLastError());
			failed_ret_count++;
		}
	}
#else
	// TODO: Test
	for(int i = 0; i < count; i++) {
		int ret = pthread_join(handle[i]->hThread, NULL);
		if(ret != 0) {
			ShowError("thread_wait_multiple(%d/%d): Failed to wait for thread[%d] %s, error: %d\n",
				i, count-1, handle[i]->myID, handle[i]->name, ret);
			failed_ret_count++;
			// Continue trying to join remaining threads
		}
	}
#endif
	if(failed_ret_count == count)
		retval = false;
	if(out_exit_code) {
		for(int i = 0; i < count; i++)
			out_exit_code[i] = handle[i]->result;
	}
	return retval;
}

/// @copydoc thread_interface::wait()
static bool thread_wait(struct thread_handle *handle, void **out_exit_code)
{
	// Hint:
	// no thread data cleanup routine call here!
	// its managed by the callProxy itself..
	bool retval = true;

#ifdef WIN32
	WaitForSingleObject(handle->hThread, INFINITE);
#else
	if (pthread_join(handle->hThread, NULL))
		retval = false;
#endif
	if(out_exit_code)
		*out_exit_code = handle->result;
	return retval;
}

/// @copydoc thread_interface::prio_set()
static void thread_prio_set(struct thread_handle *handle, enum thread_priority prio)
{
	assert(prio < THREADPRIO_LAST && prio >= 0);
	handle->prio = prio;
#ifdef _WIN32
	if(!SetThreadPriority(handle->hThread, thread_dynamic_priority[prio])) {
		ShowError("thread_prio_set: Failed to set new priority (%d) for thread[%d] %s, error %ld\n",
			prio, handle->myID, handle->name, GetLastError());
	}
#else
	// TODO: Test
	errno = 0;
	if(setpriority(PRIO_PROCESS, gettid(), thread_dynamic_priority[prio]) && errno) {
		ShowError("thread_prio_set: Failed to set new priority (%d) for thread[%d] %s, errno %d\n",
			prio, handle->myID, handle->name, errno);
	}
#endif
}

/// @copydoc thread_interface::prio_get()
static enum thread_priority thread_prio_get(struct thread_handle *handle)
{
	return handle->prio;
}

/// @copydoc thread_interface::yield()
static void thread_yield(void)
{
#ifdef WIN32
	SwitchToThread();
#else
	sched_yield();
#endif
}

/// Interface base initialization.
void thread_defaults(void)
{
	thread = &thread_s;
	thread->init = thread_init;
	thread->final = thread_final;
	thread->create = thread_create;
	thread->create_opt = thread_create_opt;
	thread->exit = thread_exit;
	thread->destroy = thread_destroy;
	thread->self = thread_self;
	thread->get_tid = thread_get_tid;
	thread->wait = thread_wait;
	thread->wait_multiple = thread_wait_multiple;
	thread->name_set = thread_name_set;
	thread->name_get = thread_name_get;
	thread->prio_set = thread_prio_set;
	thread->prio_get = thread_prio_get;
	thread->yield = thread_yield;
	thread->count = thread_count;
}
