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
#define HERCULES_CORE

#include "timer.h"

#include "common/cbasetypes.h"
#include "common/db.h"
#include "common/memmgr.h"
#include "common/nullpo.h"
#include "common/showmsg.h"
#include "common/utils.h"

#ifdef TIMER_USE_THREAD
#include "common/thread.h"
#include "common/rwlock.h"
#include "common/mutex.h"
#include "common/action.h"
#include "common/socket.h"
#endif

#ifdef WIN32
#	include "common/winapi.h" // GetTickCount()
#else
#	include <sys/time.h> // struct timeval, gettimeofday()
#	include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct timer_interface timer_s;
struct timer_interface *timer;

#ifdef TIMER_USE_THREAD
/**
 * Interface to be used by timer functions
 *
 * This is a copy of timer_s but without any of the
 * *_thread functions.
 * All functions in this interface do not try to
 * reacquire any locks.
 **/
static struct timer_interface timer_thread_s;
#endif
/**
 * Pointer to interface that's passed to timer functions
 * When TIMER_USE_THREAD is set this is a pointer to timer_thread_s,
 * otherwise this is the same as timer.
 **/
struct timer_interface *tm;

// If the server can't handle processing thousands of monsters
// or many connected clients, please increase TIMER_MIN_INTERVAL.
#define TIMER_MIN_INTERVAL 50
#define TIMER_MAX_INTERVAL 1000

// timers (array)
static struct TimerData* timer_data = NULL;
static int timer_data_max = 0;
static int timer_data_num = 1;

// free timers (array)
static int *free_timer_list = NULL;
static int free_timer_list_max = 0;
static int free_timer_list_pos = 0;

// Thread state
#ifdef TIMER_USE_THREAD
struct thread_handle *timer_thread_handle = NULL;
struct mutex_data *timer_perform_mutex = NULL;
struct mutex_data *timer_shutdown_mutex = NULL;
struct cond_data *timer_shutdown_event = NULL;
bool timer_run = true;
#endif


/// Comparator for the timer heap. (minimum tick at top)
/// Returns negative if tid1's tick is smaller, positive if tid2's tick is smaller, 0 if equal.
///
/// @param tid1 First timer
/// @param tid2 Second timer
/// @return negative if tid1 is top, positive if tid2 is top, 0 if equal
#define DIFFTICK_MINTOPCMP(tid1,tid2) DIFF_TICK(timer_data[tid1].tick,timer_data[tid2].tick)

// timer heap (binary heap of tid's)
static BHEAP_VAR(int, timer_heap);


// server startup time
static time_t start_time;


/*----------------------------
 * Timer debugging
 *----------------------------*/
static struct timer_func_list {
	struct timer_func_list* next;
	TimerFunc func;
	char* name;
} *tfl_root = NULL;

/**
 * Sets the name of a timer function.
 *
 * This is not strictly required in order to add a timer with this function
 * 'attached', the function list is used when the server is reporting errors.
 **/
static void timer_add_func_list(TimerFunc func, char *name)
{
	struct timer_func_list* tfl;

	nullpo_retv(func);
	nullpo_retv(name);
	if (name) {
		for( tfl=tfl_root; tfl != NULL; tfl=tfl->next )
		{// check suspicious cases
			if( func == tfl->func )
				ShowWarning("timer_add_func_list: duplicating function %p(%s) as %s.\n",
					tfl->func,tfl->name,name);
			else if( strcmp(name,tfl->name) == 0 )
				ShowWarning("timer_add_func_list: function %p has the same name as %p(%s)\n",
					func,tfl->func,tfl->name);
		}
		CREATE(tfl,struct timer_func_list,1);
		tfl->next = tfl_root;
		tfl->func = func;
		tfl->name = aStrdup(name);
		tfl_root = tfl;
	}
}

/// Returns the name of the timer function.
static char *search_timer_func_list(TimerFunc func)
{
	struct timer_func_list* tfl;

	for( tfl=tfl_root; tfl != NULL; tfl=tfl->next )
		if (func == tfl->func)
			return tfl->name;

	return "unknown timer function";
}

/*----------------------------
 * Get tick time
 *----------------------------*/

#if defined(ENABLE_RDTSC)
static uint64 RDTSC_BEGINTICK = 0;
static uint64 RDTSC_CLOCK = 0;

static __inline uint64 rdtsc_(void)
{
	register union {
		uint64 qw;
		uint32 dw[2];
	} t;

	asm volatile("rdtsc":"=a"(t.dw[0]), "=d"(t.dw[1]) );

	return t.qw;
}

static void rdtsc_calibrate(void)
{
	uint64 t1, t2;
	int32 i;

	ShowStatus("Calibrating Timer Source, please wait... ");

	RDTSC_CLOCK = 0;

	for(i = 0; i < 5; i++){
		t1 = rdtsc_();
		usleep(1000000); //1000 MS
		t2 = rdtsc_();
		RDTSC_CLOCK += (t2 - t1) / 1000;
	}
	RDTSC_CLOCK /= 5;

	RDTSC_BEGINTICK = rdtsc_();

	ShowMessage(" done. (Frequency: %u Mhz)\n", (uint32)(RDTSC_CLOCK/1000) );
}

#endif

/**
 * platform-abstracted tick retrieval
 * @return server's current tick in milliseconds
 */
static int64 sys_tick(void)
{
#if defined(WIN32)
#ifdef ENABLE_PERFORMANCE_COUNTER
	/**
	 * Windows high-resolution timer (number of counts)
	 * @see docs.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamp
	 *
	 * QPS activation can lead to performance degradation in systems with
	 * AMD Cool'n'Quiet technology enabled in the BIOS.
	 * @see docs.microsoft.com/en-us/troubleshoot/windows-server/performance/programs-queryperformancecounter-function-perform-poorly
	 **/
	static LARGE_INTEGER frequency_cache = {0};
	static bool has_qps = true;
	if(!frequency_cache.HighPart && has_qps) {
		has_qps = QueryPerformanceFrequency(&frequency_cache);
		if(!has_qps)
			ShowWarning("sys_tick: high-resolution timing not supported,"
				" falling back to low resolution\n");
	}

	if(has_qps) {
		LARGE_INTEGER ticks;
		// When QueryPerformanceCounter is available it does not fail.
		QueryPerformanceCounter(&ticks);
		ticks.QuadPart *= 1000;
		ticks.QuadPart /= frequency_cache.QuadPart;
		return ticks.QuadPart;
	} // Fall-back to GetTickCount if QPS is unavailable
#endif
	// Windows: GetTickCount/GetTickCount64: Return the number of
	//   milliseconds that have elapsed since the system was started.

	// GetTickCount64 is only available in Windows Vista / Windows Server
	//   2008 or newer. Since we still support older versions, this runtime
	//   check is required in order not to crash.
	// http://msdn.microsoft.com/en-us/library/windows/desktop/ms724411%28v=vs.85%29.aspx
	static bool first = true;
	static ULONGLONG (WINAPI *pGetTickCount64)(void) = NULL;

	if( first ) {
		HMODULE hlib = GetModuleHandle(TEXT("KERNEL32.DLL"));
		if( hlib != NULL )
			pGetTickCount64 = (ULONGLONG (WINAPI *)(void))GetProcAddress(hlib, "GetTickCount64");
		first = false;
	}
	if (pGetTickCount64)
		return (int64)pGetTickCount64();
	// 32-bit fall back. Note: This will wrap around every ~49 days since system startup!!!
	return (int64)GetTickCount();
#elif defined(ENABLE_RDTSC)
	// RDTSC: Returns the number of CPU cycles since reset. Unreliable if
	//   the CPU frequency is variable.
	return (int64)((rdtsc_() - RDTSC_BEGINTICK) / RDTSC_CLOCK);
#elif defined(HAVE_MONOTONIC_CLOCK)
	// Monotonic clock: Implementation-defined.
	//   Clock that cannot be set and represents monotonic time since some
	//   unspecified starting point.  This clock is not affected by
	//   discontinuous jumps in the system time (e.g., if the system
	//   administrator manually changes the  clock),  but  is  affected by
	//   the  incremental adjustments performed by adjtime(3) and NTP.
	struct timespec tval;
	clock_gettime(CLOCK_MONOTONIC, &tval);
	// int64 cast to avoid overflows on platforms where time_t is 32 bit
	return (int64)tval.tv_sec * 1000 + tval.tv_nsec / 1000000;
#else
	// Fall back, regular clock: Number of milliseconds since epoch.
	//   The time returned by gettimeofday() is affected by discontinuous
	//   jumps in the system time (e.g., if the system  administrator
	//   manually  changes  the system time).  If you need a monotonically
	//   increasing clock, see clock_gettime(2).
	struct timeval tval;
	gettimeofday(&tval, NULL);
	// int64 cast to avoid overflows on platforms where time_t is 32 bit
	return (int64)tval.tv_sec * 1000 + tval.tv_usec / 1000;
#endif
}

//////////////////////////////////////////////////////////////////////////
#if defined(TICK_CACHE) && TICK_CACHE > 1
//////////////////////////////////////////////////////////////////////////
// tick is cached for TICK_CACHE calls
static int64 gettick_cache;
static int gettick_count = 1;

static int64 timer_gettick_nocache(void)
{
	gettick_count = TICK_CACHE;
	gettick_cache = sys_tick();
	return gettick_cache;
}

static int64 timer_gettick(void)
{
	return ( --gettick_count == 0 ) ? gettick_nocache() : gettick_cache;
}
//////////////////////////////
#else
//////////////////////////////
// tick doesn't get cached
static int64 timer_gettick_nocache(void)
{
	return sys_tick();
}

static int64 timer_gettick(void)
{
	return sys_tick();
}
//////////////////////////////////////////////////////////////////////////
#endif
//////////////////////////////////////////////////////////////////////////

/*======================================
 * CORE : Timer Heap
 *--------------------------------------*/

/**
 * Adds a timer to the timer_heap
 * @mutex timer_perform_mutex
 **/
static void push_timer_heap(int tid)
{
	BHEAP_ENSURE(timer_heap, 1, 256);
	BHEAP_PUSH(timer_heap, tid, DIFFTICK_MINTOPCMP, swap);
}

/*==========================
 * Timer Management
 *--------------------------*/

/**
 * Returns a free timer id.
 * @mutex timer_perform_mutex
 **/
static int acquire_timer(void)
{
	int tid;

	// select a free timer
	if (free_timer_list_pos) {
		do {
			tid = free_timer_list[--free_timer_list_pos];
		} while(tid >= timer_data_num && free_timer_list_pos > 0);
	} else
		tid = timer_data_num;

	// check available space
	if( tid >= timer_data_num )
		// possible timer_data null pointer
		for (tid = timer_data_num; tid < timer_data_max && timer_data[tid].type; tid++);
	if (tid >= timer_data_num && tid >= timer_data_max)
	{// expand timer array
		timer_data_max += 256;
		if( timer_data )
			RECREATE(timer_data, struct TimerData, timer_data_max);
		else
			CREATE(timer_data, struct TimerData, timer_data_max);
		memset(timer_data + (timer_data_max - 256), 0, sizeof(struct TimerData)*256);
	}

	if( tid >= timer_data_num )
		timer_data_num = tid + 1;

	return tid;
}

/**
 * Starts a new timer.
 *
 * @param tick      Starting tick.
 * @param id        General purpose storage.
 * @param data      General purpose storage.
 * @param interval  Timer interval
 * @param type      Timer flag (@see timer flags)
 * @param target    Target thread (@see enum timer_target)
 * @param target_id Target id (session or action id depending on target)
 * @return Timer id
 * @retval INVALID_TIMER in failure
 * @mutex timer_perform_mutex
 **/
static int timer_add_sub(int64 tick, TimerFunc func, int id,
	intptr_t data, int interval, unsigned char type, unsigned char target,
	int32_t target_id)
{
	int tid;
	nullpo_retr(INVALID_TIMER, func);

	if (interval < 1) {
		ShowError("timer_add_sub: invalid interval (tick=%"PRId64" %p[%s] id=%d data=%"PRIdPTR" diff_tick=%"PRId64")\n",
		          tick, func, search_timer_func_list(func), id, data, DIFF_TICK(tick, timer->gettick()));
		return INVALID_TIMER;
	}

	tid = acquire_timer();
	if (timer_data[tid].type != 0 && timer_data[tid].type != TIMER_REMOVE_HEAP)
	{
		ShowError("timer_add_sub: wrong tid type: %d, [%d]%p(%s) -> %p(%s)\n",
			timer_data[tid].type, tid, func, search_timer_func_list(func),
			timer_data[tid].func, search_timer_func_list(timer_data[tid].func));
		Assert_retr(INVALID_TIMER, 0);
	}
	if (timer_data[tid].func != NULL)
	{
		ShowError("timer_add_sub: func non NULL: [%d]%p(%s) -> %p(%s)\n",
			tid, func, search_timer_func_list(func), timer_data[tid].func,
			search_timer_func_list(timer_data[tid].func));
		Assert_retr(INVALID_TIMER, 0);
	}
	timer_data[tid].tick          = tick;
	timer_data[tid].func          = func;
	timer_data[tid].id            = id;
	timer_data[tid].data          = data;
	timer_data[tid].type          = type;
	timer_data[tid].interval      = interval;
	timer_data[tid].timer_target  = target;
	timer_data[tid].target_id     = target_id;
	push_timer_heap(tid);

	return tid;
}

/**
 * Starts a new timer that is deleted once it expires (single-use).
 *
 * @param tick     Starting tick.
 * @param id       General purpose storage.
 * @param data     General purpose storage.
 * @return Timer id
 * @retval INVALID_TIMER in failure
 * @see timer_add_sub
 **/
static int timer_add(int64 tick, TimerFunc func, int id, intptr_t data)
{
	return timer->add_sub(tick, func, id, data, 1000, TIMER_ONCE_AUTODEL, TIMER_THREAD, 0);
}

/**
 * Starts a new timer that automatically restarts itself
 * (infinite loop until manually removed)
 *
 * @param tick     Starting tick.
 * @param id       General purpose storage.
 * @param data     General purpose storage.
 * @param interval Timer interval
 * @return Timer id
 * @retval INVALID_TIMER in failure
 * @see timer_add_sub
 **/
static int timer_add_interval(int64 tick, TimerFunc func, int id, intptr_t data, int interval)
{
	return timer->add_sub(tick, func, id, data, interval, TIMER_INTERVAL, TIMER_THREAD, 0);
}

/**
 * Retrieves internal timer data by copy
 *
 * @mutex timer_perfom_mutex
 **/
static const struct TimerData timer_get(int tid)
{
	/**
	 * Why return by copy? This way the callee can be sure of the ownership
	 * of the data and that the obtained timer specific data (except the general
	 * purpose storage) won't change. The previous implementation was already
	 * using a const pointer, so not much of the behavior will change [Panikon]
	 **/
	Assert_retr((struct TimerData){0}, tid > 0);
	return ( tid >= 0 && tid < timer_data_num ) ? timer_data[tid] : (struct TimerData){0};
}

/**
 * Marks a timer specified by 'id' for immediate deletion once it expires
 *
 * @param tid Timer id to be deleted
 * @param func used for debug/verification purposes
 * @retval 0 Success
 * @retval -1 No such timer
 * @retval -2 Function mismatch
 * @retval -3 Already deleted
 * @mutex timer_perfom_mutex
 **/
static int timer_do_delete(int tid, TimerFunc func)
{
	nullpo_retr(-2, func);

	if (tid < 1 || tid >= timer_data_num) {
		ShowError("timer_do_delete error : no such timer [%d](%p(%s))\n", tid, func, search_timer_func_list(func));
		Assert_retr(-1, 0);
		return -1;
	}
	if( timer_data[tid].func != func ) {
		ShowError("timer_do_delete error : function mismatch [%d]%p(%s) != %p(%s)\n", tid, timer_data[tid].func, search_timer_func_list(timer_data[tid].func), func, search_timer_func_list(func));
		Assert_retr(-2, 0);
		return -2;
	}

	if (timer_data[tid].type == 0 || timer_data[tid].type == TIMER_REMOVE_HEAP)
	{
		ShowError("timer_do_delete: timer already deleted: %d, [%d]%p(%s) -> %p(%s)\n", timer_data[tid].type, tid, func, search_timer_func_list(func), func, search_timer_func_list(func));
		Assert_retr(-3, 0);
		return -3;
	}

	timer_data[tid].func = NULL;
	timer_data[tid].type = TIMER_ONCE_AUTODEL;

	return 0;
}

/**
 * Adjusts a timer's expiration time.
 *
 * @return New tick value, or -1 if it fails.
 * @see timer_settick
 **/
static int64 timer_addtick(int tid, int64 tick)
{
	if (tid < 1 || tid >= timer_data_num) {
		ShowError("timer_addtick error : no such timer [%d]\n", tid);
		Assert_retr(-1, 0);
		return -1;
	}
	return timer->settick(tid, timer_data[tid].tick+tick);
}

/**
 * Modifies a timer's expiration time (an alternative to deleting a timer and starting a new one).
 *
 * @param tid  The timer ID.
 * @param tick New expiration time.
 * @return The new tick value.
 * @retval -1 in case of failure.
 * @mutex timer_perform_mutex
 */
static int64 timer_settick(int tid, int64 tick)
{
	int i;

	// search timer position
	ARR_FIND(0, BHEAP_LENGTH(timer_heap), i, BHEAP_DATA(timer_heap)[i] == tid);
	if (i == BHEAP_LENGTH(timer_heap)) {
		ShowError("timer_settick: no such timer [%d](%p(%s))\n", tid, timer_data[tid].func, search_timer_func_list(timer_data[tid].func));
		Assert_retr(-1, 0);
		return -1;
	}

	if (timer_data[tid].type == 0 || timer_data[tid].type == TIMER_REMOVE_HEAP) {
		ShowError("timer_settick error: set tick for deleted timer %d, [%d](%p(%s))\n", timer_data[tid].type, tid, timer_data[tid].func, search_timer_func_list(timer_data[tid].func));
		Assert_retr(-1, 0);
		return -1;
	}
	if (timer_data[tid].func == NULL) {
		ShowError("timer_settick error: set tick for timer with wrong func [%d](%p(%s))\n", tid, timer_data[tid].func, search_timer_func_list(timer_data[tid].func));
		Assert_retr(-1, 0);
		return -1;
	}

	if( tick == -1 )
		tick = 0; // add 1ms to avoid the error value -1

	if( timer_data[tid].tick == tick )
		return tick; // nothing to do, already in proper position

	// pop and push adjusted timer
	BHEAP_POPINDEX(timer_heap, i, DIFFTICK_MINTOPCMP, swap);
	timer_data[tid].tick = tick;
	BHEAP_PUSH(timer_heap, tid, DIFFTICK_MINTOPCMP, swap);
	return tick;
}

#ifdef TIMER_USE_THREAD
// @copydoc timer_add_func_list
static void timer_add_func_list_guard(TimerFunc func, char *name)
{
	mutex->lock(timer_perform_mutex);
	timer_add_func_list(func, name);
	mutex->unlock(timer_perform_mutex);
}

/**
 * @copydoc timer_add_sub
 * @remarks Adds mutex guards to timer_add_sub calls
 **/
static int timer_add_sub_guard(int64 tick, TimerFunc func, int id,
	intptr_t data, int interval, unsigned char type, unsigned char target,
	int32_t target_id
) {
	int tid;
	mutex->lock(timer_perform_mutex);
	tid = timer_add_sub(tick, func, id, data, interval, type, target, target_id);
	mutex->unlock(timer_perform_mutex);
	return tid;
}

/**
 * @copydoc timer_addtick
 * @remarks Instead of using timer as the interface uses tm
 **/
static int64 timer_addtick_tm(int tid, int64 tick)
{
	if (tid < 1 || tid >= timer_data_num) {
		ShowError("timer_addtick error : no such timer [%d]\n", tid);
		Assert_retr(-1, 0);
		return -1;
	}
	return tm->settick(tid, timer_data[tid].tick+tick);
}

/**
 * @copydoc timer_add
 * @remarks Instead of using timer as the interface uses tm
 **/
static int timer_add_tm(int64 tick, TimerFunc func, int id, intptr_t data)
{
	return tm->add_sub(tick, func, id, data, 1000, TIMER_ONCE_AUTODEL, TIMER_THREAD, 0);
}

/**
 * @copydoc timer_add_interval
 * @remarks Instead of using timer as the interface uses tm
 **/
static int timer_add_interval_tm(int64 tick, TimerFunc func, int id, intptr_t data, int interval)
{
	return tm->add_sub(tick, func, id, data, interval, TIMER_INTERVAL, TIMER_THREAD, 0);
}

/**
 * @copydoc timer_do_delete
 * @remarks Adds mutex guards
 **/
static int timer_do_delete_guard(int tid, TimerFunc func)
{
	int ret;
	mutex->lock(timer_perform_mutex);
	ret = timer_do_delete(tid, func);
	mutex->unlock(timer_perform_mutex);
	return ret;
}

/**
 * @copydoc timer_get
 * @remarks Adds mutex guards to timer_get calls
 **/
static const struct TimerData timer_get_guard(int tid)
{
	struct TimerData td;
	mutex->lock(timer_perform_mutex);
	td = ( tid >= 0 && tid < timer_data_num ) ? timer_data[tid] : (struct TimerData){0};
	mutex->unlock(timer_perform_mutex);
	return td;
}

/**
 * @copydoc timer_add_sub
 * @remarks Adds mutex guards to timer_settick calls
 **/
static int64 timer_settick_guard(int tid, int64 tick)
{
	int64 ret;
	mutex->lock(timer_perform_mutex);
	ret = timer_settick(tid, tick);
	mutex->unlock(timer_perform_mutex);
	return tid;
}

#endif

/**
 * Returns timer mutex when TIMER_USE_THREAD is defined
 **/
static struct mutex_data *timer_get_mutex(void)
{
#ifdef TIMER_USE_THREAD
	return timer_perform_mutex;
#else
	return NULL;
#endif
}

struct s_timer_action_data {
	int tid;
	struct TimerData data;
};

/**
 * Point of entry of Timer action in action workers
 * @see do_timer
 **/
static void action_timer(void *data)
{
	struct s_timer_action_data *act = data;
	if(!act->data.func) {
		ShowDebug("action_timer: Dequeued timer without associated function\n");
		return;
	}
	act->data.func(timer, act->tid,
		timer->get_server_tick(),
		act->data.id, act->data.data);
	aFree(act);
}

/**
 * Executes all expired timers.
 *
 * @param tick The current tick.
 * @return The value of the smallest non-expired timer (or 1 second if there aren't any).
 * @mutex timer_perform_mutex
 */
static int do_timer(int64 tick)
{
	int64 diff = TIMER_MAX_INTERVAL; // return value

	// process all timers one by one
	while (BHEAP_LENGTH(timer_heap) > 0) {
		int tid = BHEAP_PEEK(timer_heap);// top element in heap (smallest tick)

		diff = DIFF_TICK(timer_data[tid].tick, tick);
		if( diff > 0 )
			break; // no more expired timers to process

		// remove timer
		BHEAP_POP(timer_heap, DIFFTICK_MINTOPCMP, swap);
		timer_data[tid].type |= TIMER_REMOVE_HEAP;

#ifdef TIMER_USE_THREAD
		if(timer_data[tid].func) {
			struct s_action_queue *target_queue = NULL;
			switch(timer_data[tid].timer_target) {
				case TIMER_THREAD:
					if( diff < -1000 )
						// timer was delayed for more than 1 second, use current tick instead
						timer_data[tid].func(tm, tid, tick, timer_data[tid].id, timer_data[tid].data);
					else
						timer_data[tid].func(tm, tid, timer_data[tid].tick, timer_data[tid].id,
							timer_data[tid].data);
					break;
				case TIMER_SESSION:
				{
					struct socket_data *session = socket_io->session_from_id(timer_data[tid].target_id);
					if(session) // Otherwise session was already removed
						target_queue = action->queue_get(session);
				}
				case TIMER_ACTION:
					target_queue = action->queue_get_id(timer_data[tid].target_id);
			}
			if(target_queue) {
				/**
				 * We can't guarantee that this timer id will still be valid when
				 * the action is processed by the action worker.
				 **/
				struct s_timer_action_data *timer_action = aMalloc(sizeof(*timer_action));
				memcpy(&timer_action->data, &timer_data[tid], sizeof(timer_data[tid]));
				timer_action->tid = tid;
				action->enqueue(target_queue, action_timer, timer_action);
			}
		}
#else
		if( timer_data[tid].func ) {
			if( diff < -1000 )
				// timer was delayed for more than 1 second, use current tick instead
				timer_data[tid].func(tm, tid, tick, timer_data[tid].id, timer_data[tid].data);
			else
				timer_data[tid].func(tm, tid, timer_data[tid].tick, timer_data[tid].id, timer_data[tid].data);
		}
#endif
		// in the case the function didn't change anything...
		if( timer_data[tid].type & TIMER_REMOVE_HEAP ) {
			timer_data[tid].type &= ~TIMER_REMOVE_HEAP;

			switch( timer_data[tid].type ) {
				default:
				case TIMER_ONCE_AUTODEL:
					timer_data[tid].type = 0;
					timer_data[tid].func = NULL;
					if (free_timer_list_pos >= free_timer_list_max) {
						free_timer_list_max += 256;
						RECREATE(free_timer_list,int,free_timer_list_max);
						memset(free_timer_list + (free_timer_list_max - 256), 0, 256 * sizeof(int));
					}
					free_timer_list[free_timer_list_pos++] = tid;
				break;
				case TIMER_INTERVAL:
					if( DIFF_TICK(timer_data[tid].tick, tick) < -1000 )
						timer_data[tid].tick = tick + timer_data[tid].interval;
					else
						timer_data[tid].tick += timer_data[tid].interval;
					push_timer_heap(tid);
				break;
			}
		}
	}

	return (int)cap_value(diff, TIMER_MIN_INTERVAL, TIMER_MAX_INTERVAL);
}

static unsigned long timer_get_uptime(void)
{
	return (unsigned long)difftime(time(NULL), start_time);
}

#ifdef TIMER_USE_THREAD

static int server_tick = 0;

/**
 * Returns last tick of the timer thread
 * @see do_timer
 **/
int timer_get_server_tick(void)
{
	return InterlockedExchangeAdd(&server_tick, 0);
}

/**
 * Timer worker thread
 **/
void *timer_thread(void *not_used)
{
	mutex->lock(timer_shutdown_mutex);
	while(timer_run) {
		int next_tick;
		mutex->cond_wait(timer_shutdown_event, timer_shutdown_mutex, TIMER_MIN_INTERVAL);
		mutex->lock(timer_perform_mutex);
		next_tick = timer->perform(timer->gettick_nocache());
		mutex->unlock(timer_perform_mutex);
		InterlockedExchange(&server_tick, next_tick);
	}
	mutex->unlock(timer_shutdown_mutex);
	return NULL;
}

/**
 * Cleans up timer thread state
 **/
static void timer_thread_cleanup(void)
{
	if(timer_shutdown_mutex)
		mutex->destroy(timer_shutdown_mutex);
	if(timer_perform_mutex)
		mutex->destroy(timer_perform_mutex);
	if(timer_shutdown_event)
		mutex->cond_destroy(timer_shutdown_event);

	timer_perform_mutex  = NULL;
	timer_shutdown_mutex = NULL;
	timer_shutdown_event = NULL;
}

/**
 * Sends shutdown signal to timer thread
 **/
static void timer_thread_shutdown(void)
{
	ShowInfo("Timer thread shutdown signal...\n");
	mutex->lock(timer_shutdown_mutex);
	timer_run = false;
	mutex->cond_signal(timer_shutdown_event);
	mutex->unlock(timer_shutdown_mutex);

	thread->wait(timer_thread_handle, NULL);
	ShowInfo("Timer thread terminated successfuly\n");
	timer_thread_handle = NULL;
}

/**
 * Initializes timer thread state
 **/
static void timer_thread_init(void)
{
	timer_perform_mutex = mutex->create();
	timer_shutdown_mutex = mutex->create();
	timer_shutdown_event = mutex->cond_create();
	if(!timer_perform_mutex || !timer_shutdown_mutex || !timer_shutdown_event) {
		ShowFatalError("timer_thread_init: Failed to setup thread state!\n");
		exit(EXIT_FAILURE);
	}
	timer_thread_handle = thread->create("Timer", timer_thread, NULL);
	if(!timer_thread_handle) {
		ShowFatalError("timer_thread_init: Could not begin timer_thread!\n");
		exit(EXIT_FAILURE);
	}
	ShowInfo("Started timer thread\n");
}

#endif // TIMER_USE_THREAD

static void timer_init(void)
{
#if defined(ENABLE_RDTSC)
	rdtsc_calibrate();
#endif

	time(&start_time);
#ifdef TIMER_USE_THREAD
	timer_thread_init();
#endif
}

static void timer_final(void)
{
	struct timer_func_list *tfl;
	struct timer_func_list *next;

#ifdef TIMER_USE_THREAD
	timer_thread_shutdown();
	mutex->lock(timer_perform_mutex); // Stop any timer handling by other threads
#endif

	for( tfl=tfl_root; tfl != NULL; tfl = next ) {
		next = tfl->next; // copy next pointer
		aFree(tfl->name); // free structures
		aFree(tfl);
	}

	if (timer_data) aFree(timer_data);
	BHEAP_CLEAR(timer_heap);
	if (free_timer_list) aFree(free_timer_list);

#ifdef TIMER_USE_THREAD
	mutex->unlock(timer_perform_mutex);
	timer_thread_cleanup();
#endif
}

/*=====================================
 * Default Functions : timer.h
 * Generated by HerculesInterfaceMaker
 * created by Susu
 *-------------------------------------*/
void timer_defaults(void)
{
	timer = &timer_s;

	// Functions that don't access the time heap
	timer->gettick = timer_gettick;
	timer->gettick_nocache = timer_gettick_nocache;
	timer->get_uptime = timer_get_uptime;
	timer->perform = do_timer;
	timer->init = timer_init;
	timer->final = timer_final;
	timer->get_mutex = timer_get_mutex;
	/**
	 * Functions with time heap access
	 * The functions that aren't replaced by the *_guard alternatives are the
	 * ones that internally make calls directly to the timer-> interface. They're
	 * also the ones that need *_tm replacements in order to change their
	 * behavior when calling them from the unguarded interface.
	 **/
#ifdef TIMER_USE_THREAD
	timer->delete  = timer_do_delete_guard;
	timer->settick = timer_settick_guard;
	timer->add_sub = timer_add_sub_guard;
	timer->add_func_list = timer_add_func_list_guard;
	timer->get = timer_get_guard;
#else
	timer->delete = timer_do_delete;
	timer->add_sub = timer_add_sub;
	timer->settick = timer_settick;
	timer->add_func_list = timer_add_func_list;
	timer->get = timer_get;
#endif
	timer->add = timer_add;
	timer->add_interval = timer_add_interval;
	timer->addtick = timer_addtick;

#ifdef TIMER_USE_THREAD
	tm = &timer_thread_s;
	memcpy(&timer_thread_s, &timer, sizeof(timer_thread_s));

	tm->delete        = timer_do_delete;
	tm->settick       = timer_settick;
	tm->add_sub       = timer_add_sub;
	tm->add_func_list = timer_add_func_list;
	tm->get           = timer_get;

	tm->add           = timer_add_tm;
	tm->add_interval  = timer_add_interval_tm;
	tm->addtick       = timer_addtick_tm;
#else
	tm = timer;
#endif
}
