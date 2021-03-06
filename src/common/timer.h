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
#ifndef COMMON_TIMER_H
#define COMMON_TIMER_H

#include "common/hercules.h"

#define DIFF_TICK(a,b) ((a)-(b))
#define DIFF_TICK32(a,b) ((int32)((a)-(b)))

/**
 * Multi-threaded timer heap
 *
 * When defined the timer functions are processed in a different thread
 * and all timer insertion / deletion are guarded by a lock.
 **/
#define TIMER_USE_THREAD

#define INVALID_TIMER (-1)

// timer flags
enum {
	TIMER_NOT_SET = 0x0,
	TIMER_ONCE_AUTODEL = 0x01,
	TIMER_INTERVAL = 0x02,
	TIMER_RESERVED = 0x04,
	TIMER_REMOVE_HEAP = 0x10,
};

enum timer_target {
	TIMER_THREAD,  //< Execute timer from timer thread
	TIMER_SESSION, //< Enqueue timer to the action worker of the session
	TIMER_ACTION,  //< Enqueue timer in provided action worker
};

/**
 * Timer entry function
 *
 * @param tm   Timer interface.
 *             All timer related functions inside a timer func must be called
 *             from the provided interface, otherwise there could be deadlocks.
 *             Even if TIMER_USE_THREAD is not defined, as to keep code portable.
 * @param tick Current tick
 * @param id   Id set when adding the timer (not the same as timer id!)
 * @param data General purpose storage
 **/
typedef int (*TimerFunc)(struct timer_interface *tm, int tid, int64 tick, int id, intptr_t data);

struct TimerData {
	int64 tick;
	TimerFunc func;
	unsigned char type;
	int interval;

	unsigned char timer_target;
	int32_t target_id; // Target id (session or action id depending on target)

	// general-purpose storage
	int id;
	intptr_t data;
};


/*=====================================
* Interface : timer.h
* Generated by HerculesInterfaceMaker
* created by Susu
*-------------------------------------*/
struct timer_interface {

	/* funcs */
	int64 (*gettick) (void);
	int64 (*gettick_nocache) (void);

	int (*add) (int64 tick, TimerFunc func, int id, intptr_t data);
	int (*add_interval) (int64 tick, TimerFunc func, int id, intptr_t data, int interval);
	int (*add_sub) (int64 tick, TimerFunc func, int id, intptr_t data,
		int interval, unsigned char type, unsigned char target, int32_t target_id);
	const struct TimerData (*get) (int tid);
	int (*delete) (int tid, TimerFunc func);

	struct mutex_data *(*get_mutex) (void);

	int64 (*addtick) (int tid, int64 tick);
	int64 (*settick) (int tid, int64 tick);

	void (*add_func_list) (TimerFunc func, char* name);

	unsigned long (*get_uptime) (void);

	void (*update) (int tid, int64 tick, bool acquire_lock);
	int (*perform) (int64 tick);
	void (*init) (void);
	void (*final) (void);
#ifdef TIMER_USE_THREAD
	int (*get_server_tick) (void);
#endif
};

#ifdef HERCULES_CORE
void timer_defaults(void);
#endif // HERCULES_CORE

HPShared struct timer_interface *timer;

#endif /* COMMON_TIMER_H */
