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

#include "common/atomic.h"
#include "common/cbasetypes.h"
#include "common/core.h"
#include "common/thread.h"
#include "common/rwlock.h"
#include "common/showmsg.h"
#include "common/nullpo.h"
#include "common/utils.h"
#include "common/ers.h"
#include "common/memmgr.h"
#include "common/timer.h"
#include "common/mutex.h"

#include "test/test_entry.h"

#include <stdio.h>
#include <stdlib.h>


//
// Timer unit testing
//

int timer_unit_mod(struct timer_interface *tm, int tid, int64 tick, int id, intptr_t data) {
	if(id >= 0)
		tm->add(tick, timer_unit_mod, -1, data);
	if(data) {
		int *counter = (int*)data;
		InterlockedIncrement(counter);
	}
	return 0;
}

/**
 * Tests timer modification inside timer function
 **/
bool timer_unit_modification(void *not_used) {
	int timer_executed = 0;
	int tid;
	for(int i = 0; i < 100; i++) {
		tid = timer->add_sub(timer->gettick(), timer_unit_mod, i, (intptr_t)&timer_executed,
			(i+1)*100, TIMER_ONCE_AUTODEL);
		TEST_ASSERT(tid != INVALID_TIMER, "Failed to create timer");
	}
	// Idle
	int64 start = timer->gettick();
	while(timer->gettick() < start+200+(100)*100) {};
	TEST_ASSERT(InterlockedExchangeAdd(&timer_executed, 0) == 200, "Insufficient number of timers");
	return true;
}

int timer_unit_func(struct timer_interface *tm, int tid, int64 tick, int id, intptr_t data) {
	bool *value = (bool*)data;
	if(data)
		value[id] = true;
	return 0;
}

/**
 * Tests basic setup of timers
 **/
bool timer_unit_setup(void *not_used) {
	int tid, ret;

	timer->add_func_list(timer_unit_func, "timer_unit_func");

	ShowInfo("timer_unit_setup: Test double timer removal, expecting failed assertion\n");
	tid = timer->add(timer->gettick(), timer_unit_func, 0, 0);
	ret = timer->delete(tid, timer_unit_func);
	TEST_ASSERT(ret == 0, "Failed to delete a new timer");
	ret = timer->delete(tid, timer_unit_func);
	TEST_ASSERT(ret == -2, "Found deleted timer");

	bool data[10] = {0};
	for(int i = 0; i < sizeof(data)/sizeof(*data); i++) {
		tid = timer->add_sub(timer->gettick(), timer_unit_func, i, (intptr_t)&data,
			(i+1)*100, TIMER_ONCE_AUTODEL);
		TEST_ASSERT(tid != INVALID_TIMER, "Failed to create timer");
	}
	// Idle
	int64 start = timer->gettick();
	while(timer->gettick() < start+200+((sizeof(data)/sizeof(*data))*100)) {};

	int not_ran = 0;
	for(int i = 0; i < sizeof(data)/sizeof(*data); i++) {
		if(!data[i])
			not_ran++;
	}
	TEST_ASSERT(not_ran == 0, "Timer function failed to change provided value");
	return true;
} 

/**
 * Adds timer tests to the provided suite
 **/
struct s_test_suite *test_timer_add(struct s_test_suite *test) {
	test = test_add(test, timer_unit_setup, "Timer setup", NULL);
	test = test_add(test, timer_unit_modification, "Timer modification", NULL);
	return test;
}
