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
 *
 * This test sequence is based on Unit tests for GRWLock by Matthias Clasen (c) 2011 LGPL-2.1
 */

/**
 * Test suite entry point
 *
 * The suite acts as a server (SERVER_TYPE_UNKNOWN)
 **/
#define HERCULES_CORE

#include "common/atomic.h"
#include "common/cbasetypes.h"
#include "common/core.h"
#include "common/memmgr.h"
#include "common/thread.h"
#include "common/rwlock.h"
#include "common/showmsg.h"
#include "common/nullpo.h"
#include "common/utils.h"

#include "test/test_entry.h"

#include <stdlib.h>

/**
 * Test information (single linked list)
 **/
struct s_test_suite {
	char name[127];             //< Name
	test_function_t function;   //< Entry function
	void *data;                 //< Entry function parameter
	struct s_test_suite *next;
};

/**
 * Executes all tests in provided suite and frees allocated data
 **/
void test_do(struct s_test_suite *test) {
	ShowStatus("Begin execution\n");
	while(test) {
		struct s_test_suite *old;
		bool result;
		ShowStatus(CL_BT_WHITE"%s\n"CL_NONE, test->name);
		result = test->function(test->data);
		if(result)
			ShowMessage(CL_BT_GREEN "\t\tPASS\n" CL_NONE);
		else
			ShowMessage(CL_BT_RED "\t\tFAIL\n" CL_NONE);
		old = test;
		test = test->next;
		aFree(old);
	}
	ShowStatus("Finished executing\n");
}

/**
 * Adds a test to provided test suite
 *
 * @return Last added test
 **/
struct s_test_suite *test_add(struct s_test_suite *test, test_function_t function,
	const char *name, void *data
) {
	assert(!test->next);
	struct s_test_suite *new_test = aCalloc(1, sizeof(*test->next));
	assert(new_test);
	strcpy(new_test->name, name);
	new_test->function = function;
	new_test->data = data;
	test->next = new_test;
	return new_test;
}

/**
 * Server entry point
 **/
int do_init(int argc, char **argv) {
	ShowMessage(CL_BT_WHITE"\n[Hercules test suite]\n"CL_NONE);
	struct s_test_suite first = {0};
	struct s_test_suite *current = &first;

	current = test_timer_add(current);
	//current = test_rwlock_add(current);
	//current = test_ers_add(current);
	//showmsg->silent |= MSG_DEBUG;
	test_do(first.next);

	core->runflag = CORE_ST_STOP;
	return EXIT_SUCCESS;
}

void do_abort(void) {
}

void set_server_type(void) {
	SERVER_TYPE = SERVER_TYPE_UNKNOWN;
}

int do_final(void) {
	ShowStatus("==========\n");

	return EXIT_SUCCESS;
}

int parse_console(const char* command){
	return 0;
}

void cmdline_args_init_local(void) {
}
