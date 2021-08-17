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

#include "common/cbasetypes.h"
#include "common/showmsg.h"
#include "common/utils.h"
#include "common/memmgr.h"
#include "common/db.h"
#include "common/mutex.h"

#include "test/test_entry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//
// Miscellaneous unit testing
//

#define QUEUE_INSERTION_COUNT 200
/**
 * Tests FIFO property
 **/
bool queue_unit_fifo(void *not_used) {
	int i;
	QUEUE_DECL(int) int_queue = QUEUE_STATIC_INITIALIZER;
	for(i = 1; i <= QUEUE_INSERTION_COUNT; i++)
		QUEUE_ENQUEUE(int_queue, i, 2);
	TEST_ASSERT(QUEUE_LENGTH(int_queue) == QUEUE_INSERTION_COUNT, "Insufficient length");

	for(i = 1; i <= 50; i++)
		QUEUE_DEQUEUE(int_queue);

	while(QUEUE_LENGTH(int_queue)) {
		int dequeue_value;
		dequeue_value = QUEUE_FRONT(int_queue);
		QUEUE_DEQUEUE(int_queue);
		TEST_ASSERT(dequeue_value == i, "Dequeued invalid value");
		i++;
	}
	QUEUE_CLEAR(int_queue);
	return true;
}


/**
 * Adds miscellaneous tests to the provided suite
 **/
struct s_test_suite *test_misc_add(struct s_test_suite *test) {
	test = test_add(test, queue_unit_fifo, "QUEUE FIFO", NULL);
	return test;
}
