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
#define HERCULES_CORE

#include "common/atomic.h"
#include "common/cbasetypes.h"
#include "common/core.h"
#include "common/thread.h"
#include "common/rwlock.h"
#include "common/showmsg.h"
#include "common/nullpo.h"
#include "common/utils.h"

#include "test/test_entry.h"

#include <stdio.h>
#include <stdlib.h>


//
// Read-write lock unit testing
//

/**
 * Tests write lock acquiral and release
 **/
static bool rwlock_unit_write(void *data) {
	struct rwlock_data *lock = rwlock->create();
	assert(lock);

	rwlock->write_lock(lock);
	rwlock->write_unlock(lock);
	rwlock->write_lock(lock);
	rwlock->write_unlock(lock);

	rwlock->destroy(lock);
	return true;
}

/**
 * Tests write lock acquiral and trylock
 **/
static bool rwlock_unit_write_try(void *data) {
	struct rwlock_data *lock = rwlock->create();
	bool ret;
	assert(lock);

	ret = rwlock->write_trylock(lock);
	TEST_ASSERT(ret, "Failed to get clean write lock");
	ret = rwlock->write_trylock(lock);
	TEST_ASSERT(!ret, "Got write lock with owner");
	rwlock->write_unlock(lock);

	rwlock->destroy(lock);
	return true;
}

/**
 * Tests read lock acquiral and release
 **/
static bool rwlock_unit_read(void *data) {
	struct rwlock_data *lock = rwlock->create();
	assert(lock);

	rwlock->read_lock(lock);
	rwlock->read_unlock(lock);
	rwlock->read_lock(lock);
	rwlock->read_unlock(lock);

	rwlock->destroy(lock);
	return true;
}

/**
 * Tests read lock acquiral and trylock
 **/
static bool rwlock_unit_read_try(void *data) {
	struct rwlock_data *lock = rwlock->create();
	bool ret;
	assert(lock);

	ret = rwlock->read_trylock(lock);
	TEST_ASSERT(ret, "Failed to get clean read lock");
	ret = rwlock->read_trylock(lock);
	TEST_ASSERT(ret, "Failed to reacquire read lock");
	rwlock->read_unlock(lock);

	rwlock->destroy(lock);
	return true;
}

/**
 * Tests failure states of read/write trylocks
 **/
static bool rwlock_unit_failure_try(void *data) {
	struct rwlock_data *lock = rwlock->create();
	bool ret;
	assert(lock);

	rwlock->write_lock(lock);
	ret = rwlock->read_trylock(lock);
	TEST_ASSERT(!ret, "Acquired read lock while write lock was set");
	rwlock->write_unlock(lock);

	rwlock->read_lock(lock);
	ret = rwlock->write_trylock(lock);
	TEST_ASSERT(!ret, "Acquired write lock while read lock was set");
	rwlock->read_unlock(lock);

	rwlock->destroy(lock);
	return true;
}

#define UNIT_RWLOCK_ACQUIRE_ITERATIONS 10000
#define UNIT_RWLOCK_ACQUIRE_LOCK_COUNT 48
#define UNIT_RWLOCK_ACQUIRE_THREAD_COUNT 10
static struct thread_handle *lock_owner[UNIT_RWLOCK_ACQUIRE_LOCK_COUNT];
static struct rwlock_data *lock[UNIT_RWLOCK_ACQUIRE_LOCK_COUNT];

/**
 * Verifies if the lock_owner was changed by another thread
 *
 * @param index Lock index to be acquired
 * @see rwlock_unit_acquire_thread_worker
 * @see rwlock_unit_acquire_concurrent
 **/
static bool rwlock_unit_acquire(int index) {
	struct thread_handle *self = thread->self();

	if(!rwlock->write_trylock(lock[index])) {
		ShowDebug("rwlock_unit_acquire: Thread %d blocking on lock %d\n",
			thread->get_tid(), index);
		rwlock->write_lock(lock[index]);
	}
	TEST_ASSERT(lock_owner[index] == NULL, "Acquired a lock with an owner");
	lock_owner[index] = self;

	// Let other threads try to change this owner
	thread->yield();
	thread->yield();
	thread->yield();

	TEST_ASSERT(lock_owner[index] == self, "Lost lock ownership after yield");
	lock_owner[index] = NULL;
	rwlock->write_unlock(lock[index]);
	return true;
}

/**
 * Worker thread for writer acquiral test
 *
 * @see rwlock_unit_acquire_concurrent
 **/
void *rwlock_unit_acquire_thread_worker(void *param) {
	bool *thread_result = param;
	srand(time(NULL));

	int failed_acquire = 0;
	for(int i = 0; i < UNIT_RWLOCK_ACQUIRE_ITERATIONS; i++) {
		if(!rwlock_unit_acquire(rand()%UNIT_RWLOCK_ACQUIRE_LOCK_COUNT))
			failed_acquire++;
	}
	*thread_result = (!failed_acquire);
	return NULL;
}

/**
 * Tests write lock with multiple concurrent threads
 *
 * Also tests mutex->cond_wait extensively
 **/
static bool rwlock_unit_acquire_concurrent(void *data) {
	struct thread_handle *threads[UNIT_RWLOCK_ACQUIRE_THREAD_COUNT];
	bool thread_result[UNIT_RWLOCK_ACQUIRE_THREAD_COUNT] = {0}; // out_exit_code is not set on WIN32
	int i;

	ShowDebug("rwlock_unit_acquire_concurrent: Setup locks (%d)\n",
		UNIT_RWLOCK_ACQUIRE_LOCK_COUNT);
	for(i = 0; i < UNIT_RWLOCK_ACQUIRE_LOCK_COUNT; i++) {
		lock[i] = rwlock->create();
		assert(lock[i]);
		lock_owner[i] = NULL;
	}

	ShowDebug("rwlock_unit_acquire_concurrent: Begin threads (%d), iteration count %d\n",
		UNIT_RWLOCK_ACQUIRE_THREAD_COUNT, UNIT_RWLOCK_ACQUIRE_ITERATIONS);
	for(i = 0; i < UNIT_RWLOCK_ACQUIRE_THREAD_COUNT; i++) {
		threads[i] = thread->create_opt("RWLOCK acquire", rwlock_unit_acquire_thread_worker,
			&thread_result[i],
			1024, THREADPRIO_NORMAL);
	}

	ShowDebug("rwlock_unit_acquire_concurrent: Waiting threads\n");
	thread->wait_multiple(threads, UNIT_RWLOCK_ACQUIRE_THREAD_COUNT, NULL);
	int failed_thread_count = 0;
	for(i = 0; i < UNIT_RWLOCK_ACQUIRE_THREAD_COUNT; i++) {
		if(!thread_result[i])
			failed_thread_count++;
	}
	ShowDebug("rwlock_unit_acquire_concurrent: Destroying locks\n");
	for(i = 0; i < UNIT_RWLOCK_ACQUIRE_LOCK_COUNT; i++)
		rwlock->destroy(lock[i]);

	TEST_ASSERT(failed_thread_count == 0, "Failure in acquiral thread");

	for(i = 0; i < UNIT_RWLOCK_ACQUIRE_LOCK_COUNT; i++)
		TEST_ASSERT(lock_owner[i] == NULL, "Owned lock found after destruction");
	ShowDebug("rwlock_unit_acquire_concurrent: Done\n");
	return true;
}

static struct rwlock_data *even_lock = NULL;
static int even;

static bool rwlock_unit_change_even(int number) {
	rwlock->write_lock(even_lock);
	TEST_ASSERT(even%2 == 0, "Received uneven value");

	even += 1;
	if(number == 0)
		even += 1;
	else
		even -= 1;

	TEST_ASSERT(even%2 == 0, "Value not even after operations");
	rwlock->write_unlock(even_lock);
	return true;
}

static bool rwlock_unit_verify_even(void) {
	rwlock->read_lock(even_lock);
	TEST_ASSERT(even%2 == 0, "Value was uneven upon verification");
	rwlock->read_unlock(even_lock);
	return true;
}

#define UNIT_RWLOCK_EVEN_ITERATIONS 10000

struct s_even_result {
	bool retval;
	int parameter;
};

static void *rwlock_unit_even_writer(void *data) {
	struct s_even_result *result = data;
	for(int i = 0; i < UNIT_RWLOCK_EVEN_ITERATIONS; i++)
		result->retval = rwlock_unit_change_even(result->parameter);
	return NULL;
}

static void *rwlock_unit_even_reader(void *data) {
	struct s_even_result *result = data;
	for(int i = 0; i < UNIT_RWLOCK_EVEN_ITERATIONS; i++)
		result->retval = rwlock_unit_verify_even();
	return NULL;
}

static bool rwlock_unit_concurrent_write(void *data) {
	struct thread_handle *thread_writer[2];
	struct s_even_result writer_result[2] = {0};
	struct thread_handle *thread_reader[10];
	struct s_even_result reader_result[10] = {0};

	even_lock = rwlock->create();

	int i;
	int writer_count = sizeof(thread_writer)/sizeof(*thread_writer);
	int reader_count = sizeof(thread_reader)/sizeof(*thread_reader);

	for(i = 0; i < writer_count; i++)
		thread_writer[i] = thread->create("RWLOCK writer", rwlock_unit_even_writer,
			&writer_result[i]);
	for(i = 0; i < reader_count; i++)
		thread_reader[i] = thread->create("RWLOCK reader", rwlock_unit_even_reader,
			&reader_result[i]);

	int failed_thread_count = 0;
	thread->wait_multiple(thread_writer, writer_count, NULL);
	thread->wait_multiple(thread_reader, reader_count, NULL);
	for(i = 0; i < writer_count; i++) {
		if(!writer_result[i].retval)
			failed_thread_count++;
	}
	for(i = 0; i < reader_count; i++) {
		if(!reader_result[i].retval)
			failed_thread_count++;
	}

	TEST_ASSERT(even%2 == 0, "Uneven number after thread operations");
	TEST_ASSERT(failed_thread_count == 0, "Failure in thread");

	rwlock->destroy(even_lock);
	return true;
}

/**
 * Adds read-write lock tests to the provided suite
 **/
struct s_test_suite *test_rwlock_add(struct s_test_suite *test) {
	test = test_add(test, rwlock_unit_write,               "RWLOCK Write", NULL);
	test = test_add(test, rwlock_unit_write_try,           "RWLOCK Write try", NULL);
	test = test_add(test, rwlock_unit_read,                "RWLOCK Read", NULL);
	test = test_add(test, rwlock_unit_read_try,            "RWLOCK Read try", NULL);
	test = test_add(test, rwlock_unit_failure_try,         "RWLOCK Failure try", NULL);
	test = test_add(test, rwlock_unit_acquire_concurrent,  "RWLOCK Concurrent acquire", NULL);
	test = test_add(test, rwlock_unit_concurrent_write,    "RWLOCK Concurrent write", NULL);
	return test;
}
