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

#include "test/test_entry.h"

#include <stdio.h>
#include <stdlib.h>


//
// Entry Reusage System unit testing
//


/**
 * ERS worker thread
 *
 * Creates a new ERS instance and allocates memory.
 * @param param Initialized ers_collection_t object
 * @return Boolean thread success.
 **/
void *ers_unit_worker_instance_alloc(void *param) {
	ERS *instance;
	struct ers_collection_t *collection = param;
	struct rwlock_data *ers_list_lock = ers_global_lock();
	struct rwlock_data *collection_lock = ers_collection_lock(collection);
	TEST_ASSERT(ers_list_lock, "No global lock found!");
	TEST_ASSERT(collection_lock, "No collection lock!");

	rwlock->read_lock(ers_list_lock);
	rwlock->write_lock(collection_lock);
	instance = ers_new(collection, 32, "ers_leak_detection", ERS_OPT_FREE_NAME);
	TEST_ASSERT(instance, "Failed to setup new instance!");
	rwlock->write_unlock(collection_lock);
	thread->yield();

	void *allocated_memory[10];
	rwlock->read_lock(collection_lock);
	for(int i = 0; i < sizeof(allocated_memory)/sizeof(*allocated_memory); i++) {
		rwlock->write_lock(instance->cache_lock);
		thread->yield();
		allocated_memory[i] = instance->alloc(instance);
		TEST_ASSERT(allocated_memory[i], "Failed to allocate memory");
		rwlock->write_unlock(instance->cache_lock);
	}
	rwlock->read_unlock(collection_lock);
	thread->yield();
	rwlock->read_unlock(ers_list_lock);
	return (void*)true;
}

/**
 * Tests ERS reporting system
 **/
bool ers_unit_report(void *not_used) {
	struct ers_collection_t *collection;
	collection = ers_collection_create(MEMORYTYPE_SHARED);
	TEST_ASSERT(collection, "Failed to setup collection");

	struct thread_handle *threads[10] = {0};
	void *retval[10] = {NULL};
	for(int i = 0; i < sizeof(threads)/sizeof(*threads); i++) {
		threads[i] = thread->create_opt("ERS report", ers_unit_worker_instance_alloc,
			collection,
			1024, THREADPRIO_NORMAL);
	}

	int failure_count = 0;
	thread->wait_multiple(threads, sizeof(threads)/sizeof(*threads), retval);
	for(int i = 0; i < sizeof(threads)/sizeof(*threads); i++) {
		if(!(bool)retval[i])
			failure_count++;
	}
	ers_report();
	ers_collection_destroy(collection);
	return (failure_count == 0);
}

/**
 * ERS worker thread
 *
 * Creates a new ERS instance and tries memory management.
 * @param param Initialized ers_collection_t object
 * @return Boolean thread success.
 **/
void *ers_unit_worker_instance_creator(void *param) {
	ERS *instance;
	struct ers_collection_t *collection = param;
	struct rwlock_data *ers_list_lock = ers_global_lock();
	struct rwlock_data *collection_lock = ers_collection_lock(collection);
	TEST_ASSERT(ers_list_lock, "No global lock found!");
	TEST_ASSERT(collection_lock, "No collection lock!");

	rwlock->read_lock(ers_list_lock);
	rwlock->write_lock(collection_lock);
	instance = ers_new(collection, 32, "ers_leak_detection", ERS_OPT_FREE_NAME);
	TEST_ASSERT(instance, "Failed to setup new instance!");
	rwlock->write_unlock(collection_lock);
	thread->yield();

	void *allocated_memory[10];
	rwlock->read_lock(collection_lock);
	for(int i = 0; i < sizeof(allocated_memory)/sizeof(*allocated_memory); i++) {
		rwlock->write_lock(instance->cache_lock);
		thread->yield();
		allocated_memory[i] = instance->alloc(instance);
		TEST_ASSERT(allocated_memory[i], "Failed to allocate memory");
		rwlock->write_unlock(instance->cache_lock);
	}
	for(int i = 0; i < sizeof(allocated_memory)/sizeof(*allocated_memory); i++) {
		rwlock->write_lock(instance->cache_lock);
		instance->free(instance, allocated_memory[i]);
		rwlock->write_unlock(instance->cache_lock);
	}
	rwlock->read_unlock(collection_lock);
	thread->yield();

	rwlock->write_lock(collection_lock);
	int leak_count = instance->destroy(instance);
	TEST_ASSERT(leak_count == 0, "Leaks found in instance");
	rwlock->write_unlock(collection_lock);

	rwlock->read_unlock(ers_list_lock);
	return (void*)true;
}

/**
 * Concurrent creation and deletion of instances and caches
 **/
bool ers_unit_concurrent_creation(void *not_used) {
	struct ers_collection_t *collection;
	collection = ers_collection_create(MEMORYTYPE_SHARED);
	TEST_ASSERT(collection, "Failed to setup collection");

	struct thread_handle *threads[10] = {0};
	for(int i = 0; i < sizeof(threads)/sizeof(*threads); i++) {
		threads[i] = thread->create_opt("ERS concurrent", ers_unit_worker_instance_creator,
			collection,
			1024, THREADPRIO_NORMAL);
	}
	int failure_count = 0;
	for(int i = 0; i < sizeof(threads)/sizeof(*threads); i++) {
		void *ret;
		thread->wait(threads[i], &ret);
		if(!(bool)ret)
			failure_count++;
	}

	ers_collection_destroy(collection);
	return (failure_count == 0);
}

/**
 * Tests leak detection
 **/
bool ers_unit_leak_detection(void *not_used) {
	struct ers_collection_t *collection;
	ERS *ers;
	collection = ers_collection_create(MEMORYTYPE_SHARED);
	TEST_ASSERT(collection, "Failed to setup collection");

	ers = ers_new(collection, 32, "ers_leak_detection", ERS_OPT_FREE_NAME);
	TEST_ASSERT(ers, "Failed to setup new instance!");

	int expected_leak = 25;
	for(int i = 0; i < expected_leak; i++)
		TEST_ASSERT(ers->alloc(ers), "Failed to alloc memory for new entry");

	ShowInfo("ers_unit_leak_detection: %d leaks expected\n", expected_leak);
	int leak_count = ers->destroy(ers);
	TEST_ASSERT(leak_count == expected_leak, "Failed to identify correct ammount of leaks");
	ers_collection_destroy(collection);
	return true;
}

/**
 * Tests alloc and free
 **/
bool ers_unit_allocation(void *not_used) {
	struct ers_collection_t *collection;
	ERS *ers;
	collection = ers_collection_create(MEMORYTYPE_SHARED);
	TEST_ASSERT(collection, "Failed to setup collection");

	ers = ers_new(collection, 32, "ers_test", ERS_OPT_FREE_NAME);
	TEST_ASSERT(ers, "Failed to setup new instance!");

	void *new_entry = ers->alloc(ers);
	TEST_ASSERT(ers, "Failed to alloc memory for new entry");
	ers->free(ers, new_entry);

	ers->destroy(ers);
	ers_collection_destroy(collection);
	return true;
}

/**
 * Tests interface creation
 **/
bool ers_unit_setup_interface(void *not_used) {
	struct ers_collection_t *collection;
	ERS *ers;
	collection = ers_collection_create(MEMORYTYPE_SHARED);
	TEST_ASSERT(collection, "Failed to setup collection");

	ers = ers_new(collection, 32, "ers_test", ERS_OPT_FREE_NAME);
	TEST_ASSERT(ers, "Failed to setup new instance!");
	ers->destroy(ers);

	ERS *ers_multiple[5];
	for(int i = 0; i < sizeof(ers_multiple)/sizeof(*ers_multiple); i++)
		ers_multiple[i] = ers_new(collection, 32*i, "test_name", ERS_OPT_NONE);
	ers_collection_destroy(collection);
	return true;
}

/**
 * Tests collection setup
 **/
bool ers_unit_setup(void *not_used) {
	struct ers_collection_t *collection;
	collection = ers_collection_create(MEMORYTYPE_SHARED);
	TEST_ASSERT(collection, "Failed to setup collection");
	ers_collection_destroy(collection);

	struct ers_collection_t *collection_multiple[5];
	for(int i = 0; i < sizeof(collection_multiple)/sizeof(*collection_multiple); i++)
		collection_multiple[i] = ers_collection_create(MEMORYTYPE_SHARED);
	ers_final(MEMORYTYPE_SHARED);

	ers_init();
	for(int i = 0; i < sizeof(collection_multiple)/sizeof(*collection_multiple); i++)
		collection_multiple[i] = ers_collection_create(MEMORYTYPE_LOCAL);
	ers_final(MEMORYTYPE_LOCAL);

	ers_init();
	return true;
}

/**
 * Adds read-write lock tests to the provided suite
 **/
struct s_test_suite *test_ers_add(struct s_test_suite *test) {
	test = test_add(test, ers_unit_setup, "ERS setup", NULL);
	test = test_add(test, ers_unit_setup_interface, "ERS interface", NULL);
	test = test_add(test, ers_unit_allocation, "ERS alloc", NULL);
	test = test_add(test, ers_unit_leak_detection, "ERS leak detection", NULL);
	test = test_add(test, ers_unit_concurrent_creation, "ERS concurrent", NULL);
	test = test_add(test, ers_unit_report, "ERS report", NULL);
	return test;
}
