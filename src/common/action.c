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

#include "action.h"

#include "common/cbasetypes.h"
#include "common/showmsg.h"
#include "common/memmgr.h"
#include "common/ers.h"
#include "common/db.h"
#include "common/mutex.h"
#include "common/rwlock.h"
#include "common/thread.h"
#include "common/socket.h"
#include "common/random.h"
#include "common/utils.h"
#include "common/nullpo.h"

#include <stdlib.h>

static struct action_interface action_s;
struct action_interface *action;

/**
 * Action data
 * Data used in order to synchronize operations on a single thread via
 * an action queue.
 * @see action_enqueue
 **/
struct s_action_data {
	ActionFunc perform;
	void *data;
};

/**
 * Action queue
 * @mutex s_action_queue mutex
 * @see action_queue_create
 **/
struct s_action_queue {
	// FIFO queue
	QUEUE_DECL(struct s_action_data*) data;

	struct mutex_data *mutex;  //< Action queue mutex
	struct cond_data *dequeue; //< Condition to trigger a dequeue
	bool running;              //< Loop control
	ERS *action_ers;           //< ERS for new actions

	struct thread_handle *thread;//< Action worker thread (_only_ for waiting)
	uint32_t list_index;         //< Position in action_queue_list

	void (*init) (void *param);  //< First function to be executed by action thread
	void *init_param;            //< Parameter to init
	void (*final) (void *param); //< Last function to be executed by action thread
	void *final_param;           //< Parameter to final
};

/**
 * List of action queues
 **/
static INDEX_MAP_DECL(struct s_action_queue) action_queue_list = INDEX_MAP_STATIC_INITIALIZER(MEMORYTYPE_SHARED);
static struct mutex_data *action_queue_list_mutex = NULL;

/**
 * Action thread counter (protected by interlocked access)
 **/
static int32_t action_ready = 0;

static thread_local int32_t l_list_index = -1;

/**
 * Initial length of the action queue list (this number is multiplied by 32)
 * @see action_queue_init
 * @see INDEX_MAP_CREATE
 **/
#define ACTION_LIST_INITIAL_LENGTH 1

/**
 * Returns action_ready counter
 **/
static int32_t action_ready_get(void)
{
	return InterlockedExchangeAdd(&action_ready, 0);
}

/**
 * Enqueues an action to provided queue.
 *
 * @param queue   Action queue
 * @param perform Action to be performed
 * @param data    Data to be passed as parameter
 **/
void action_enqueue(struct s_action_queue *queue, ActionFunc perform, void *data)
{
	struct s_action_data *act;
	if(!queue) {
		ShowDebug("action_enqueue: Invalid queue\n");
		return;
	}
	mutex->lock(queue->mutex);

	rwlock->read_lock(queue->action_ers->collection_lock);
	mutex->lock(queue->action_ers->cache_mutex);
	act = ers_alloc(queue->action_ers);
	mutex->unlock(queue->action_ers->cache_mutex);
	rwlock->read_unlock(queue->action_ers->collection_lock);

	act->data = data;
	act->perform = perform;
	QUEUE_ENQUEUE(queue->data, act, 10);
	mutex->cond_broadcast(queue->dequeue);
	mutex->unlock(queue->mutex);
}

/**
 * Sets queue id for a session
 * @param session
 * @return Success (bool)
 * @mutex session->mutex
 **/
static bool action_queue_set(struct socket_data *session, int32_t queue_id)
{
	if(queue_id < 0)
		return false;
	if(queue_id >= INDEX_MAP_LENGTH(action_queue_list))
		return false;
	session->action_queue_id = queue_id;
	return true;
}

/**
 * Returns a random action queue
 * @return NULL No queues available
 **/
static struct s_action_queue *action_queue_get_random(void)
{
	struct s_action_queue *queue = NULL;
	int32_t empty_idx = INDEX_MAP_EMPTY(action_queue_list);
	int32_t rnd_idx = 0;

	if(empty_idx == 0) // No action queue available
		return NULL;

	if(empty_idx < 0)
		rnd_idx = rnd->value(0, INDEX_MAP_LENGTH(action_queue_list)-1);
	else
		rnd_idx = rnd->value(0, empty_idx-1);
	queue = INDEX_MAP_INDEX(action_queue_list, rnd_idx);
	if(queue)
		return queue;

	// Shouldn't happen
	ShowDebug("action_queue_get_random: Failed to find action queue\n");
	for(int i = 0; i < INDEX_MAP_LENGTH(action_queue_list); i++) {
		queue = INDEX_MAP_INDEX(action_queue_list, i);
		if(queue)
			return queue;
	}
	return NULL;
}

/**
 * Returns appropriate queue for a given session.
 * When session doesn't have any queue attached randomizes and attaches a queue.
 *
 * @param session
 * @return Action queue
 * @retval NULL Failed to find appropriate queue
 **/
static struct s_action_queue *action_queue_get(struct socket_data *session)
{
	if(session->action_queue_id < 0) {
		struct s_action_queue *queue = action->queue_get_random();
		if(queue)
			action->queue_set(session, action->queue_get_index(queue));
		return queue;
	}
	if(session->action_queue_id >= INDEX_MAP_LENGTH(action_queue_list))
		return NULL;
	return INDEX_MAP_INDEX(action_queue_list, session->action_queue_id);
}

/**
 * Returns pointer to queue with given id
 *
 * @return Action queue
 * @retval NULL Failed to find appropriate queue
 **/
static struct s_action_queue *action_queue_get_id(int32_t queue_id)
{
	if(queue_id < 0)
		return NULL;
	if(queue_id >= INDEX_MAP_LENGTH(action_queue_list))
		return NULL;
	return INDEX_MAP_INDEX(action_queue_list, queue_id);
}

/**
 * Returns index of given queue
 **/
static uint32 action_queue_get_index(struct s_action_queue *queue)
{
	return queue->list_index;
}

/**
 * Returns index of current thread
 * @return -1 Not a valid action thread
 **/
static int32 action_queue_index(void)
{
	// Only action workers
	if(!(thread->flag_get()&THREADFLAG_ACTION))
		return -1;
	return l_list_index;
}

/**
 * Worker thread
 *
 * Thread responsible for dequeuals for a given action queue.
 * Each thread executes part of the business logic for the server and can
 * block in an action if necessary unlike I/O workers.
 * @param param Action queue
 **/
static void *action_worker(void *param)
{
	struct s_action_queue *queue = param;
	nullpo_retr(NULL, queue);

	thread->flag_set(THREADFLAG_ACTION);
	InterlockedIncrement(&action_ready);
	VECTOR_DECL(struct s_action_data *) action_vector = VECTOR_STATIC_INITIALIZER;
	VECTOR_ENSURE_LOCAL(action_vector, QUEUE_CAPACITY(queue->data), 1);

	if(queue->init)
		queue->init(queue->init_param);

	while(queue->running) {
		struct s_action_data *act = NULL;
		mutex->lock(queue->mutex);
		if(!QUEUE_LENGTH(queue->data))
			mutex->cond_wait(queue->dequeue, queue->mutex, -1); // Block until new action

		while(QUEUE_LENGTH(queue->data)) {
			act = QUEUE_FRONT(queue->data);
			QUEUE_DEQUEUE(queue->data);
			if(!act)
				continue;
			/**
			 * Copy data to a private vector in order not to lock the queue for
			 * too long and also to minimize mutex calls when freeing each of the
			 * actions.
			 **/
			VECTOR_ENSURE_LOCAL(action_vector, 1, 5);
			VECTOR_PUSH(action_vector, act);
		}

		mutex->unlock(queue->mutex);
		if(!VECTOR_LENGTH(action_vector))
			continue; // Shutdown or mis-signal

		for(int i = 0; i < VECTOR_LENGTH(action_vector); i++) {
			act = VECTOR_INDEX(action_vector, i);
			if(act->perform)
				act->perform(act->data);
		}

		rwlock->read_lock(queue->action_ers->collection_lock);
		mutex->lock(queue->action_ers->cache_mutex);
		for(int i = 0; i < VECTOR_LENGTH(action_vector); i++) {
			act = VECTOR_INDEX(action_vector, i);
			ers_free(queue->action_ers, act);
		}
		mutex->unlock(queue->action_ers->cache_mutex);
		rwlock->read_unlock(queue->action_ers->collection_lock);

		VECTOR_TRUNCATE(action_vector);
	}
	if(queue->final)
		queue->final(queue->final_param);

	VECTOR_CLEAR_LOCAL(action_vector);
	InterlockedDecrement(&action_ready);
	ShowInfo("action_worker(%d): Shutting down! (thread id %d)\n",
		queue->list_index, thread->get_tid());
	return NULL;
}

/**
 * Shuts down action worker and then destroys an action queue.
 *
 * @param queue Action queue to be destroyed.
 * Acquires collection lock.
 **/
void action_queue_destroy(struct s_action_queue *queue)
{
	// Remove from list so no more actions are queued
	mutex->lock(action_queue_list_mutex);
	INDEX_MAP_REMOVE(action_queue_list, queue->list_index);
	mutex->unlock(action_queue_list_mutex);

	ShowInfo("Action worker (%d) shutdown signal\n", queue->list_index);

	mutex->lock(queue->mutex);
	queue->running = false;
	mutex->cond_signal(queue->dequeue);
	mutex->unlock(queue->mutex);

	thread->wait(queue->thread, NULL);

	QUEUE_CLEAR_SHARED(queue->data);
	mutex->destroy(queue->mutex);
	mutex->cond_destroy(queue->dequeue);

	struct rwlock_data *collection_lock = queue->action_ers->collection_lock;
	rwlock->write_lock(collection_lock);
	ers_destroy(queue->action_ers);
	rwlock->write_unlock(collection_lock);

	aFree(queue);
}

/**
 * Creates a new action queue.
 *
 * @param initial_capacity Initial queue length
 * @param collection       ERS collection to be used when generating action caches
 * @param init             First function to be executed by action thread (can be NULL)
 * @param init_param       Parameter to init
 * @param final            Last function to be executed by action thread (can be NULL)
 * @param final_param      Parameter to final
 * @return New queue
 * @retval NULL Failed to create new queue
 * Acquires collection lock
 * The collection must remain valid until thread shutdown
 **/
struct s_action_queue *action_queue_create(int initial_capacity,
	struct ers_collection_t *collection, void (*init) (void *param),
	void *init_param, void (*final) (void *param), void *final_param
) {
	struct s_action_queue *queue = aCalloc(1,sizeof(*queue));
	QUEUE_INIT_CAPACITY_SHARED(queue->data, initial_capacity);
	queue->mutex = mutex->create();
	if(!queue->mutex) {
		ShowError("action_queue_create: Failed to create queue mutex\n");
		goto cleanup;
	}
	queue->dequeue = mutex->cond_create();
	if(!queue->dequeue) {
		ShowError("action_queue_create: Failed to create queue condition\n");
		goto cleanup;
	}
	rwlock->write_lock(ers_collection_lock(collection));
	queue->action_ers = ers_new(collection, sizeof(struct s_action_data),
		                        "action::action_ers", ERS_OPT_NONE);
	rwlock->write_unlock(ers_collection_lock(collection));
	if(!queue->action_ers) {
		ShowError("action_queue_create: Failed to setup ERS\n");
		goto cleanup;
	}
	mutex->lock(action_queue_list_mutex);
	INDEX_MAP_ADD(action_queue_list, queue, queue->list_index);
	mutex->unlock(action_queue_list_mutex);
	l_list_index = queue->list_index;
	queue->running = true;
	queue->init = init;
	queue->init_param = init_param;
	queue->final = final;
	queue->final_param = final_param;
	queue->thread = thread->create("Action worker", action_worker, queue);
	if(!queue->thread) {
		ShowError("action_queue_create: Failed to create new thread\n");
		goto cleanup;
	}
	return queue;

cleanup:
	QUEUE_CLEAR_SHARED(queue->data);
	if(queue->mutex)
		mutex->destroy(queue->mutex);
	if(queue->dequeue)
		mutex->cond_destroy(queue->dequeue);
	if(queue->action_ers) {
		rwlock->write_lock(ers_collection_lock(collection));
		ers_destroy(queue->action_ers);
		rwlock->write_unlock(ers_collection_lock(collection));
	}
	aFree(queue);
	return NULL;
}

/**
 * Finalizes action queue
 **/
void action_queue_final(void)
{
	for(int i = 0; i < INDEX_MAP_LENGTH(action_queue_list); i++) {
		struct s_action_queue *queue = INDEX_MAP_INDEX(action_queue_list, i);
		if(!queue)
			continue;
		action_queue_destroy(queue);
	}
	mutex->destroy(action_queue_list_mutex);
	INDEX_MAP_DESTROY(action_queue_list);
}

/**
 * Initializes action queue
 **/
void action_queue_init(void)
{
	action_queue_list_mutex = mutex->create();
	if(!action_queue_list_mutex) {
		ShowFatalError("action_queue_init: Failed to create global mutex!\n");
		exit(EXIT_FAILURE);
	}
	INDEX_MAP_CREATE(action_queue_list, ACTION_LIST_INITIAL_LENGTH, MEMORYTYPE_SHARED);
}

/// Interface base initialization.
void action_defaults(void)
{
	action = &action_s;
	action->ready            = action_ready_get;
	action->enqueue          = action_enqueue;
	action->queue_set        = action_queue_set;
	action->queue_index      = action_queue_index;
	action->queue_get_random = action_queue_get_random;
	action->queue_get        = action_queue_get;
	action->queue_get_id     = action_queue_get_id;
	action->queue_get_index  = action_queue_get_index;
	action->queue_get        = action_queue_get;
	action->queue_destroy    = action_queue_destroy;
	action->queue_create     = action_queue_create;

	action->queue_final = action_queue_final;
	action->queue_init  = action_queue_init;
}
