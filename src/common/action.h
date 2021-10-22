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
#ifndef COMMON_ACTION_H
#define COMMON_ACTION_H

#include "common/hercules.h"

/**
 * Action function
 * Function to be executed upon dequeual of an action data object.
 **/
typedef void (*ActionFunc)(void *data);

struct s_action_queue;

/// The action interface
struct action_interface {
	int32_t (*ready)(void);

	void (*enqueue)(struct s_action_queue *queue, ActionFunc perform, void *data);
	bool (*queue_set)(struct socket_data *session, int32_t queue_id);
	struct s_action_queue *(*queue_get_random) (void);
	struct s_action_queue *(*queue_get)(struct socket_data *session);
	struct s_action_queue *(*queue_get_id)(int32_t queue_id);
	uint32_t (*queue_get_index)(struct s_action_queue *queue);
	int32 (*queue_index) (void);
	void (*queue_destroy)(struct s_action_queue *queue);
	struct s_action_queue *(*queue_create)(int initial_capacity, struct ers_collection_t *collection, void (*init) (void *param), void *init_param, void (*final) (void *param), void *final_param);

	void (*queue_final)(void);
	void (*queue_init)(void);
};

#ifdef HERCULES_CORE
void action_defaults(void);
#endif // HERCULES_CORE

HPShared struct action_interface *action; ///< Pointer to the thread interface.

#endif /* COMMON_ACTION_H */
