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
#ifndef COMMON_RWLOCK_H
#define COMMON_RWLOCK_H

#include "common/hercules.h"

/**
 * Enable debug functionality in order to identify common deadlocks
 **/
#define RWLOCK_DEBUG

struct rwlock_data; //< Read-write lock

// Read-write lock interface
struct rwlock_interface {
	void (*read_unlock)(struct rwlock_data *rwlock);
	bool (*read_trylock)(struct rwlock_data *rwlock);
	void (*read_lock)(struct rwlock_data *rwlock);

	void (*write_unlock)(struct rwlock_data *rwlock);
	bool (*write_trylock)(struct rwlock_data *rwlock);
	void (*write_lock)(struct rwlock_data *rwlock);

	void (*destroy)(struct rwlock_data *rwlock);
	struct rwlock_data *(*create) (void);
};

#ifdef HERCULES_CORE
void rwlock_defaults(void);
#endif

HPShared struct rwlock_interface *rwlock; //< Pointer to the rwlock interface.

#endif /* COMMON_RWLOCK_H */
