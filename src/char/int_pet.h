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
#ifndef CHAR_INT_PET_H
#define CHAR_INT_PET_H

#include "common/hercules.h"

struct s_pet;

/**
 * inter_pet interface
 **/
struct inter_pet_interface {
	int (*tosql) (const struct s_pet *p);
	bool (*fromsql) (int pet_id, struct s_pet* p);
	uint8 (*rename) (int pet_id, const char *esc_name);
	int (*sql_init) (void);
	void (*sql_final) (void);
	bool (*delete_) (int pet_id);

	bool (*load) (int account_id, int char_id, int pet_id, struct s_pet *out);
};

#ifdef HERCULES_CORE
void inter_pet_defaults(void);
#endif // HERCULES_CORE

HPShared struct inter_pet_interface *inter_pet;

#endif /* CHAR_INT_PET_H */
