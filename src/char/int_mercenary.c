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
#define HERCULES_CORE

#include "int_mercenary.h"

#include "char/char.h"
#include "char/inter.h"
#include "char/mapif.h"
#include "common/cbasetypes.h"
#include "common/memmgr.h"
#include "common/mmo.h"
#include "common/nullpo.h"
#include "common/showmsg.h"
#include "common/socket.h"
#include "common/sql.h"
#include "common/strlib.h"
#include "common/utils.h"

#include <stdio.h>
#include <stdlib.h>

static struct inter_mercenary_interface inter_mercenary_s;
struct inter_mercenary_interface *inter_mercenary;

static bool inter_mercenary_owner_fromsql(int char_id, struct mmo_charstatus *status)
{
	char* data;
	struct Sql *sql_handle = inter->sql_handle_get();

	nullpo_ret(status);
	if( SQL_ERROR == SQL->Query(sql_handle, "SELECT `merc_id`, `arch_calls`, `arch_faith`, `spear_calls`, `spear_faith`, `sword_calls`, `sword_faith` FROM `%s` WHERE `char_id` = '%d'", mercenary_owner_db, char_id) )
	{
		Sql_ShowDebug(sql_handle);
		return false;
	}

	if( SQL_SUCCESS != SQL->NextRow(sql_handle) )
	{
		SQL->FreeResult(sql_handle);
		return false;
	}

	SQL->GetData(sql_handle,  0, &data, NULL); status->mer_id = atoi(data);
	SQL->GetData(sql_handle,  1, &data, NULL); status->arch_calls = atoi(data);
	SQL->GetData(sql_handle,  2, &data, NULL); status->arch_faith = atoi(data);
	SQL->GetData(sql_handle,  3, &data, NULL); status->spear_calls = atoi(data);
	SQL->GetData(sql_handle,  4, &data, NULL); status->spear_faith = atoi(data);
	SQL->GetData(sql_handle,  5, &data, NULL); status->sword_calls = atoi(data);
	SQL->GetData(sql_handle,  6, &data, NULL); status->sword_faith = atoi(data);
	SQL->FreeResult(sql_handle);

	return true;
}

/**
 * Saves mercenary data to database
 *
 * @retval 0 Success
 *
 * This function returns 0 upon success so it follows other 'tosql' functions [Panikon]
 **/
static int inter_mercenary_owner_tosql(int char_id, struct mmo_charstatus *status)
{
	struct Sql *sql_handle = inter->sql_handle_get();
	nullpo_ret(status);
	if( SQL_ERROR == SQL->Query(sql_handle,
		"REPLACE INTO `%s` (`char_id`, `merc_id`, `arch_calls`, `arch_faith`,"
		"`spear_calls`, `spear_faith`, `sword_calls`, `sword_faith`) "
		"VALUES ('%d', '%d', '%d', '%d', '%d', '%d', '%d', '%d')",
		mercenary_owner_db, char_id, status->mer_id, status->arch_calls,
		status->arch_faith, status->spear_calls, status->spear_faith,
		status->sword_calls, status->sword_faith)
	) {
		Sql_ShowDebug(sql_handle);
		return 1;
	}

	return 0;
}

static bool inter_mercenary_owner_delete(int char_id)
{
	struct Sql *sql_handle = inter->sql_handle_get();
	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `char_id` = '%d'", mercenary_owner_db, char_id) )
		Sql_ShowDebug(sql_handle);

	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `char_id` = '%d'", mercenary_db, char_id) )
		Sql_ShowDebug(sql_handle);

	return true;
}

/**
 * Creates a new mercenary with the given data.
 *
 * @remark
 *   The mercenary ID is expected to be 0, and will be filled with the newly
 *   assigned ID.
 *
 * @param[in,out] merc The new mercenary's data.
 * @retval false in case of errors.
 */
static bool inter_mercenary_create(struct s_mercenary *merc)
{
	struct Sql *sql_handle = inter->sql_handle_get();
	nullpo_retr(false, merc);
	Assert_retr(false, merc->mercenary_id == 0);

	if (SQL_ERROR == SQL->Query(sql_handle,
			"INSERT INTO `%s` (`char_id`,`class`,`hp`,`sp`,`kill_counter`,`life_time`) VALUES ('%d','%d','%d','%d','%u','%u')",
			mercenary_db, merc->char_id, merc->class_, merc->hp, merc->sp, merc->kill_count, merc->life_time)) {
		Sql_ShowDebug(sql_handle);
		return false;
	}
	merc->mercenary_id = (int)SQL->LastInsertId(sql_handle);

	return true;
}

/**
 * Saves an existing mercenary.
 *
 * @param merc The mercenary's data.
 * @retval false in case of errors.
 */
static bool inter_mercenary_save(const struct s_mercenary *merc)
{
	struct Sql *sql_handle = inter->sql_handle_get();
	nullpo_retr(false, merc);
	Assert_retr(false, merc->mercenary_id > 0);

	if (SQL_ERROR == SQL->Query(sql_handle,
			"UPDATE `%s` SET `char_id` = '%d', `class` = '%d', `hp` = '%d', `sp` = '%d', `kill_counter` = '%u', `life_time` = '%u' WHERE `mer_id` = '%d'",
			mercenary_db, merc->char_id, merc->class_, merc->hp, merc->sp, merc->kill_count, merc->life_time, merc->mercenary_id)) {
		Sql_ShowDebug(sql_handle);
		return false;
	}

	return true;
}

static bool inter_mercenary_load(int merc_id, int char_id, struct s_mercenary *merc)
{
	char* data;
	struct Sql *sql_handle = inter->sql_handle_get();

	nullpo_ret(merc);
	memset(merc, 0, sizeof(struct s_mercenary));
	merc->mercenary_id = merc_id;
	merc->char_id = char_id;

	if( SQL_ERROR == SQL->Query(sql_handle, "SELECT `class`, `hp`, `sp`, `kill_counter`, `life_time` FROM `%s` WHERE `mer_id` = '%d' AND `char_id` = '%d'", mercenary_db, merc_id, char_id) )
	{
		Sql_ShowDebug(sql_handle);
		return false;
	}

	if( SQL_SUCCESS != SQL->NextRow(sql_handle) )
	{
		SQL->FreeResult(sql_handle);
		return false;
	}

	SQL->GetData(sql_handle,  0, &data, NULL); merc->class_ = atoi(data);
	SQL->GetData(sql_handle,  1, &data, NULL); merc->hp = atoi(data);
	SQL->GetData(sql_handle,  2, &data, NULL); merc->sp = atoi(data);
	SQL->GetData(sql_handle,  3, &data, NULL); merc->kill_count = atoi(data);
	SQL->GetData(sql_handle,  4, &data, NULL); merc->life_time = atoi(data);
	SQL->FreeResult(sql_handle);
	if (chr->show_save_log)
		ShowInfo("Mercenary loaded (%d - %d).\n", merc->mercenary_id, merc->char_id);

	return true;
}

static bool inter_mercenary_delete(int merc_id)
{
	struct Sql *sql_handle = inter->sql_handle_get();
	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `mer_id` = '%d'", mercenary_db, merc_id) )
	{
		Sql_ShowDebug(sql_handle);
		return false;
	}

	return true;
}

static int inter_mercenary_sql_init(void)
{
	return 0;
}

static void inter_mercenary_sql_final(void)
{
	return;
}

void inter_mercenary_defaults(void)
{
	inter_mercenary = &inter_mercenary_s;

	inter_mercenary->owner_fromsql = inter_mercenary_owner_fromsql;
	inter_mercenary->owner_tosql = inter_mercenary_owner_tosql;
	inter_mercenary->owner_delete = inter_mercenary_owner_delete;

	inter_mercenary->sql_init = inter_mercenary_sql_init;
	inter_mercenary->sql_final = inter_mercenary_sql_final;

	inter_mercenary->create = inter_mercenary_create;
	inter_mercenary->load = inter_mercenary_load;
	inter_mercenary->save = inter_mercenary_save;
	inter_mercenary->delete = inter_mercenary_delete;
}
