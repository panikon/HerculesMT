/**
* This file is part of Hercules.
* http://herc.ws - http://github.com/HerculesWS/Hercules
*
* Copyright (C) 2017-2021 Hercules Dev Team
* Copyright (C) Smokexyz
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

#include "int_achievement.h"

#include "char/char.h"
#include "char/inter.h"
#include "char/mapif.h"

#include "common/db.h"
#include "common/memmgr.h"
#include "common/mmo.h"
#include "common/nullpo.h"
#include "common/showmsg.h"
#include "common/socket.h"
#include "common/sql.h"
#include "common/strlib.h"
#include "common/mutex.h"

#include <stdio.h>
#include <stdlib.h>

static struct inter_achievement_interface inter_achievement_s;
struct inter_achievement_interface *inter_achievement;

/**
 * Saves changed achievements for a character.
 * @param[in]   char_id     character identifier.
 * @param[out]  cp          pointer to loaded achievements.
 * @param[in]   p           pointer to map-sent character achievements.
 * @return number of achievements saved.
 * @mutex char_achievements_mutex
 */
static int inter_achievement_tosql(int char_id, struct char_achievements *cp, const struct char_achievements *p)
{
	StringBuf buf;
	int i = 0, rows = 0;
	struct Sql *sql_handle = inter->sql_handle_get();

	nullpo_ret(cp);
	nullpo_ret(p);
	Assert_ret(char_id > 0);

	StrBuf->Init(&buf);
	StrBuf->Printf(&buf, "REPLACE INTO `%s` (`char_id`, `ach_id`, `completed_at`, `rewarded_at`", char_achievement_db);
	for (i = 0; i < MAX_ACHIEVEMENT_OBJECTIVES; i++)
		StrBuf->Printf(&buf, ", `obj_%d`", i);
	StrBuf->AppendStr(&buf, ") VALUES ");

	for (i = 0; i < VECTOR_LENGTH(*p); i++) {
		int j = 0;
		bool save = false;
		struct achievement *pa = &VECTOR_INDEX(*p, i), *cpa = NULL;

		ARR_FIND(0, VECTOR_LENGTH(*cp), j, ((cpa = &VECTOR_INDEX(*cp, j)) && cpa->id == pa->id));

		if (j == VECTOR_LENGTH(*cp))
			save = true;
		else if(cpa->id != pa->id || cpa->completed_at != pa->completed_at
		     || cpa->rewarded_at != pa->rewarded_at
			 || memcmp(cpa->objective, pa->objective, sizeof(cpa->objective))
			)
			save = true;

		if (save) {
			StrBuf->Printf(&buf, "%s('%d', '%d', '%"PRId64"', '%"PRId64"'", rows ?", ":"", char_id, pa->id, (int64)pa->completed_at, (int64)pa->rewarded_at);
			for (j = 0; j < MAX_ACHIEVEMENT_OBJECTIVES; j++)
				StrBuf->Printf(&buf, ", '%d'", pa->objective[j]);
			StrBuf->AppendStr(&buf, ")");
			rows++;
		}
	}

	if (rows > 0 && SQL_ERROR == SQL->QueryStr(sql_handle, StrBuf->Value(&buf))) {
		Sql_ShowDebug(sql_handle);
		StrBuf->Destroy(&buf); // Destroy the buffer.
		return 0;
	}
	// Destroy the buffer.
	StrBuf->Destroy(&buf);

	if (rows) {
		ShowInfo("achievements saved for char %d (total: %d, saved: %d)\n", char_id, VECTOR_LENGTH(*p), rows);

		/* Sync with inter-db acheivements. */
		VECTOR_CLEAR(*cp);
		VECTOR_ENSURE(*cp, VECTOR_LENGTH(*p), 1);
		VECTOR_PUSHARRAY(*cp, VECTOR_DATA(*p), VECTOR_LENGTH(*p));
	}

	return rows;
}

/**
 * Retrieves all achievements of a character.
 * @param[in]  char_id  character identifier.
 * @param[out] cp       pointer to character achievements structure.
 * @return true on success, false on failure.
 */
static bool inter_achievement_fromsql(int char_id, struct char_achievements *cp)
{
	StringBuf buf;
	char *data;
	int i = 0, num_rows = 0;
	struct Sql *sql_handle = inter->sql_handle_get();

	nullpo_ret(cp);

	Assert_ret(char_id > 0);

	// char_achievements (`char_id`, `ach_id`, `completed_at`, `rewarded_at`, `obj_0`, `obj_2`, ...`obj_9`)
	StrBuf->Init(&buf);
	StrBuf->AppendStr(&buf, "SELECT `ach_id`, `completed_at`, `rewarded_at`");
	for (i = 0; i < MAX_ACHIEVEMENT_OBJECTIVES; i++)
		StrBuf->Printf(&buf, ", `obj_%d`", i);
	StrBuf->Printf(&buf, " FROM `%s` WHERE `char_id` = '%d' ORDER BY `ach_id`", char_achievement_db, char_id);

	if (SQL_ERROR == SQL->QueryStr(sql_handle, StrBuf->Value(&buf))) {
		Sql_ShowDebug(sql_handle);
		StrBuf->Destroy(&buf);
		return false;
	}

	VECTOR_CLEAR(*cp);

	if ((num_rows = (int) SQL->NumRows(sql_handle)) != 0) {
		int j = 0;

		VECTOR_ENSURE(*cp, num_rows, 1);

		for (i = 0; i < num_rows && SQL_SUCCESS == SQL->NextRow(sql_handle); i++) {
			struct achievement t_ach = { 0 };
			SQL->GetData(sql_handle, 0, &data, NULL); t_ach.id = atoi(data);
			SQL->GetData(sql_handle, 1, &data, NULL); t_ach.completed_at = atoi(data);
			SQL->GetData(sql_handle, 2, &data, NULL); t_ach.rewarded_at = atoi(data);
			/* Objectives */
			for (j = 0; j < MAX_ACHIEVEMENT_OBJECTIVES; j++) {
				SQL->GetData(sql_handle, j + 3, &data, NULL);
				t_ach.objective[j] = atoi(data);
			}
			/* Add Entry */
			VECTOR_PUSH(*cp, t_ach);
		}
	}

	SQL->FreeResult(sql_handle);

	StrBuf->Destroy(&buf);

	if (num_rows > 0)
		ShowInfo("achievements loaded for char %d (total: %d)\n", char_id, num_rows);

	return true;
}

/**
 * Initialization function
 */
static int inter_achievement_sql_init(void)
{
	// Initialize the loaded db storage.
	// used as a comparand against map-server achievement data before saving.
	inter_achievement->char_achievements = idb_alloc(DB_OPT_RELEASE_DATA);
	return 1;
}

/**
 * This function ensures idb's entry.
 */
static struct DBData inter_achievement_ensure_char_achievements(const struct DBKey_s *key, va_list args)
{
	struct char_achievements *ca = NULL;

	CREATE(ca, struct char_achievements, 1);
	VECTOR_INIT(*ca);

	return DB->ptr2data(ca);
}

/**
 * Cleaning function called through db_destroy()
 */
static int inter_achievement_char_achievements_clear(const struct DBKey_s *key, struct DBData *data, va_list args)
{
	struct char_achievements *ca = DB->data2ptr(data);

	VECTOR_CLEAR(*ca);

	return 0;
}

/**
 * Finalization function.
 */
static void inter_achievement_sql_final(void)
{
	db_lock(inter_achievement->char_achievements, WRITE_LOCK);
	inter_achievement->char_achievements->destroy(
		inter_achievement->char_achievements,
		inter_achievement->char_achievements_clear);
}

/**
 * Inter-achievement interface.
 */
void inter_achievement_defaults(void)
{
	inter_achievement = &inter_achievement_s;
	/* */
	inter_achievement->ensure_char_achievements = inter_achievement_ensure_char_achievements;
	/* */
	inter_achievement->sql_init = inter_achievement_sql_init;
	inter_achievement->sql_final = inter_achievement_sql_final;
	/* */
	inter_achievement->tosql = inter_achievement_tosql;
	inter_achievement->fromsql = inter_achievement_fromsql;
	/* */
	inter_achievement->char_achievements_clear = inter_achievement_char_achievements_clear;
}
