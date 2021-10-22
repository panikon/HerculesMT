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

#include "int_pet.h"

#include "char/char.h"
#include "char/inter.h"
#include "char/mapif.h"
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

static struct inter_pet_interface inter_pet_s;
struct inter_pet_interface *inter_pet;

/**
 * Renames a pet
 *
 * @param esc_name Escaped and normalized name.
 * @retval 0 Successfuly updated name
 * @retval 3 Already renamed
 * @retval 4 Not found
 * @see mapif_parse_NameChangeRequest
 **/
static uint8 inter_pet_rename(int pet_id, const char *esc_name)
{
	struct Sql *sql_handle = inter->sql_handle_get();
	int sql_result = 
	SQL->Query(sql_handle,
		"UPDATE `%s` SET `name` = '%s', `rename_flag`='1' WHERE `pet_id` = '%d' AND `rename_flag` = '0'",
		pet_db, esc_name, pet_id);
	if(SQL_ERROR == sql_result) {
		Sql_ShowDebug(sql_handle);
		return 4; // Not found
	}
	if(SQL->NumAffectedRows(sql_handle) <= 0)
		return 3; // Already renamed

	return 0;
}

/**
 * Saves a pet to the SQL database.
 *
 * Table structure:
 * `pet` (`pet_id`, `class`, `name`, `account_id`, `char_id`, `level`, `egg_id`, `equip`, `intimate`, `hungry`, `rename_flag`, `incubate`, `autofeed`)
 *
 * @remark In case of newly created pet, the pet ID is not updated to reflect the newly assigned ID. The caller must do so.
 *
 * @param p The pet data to save.
 * @return The ID of the saved pet, or 0 in case of errors.
 *
 **/
static int inter_pet_tosql(const struct s_pet *p)
{
	nullpo_ret(p);
	struct Sql *sql_handle = inter->sql_handle_get();

	struct SqlStmt *stmt = SQL->StmtMalloc(sql_handle);

	if (stmt == NULL) {
		SqlStmt_ShowDebug(stmt);
		return 0;
	}

	int pet_id = 0;

	if (p->pet_id == 0) { // New pet.
		const char *query = "INSERT INTO `%s` "
			"(`class`, `name`, `account_id`, `char_id`, `level`, `egg_id`, `equip`, "
			"`intimate`, `hungry`, `rename_flag`, `incubate`, `autofeed`) "
			"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

		if (SQL_ERROR == SQL->StmtPrepare(stmt, query, pet_db) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 0, SQLDT_INT32, &p->class_, sizeof(p->class_)) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 1, SQLDT_STRING, &p->name, strnlen(p->name, sizeof(p->name))) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 2, SQLDT_INT32, &p->account_id, sizeof(p->account_id)) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 3, SQLDT_INT32, &p->char_id, sizeof(p->char_id)) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 4, SQLDT_INT16, &p->level, sizeof(p->level)) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 5, SQLDT_INT32, &p->egg_id, sizeof(p->egg_id)) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 6, SQLDT_INT32, &p->equip, sizeof(p->equip)) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 7, SQLDT_INT16, &p->intimate, sizeof(p->intimate)) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 8, SQLDT_INT16, &p->hungry, sizeof(p->hungry)) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 9, SQLDT_INT8, &p->rename_flag, sizeof(p->rename_flag)) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 10, SQLDT_INT8, &p->incubate, sizeof(p->incubate)) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 11, SQLDT_INT32, &p->autofeed, sizeof(p->autofeed)) ||
		    SQL_ERROR == SQL->StmtExecute(stmt)) {
			SqlStmt_ShowDebug(stmt);
			SQL->StmtFree(stmt);
			return 0;
		}

		pet_id = (int)SQL->LastInsertId(sql_handle);
	} else { // Update pet.
		const char *query = "UPDATE `%s` SET "
			"`class`=?, `name`=?, `account_id`=?, `char_id`=?, `level`=?, `egg_id`=?, `equip`=?, "
			"`intimate`=?, `hungry`=?, `rename_flag`=?, `incubate`=?, `autofeed`=? "
			"WHERE `pet_id`=?";

		if (SQL_ERROR == SQL->StmtPrepare(stmt, query, pet_db) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 0, SQLDT_INT32, &p->class_, sizeof(p->class_)) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 1, SQLDT_STRING, &p->name, strnlen(p->name, sizeof(p->name))) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 2, SQLDT_INT32, &p->account_id, sizeof(p->account_id)) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 3, SQLDT_INT32, &p->char_id, sizeof(p->char_id)) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 4, SQLDT_INT16, &p->level, sizeof(p->level)) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 5, SQLDT_INT32, &p->egg_id, sizeof(p->egg_id)) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 6, SQLDT_INT32, &p->equip, sizeof(p->equip)) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 7, SQLDT_INT16, &p->intimate, sizeof(p->intimate)) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 8, SQLDT_INT16, &p->hungry, sizeof(p->hungry)) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 9, SQLDT_INT8, &p->rename_flag, sizeof(p->rename_flag)) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 10, SQLDT_INT8, &p->incubate, sizeof(p->incubate)) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 11, SQLDT_INT32, &p->autofeed, sizeof(p->autofeed)) ||
		    SQL_ERROR == SQL->StmtBindParam(stmt, 12, SQLDT_INT32, &p->pet_id, sizeof(p->pet_id)) ||
		    SQL_ERROR == SQL->StmtExecute(stmt)) {
			SqlStmt_ShowDebug(stmt);
			SQL->StmtFree(stmt);
			return 0;
		}

		pet_id = p->pet_id;
	}

	SQL->StmtFree(stmt);

	if (chr->show_save_log)
		ShowInfo("Pet saved %d - %s.\n", pet_id, p->name);

	return pet_id;
}

/**
 * Loads a pet's data from the SQL database.
 *
 * Table structure:
 * `pet` (`pet_id`, `class`, `name`, `account_id`, `char_id`, `level`, `egg_id`, `equip`, `intimate`, `hungry`, `rename_flag`, `incubate`, `autofeed`)
 *
 * @param pet_id The pet's ID.
 * @param p The pet data to save the SQL data in, 0 initialized.
 * @return BOOL Success
 *
 **/
static bool inter_pet_fromsql(int pet_id, struct s_pet *p)
{
	struct Sql *sql_handle = inter->sql_handle_get();
	struct SqlStmt *stmt = SQL->StmtMalloc(sql_handle);

	if (stmt == NULL) {
		SqlStmt_ShowDebug(stmt);
		return false;
	}

#ifdef NOISY
	ShowInfo("Loading pet (%d)...\n",pet_id);
#endif

	const char *query = "SELECT "
		"`class`, `name`, `account_id`, `char_id`, `level`, `egg_id`, `equip`, "
		"`intimate`, `hungry`, `rename_flag`, `incubate`, `autofeed` "
		"FROM `%s` WHERE `pet_id`=?";

	if (SQL_ERROR == SQL->StmtPrepare(stmt, query, pet_db) ||
	    SQL_ERROR == SQL->StmtBindParam(stmt, 0, SQLDT_INT32, &pet_id, sizeof(pet_id)) ||
	    SQL_ERROR == SQL->StmtExecute(stmt) ||
	    SQL_ERROR == SQL->StmtBindColumn(stmt, 0, SQLDT_INT32, &p->class_, sizeof(p->class_), NULL, NULL) ||
	    SQL_ERROR == SQL->StmtBindColumn(stmt, 1, SQLDT_STRING, &p->name, sizeof(p->name), NULL, NULL) ||
	    SQL_ERROR == SQL->StmtBindColumn(stmt, 2, SQLDT_INT32, &p->account_id, sizeof(p->account_id), NULL, NULL) ||
	    SQL_ERROR == SQL->StmtBindColumn(stmt, 3, SQLDT_INT32, &p->char_id, sizeof(p->char_id), NULL, NULL) ||
	    SQL_ERROR == SQL->StmtBindColumn(stmt, 4, SQLDT_INT16, &p->level, sizeof(p->level), NULL, NULL) ||
	    SQL_ERROR == SQL->StmtBindColumn(stmt, 5, SQLDT_INT32, &p->egg_id, sizeof(p->egg_id), NULL, NULL) ||
	    SQL_ERROR == SQL->StmtBindColumn(stmt, 6, SQLDT_INT32, &p->equip, sizeof(p->equip), NULL, NULL) ||
	    SQL_ERROR == SQL->StmtBindColumn(stmt, 7, SQLDT_INT16, &p->intimate, sizeof(p->intimate), NULL, NULL) ||
	    SQL_ERROR == SQL->StmtBindColumn(stmt, 8, SQLDT_INT16, &p->hungry, sizeof(p->hungry), NULL, NULL) ||
	    SQL_ERROR == SQL->StmtBindColumn(stmt, 9, SQLDT_INT8, &p->rename_flag, sizeof(p->rename_flag), NULL, NULL) ||
	    SQL_ERROR == SQL->StmtBindColumn(stmt, 10, SQLDT_INT8, &p->incubate, sizeof(p->incubate), NULL, NULL) ||
	    SQL_ERROR == SQL->StmtBindColumn(stmt, 11, SQLDT_INT32, &p->autofeed, sizeof(p->autofeed), NULL, NULL)) {
		SqlStmt_ShowDebug(stmt);
		SQL->StmtFree(stmt);
		return false;
	}

	if (SQL->StmtNumRows(stmt) < 1) {
		ShowError("inter_pet_fromsql: Requested non-existant pet ID: %d\n", pet_id);
		SQL->StmtFree(stmt);
		return false;
	}

	if (SQL_ERROR == SQL->StmtNextRow(stmt)) {
		SqlStmt_ShowDebug(stmt);
		SQL->StmtFree(stmt);
		return false;
	}

	SQL->StmtFree(stmt);
	p->pet_id = pet_id;

	if (chr->show_save_log)
		ShowInfo("Pet loaded %d - %s.\n", pet_id, p->name);

	return true;
}
//----------------------------------------------

static int inter_pet_sql_init(void)
{
	return 0;
}

static void inter_pet_sql_final(void)
{
	return;
}

/**
 * Removes a pet with `pet_id` from database
 * @return bool success
 **/
static bool inter_pet_delete(int pet_id)
{
	struct Sql *sql_handle = inter->sql_handle_get();
	ShowInfo("delete pet request: %d...\n",pet_id);

	if(SQL_ERROR == SQL->Query(sql_handle,
		"DELETE FROM `%s` WHERE `pet_id`='%d'", pet_db, pet_id)
	) {
		Sql_ShowDebug(sql_handle);
		return false;
	}
	return true;
}

/**
 * Loads pet from database
 *
 * @param out Object to be filled (0 initialized)
 * @return BOOL Success
 **/
static bool inter_pet_load(int account_id, int char_id, int pet_id, struct s_pet *out)
{
	if(!inter_pet->fromsql(pet_id, out))
		return false;

	if(out->incubate == 1) {
		out->account_id = out->char_id = 0;
		return true;
	}
	if(account_id == out->account_id && char_id == out->char_id)
		return true;
	return false;
}

void inter_pet_defaults(void)
{
	inter_pet = &inter_pet_s;

	inter_pet->tosql = inter_pet_tosql;
	inter_pet->fromsql = inter_pet_fromsql;
	inter_pet->rename = inter_pet_rename;
	inter_pet->sql_init = inter_pet_sql_init;
	inter_pet->sql_final = inter_pet_sql_final;
	inter_pet->delete_ = inter_pet_delete;

	inter_pet->load = inter_pet_load;
}
