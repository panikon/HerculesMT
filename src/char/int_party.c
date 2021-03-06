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

#include "int_party.h"

#include "char/char.h"
#include "char/inter.h"
#include "char/mapif.h"
#include "common/cbasetypes.h"
#include "common/db.h"
#include "common/memmgr.h"
#include "common/mapindex.h"
#include "common/mmo.h"
#include "common/nullpo.h"
#include "common/showmsg.h"
#include "common/socket.h"
#include "common/sql.h"
#include "common/strlib.h"
#include "common/rwlock.h"
#include "common/mutex.h"

#include <stdio.h>
#include <stdlib.h>

static struct inter_party_interface inter_party_s;
struct inter_party_interface *inter_party;

/**
 * Updates party's level range and disables even share if requirements are not fulfilled.
 *
 * @param p The party.
 * @return 0 on failure, 1 on success.
 * @mutex inter_party->mutex_db
 **/
static int inter_party_check_lv(struct party_data *p)
{
	nullpo_ret(p);

	p->min_lv = MAX_LEVEL;
	p->max_lv = 1;

	for (int i = 0; i < MAX_PARTY; i++) {
		if (p->party.member[i].online == 0 || p->party.member[i].char_id == p->family)
			continue; /// If not online OR if it's a family party and this is the child, don't affect exp range.

		p->min_lv = min(p->min_lv, p->party.member[i].lv);
		p->max_lv = max(p->max_lv, p->party.member[i].lv);
	}

	if (p->party.exp == 1 && inter_party->check_exp_share(p) == 0) {
		p->party.exp = 0;
		mapif->party_optionchanged(0, &p->party, 0, 0);
		inter_party->tosql(&p->party, PS_BASIC, 0);
		return 0;
	}

	return 1;
}

/**
 * Checks if a party is a family state party. (Family share feature.)
 * Conditions for a family state party:
 * - All party members have to belong to the same family. Not even offline strangers are allowed.
 *   So only parties with 2 or 3 members come in question.
 * - At least one parent has to be on the same map with the child.
 * - Parents within the party have to be level 70 or higher, even when offline.
 *
 * @param p The party.
 * @return The child's char ID on success, otherwise 0.
 *
 * Acquires db_lock(chr->char_db_)
 * @mutex inter_party->mutex_db
 **/
static int inter_party_is_family_party(struct party_data *p)
{
	nullpo_ret(p);

	if (p->size < 2 || p->size > 3 || p->party.count < 2)
		return 0;

	int child_id = 0;

	db_lock(chr->char_db_, READ_LOCK);

	for (int i = 0; i < MAX_PARTY - 1; i++) {
		if (p->party.member[i].online == 0)
			continue;

		struct mmo_charstatus *char_i = idb_get(chr->char_db_, p->party.member[i].char_id);

		if (char_i == NULL)
			continue;

		for (int j = i + 1; j < MAX_PARTY; j++) {
			if (p->party.member[j].online == 0)
				continue;

			struct mmo_charstatus *char_j = idb_get(chr->char_db_, p->party.member[j].char_id);

			if (char_j == NULL)
				continue;

			if (p->party.member[i].map != p->party.member[j].map)
				continue;

			if (char_i->char_id == char_j->child && char_j->base_level >= 70)
				child_id = char_i->char_id;

			if (char_j->char_id == char_i->child && char_i->base_level >= 70)
				child_id = char_j->char_id;

			if (child_id != 0)
				break;
		}

		if (child_id != 0)
			break;
	}

	if (child_id != 0 && p->size > 2) {
		for (int i = 0; i < MAX_PARTY; i++) {
			struct mmo_charstatus *party_member = idb_get(chr->char_db_, p->party.member[i].char_id);

			/// Check if there is a stranger within the party.
			if (party_member != NULL && party_member->char_id != child_id && party_member->child != child_id) {
				child_id = 0; /// Stranger detected.
				break;
			}

			/// Check if there is a parents with level lower than 70 within the party.
			if (party_member != NULL && party_member->child == child_id && party_member->base_level < 70) {
				child_id = 0; /// Parent with level lower than 70 detected.
				break;
			}
		}
	}

	db_unlock(chr->char_db_);
	return child_id;
}

/**
 * Calculates the state of a party.
 *
 * @param p The party.
 * @lock db_lock(inter_party->db)
 **/
static void inter_party_calc_state(struct party_data *p)
{
	nullpo_retv(p);

	p->party.count = 0;
	p->size = 0;

	for (int i = 0; i < MAX_PARTY; i++) {
		if (p->party.member[i].lv == 0) /// Is this even possible? [Kenpachi]
			continue;

		p->size++;

		if (p->party.member[i].online == 1)
			p->party.count++;
	}

	p->family = inter_party->is_family_party(p);
	inter_party->check_lv(p);
}

/**
 * Saves party to database
 *
 * @mutex inter_party->mutex_db
 **/
static int inter_party_tosql(struct party *p, int flag, int index)
{
	// 'party' ('party_id','name','exp','item','leader_id','leader_char')
	char esc_name[ESC_NAME_LENGTH];// escaped party name
	int party_id;
	struct Sql *sql_handle = inter->sql_handle_get();

	if(p == NULL || p->party_id == 0)
		return 0;
	Assert_ret(index >= 0 && index < MAX_PARTY);
	party_id = p->party_id;

#ifdef NOISY
	ShowInfo("Save party request ("CL_BOLD"%d"CL_RESET" - %s).\n", party_id, p->name);
#endif
	SQL->EscapeStringLen(sql_handle, esc_name, p->name, strnlen(p->name, NAME_LENGTH));

	if( flag & PS_BREAK )
	{// Break the party
		// we'll skip name-checking and just reset everyone with the same party id [celest]
		if( SQL_ERROR == SQL->Query(sql_handle, "UPDATE `%s` SET `party_id`='0' WHERE `party_id`='%d'", char_db, party_id) )
			Sql_ShowDebug(sql_handle);
		if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `party_id`='%d'", party_db, party_id) )
			Sql_ShowDebug(sql_handle);
		//Remove from memory
		idb_remove(inter_party->db, party_id);
		return 1;
	}

	if( flag & PS_CREATE )
	{// Create party
		if( SQL_ERROR == SQL->Query(sql_handle, "INSERT INTO `%s` "
			"(`name`, `exp`, `item`, `leader_id`, `leader_char`) "
			"VALUES ('%s', '%d', '%d', '%d', '%d')",
			party_db, esc_name, p->exp, p->item, p->member[index].account_id, p->member[index].char_id) )
		{
			Sql_ShowDebug(sql_handle);
			return 0;
		}
		party_id = p->party_id = (int)SQL->LastInsertId(sql_handle);
	}

	if( flag & PS_BASIC )
	{// Update party info.
		if( SQL_ERROR == SQL->Query(sql_handle, "UPDATE `%s` SET `name`='%s', `exp`='%d', `item`='%d' WHERE `party_id`='%d'",
			party_db, esc_name, p->exp, p->item, party_id) )
			Sql_ShowDebug(sql_handle);
	}

	if( flag & PS_LEADER )
	{// Update leader
		if( SQL_ERROR == SQL->Query(sql_handle, "UPDATE `%s`  SET `leader_id`='%d', `leader_char`='%d' WHERE `party_id`='%d'",
			party_db, p->member[index].account_id, p->member[index].char_id, party_id) )
			Sql_ShowDebug(sql_handle);
	}

	if( flag & PS_ADDMEMBER )
	{// Add one party member.
		if( SQL_ERROR == SQL->Query(sql_handle, "UPDATE `%s` SET `party_id`='%d' WHERE `account_id`='%d' AND `char_id`='%d'",
			char_db, party_id, p->member[index].account_id, p->member[index].char_id) )
			Sql_ShowDebug(sql_handle);
	}

	if( flag & PS_DELMEMBER )
	{// Remove one party member.
		if( SQL_ERROR == SQL->Query(sql_handle, "UPDATE `%s` SET `party_id`='0' WHERE `party_id`='%d' AND `account_id`='%d' AND `char_id`='%d'",
			char_db, party_id, p->member[index].account_id, p->member[index].char_id) )
			Sql_ShowDebug(sql_handle);
	}

	if (chr->show_save_log)
		ShowInfo("Party Saved (%d - %s)\n", party_id, p->name);
	return 1;
}

/**
 * Updates the `char`.`party_id` column and removes party data from memory.
 * Sets the party ID of all characters whose party ID matches the passed one to 0.
 * Calls idb_remove() to remove party data from memory.
 *
 * @param party_id The party ID.
 * @return 0 on failure, 1 on success.
 * @lock db_lock(inter_party->db)
 **/
static int inter_party_del_nonexistent_party(int party_id)
{
	struct Sql *sql_handle = inter->sql_handle_get();
	struct SqlStmt *stmt = SQL->StmtMalloc(sql_handle);

	if (stmt == NULL) {
		SqlStmt_ShowDebug(stmt);
		return 0;
	}

	const char *query = "UPDATE `%s` SET `party_id`='0' WHERE `party_id`=?";

	if (SQL_ERROR == SQL->StmtPrepare(stmt, query, char_db)
	    || SQL_ERROR == SQL->StmtBindParam(stmt, 0, SQLDT_UINT32, &party_id, sizeof(party_id))
	    || SQL_ERROR == SQL->StmtExecute(stmt)) {
			SqlStmt_ShowDebug(stmt);
			SQL->StmtFree(stmt);
			return 0;
	}

	idb_remove(inter_party->db, party_id);

	return 1;
}

/**
 * Loads party from database or from cache if available
 *
 * @return party_data
 * @lock db_lock(inter_party->db)
 **/
static struct party_data *inter_party_fromsql(int party_id)
{
	int leader_id = 0;
	int leader_char = 0;
	struct party_data* p;
	struct party_member* m;
	char* data;
	size_t len;
	int i;
	struct Sql *sql_handle = inter->sql_handle_get();

#ifdef NOISY
	ShowInfo("Load party request ("CL_BOLD"%d"CL_RESET")\n", party_id);
#endif
	if(party_id <= 0)
		return NULL;

	//Load from memory
	p = idb_get(inter_party->db, party_id);
	if(p != NULL)
		return p;

	CREATE(p, struct party_data, 1);

	if(SQL_ERROR == SQL->Query(sql_handle,
	                           "SELECT `party_id`, `name`,`exp`,`item`, "
	                           "`leader_id`, `leader_char` "
	                           "FROM `%s` WHERE `party_id`='%d'",
	                           party_db, party_id)
	) {
		aFree(p);
		Sql_ShowDebug(sql_handle);
		return NULL;
	}

	if(SQL_SUCCESS != SQL->NextRow(sql_handle)) {
		aFree(p);
		return NULL;
	}

	p->party.party_id = party_id;
	SQL->GetData(sql_handle, 1, &data, &len); memcpy(p->party.name, data, min(len, NAME_LENGTH));
	SQL->GetData(sql_handle, 2, &data, NULL); p->party.exp = (atoi(data) ? 1 : 0);
	SQL->GetData(sql_handle, 3, &data, NULL); p->party.item = atoi(data);
	SQL->GetData(sql_handle, 4, &data, NULL); leader_id = atoi(data);
	SQL->GetData(sql_handle, 5, &data, NULL); leader_char = atoi(data);
	SQL->FreeResult(sql_handle);

	// Load members
	if(SQL_ERROR == SQL->Query(sql_handle,
	                           "SELECT `account_id`,`char_id`,`name`,"
	                           "`base_level`,`last_map`,`online`,`class` "
	                           "FROM `%s` WHERE `party_id`='%d'",
	                           char_db, party_id)
	) {
		aFree(p);
		Sql_ShowDebug(sql_handle);
		return NULL;
	}
	for( i = 0; i < MAX_PARTY && SQL_SUCCESS == SQL->NextRow(sql_handle); ++i )
	{
		m = &p->party.member[i];
		SQL->GetData(sql_handle, 0, &data, NULL); m->account_id = atoi(data);
		SQL->GetData(sql_handle, 1, &data, NULL); m->char_id = atoi(data);
		SQL->GetData(sql_handle, 2, &data, &len); memcpy(m->name, data, min(len, NAME_LENGTH));
		SQL->GetData(sql_handle, 3, &data, NULL); m->lv = atoi(data);
		SQL->GetData(sql_handle, 4, &data, NULL); m->map = mapindex->name2id(data);
		SQL->GetData(sql_handle, 5, &data, NULL); m->online = (atoi(data) ? 1 : 0);
		SQL->GetData(sql_handle, 6, &data, NULL); m->class = atoi(data);
		m->leader = (m->account_id == leader_id && m->char_id == leader_char ? 1 : 0);
	}
	SQL->FreeResult(sql_handle);

	if (chr->show_save_log)
		ShowInfo("Party loaded (%d - %s).\n", party_id, p->party.name);

	// Add party to memory and init state
	inter_party->calc_state(p);
	idb_put(inter_party->db, party_id, p);
	return p;
}

static int inter_party_sql_init(void)
{
	inter_party->db = idb_alloc(DB_OPT_RELEASE_DATA);

#if 0 // Enable if you want to do a party_db cleanup (remove parties with no members) on startup.[Skotlex]
	struct Sql *sql_handle = inter->sql_handle_get();
	ShowStatus("cleaning party table...\n");
	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` USING `%s` LEFT JOIN `%s` ON `%s`.leader_id =`%s`.account_id AND `%s`.leader_char = `%s`.char_id WHERE `%s`.account_id IS NULL",
		party_db, party_db, char_db, party_db, char_db, party_db, char_db, char_db) )
		Sql_ShowDebug(sql_handle);
#endif // 0
	return 0;
}

static void inter_party_sql_final(void)
{
	db_lock(inter_party->db, WRITE_LOCK);
	inter_party->db->destroy(inter_party->db, NULL);
	return;
}

/**
 * Search for the party according to its name
 *
 * @param esc_name Normalized and escaped name (can be NULL)
 * @lock db_lock(inter_party->db)
 **/
static struct party_data *inter_party_search_partyname(const char *const str, const char *esc)
{
	char esc_name_[ESC_NAME_LENGTH];
	char* data;
	struct party_data* p = NULL;
	struct Sql *sql_handle = inter->sql_handle_get();

	if(!esc) {
		SQL->EscapeStringLen(sql_handle, esc_name_, str, safestrnlen(str, NAME_LENGTH));
		esc = esc_name_;
	}
		
	if( SQL_ERROR == SQL->Query(sql_handle, "SELECT `party_id` FROM `%s` WHERE `name`='%s'", party_db, esc) )
		Sql_ShowDebug(sql_handle);
	else if( SQL_SUCCESS == SQL->NextRow(sql_handle) ) {
		SQL->GetData(sql_handle, 0, &data, NULL);
		p = inter_party->fromsql(atoi(data));
	}
	SQL->FreeResult(sql_handle);

	return p;
}

/**
 * Checks if a party fulfills the requirements to share EXP.
 *
 * @param p The party.
 * @return 1 if party can share EXP, otherwise 0.
 *
 * @lock db_lock(inter_party->db)
 **/
static int inter_party_check_exp_share(struct party_data *const p)
{
	nullpo_ret(p);

	return (p->party.count < 2 || p->family != 0 || p->max_lv - p->min_lv <= party_share_level);
}

/**
 * Is there any member in the party?
 *
 * @return 0 Success
 * @lock db_lock(inter_party->db)
 **/
static bool inter_party_check_empty(struct party_data *p)
{
	int i;
	if(p == NULL||p->party.party_id == 0)
		return 1;
	for(i = 0; i < MAX_PARTY && !p->party.member[i].account_id; i++);
	if(i < MAX_PARTY)
		return 0;
	// If there is no member, then break the party
	mapif->party_broken(p->party.party_id,0);
	inter_party->tosql(&p->party, PS_BREAK, 0);
	return 1;
}

/**
 * Creates a Party
 *
 * @lock db_lock(inter_party->db)
 **/
static struct party_data *inter_party_create(const char *name, int item, int item2, const struct party_member *leader)
{
	struct party_data *p;
	char esc_name[ESC_NAME_LENGTH];

	nullpo_ret(name);
	nullpo_ret(leader);
	if(!*name)
		return NULL;

	if(chr->check_symbols(name))
		return NULL; // Invalid letters/symbols in party name
	chr->escape_normalize_name(name, esc_name);
	normalize_name(esc_name, "\""); // client-special-char
	trim(esc_name);

	if(inter_party->search_partyname(name, esc_name) != NULL)
		return NULL;

	p = aCalloc(1, sizeof(struct party_data));

	safestrncpy(p->party.name, esc_name, NAME_LENGTH);
	p->party.exp=0;
	p->party.item=(item?1:0)|(item2?2:0);

	memcpy(&p->party.member[0], leader, sizeof(struct party_member));
	p->party.member[0].leader=1;
	p->party.member[0].online=1;

	p->party.party_id=-1;//New party.
	if(!inter_party->tosql(&p->party, PS_CREATE | PS_ADDMEMBER, 0)) {
		aFree(p);
		return NULL;
	}

	//Add party to db
	inter_party->calc_state(p);
	idb_put(inter_party->db, p->party.party_id, p);

	return p;
}

/**
 * Add a player to party request.
 *
 * @param party_id The ID of the party.
 * @param member The member to add.
 * @return true on success, otherwise false.
 *
 * Acquires db_lock(inter_party->db)
 **/
static bool inter_party_add_member(int party_id, const struct party_member *member)
{
	nullpo_retr(false, member);

	if(party_id < 1) /// Invalid party ID.
		return false;

	db_lock(inter_party->db, WRITE_LOCK);
	struct party_data *p = inter_party->fromsql(party_id);

	if(p == NULL) { /// Party does not exist.
		inter_party->del_nonexistent_party(party_id);
		db_unlock(inter_party->db);
		return false;
	}

	int i;

	ARR_FIND(0, MAX_PARTY, i, p->party.member[i].account_id == 0);
	if(i == MAX_PARTY) { /// Party is full.
		db_unlock(inter_party->db);
		return false;
	}

	memcpy(&p->party.member[i], member, sizeof(struct party_member));
	p->party.member[i].leader = 0;
	inter_party->calc_state(p); /// Count online/offline members and check family state and even share range.
	mapif->party_info(NULL, p->party.party_id, 0, &p->party);
	inter_party->tosql(&p->party, PS_ADDMEMBER, i);

	db_unlock(inter_party->db);
	return true;
}

/**
 * Party setting change request
 *
 * Acquires db_lock(inter_party->db)
 **/
static bool inter_party_change_option(int party_id, int account_id, int exp, int item, struct socket_data *session)
{
	struct party_data *p;
	int flag = 0;

	db_lock(inter_party->db, WRITE_LOCK);
	p = inter_party->fromsql(party_id);
	if(!p) {
		inter_party->del_nonexistent_party(party_id);
		db_unlock(inter_party->db);
		return false;
	}

	p->party.exp=exp;
	if( exp && !inter_party->check_exp_share(p) ){
		flag|=0x01;
		p->party.exp=0;
	}
	p->party.item = item&0x3; //Filter out invalid values.
	mapif->party_optionchanged(session, &p->party, account_id, flag);
	inter_party->tosql(&p->party, PS_BASIC, 0);

	db_unlock(inter_party->db);
	return true;
}

/**
 * Leave party request.
 *
 * @param party_id The ID of the party.
 * @param account_id The account ID of the leaving character.
 * @param char_id The char ID of the leaving character.
 * @return true on success, otherwise false.
 *
 * Acquires db_lock(inter_party->db)
 **/
static bool inter_party_leave(int party_id, int account_id, int char_id)
{
	if (party_id < 1) /// Invalid party ID.
		return false;

	db_lock(inter_party->db, WRITE_LOCK);
	struct party_data *p = inter_party->fromsql(party_id);

	if(p == NULL) { /// Party does not exist.
		inter_party->del_nonexistent_party(party_id);
		db_unlock(inter_party->db);
		return false;
	}

	int i;
	ARR_FIND(0, MAX_PARTY, i, p->party.member[i].account_id == account_id && p->party.member[i].char_id == char_id);

	if(i == MAX_PARTY) { /// Character not found in party.
		inter_party->remove_orphaned_member(char_id, party_id);
		db_unlock(inter_party->db);
		return false;
	}

	mapif->party_withdraw(party_id, account_id, char_id);

	if (p->party.member[i].online == 1)
		p->party.member[i].online = 0;

	inter_party->tosql(&p->party, PS_DELMEMBER, i);
	memset(&p->party.member[i], 0, sizeof(struct party_member));
	inter_party->calc_state(p); /// Count online/offline members and check family state and even share range.

	if (inter_party->check_empty(p) == 0)
		mapif->party_info(NULL, p->party.party_id, 0, &p->party);

	db_unlock(inter_party->db);
	return true;
}

/**
 * Updates party data if a member changes map or levels up.
 *
 * @param party_id The ID of the party.
 * @param account_id The character's account ID.
 * @param char_id The character's char ID.
 * @param map The character's map index.
 * @param online The character's online state.
 * @param lv The character's level.
 * @return true on success, otherwise false.
 *
 * Acquires db_lock(inter_party->db)
 **/
static bool inter_party_change_map(int party_id, int account_id, int char_id, unsigned short map, int online, int lv)
{
	if(party_id < 1) /// Invalid party ID.
		return false;


	db_lock(inter_party->db, WRITE_LOCK);
	struct party_data *p = inter_party->fromsql(party_id);

	if(p == NULL) { /// Party does not exist.
		inter_party->del_nonexistent_party(party_id);
		db_unlock(inter_party->db);
		return false;
	}

	int i;

	ARR_FIND(0, MAX_PARTY, i, p->party.member[i].account_id == account_id && p->party.member[i].char_id == char_id);
	if(i == MAX_PARTY) { /// Character not found in party.
		inter_party->remove_orphaned_member(char_id, party_id);
		db_unlock(inter_party->db);
		return false;
	}

	if (p->party.member[i].online != online)
		p->party.member[i].online = online;

	if (p->party.member[i].lv != lv)
		p->party.member[i].lv = lv;

	if (p->party.member[i].map != map)
		p->party.member[i].map = map;

	inter_party->calc_state(p); /// Count online/offline members and check family state and even share range.
	mapif->party_membermoved(&p->party, i); /// Send online/offline update.
	db_unlock(inter_party->db);

	return true;
}

/**
 * Request party dissolution
 *
 * Acquires db_lock(inter_party->db)
 **/
static bool inter_party_disband(int party_id)
{
	struct party_data *p;

	db_lock(inter_party->db, WRITE_LOCK);
	p = inter_party->fromsql(party_id);
	if(!p) {
		inter_party->del_nonexistent_party(party_id);
		db_unlock(inter_party->db);
		return false;
	}
	inter_party->tosql(&p->party,PS_BREAK,0);
	mapif->party_broken(party_id, 1);
	db_unlock(inter_party->db);
	return true;
}

/**
 * Changes party leader
 *
 * @param account_id AID of new leader
 * @param char_id    CID of new leader
 * Acquires db_lock(inter_party->db)
 **/
static bool inter_party_change_leader(int party_id, int account_id, int char_id)
{
	struct party_data *p;
	int i;

	db_lock(inter_party->db, WRITE_LOCK);
	p = inter_party->fromsql(party_id);

	if(!p) {
		inter_party->del_nonexistent_party(party_id);
		db_unlock(inter_party->db);
		return false;
	}

	int leader_idx = -1;
	int member_idx = -1;
	for(i = 0; i < MAX_PARTY; i++) {
		if(p->party.member[i].leader)
			leader_idx = i;
		if(p->party.member[i].account_id == account_id
		&& p->party.member[i].char_id == char_id)
			member_idx = i;
	}
	if(leader_idx == -1) {
		ShowError("inter_party_change_leader: Party %d with no leader! Deleting...\n");
		inter_party->del_nonexistent_party(party_id);
		db_unlock(inter_party->db);
		return false;
	}
	if(member_idx == -1) {
		ShowError("inter_party_change_leader: Character (CID %d) outside party (PID %d)\n",
			char_id, party_id);
		inter_party->remove_orphaned_member(char_id, party_id);
		db_unlock(inter_party->db);
	}

	// Update cache
	p->party.member[leader_idx].leader = 0;
	p->party.member[member_idx].leader = 1;

	inter_party->tosql(&p->party,PS_LEADER, member_idx);
	return true;
}

/**
 * Sets party_id to 0 of a given char_id
 *
 * This is used for players that are not in party_db but have party_ids
 **/
static void inter_party_remove_orphaned_member(int char_id, int party_id)
{
	struct Sql *sql_handle = inter->sql_handle_get();
	ShowDebug("inter_party_removed_orphaned_member: Removing orphaned member (CID %d, PID %d)\n",
		char_id, party_id);
	if(SQL_ERROR == SQL->Query(sql_handle,
	                           "UPDATE `%s` SET party_id = '0' WHERE char_id='%d' AND party_id='%d'",
	                           char_db, char_id, party_id)
	)
		Sql_ShowDebug(sql_handle);
}

/**
 * Searches in database for the party_id of given character
 *
 * @return party id
 * @retval 0 Couldn't find party
 **/
static int inter_party_find(int char_id)
{
	char *data;
	struct Sql *sql_handle = inter->sql_handle_get();

	if(SQL_ERROR == SQL->Query(sql_handle,
	                           "SELECT party_id FROM `%s` WHERE char_id='%d'",
	                           char_db, char_id)
	) {
		Sql_ShowDebug(sql_handle);
		return 0;
	}

	if(SQL_SUCCESS != SQL->NextRow(sql_handle))
		return 0;

	SQL->GetData(sql_handle, 0, &data, NULL);
	int party_id = atoi(data);
	SQL->FreeResult(sql_handle);
	return party_id;
}

/**
 * Sets the online state of a charcter within a party to online.
 *
 * @param char_id The character's char ID.
 * @param party_id The ID of the party.
 * @return 1 on success, otherwise 0.
 * Acquires db_lock(inter_party->db)
 **/
static int inter_party_CharOnline(int char_id, int party_id)
{
	if(party_id == INDEX_NOT_FOUND) /// Get party_id from the database.
		party_id = inter_party->find(char_id);

	if(party_id == 0) /// Character isn't member of a party.
		return 0;

	db_lock(inter_party->db, WRITE_LOCK);
	struct party_data *p = inter_party->fromsql(party_id);

	if(p == NULL) { /// Party does not exist.
		inter_party->del_nonexistent_party(party_id);
		db_unlock(inter_party->db);
		return 0;
	}

	int i;
	ARR_FIND(0, MAX_PARTY, i, p->party.member[i].char_id == char_id);
	if(i == MAX_PARTY) { /// Character not found in party.
		inter_party->remove_orphaned_member(char_id, party_id);
		return 0;
	}

	p->party.member[i].online = 1; /// Set member online.
	inter_party->calc_state(p); /// Count online/offline members and check family state and even share range.
	db_unlock(inter_party->db);
	return 1;
}

/**
 * Sets the online state of a charcter within a party to offline.
 *
 * @param char_id The character's char ID.
 * @param party_id The ID of the party.
 * @return 1 on success, otherwise 0.
 * Acquires db_lock(inter_party->db)
 **/
static int inter_party_CharOffline(int char_id, int party_id)
{
	if(party_id == INDEX_NOT_FOUND) /// Get party_id from the database.
		party_id = inter_party->find(char_id);

	if(party_id == 0) /// Character isn't member of a party.
		return 0;

	db_lock(inter_party->db, WRITE_LOCK);
	struct party_data *p = inter_party->fromsql(party_id);

	if(p == NULL) { /// Party does not exist.
		inter_party->del_nonexistent_party(party_id);
		db_unlock(inter_party->db);
		return 0;
	}

	int i;
	ARR_FIND(0, MAX_PARTY, i, p->party.member[i].char_id == char_id);
	if(i == MAX_PARTY) { /// Character not found in party.
		inter_party->remove_orphaned_member(char_id, party_id);
		return 0;
	}

	p->party.member[i].online = 0; /// Set member offline.
	inter_party->calc_state(p); /// Count online/offline members and check family state and even share range.

	if(p->party.count == 0) /// Parties don't have any data that needs be saved at this point... so just remove it from memory.
		idb_remove(inter_party->db, party_id);

	db_unlock(inter_party->db);
	return 1;
}

void inter_party_defaults(void)
{
	inter_party = &inter_party_s;

	inter_party->db = NULL;

	inter_party->sql_init = inter_party_sql_init;
	inter_party->sql_final = inter_party_sql_final;
	inter_party->remove_orphaned_member = inter_party_remove_orphaned_member;
	inter_party->find = inter_party_find;
	inter_party->check_lv = inter_party_check_lv;
	inter_party->is_family_party = inter_party_is_family_party;
	inter_party->calc_state = inter_party_calc_state;
	inter_party->tosql = inter_party_tosql;
	inter_party->del_nonexistent_party = inter_party_del_nonexistent_party;
	inter_party->fromsql = inter_party_fromsql;
	inter_party->search_partyname = inter_party_search_partyname;
	inter_party->check_exp_share = inter_party_check_exp_share;
	inter_party->check_empty = inter_party_check_empty;
	inter_party->leave = inter_party_leave;
	inter_party->CharOnline = inter_party_CharOnline;
	inter_party->CharOffline = inter_party_CharOffline;

	inter_party->create = inter_party_create;
	inter_party->add_member = inter_party_add_member;
	inter_party->change_option = inter_party_change_option;
	inter_party->change_map = inter_party_change_map;
	inter_party->disband = inter_party_disband;
	inter_party->change_leader = inter_party_change_leader;
}
