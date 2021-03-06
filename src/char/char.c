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

#include "config/core.h" // CONSOLE_INPUT
#include "char/char.h"

#include "char/HPMchar.h"
#include "char/geoip.h"
#include "char/int_auction.h"
#include "char/int_clan.h"
#include "char/int_elemental.h"
#include "char/int_guild.h"
#include "char/int_homun.h"
#include "char/int_mail.h"
#include "char/int_mercenary.h"
#include "char/int_party.h"
#include "char/int_pet.h"
#include "char/int_quest.h"
#include "char/int_rodex.h"
#include "char/int_storage.h"
#include "char/int_achievement.h"
#include "char/inter.h"
#include "char/loginif.h"
#include "char/mapif.h"
#include "char/packets_hc_struct.h"
#include "char/pincode.h"
#include "char/chclif.h"

#include "common/HPM.h"
#include "common/cbasetypes.h"
#include "common/conf.h"
#include "common/console.h"
#include "common/core.h"
#include "common/ers.h"
#include "common/db.h"
#include "common/memmgr.h"
#include "common/mapindex.h"
#include "common/mmo.h"
#include "common/nullpo.h"
#include "common/packetsstatic_len.h"
#include "common/showmsg.h"
#include "common/socket.h"
#include "common/strlib.h"
#include "common/sql.h"
#include "common/timer.h"
#include "common/utils.h"

#include "common/rwlock.h"
#include "common/mutex.h"
#include "common/atomic.h"
#include "common/action.h"
#include "common/packets_zw_struct.h"

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h> // stat()

#if MAX_MAP_SERVERS > 1
#	ifdef _MSC_VER
#		pragma message("WARNING: your settings allow more than one map server to connect, this is deprecated dangerous feature USE IT AT YOUR OWN RISK")
#	else
#		warning your settings allow more than one map server to connect, this is deprecated dangerous feature USE IT AT YOUR OWN RISK
#	endif
#endif

/**
 * Private declarations
 *
 * These declarations don't need any locks to be accessed because they're only
 * changed on server startup [Panikon]
 **/
char char_db[256] = "char";
char scdata_db[256] = "sc_data";
char cart_db[256] = "cart_inventory";
char inventory_db[256] = "inventory";
char charlog_db[256] = "charlog";
char storage_db[256] = "storage";
char interlog_db[256] = "interlog";
char skill_db[256] = "skill";
char memo_db[256] = "memo";
char guild_db[256] = "guild";
char guild_alliance_db[256] = "guild_alliance";
char guild_castle_db[256] = "guild_castle";
char guild_expulsion_db[256] = "guild_expulsion";
char guild_member_db[256] = "guild_member";
char guild_position_db[256] = "guild_position";
char guild_skill_db[256] = "guild_skill";
char guild_storage_db[256] = "guild_storage";
char party_db[256] = "party";
char pet_db[256] = "pet";
char mail_db[256] = "mail"; // MAIL SYSTEM
char auction_db[256] = "auction"; // Auctions System
static char friend_db[256] = "friends";
static char hotkey_db[256] = "hotkey";
char quest_db[256] = "quest";
char rodex_db[256] = "rodex_mail";
char rodex_item_db[256] = "rodex_items";
char homunculus_db[256] = "homunculus";
char skill_homunculus_db[256] = "skill_homunculus";
char mercenary_db[256] = "mercenary";
char mercenary_owner_db[256] = "mercenary_owner";
char ragsrvinfo_db[256] = "ragsrvinfo";
char elemental_db[256] = "elemental";
static char account_data_db[256] = "account_data";
char acc_reg_num_db[32] = "acc_reg_num_db";
char acc_reg_str_db[32] = "acc_reg_str_db";
char char_reg_str_db[32] = "char_reg_str_db";
char char_reg_num_db[32] = "char_reg_num_db";
char char_achievement_db[256] = "char_achievements";

static struct char_interface char_s;
struct char_interface *chr;

static char wisp_server_name[NAME_LENGTH] = "Server";
static char login_ip_str[128];
static uint32 login_ip = 0;
static uint16 login_port = 6900;
static char char_ip_str[128];
static char bind_ip_str[128];
static uint32 bind_ip = INADDR_ANY;
static int char_maintenance_min_group_id = 0;
static bool enable_char_creation = true; ///< Whether to allow character creation.

static bool name_ignoring_case = false; // Allow or not identical name for characters but with a different case by [Yor]
int char_name_option = 0; // Option to know which letters/symbols are authorized in the name of a character (0: all, 1: only those in char_name_letters, 2: all EXCEPT those in char_name_letters) by [Yor]
static char unknown_char_name[NAME_LENGTH] = "Unknown"; // Name to use when the requested name cannot be determined
#define TRIM_CHARS "\255\xA0\032\t\x0A\x0D " //The following characters are trimmed regardless because they cause confusion and problems on the servers. [Skotlex]
char char_name_letters[1024] = ""; // list of letters/symbols allowed (or not) in a character name. by [Yor]

static int char_del_level = 0; ///< From which level you can delete character [Lupus]
static int char_del_delay = 86400;
static bool char_aegis_delete = false; ///< Verify if char is in guild/party or char and reacts as Aegis does (disallow deletion), @see chr->delete2_req.
static bool char_aegis_rename = false; // whether or not the player can be renamed while in party/guild

static int max_connect_user = -1;
static int gm_allow_group = -1;
int autosave_interval = DEFAULT_AUTOSAVE_INTERVAL;
static int start_zeny = 0;

/// Start items for new characters
struct start_item_s {
	int id;
	int amount;
	int loc;
	bool stackable;
};
static VECTOR_DECL(struct start_item_s) start_items;

int guild_exp_rate = 100;

//Custom limits for the fame lists. [Skotlex]
static int fame_list_size_chemist = MAX_FAME_LIST;
static int fame_list_size_smith   = MAX_FAME_LIST;
static int fame_list_size_taekwon = MAX_FAME_LIST;

/**
 * Char-server-side stored fame lists [DracoRPG]
 *
 * Fame lists are always calculated on the fly by the char-server using fame
 * values of all characters in 'char_db', @see chr->read_fame_list. This
 * loading is triggered either by the initialization of the char-server or
 * when ZW_FAME_LIST_BUILD (map-server sends when a character job changes).
 * Otherwise they are updated by ZW_FAME_LIST_UPDATE.
 **/
static struct fame_list smith_fame_list[MAX_FAME_LIST];
static struct fame_list chemist_fame_list[MAX_FAME_LIST];
static struct fame_list taekwon_fame_list[MAX_FAME_LIST];
static struct mutex_data *fame_list_mutex = NULL;

// Initial position (it's possible to set it in conf file)
#ifdef RENEWAL
static struct point start_point = { 0, 97, 90 };
#else
static struct point start_point = { 0, 53, 111 };
#endif

/**
 * RO skill id to internal skill index
 * This is used so the internal indices of the map-server and the char-server
 * are in sync. The reason that mmo_charstatus::skill doesn't map 1-to-1 to
 * the RO indices is to avoid wasting internal space with skipped or
 * non-implemented ids.
 *
 * @see mmo_charstatus::skill
 * @see char_mmo_char_fromsql
 * @see char_parse_frommap_skillid2idx
 **/
static unsigned short skillid2idx[MAX_SKILL_ID];
static struct rwlock_data *skillid2idx_lock = NULL;

//-----------------------------------------------------
// Auth database
//-----------------------------------------------------
#define AUTH_TIMEOUT 30000

/**
 * Authentication DB
 *
 * Entries of this database are used so we can keep track of the users
 * that were already authenticated by us and are currently moving to a
 * map-server. Entries are added using chr->create_auth_entry and then
 * removed in char_parse_frommap_auth_request after a succesful auth.
 * After removal the character is added to chr->online_char_db.
 *
 * @see char_create_auth_entry
 * @see char_parse_frommap_auth_request
 *
 * int account_id -> struct char_auth_node*
 *
 * TODO: Verify if it'd be less expensive to use a unique auth db per
 * map-server so we can reduce the number of lock calls [Panikon]
 **/
static struct DBMap *auth_db;

//-----------------------------------------------------
// Online User Database
//-----------------------------------------------------

/**
 * Creates character data for online db.
 *
 * @see online_char_db
 * @see DBCreateData
 * @lock db_lock(chr->online_char_db)
 **/
static struct DBData char_create_online_char_data(const struct DBKey_s *key, va_list args)
{
	struct online_char_data* character;
	CREATE(character, struct online_char_data, 1);
	character->account_id = key->u.i;
	character->char_id = -1;
	character->server = -1;
	character->pincode_enable = -1;
	character->session_id = -1;
	character->waiting_disconnect = INVALID_TIMER;
	return DB->ptr2data(character);
}

/**
 * Sets account online in char-server (in char-selection screen)
 *
 * Acquires db_lock(chr->online_char_db)
 * Acquires map_server_list_lock
 * @see online_char_db
 **/
static void char_set_char_charselect(int account_id)
{
	struct online_char_data* character;

	db_lock(chr->online_char_db, WRITE_LOCK);
	character = idb_ensure(chr->online_char_db, account_id, chr->create_online_char_data);

	if(character->server > -1) {
		// Coming from map-server
		struct mmo_map_server *server;
		rwlock->read_lock(chr->map_server_list_lock);
		server = INDEX_MAP_INDEX(chr->map_server_list, character->server);
		if(server)
			InterlockedDecrement(&server->user_count);
		rwlock->read_unlock(chr->map_server_list_lock);
	}

	character->char_id = -1;
	character->server = -1;
	if(character->pincode_enable == -1)
		character->pincode_enable = pincode->charselect + pincode->enabled;

	if(character->waiting_disconnect != INVALID_TIMER) {
		timer->delete(character->waiting_disconnect, chr->waiting_disconnect);
		character->waiting_disconnect = INVALID_TIMER;
	}

	db_unlock(chr->online_char_db);

	if(chr->login_session)
		loginif->set_account_online(account_id);
}

/**
 * Sets character online, notifies login-server.
 * This is called after the map-server authenticated the character connection.
 * @remarks
 * Also verifies if there's any conflicts between map-servers
 *
 * @param map_id Map position in map list, set to -2 to do a dummy online set (only db)
 * @see online_char_db
 * @readlock chr->map_server_list_lock
 * Acquires db_lock(chr->online_char_db)
 * Acquires db_lock(chr->char_db_)
 **/
static void char_set_char_online(int map_id, int char_id, int account_id)
{
	struct online_char_data *character;

	//Update DB
	struct Sql *sql_handle = inter->sql_handle_get();
	if(SQL_ERROR == SQL->Query(sql_handle,
		"UPDATE `%s` SET `online`='1' WHERE `char_id`='%d' LIMIT 1", char_db, char_id)
	)
		Sql_ShowDebug(sql_handle);

	//Check to see for online conflicts
	db_lock(chr->online_char_db, WRITE_LOCK);
	character = idb_ensure(chr->online_char_db, account_id, chr->create_online_char_data);
	if(character->char_id != -1
	&& character->server > -1
	&& character->server != map_id
	) {
		ShowNotice("chr->set_char_online: Character %d:%d marked in map server %d, "
			"but map server %d claims to have (%d:%d) online!\n",
			character->account_id, character->char_id, character->server,
			map_id, account_id, char_id);
		struct mmo_map_server *server;
		server = INDEX_MAP_INDEX(chr->map_server_list, character->server);
		if(!server) {
			ShowDebug("chr->set_char_online: Character %d:%d marked in "
				"invalid map server %d\n", character->account_id,
				character->char_id, character->server);
		} else {
			InterlockedDecrement(&server->user_count);
			mapif->disconnectplayer(server->session, character->account_id,
				character->char_id, 2); // 2: Already connected to server
		}
	}

	//Update state data
	character->char_id = char_id;
	character->server = map_id;

	//Get rid of disconnect timer
	if(character->waiting_disconnect != INVALID_TIMER) {
		timer->delete(character->waiting_disconnect, chr->waiting_disconnect);
		character->waiting_disconnect = INVALID_TIMER;
	}
	db_unlock(chr->online_char_db);

	//Set char online in guild cache. If char is in memory, use the guild id on it, otherwise seek it.
	int guild_id = -1;
	db_lock(chr->char_db_, READ_LOCK);
	struct mmo_charstatus *cp = idb_get(chr->char_db_,char_id);
	guild_id = cp?cp->guild_id:-1;
	db_unlock(chr->char_db_);
	inter_guild->CharOnline(char_id, guild_id);

	//Notify login server
	if(chr->login_session)
		loginif->set_account_online(account_id);
}

/**
 * Sets character offline.
 *
 * @param char_id Character to be set, when -1 sets all characters of this account.
 * @readlock chr->map_server_list_lock
 * Acquires db_lock(chr->char_db_)
 * Acquires db_lock(inter_achievement->char_achievements)
 **/
static void char_set_char_offline(int char_id, int account_id)
{
	struct online_char_data* character;
	struct Sql *sql_handle = inter->sql_handle_get();

	if(char_id == -1) {
		if( SQL_ERROR == SQL->Query(sql_handle,
			"UPDATE `%s` SET `online`='0' WHERE `account_id`='%d'",
			char_db, account_id)
		)
			Sql_ShowDebug(sql_handle);
	} else {
		int guild_id = -1;
		db_lock(chr->char_db_, WRITE_LOCK);
		struct mmo_charstatus *cp = idb_get(chr->char_db_, char_id);
		if(cp) {
			guild_id = cp->guild_id;
			idb_remove(chr->char_db_, char_id);
		}
		db_unlock(chr->char_db_);
		inter_guild->CharOffline(char_id, guild_id);

		/* Character Achievements */
		db_lock(inter_achievement->char_achievements, WRITE_LOCK);
		struct char_achievements *c_ach = idb_get(inter_achievement->char_achievements,
											      char_id);
		if(c_ach != NULL) {
			VECTOR_CLEAR(*c_ach);
			idb_remove(inter_achievement->char_achievements, char_id);
		}
		db_unlock(inter_achievement->char_achievements);

		if( SQL_ERROR == SQL->Query(sql_handle,
			"UPDATE `%s` SET `online`='0' WHERE `char_id`='%d' LIMIT 1", char_db, char_id)
		)
			Sql_ShowDebug(sql_handle);
	}

	character = idb_get(chr->online_char_db, account_id);
	if(character != NULL) {
		//We don't free yet to avoid aCalloc/aFree spamming during char change. [Skotlex]
		if(character->server > -1) {
			struct mmo_map_server *server = INDEX_MAP_INDEX(chr->map_server_list,
											                character->server);
			if(server)
				InterlockedDecrement(&server->user_count);
		}

		if(character->waiting_disconnect != INVALID_TIMER) {
			timer->delete(character->waiting_disconnect, chr->waiting_disconnect);
			character->waiting_disconnect = INVALID_TIMER;
		}

		if(character->char_id == char_id) {
			character->char_id = -1;
			character->server = -1;
			character->pincode_enable = -1;
		}
	}

	//Remove char if 1- Set all offline, or 2- character is no longer connected to char-server.
	if(chr->login_session
	&& (char_id == -1 || character == NULL || character->session_id == -1))
		loginif->set_account_offline(account_id);
}

/**
 * Removes all characters of a given server, and sets them to unknown server (-2)
 * This is done after receiving the character list of a server or when
 * a server disconnects.
 *
 * @param server_id Server id, when set to -1 disconnects all characters
 * @see char_parse_frommap_set_users
 * @see mapif_server_reset
 * @see chr->online_char_db
 * @see DBApply
 * @lock db_lock(chr->online_char_db)
 */
static int char_db_setoffline(const struct DBKey_s *key, struct DBData *data, va_list ap)
{
	struct online_char_data *character = DB->data2ptr(data);
	int server_id = va_arg(ap, int);
	nullpo_ret(character);
	if(server_id == -1) {
		character->char_id = -1;
		character->server = -1;
		if(character->waiting_disconnect != INVALID_TIMER) {
			timer->delete(character->waiting_disconnect, chr->waiting_disconnect);
			character->waiting_disconnect = INVALID_TIMER;
		}
	} else if (character->server == server_id)
		character->server = -2; //In some map server that we aren't connected to.
	return 0;
}

/**
 * Kicks all characters of a given server.
 *
 * @param server_id Server id, when set to -1 disconnects all characters
 * @return 1 Character disconnected
 * @see chr->online_char_db
 * @see DBApply
 * @readlock chr->map_server_list_lock
 * @lock db_lock(chr->online_char_db)
 */
static int char_db_kickoffline(const struct DBKey_s *key, struct DBData *data, va_list ap)
{
	struct online_char_data *character = DB->data2ptr(data);
	int server_id = va_arg(ap, int);
	nullpo_ret(character);

	if(server_id > -1 && character->server != server_id)
		return 0;

	//Kick out any connected characters, and set them offline as appropriate.
	if(character->server > -1 && character->server < MAX_MAP_SERVERS) {
		struct mmo_map_server *server;
		server = INDEX_MAP_INDEX(chr->map_server_list, character->server);
		mapif->disconnectplayer(server->session, character->account_id,
			character->char_id, NBE_SERVER_CLOSED);
	} else if (character->waiting_disconnect == INVALID_TIMER)
		chr->set_char_offline(character->char_id, character->account_id);
	else
		return 0; // fail

	return 1;
}

/**
 * Sets all users of a map server offline.
 *
 * @param id Map server id, when -1 sets all users.
 * @readlock chr->map_server_list_lock
 * Acquires online_char_db
 **/
static void char_set_all_offline(int id)
{
	if (id < 0)
		ShowNotice("Sending all users offline.\n");
	else
		ShowNotice("Sending users of map-server %d offline.\n",id);

	db_lock(chr->online_char_db, WRITE_LOCK);
	chr->online_char_db->foreach(chr->online_char_db,chr->db_kickoffline,id);
	db_unlock(chr->online_char_db);

	if(id >= 0 || !chr->login_session)
		return;
	loginif->set_all_offline();
}

/**
 * Disconnect timer
 * Invoked 15 seconds after mapif->disconnectplayer in case the map server doesn't
 * replies/disconnect the player we tried to kick.
 *
 * @see online_char_db
 * @author [Skotlex]
 *
 * Acquires db_lock(chr->online_char_db)
 **/
static int char_waiting_disconnect(struct timer_interface *tm, int tid, int64 tick, int id, intptr_t data)
{
	db_lock(chr->online_char_db, WRITE_LOCK);
	struct online_char_data* character = idb_get(chr->online_char_db, id);
	if(character && character->waiting_disconnect == tid) {
		//Mark it offline due to timeout.
		character->waiting_disconnect = INVALID_TIMER;
		chr->set_char_offline(character->char_id, character->account_id);
	}
	db_unlock(chr->online_char_db);
	return 0;
}

/**
 * Verifies if character is still connected to char-server of if is connected
 * to a valid map-server, if not removes them from the database.
 *
 * @see char_online_data_cleanup
 * @see online_char_db
 * @see DBApply
 * @lock db_lock(chr->online_char_db)
 **/
static int char_online_data_cleanup_sub(const struct DBKey_s *key, struct DBData *data, va_list ap)
{
	struct online_char_data *character = DB->data2ptr(data);
	nullpo_ret(character);
	if (character->session_id != -1)
		return 0; //Character still connected
	if (character->server == -2) //Unknown server.. set them offline
		chr->set_char_offline(character->char_id, character->account_id);
	if (character->server < 0)
		//Free data from players that have not been online for a while.
		db_remove(chr->online_char_db, *key);
	return 0;
}

/**
 * Global cleanup timer
 * Checks global timeout of each character entry.
 *
 * @see online_char_db
 * Acquires db_lock(chr->online_char_db);
 **/
static int char_online_data_cleanup(struct timer_interface *tm, int tid, int64 tick, int id, intptr_t data)
{
	db_lock(chr->online_char_db, WRITE_LOCK);
	chr->online_char_db->foreach(chr->online_char_db, chr->online_data_cleanup_sub);
	db_unlock(chr->online_char_db);
	return 0;
}

/**
 * Updates online SQL database and sets all players offline
 **/
static void char_set_all_offline_sql(void)
{
	struct Sql *sql_handle = inter->sql_handle_get();
	//Set all players to 'OFFLINE'
	if( SQL_ERROR == SQL->Query(sql_handle, "UPDATE `%s` SET `online` = '0'", char_db) )
		Sql_ShowDebug(sql_handle);
	if( SQL_ERROR == SQL->Query(sql_handle, "UPDATE `%s` SET `online` = '0'", guild_member_db) )
		Sql_ShowDebug(sql_handle);
	if( SQL_ERROR == SQL->Query(sql_handle, "UPDATE `%s` SET `connect_member` = '0'", guild_db) )
		Sql_ShowDebug(sql_handle);
}

/**
 * Sets up new entry for char_db_
 *
 * @see chr->char_db_
 * @see DBCreateData
 * @writelock db_lock(chr->char_db_)
 */
static struct DBData char_create_charstatus(const struct DBKey_s *key, va_list args)
{
	struct mmo_charstatus *cp;
	cp = aCalloc(1,sizeof(struct mmo_charstatus));
	cp->char_id = key->u.i;
	return DB->ptr2data(cp);
}

/**
 * Converts char save flags to a string
 * @see char_save_flag
 **/
static char *char_mmo_flag2str(char *save_status, size_t len, int32 save_flag)
{
	// With this approach we can avoid multiple strcat calls in _tosql and _fromsql
	snprintf(save_status, len,
		"%s%s%s%s%s%s%s%s%s%s",
		(save_flag&CHARSAVE_INVENTORY)?" INVENTORY":"",
		(save_flag&CHARSAVE_CART)?" CART":"",
		(save_flag&CHARSAVE_STATUS_LONG)?" STATUS_LONG":"",
		(save_flag&CHARSAVE_ACCDATA)?" ACCDATA":"",
		(save_flag&CHARSAVE_STATUS_SHORT)?" STATUS_SHORT":"",
		(save_flag&CHARSAVE_MERCENARY)?" MERCENARY":"",
		(save_flag&CHARSAVE_MEMO)?" MEMO":"",
		(save_flag&CHARSAVE_SKILL)?" SKILL":"",
		(save_flag&CHARSAVE_FRIENDS)?" FRIENDS":"",
		(save_flag&CHARSAVE_HOTKEYS)?" HOTKEYS":""
	);
	return save_status;
}

/**
 * Compares the different item groups in two mmo_charstatus objects and returns
 * the different flags
 *
 * @return uint32 with the proper char_save_flags set
 * @see char_save_flag
 **/
static int32 char_mmo_char_compare(const struct mmo_charstatus *cp, const struct mmo_charstatus *p)
{
	int32 flag = CHARSAVE_NONE;

	// Inventory data
	if(memcmp(p->inventory, cp->inventory, sizeof(p->inventory)))
		flag |= CHARSAVE_INVENTORY;
	// Cart data
	if(memcmp(p->cart, cp->cart, sizeof(p->cart)))
		flag |= CHARSAVE_CART;

	// Long status (most frequently changed status)
	if((p->base_exp != cp->base_exp) || (p->base_level != cp->base_level)
	|| (p->job_level != cp->job_level) || (p->job_exp != cp->job_exp)
	|| (p->zeny != cp->zeny)
	|| (p->last_point.map != cp->last_point.map)
	|| (p->last_point.x != cp->last_point.x)
	|| (p->last_point.y != cp->last_point.y)
	|| (p->max_hp != cp->max_hp) || (p->hp != cp->hp)
	|| (p->max_sp != cp->max_sp) || (p->sp != cp->sp)
	|| (p->status_point != cp->status_point)
	|| (p->skill_point != cp->skill_point)
	|| (p->str != cp->str) || (p->agi != cp->agi) || (p->vit != cp->vit)
	|| (p->int_ != cp->int_) || (p->dex != cp->dex) || (p->luk != cp->luk)
	|| (p->option != cp->option) || (p->party_id != cp->party_id)
	|| (p->guild_id != cp->guild_id) || (p->pet_id != cp->pet_id)
	|| (p->look.weapon != cp->look.weapon) || (p->hom_id != cp->hom_id)
	|| (p->ele_id != cp->ele_id) || (p->look.shield != cp->look.shield)
	|| (p->look.head_top != cp->look.head_top)
	|| (p->look.head_mid != cp->look.head_mid)
	|| (p->look.head_bottom != cp->look.head_bottom)
	|| (p->delete_date != cp->delete_date) || (p->rename != cp->rename)
	|| (p->slotchange != cp->slotchange) || (p->look.robe != cp->look.robe)
	|| (p->show_equip != cp->show_equip) || (p->allow_party != cp->allow_party)
	|| (p->font != cp->font) || (p->uniqueitem_counter != cp->uniqueitem_counter)
	|| (p->hotkey_rowshift != cp->hotkey_rowshift)
	|| (p->hotkey_rowshift2 != cp->hotkey_rowshift2)
	|| (p->clan_id != cp->clan_id) || (p->last_login != cp->last_login)
	|| (p->title_id != cp->title_id) || (p->inventorySize != cp->inventorySize)
	|| (p->allow_call != cp->allow_call)
	)
		flag |= CHARSAVE_STATUS_LONG;

	// Account data
	if(p->bank_vault != cp->bank_vault || p->mod_exp != cp->mod_exp
	|| p->mod_drop != cp->mod_drop || p->mod_death != cp->mod_death
	|| p->attendance_count != cp->attendance_count
	|| p->attendance_timer != cp->attendance_timer
	)
		flag |= CHARSAVE_ACCDATA;

	// Values that will seldom change (to speed up saving)
	if((p->hair != cp->hair) || (p->hair_color != cp->hair_color)
	|| (p->clothes_color != cp->clothes_color) || (p->body != cp->body)
	|| (p->class != cp->class) || (p->partner_id != cp->partner_id)
	|| (p->father != cp->father) || (p->mother != cp->mother)
	|| (p->child != cp->child) || (p->karma != cp->karma)
	|| (p->manner != cp->manner) || (p->fame != cp->fame)
	)
		flag |= CHARSAVE_STATUS_SHORT;

	// Mercenary
	if((p->mer_id != cp->mer_id) || (p->arch_calls != cp->arch_calls)
	|| (p->arch_faith != cp->arch_faith) || (p->spear_calls != cp->spear_calls)
	|| (p->spear_faith != cp->spear_faith) || (p->sword_calls != cp->sword_calls)
	|| (p->sword_faith != cp->sword_faith)
	)
		flag |= CHARSAVE_MERCENARY;

	// memo points
	if(memcmp(p->memo_point, cp->memo_point, sizeof(p->memo_point)))
		flag |= CHARSAVE_MEMO;

	// Skills
	if(memcmp(p->skill, cp->skill, sizeof(p->skill)))
		flag |= CHARSAVE_SKILL;

	// Friends
	for(int i = 0; i < MAX_FRIENDS; i++) {
		if(p->friends[i].char_id != cp->friends[i].char_id
		|| p->friends[i].account_id != cp->friends[i].account_id
		) {
			flag |= CHARSAVE_FRIENDS;
			break;
		}
	}

#ifdef HOTKEY_SAVING
	for(int i = 0; i < ARRAYLENGTH(p->hotkeys); i++) {
		if(memcmp(&p->hotkeys[i], &cp->hotkeys[i], sizeof(struct hotkey))) {
			flag |= CHARSAVE_HOTKEYS;
			break;
		}
	}
#endif
	return flag;
}

/**
 * Updates database with charstatus data.
 * Currently when there's an error at any point of the saving process the server
 * doesn't update the internal cache.
 *
 * @retval  0 Success
 * @retval -1 Save request ignored (id mismatch)
 * @retval >0 Internal cache was not updated, value with successfuly saved data.
 * @see char_save_flag
 *
 * Acquires db_lock(chr->char_db_)
 **/
static int char_mmo_char_tosql(int char_id, struct mmo_charstatus *p)
{
	struct mmo_charstatus *cp;
	StringBuf buf;
	int32 save_flag, control_flag;
	struct Sql *sql_handle = inter->sql_handle_get();

	nullpo_ret(p);
	if(char_id != p->char_id) {
		ShowError("char_mmo_char_tosql: id mismatch (%d:%d), ignoring save request\n",
			char_id, p->char_id);
		return -1;
	}

	db_lock(chr->char_db_, WRITE_LOCK);
	cp = idb_ensure(chr->char_db_, char_id, chr->create_charstatus);
	save_flag = chr->mmo_char_compare(cp, p);
	control_flag = save_flag;
	StrBuf->Init(&buf);

	// Inventory data
	if(save_flag&CHARSAVE_INVENTORY) {
		if(chr->memitemdata_to_sql(p->inventory, -1, p->char_id, TABLE_INVENTORY))
			save_flag &= ~CHARSAVE_INVENTORY;
	}

	// Cart data
	if(save_flag&CHARSAVE_CART) {
		if(chr->memitemdata_to_sql(p->cart, -1, p->char_id, TABLE_CART))
			save_flag &= ~CHARSAVE_CART;
	}

	// Long status (most frequently changed status)
	if(save_flag&CHARSAVE_STATUS_LONG) {
		unsigned int opt = 0;

		if(p->inventorySize <= 0 || p->inventorySize > MAX_INVENTORY) {
			ShowError("Wrong inventorySize field: %d. Must be in range 1 to %d. "
			          "Character %s (CID: %d, AID: %d)\n",
			          p->inventorySize, MAX_INVENTORY, p->name, p->char_id, p->account_id);
			Assert_report(0);
			p->inventorySize = FIXED_INVENTORY_SIZE;
		}

		if(p->allow_party)
			opt |= OPT_ALLOW_PARTY;
		if(p->show_equip)
			opt |= OPT_SHOW_EQUIP;
		if(p->allow_call)
			opt |= OPT_ALLOW_CALL;

		if( SQL_ERROR == SQL->Query(sql_handle, "UPDATE `%s` SET `base_level`='%d', `job_level`='%d',"
			"`base_exp`='%"PRIu64"', `job_exp`='%"PRIu64"', `zeny`='%d',"
			"`max_hp`='%d',`hp`='%d',`max_sp`='%d',`sp`='%d',`status_point`='%d',`skill_point`='%d',"
			"`str`='%d',`agi`='%d',`vit`='%d',`int`='%d',`dex`='%d',`luk`='%d',"
			"`option`='%u',`party_id`='%d',`guild_id`='%d',`pet_id`='%d',`homun_id`='%d',`elemental_id`='%d',"
			"`weapon`='%d',`shield`='%d',`head_top`='%d',`head_mid`='%d',`head_bottom`='%d',"
			"`last_map`='%s',`last_x`='%d',`last_y`='%d',`save_map`='%s',`save_x`='%d',`save_y`='%d', `rename`='%d',"
			"`delete_date`='%lu',`robe`='%d',`slotchange`='%d', `char_opt`='%u', `font`='%u', `uniqueitem_counter` ='%u',"
			"`hotkey_rowshift`='%d',`hotkey_rowshift2`='%d',`clan_id`='%d',`last_login`='%"PRId64"',"
			"`title_id`='%d', `inventory_size`='%d'"
			" WHERE  `account_id`='%d' AND `char_id` = '%d'",
			char_db, p->base_level, p->job_level,
			p->base_exp, p->job_exp, p->zeny,
			p->max_hp, p->hp, p->max_sp, p->sp, p->status_point, p->skill_point,
			p->str, p->agi, p->vit, p->int_, p->dex, p->luk,
			p->option, p->party_id, p->guild_id, p->pet_id, p->hom_id, p->ele_id,
			p->look.weapon, p->look.shield, p->look.head_top, p->look.head_mid, p->look.head_bottom,
			mapindex_id2name(p->last_point.map), p->last_point.x, p->last_point.y,
			mapindex_id2name(p->save_point.map), p->save_point.x, p->save_point.y, p->rename,
			(unsigned long)p->delete_date,  // FIXME: platform-dependent size
			p->look.robe,p->slotchange,opt,p->font,p->uniqueitem_counter,
			p->hotkey_rowshift, p->hotkey_rowshift2, p->clan_id, p->last_login,
			p->title_id, p->inventorySize,
			p->account_id, p->char_id) )
		{
			Sql_ShowDebug(sql_handle);
			save_flag &= ~CHARSAVE_STATUS_LONG;
		}
	}

	//Values that will seldom change (to speed up saving)
	if(save_flag&CHARSAVE_STATUS_SHORT) {
		if( SQL_ERROR == SQL->Query(sql_handle, "UPDATE `%s` SET `class`='%d',"
			"`hair`='%d', `hair_color`='%d', `clothes_color`='%d', `body`='%d',"
			"`partner_id`='%d', `father`='%d', `mother`='%d', `child`='%d',"
			"`karma`='%d', `manner`='%d', `fame`='%d'"
			" WHERE  `account_id`='%d' AND `char_id` = '%d'",
			char_db, p->class,
			p->hair, p->hair_color, p->clothes_color, p->body,
			p->partner_id, p->father, p->mother, p->child,
			p->karma, p->manner, p->fame,
			p->account_id, p->char_id) )
		{
			Sql_ShowDebug(sql_handle);
			save_flag &= ~CHARSAVE_STATUS_SHORT;
		}
	}

	// Account data
	if(save_flag&CHARSAVE_ACCDATA) {
		if(SQL_ERROR == SQL->Query(sql_handle,
			"REPLACE INTO `%s` (`account_id`,`bank_vault`,`base_exp`,`base_drop`,"
			"`base_death`,`attendance_count`,`attendance_timer`) "
			"VALUES ('%d','%d','%d','%d','%d','%d','%"PRId64"')",
			account_data_db, p->account_id, p->bank_vault, p->mod_exp, p->mod_drop,
			p->mod_death, p->attendance_count, p->attendance_timer)
		) {
			Sql_ShowDebug(sql_handle);
			save_flag &= ~CHARSAVE_ACCDATA;
		}
	}

	// Mercenary Owner
	if(save_flag&CHARSAVE_MERCENARY) {
		if(inter_mercenary->owner_tosql(char_id, p))
			save_flag &= ~CHARSAVE_MERCENARY;
	}

	// memo points
	if(save_flag&CHARSAVE_MEMO) {
		char esc_mapname[ESC_NAME_LENGTH];

		//`memo` (`memo_id`,`char_id`,`map`,`x`,`y`)
		if(SQL_ERROR == SQL->Query(sql_handle,
		  "DELETE FROM `%s` WHERE `char_id`='%d'", memo_db, p->char_id)
		) {
			Sql_ShowDebug(sql_handle);
			save_flag &= ~CHARSAVE_MEMO;
		} else {
			//insert here.
			StrBuf->Clear(&buf);
			StrBuf->Printf(&buf, "INSERT INTO `%s`(`char_id`,`map`,`x`,`y`) VALUES ",
				memo_db);

			int count = 0;
			for(int i = 0; i < MAX_MEMOPOINTS; ++i) {
				if(p->memo_point[i].map) {
					if(count)
						StrBuf->AppendStr(&buf, ",");
					SQL->EscapeString(sql_handle, esc_mapname,
						mapindex_id2name(p->memo_point[i].map));
					StrBuf->Printf(&buf, "('%d', '%s', '%d', '%d')", char_id,
						esc_mapname, p->memo_point[i].x, p->memo_point[i].y);
					++count;
				}
			}
			if(count && SQL_ERROR == SQL->QueryStr(sql_handle, StrBuf->Value(&buf))) {
				Sql_ShowDebug(sql_handle);
				save_flag &= ~CHARSAVE_MEMO;
			}
		}
	}

	// Skills
	if(save_flag&CHARSAVE_SKILL) {
		//`skill` (`char_id`, `id`, `lv`)
		if( SQL_ERROR == SQL->Query(sql_handle,
			"DELETE FROM `%s` WHERE `char_id`='%d'", skill_db, p->char_id)
		) {
			Sql_ShowDebug(sql_handle);
			save_flag &= ~CHARSAVE_SKILL;
		} else {
			StrBuf->Clear(&buf);
			StrBuf->Printf(&buf, "INSERT INTO `%s`(`char_id`,`id`,`lv`,`flag`) VALUES ",
				skill_db);
			//insert here.
			int count = 0;
			for(int i = 0; i < MAX_SKILL_DB; ++i) {
				if(p->skill[i].id == 0)
					continue;
				if(p->skill[i].flag == SKILL_FLAG_TEMPORARY)
					continue;
				if(p->skill[i].flag == SKILL_FLAG_PLAGIARIZED)
					continue;
				if(p->skill[i].lv == 0
				&& (p->skill[i].flag == SKILL_FLAG_PERM_GRANTED
				    || p->skill[i].flag == SKILL_FLAG_PERMANENT)
				)
					continue;
				if(p->skill[i].flag == SKILL_FLAG_REPLACED_LV_0)
					continue;

				if(Assert_chk(p->skill[i].flag == SKILL_FLAG_PERMANENT
				           || p->skill[i].flag == SKILL_FLAG_PERM_GRANTED
				           || p->skill[i].flag > SKILL_FLAG_REPLACED_LV_0)
				)
					continue;
				if(count != 0)
					StrBuf->AppendStr(&buf, ",");
				int saved_lv = (p->skill[i].flag > SKILL_FLAG_REPLACED_LV_0) ?
					p->skill[i].flag - SKILL_FLAG_REPLACED_LV_0 : p->skill[i].lv;
				int skill_flag = (p->skill[i].flag == SKILL_FLAG_PERM_GRANTED) ?
					p->skill[i].flag : 0; // other flags do not need to be saved
				StrBuf->Printf(&buf, "('%d','%d','%d','%d')",
					char_id, p->skill[i].id, saved_lv, skill_flag);

				++count;
			}
			if(count != 0
			&& SQL_ERROR == SQL->QueryStr(sql_handle, StrBuf->Value(&buf))
			) {
				Sql_ShowDebug(sql_handle);
				save_flag &= ~CHARSAVE_SKILL;
			}
		}
	}

	// Friends
	if(save_flag&CHARSAVE_FRIENDS) {
		if(SQL_ERROR == SQL->Query(sql_handle,
			"DELETE FROM `%s` WHERE `char_id`='%d'",
			friend_db, char_id)
		) {
			Sql_ShowDebug(sql_handle);
			save_flag &= ~CHARSAVE_FRIENDS;
		} else {
			StrBuf->Clear(&buf);
			StrBuf->Printf(&buf,
				"INSERT INTO `%s` (`char_id`, `friend_account`, `friend_id`) VALUES ",
				friend_db);
			int count = 0;
			for(int i = 0; i < MAX_FRIENDS; ++i) {
				if(p->friends[i].char_id > 0) {
					if(count)
						StrBuf->AppendStr(&buf, ",");
					StrBuf->Printf(&buf, "('%d','%d','%d')", char_id,
						p->friends[i].account_id, p->friends[i].char_id);
					count++;
				}
			}
			if(count
			&& SQL_ERROR == SQL->QueryStr(sql_handle, StrBuf->Value(&buf))
			) {
				Sql_ShowDebug(sql_handle);
				save_flag &= ~CHARSAVE_FRIENDS;
			}
		}
	}

#ifdef HOTKEY_SAVING
	// Hotkeys
	if(save_flag&CHARSAVE_HOTKEYS) {
		StrBuf->Clear(&buf);
		StrBuf->Printf(&buf, "REPLACE INTO `%s` "
			"(`char_id`, `hotkey`, `type`, `itemskill_id`, `skill_lvl`) VALUES ",
			hotkey_db);
		int count = 0;
		for(int i = 0; i < ARRAYLENGTH(p->hotkeys); i++) {
			if(memcmp(&p->hotkeys[i], &cp->hotkeys[i], sizeof(struct hotkey))) {
				if(count)
					StrBuf->AppendStr(&buf, ",");// not the first hotkey
				StrBuf->Printf(&buf, "('%d','%u','%u','%u','%u')", char_id,
					(unsigned int)i, (unsigned int)p->hotkeys[i].type, p->hotkeys[i].id,
					(unsigned int)p->hotkeys[i].lv);
				count++;
			}
		}
		if(count
		&& SQL_ERROR == SQL->QueryStr(sql_handle, StrBuf->Value(&buf))
		) {
			Sql_ShowDebug(sql_handle);
			save_flag &= ~CHARSAVE_HOTKEYS;
		}
	}
#endif

	StrBuf->Destroy(&buf);
	if(chr->show_save_log && save_flag != CHARSAVE_NONE) {
		char save_status[128];
		ShowInfo("Saved char %d - %s:%s.\n", char_id, p->name,
			chr->mmo_flag2str(save_status, sizeof(save_status), save_flag));
	}
	if(save_flag == control_flag) {
		// No errors
		memcpy(cp, p, sizeof(struct mmo_charstatus));
		save_flag = 0; // Cache updated
	}
	db_unlock(chr->char_db_);
	return save_flag;
}

/**
 * Gets a player object's item data from an sql table. [Smokexyz/Hercules]
 * @param[in|out] items     reference to the item list of a character/account/guild.
 * @param[in]     max       Max amount of items to be pulled into the list.
 * @param[in]     guid      Unique ID of the player object (account_id, char_id, guild_id).
 * @param[in]     table     Table to be used for the transaction.
 * @return -1 on failure or number of items added to the list if successful.
 */
static int char_getitemdata_from_sql(struct item *items, int max, int guid, enum inventory_table_type table)
{
	int i = 0;
	struct SqlStmt *stmt = NULL;
	const char *tablename = NULL;
	const char *selectoption = NULL;
	bool has_favorite = false;
	StringBuf buf;
	struct item item = { 0 }; // temp storage variable
	struct Sql *sql_handle = inter->sql_handle_get();

	if (max > 0)
		nullpo_retr(-1, items);
	Assert_retr(-1, guid > 0);

	// Initialize the array.
	if (max > 0)
		memset(items, 0x0, sizeof(struct item) * max);

	switch (table) {
	case TABLE_INVENTORY:
		tablename = inventory_db;
		selectoption = "char_id";
		has_favorite = true;
		break;
	case TABLE_CART:
		tablename = cart_db;
		selectoption = "char_id";
		break;
	case TABLE_GUILD_STORAGE:
		tablename = guild_storage_db;
		selectoption = "guild_id";
		break;
	case TABLE_STORAGE:
	default:
		ShowError("char_getitemdata_from_sql: Invalid table type %d!\n", (int) table);
		Assert_retr(-1, table);
		return -1;
	}

	StrBuf->Init(&buf);
	StrBuf->AppendStr(&buf, "SELECT `id`, `nameid`, `amount`, `equip`, `identify`, `refine`, `attribute`, `expire_time`, `bound`, `unique_id`");
	for(i = 0; i < MAX_SLOTS; i++)
		StrBuf->Printf(&buf, ", `card%d`", i);
	for(i = 0; i < MAX_ITEM_OPTIONS; i++)
		StrBuf->Printf(&buf, ", `opt_idx%d`, `opt_val%d`", i, i);
	if (has_favorite)
		StrBuf->AppendStr(&buf, ", `favorite`");
	StrBuf->Printf(&buf, " FROM `%s` WHERE `%s`=?", tablename, selectoption);

	stmt = SQL->StmtMalloc(sql_handle);
	if (SQL_ERROR == SQL->StmtPrepareStr(stmt, StrBuf->Value(&buf))
		|| SQL_ERROR == SQL->StmtBindParam(stmt, 0, SQLDT_INT, &guid, sizeof guid)
		|| SQL_ERROR == SQL->StmtExecute(stmt)) {
		SqlStmt_ShowDebug(stmt);
		SQL->StmtFree(stmt);
		StrBuf->Destroy(&buf);
		return -1;
	}

	if (SQL_ERROR == SQL->StmtBindColumn(stmt, 0, SQLDT_INT,    &item.id,          sizeof item.id,          NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 1, SQLDT_INT,    &item.nameid,      sizeof item.nameid,      NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 2, SQLDT_SHORT,  &item.amount,      sizeof item.amount,      NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 3, SQLDT_UINT,   &item.equip,       sizeof item.equip,       NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 4, SQLDT_CHAR,   &item.identify,    sizeof item.identify,    NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 5, SQLDT_CHAR,   &item.refine,      sizeof item.refine,      NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 6, SQLDT_CHAR,   &item.attribute,   sizeof item.attribute,   NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 7, SQLDT_UINT,   &item.expire_time, sizeof item.expire_time, NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 8, SQLDT_UCHAR,  &item.bound,       sizeof item.bound,       NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 9, SQLDT_UINT64, &item.unique_id,   sizeof item.unique_id,   NULL, NULL)
	) {
		SqlStmt_ShowDebug(stmt);
	}

	for (i = 0; i < MAX_SLOTS; i++) {
		if (SQL_ERROR == SQL->StmtBindColumn(stmt, 10 + i, SQLDT_INT, &item.card[i], sizeof item.card[i], NULL, NULL))
			SqlStmt_ShowDebug(stmt);
	}

	for (i = 0; i < MAX_ITEM_OPTIONS; i++) {
		if (SQL_ERROR == SQL->StmtBindColumn(stmt, 10 + MAX_SLOTS + i * 2, SQLDT_INT16, &item.option[i].index, sizeof item.option[i].index, NULL, NULL)
		 || SQL_ERROR == SQL->StmtBindColumn(stmt, 11 + MAX_SLOTS + i * 2, SQLDT_INT16, &item.option[i].value, sizeof item.option[i].index, NULL, NULL))
			SqlStmt_ShowDebug(stmt);
	}

	if (has_favorite) {
		if (SQL_ERROR == SQL->StmtBindColumn(stmt, 10 + MAX_SLOTS + MAX_ITEM_OPTIONS * 2, SQLDT_CHAR, &item.favorite, sizeof item.favorite, NULL, NULL))
			SqlStmt_ShowDebug(stmt);
	}

	if (SQL->StmtNumRows(stmt) > 0 ) {
		i = 0;
		while (SQL_SUCCESS == SQL->StmtNextRow(stmt) && i < max) {
			items[i++] = item;
		}
	}

	SQL->StmtFree(stmt);
	StrBuf->Destroy(&buf);

	return i;
}

/**
 * Saves an array of 'item' entries into the specified table. [Smokexyz/Hercules]
 * @param[in] items        The items array.
 * @param[in] current_size The current size of the items array (-1 to automatically use the maximum size, for fixed size inventories).
 * @param[in] guid         The character/account/guild ID (depending on table).
 * @param[in] table        The type of table (@see enum inventory_table_type).
 * @retval -1 in case of failure, or number of changes made within the table.
 */
static int char_memitemdata_to_sql(const struct item *p_items, int current_size, int guid, enum inventory_table_type table)
{
	const char *tablename = NULL;
	const char *selectoption = NULL;
	bool has_favorite = false;
	int total_updates = 0, total_deletes = 0, total_inserts = 0, total_changes = 0;
	int max_size = 0;
	int db_size = 0;
	struct Sql *sql_handle = inter->sql_handle_get();

	switch (table) {
	case TABLE_INVENTORY:
		tablename = inventory_db;
		selectoption = "char_id";
		has_favorite = true;
		max_size = MAX_INVENTORY;
		break;
	case TABLE_CART:
		tablename = cart_db;
		selectoption = "char_id";
		max_size = MAX_CART;
		break;
	case TABLE_GUILD_STORAGE:
		tablename = guild_storage_db;
		selectoption = "guild_id";
		max_size = MAX_GUILD_STORAGE;
		break;
	case TABLE_STORAGE:
	default:
		ShowError("Invalid table type %d!\n", (int) table);
		Assert_retr(-1, table);
		return -1;
	}
	if (current_size == -1)
		current_size = max_size;

	bool *matched_p = NULL;
	if (current_size > 0) {
		nullpo_ret(p_items);

		matched_p = aCalloc(current_size, sizeof(bool));
	}

	StringBuf buf;
	StrBuf->Init(&buf);

	/**
	 * If the storage table is not empty, check for items and replace or delete where needed.
	 */
	struct item *cp_items = aCalloc(max_size, sizeof(struct item));
	if ((db_size = chr->getitemdata_from_sql(cp_items, max_size, guid, table)) > 0) {
		int *deletes = aCalloc(db_size, sizeof(struct item));

		for (int i = 0; i < db_size; i++) {
			const struct item *cp_it = &cp_items[i];

			int j = 0;
			ARR_FIND(0, current_size, j,
					 matched_p[j] != true
					 && p_items[j].nameid != 0
					 && cp_it->nameid == p_items[j].nameid
					 && cp_it->unique_id == p_items[j].unique_id
					 && memcmp(p_items[j].card, cp_it->card, sizeof(int) * MAX_SLOTS) == 0
					 && memcmp(p_items[j].option, cp_it->option, 5 * MAX_ITEM_OPTIONS) == 0);

			if (j < current_size) { // Item found.
				matched_p[j] = true; // Mark the item as matched.

				// If the amount has changed, set for replacement with current item properties.
				if (memcmp(cp_it, &p_items[j], sizeof(struct item)) != 0) {
					if (total_updates == 0) {
						StrBuf->Clear(&buf);
						StrBuf->Printf(&buf, "REPLACE INTO `%s` (`id`, `%s`, `nameid`, `amount`, `equip`, `identify`, `refine`, `attribute`", tablename, selectoption);
						for (int k = 0; k < MAX_SLOTS; k++)
							StrBuf->Printf(&buf, ", `card%d`", k);
						for (int k = 0; k < MAX_ITEM_OPTIONS; k++)
							StrBuf->Printf(&buf, ", `opt_idx%d`, `opt_val%d`", k, k);
						StrBuf->AppendStr(&buf, ", `expire_time`, `bound`, `unique_id`");
						if (has_favorite)
							StrBuf->AppendStr(&buf, ", `favorite`");

						StrBuf->AppendStr(&buf, ") VALUES ");

					}

					StrBuf->Printf(&buf, "%s('%d', '%d', '%d', '%d', '%u', '%d', '%d', '%d'",
								   total_updates > 0 ? ", " : "", cp_it->id, guid, p_items[j].nameid, p_items[j].amount, p_items[j].equip, p_items[j].identify, p_items[j].refine, p_items[j].attribute);
					for (int k = 0; k < MAX_SLOTS; k++)
						StrBuf->Printf(&buf, ", '%d'", p_items[j].card[k]);
					for (int k = 0; k < MAX_ITEM_OPTIONS; ++k)
						StrBuf->Printf(&buf, ", '%d', '%d'", p_items[j].option[k].index, p_items[j].option[k].value);
					StrBuf->Printf(&buf, ", '%u', '%d', '%"PRIu64"'", p_items[j].expire_time, p_items[j].bound, p_items[j].unique_id);
					if (has_favorite)
						StrBuf->Printf(&buf, ", %d", p_items[j].favorite);

					StrBuf->AppendStr(&buf, ")");

					total_updates++;
				}
			} else { // Doesn't exist in the table, set for deletion.
				deletes[total_deletes++] = cp_it->id;
			}
		}

		if (total_updates > 0 && SQL_ERROR == SQL->QueryStr(sql_handle, StrBuf->Value(&buf)))
			Sql_ShowDebug(sql_handle);

		/**
		 * Handle deletions, if any.
		 */
		if (total_deletes > 0) {
			StrBuf->Clear(&buf);
			StrBuf->Printf(&buf, "DELETE FROM `%s` WHERE `id` IN (", tablename);
			for (int i = 0; i < total_deletes; i++)
				StrBuf->Printf(&buf, "%s'%d'", i == 0 ? "" : ", ", deletes[i]);

			StrBuf->AppendStr(&buf, ");");

			if (SQL_ERROR == SQL->QueryStr(sql_handle, StrBuf->Value(&buf)))
				Sql_ShowDebug(sql_handle);
		}

		aFree(deletes);
	}

	/**
	 * Check for new items and add if required.
	 */
	for (int i = 0; i < current_size; i++) {
		const struct item *p_it = &p_items[i];

		if (matched_p[i] || p_it->nameid == 0)
			continue;

		if (total_inserts == 0) {
			StrBuf->Clear(&buf);
			StrBuf->Printf(&buf, "INSERT INTO `%s` (`%s`, `nameid`, `amount`, `equip`, `identify`, `refine`, `attribute`, `expire_time`, `bound`, `unique_id`", tablename, selectoption);
			for (int j = 0; j < MAX_SLOTS; ++j)
				StrBuf->Printf(&buf, ", `card%d`", j);
			for (int j = 0; j < MAX_ITEM_OPTIONS; ++j)
				StrBuf->Printf(&buf, ", `opt_idx%d`, `opt_val%d`", j, j);
			if (has_favorite)
				StrBuf->AppendStr(&buf, ", `favorite`");
			StrBuf->AppendStr(&buf, ") VALUES ");
		}

		StrBuf->Printf(&buf, "%s('%d', '%d', '%d', '%u', '%d', '%d', '%d', '%u', '%d', '%"PRIu64"'",
					   total_inserts > 0 ? ", " : "", guid, p_it->nameid, p_it->amount, p_it->equip, p_it->identify, p_it->refine,
					   p_it->attribute, p_it->expire_time, p_it->bound, p_it->unique_id);

		for (int j = 0; j < MAX_SLOTS; ++j)
			StrBuf->Printf(&buf, ", '%d'", p_it->card[j]);
		for (int j = 0; j < MAX_ITEM_OPTIONS; ++j)
			StrBuf->Printf(&buf, ", '%d', '%d'", p_it->option[j].index, p_it->option[j].value);

		if (has_favorite)
			StrBuf->Printf(&buf, ", '%d'", p_it->favorite);

		StrBuf->AppendStr(&buf, ")");

		total_inserts++;
	}

	if (total_inserts > 0 && SQL_ERROR == SQL->QueryStr(sql_handle, StrBuf->Value(&buf)))
		Sql_ShowDebug(sql_handle);

	StrBuf->Destroy(&buf);

	aFree(cp_items);
	if (matched_p != NULL)
		aFree(matched_p);

	ShowInfo("%s save complete - guid: %d (replace: %d, insert: %d, delete: %d)\n", tablename, guid, total_updates, total_inserts, total_deletes);

	return total_changes;
}

/**
 * Returns the correct gender ID for the given character and enum value.
 *
 * If the per-character sex is defined but not supported by the current packetver, the database entries are corrected.
 *
 * @param sd Character data, if available.
 * @param p  Character status.
 * @param sex Character sex (database enum)
 *
 * @retval SEX_MALE if the per-character sex is male
 * @retval SEX_FEMALE if the per-character sex is female
 * @retval 99 if the per-character sex is not defined or the current PACKETVER doesn't support it.
 */
static int char_mmo_gender(const struct char_session_data *sd, const struct mmo_charstatus *p, char sex)
{
#if PACKETVER >= 20141016
	(void)sd; (void)p; // Unused
	switch (sex) {
		case 'M':
			return SEX_MALE;
		case 'F':
			return SEX_FEMALE;
		case 'U':
		default:
			return 99;
	}
#else
	struct Sql *sql_handle = inter->sql_handle_get();
	if (sex == 'M' || sex == 'F') {
		if (!sd) {
			// sd is not available, there isn't much we can do. Just return and print a warning.
			ShowWarning("Character '%s' (CID: %d, AID: %d) has sex '%c', but PACKETVER does not support per-character sex. Defaulting to 'U'.\n",
					p->name, p->char_id, p->account_id, sex);
			return 99;
		}
		if ((sex == 'M' && sd->sex == SEX_FEMALE)
		 || (sex == 'F' && sd->sex == SEX_MALE)) {
			ShowWarning("Changing sex of character '%s' (CID: %d, AID: %d) to 'U' due to incompatible PACKETVER.\n", p->name, p->char_id, p->account_id);
			chr->changecharsex(p->char_id, sd->sex);
		} else {
			ShowInfo("Resetting sex of character '%s' (CID: %d, AID: %d) to 'U' due to incompatible PACKETVER.\n", p->name, p->char_id, p->account_id);
		}
		if (SQL_ERROR == SQL->Query(sql_handle, "UPDATE `%s` SET `sex` = 'U' WHERE `char_id` = '%d'", char_db, p->char_id)) {
			Sql_ShowDebug(sql_handle);
		}
	}
	return 99;
#endif
}

//=====================================================================================================
// Loads the basic character rooster for the given account. Returns total buffer used.
static int char_mmo_chars_fromsql(struct char_session_data *sd, uint8 *buf, int *count)
{
	struct SqlStmt *stmt;
	struct mmo_charstatus p;
	int j = 0, i;
	char last_map[MAP_NAME_LENGTH_EXT];
	time_t unban_time = 0;
	char sex[2];

	if (count)
		*count = 0;

	nullpo_ret(sd);
	nullpo_ret(buf);

	struct Sql *sql_handle = inter->sql_handle_get();

	stmt = SQL->StmtMalloc(sql_handle);
	if( stmt == NULL ) {
		SqlStmt_ShowDebug(stmt);
		return 0;
	}
	memset(&p, 0, sizeof(p));

	for(i = 0 ; i < MAX_CHARS; i++ ) {
		sd->found_char[i] = -1;
		sd->unban_time[i] = 0;
	}

	// read char data
	if (SQL_ERROR == SQL->StmtPrepare(stmt, "SELECT "
		"`char_id`,`char_num`,`name`,`class`,`base_level`,`job_level`,`base_exp`,`job_exp`,`zeny`,"
		"`str`,`agi`,`vit`,`int`,`dex`,`luk`,`max_hp`,`hp`,`max_sp`,`sp`,"
		"`status_point`,`skill_point`,`option`,`karma`,`manner`,`hair`,`hair_color`,"
		"`clothes_color`,`body`,`weapon`,`shield`,`head_top`,`head_mid`,`head_bottom`,`last_map`,`rename`,`delete_date`,"
		"`robe`,`slotchange`,`unban_time`,`sex`,`title_id`,`inventory_size`"
		" FROM `%s` WHERE `account_id`='%d' AND `char_num` < '%d'", char_db, sd->account_id, MAX_CHARS)
	 || SQL_ERROR == SQL->StmtExecute(stmt)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 0,  SQLDT_INT,    &p.char_id,          sizeof p.char_id,          NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 1,  SQLDT_UCHAR,  &p.slot,             sizeof p.slot,             NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 2,  SQLDT_STRING, &p.name,             sizeof p.name,             NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 3,  SQLDT_INT,    &p.class,            sizeof p.class,            NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 4,  SQLDT_INT,    &p.base_level,       sizeof p.base_level,       NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 5,  SQLDT_INT,    &p.job_level,        sizeof p.job_level,        NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 6,  SQLDT_UINT64, &p.base_exp,         sizeof p.base_exp,         NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 7,  SQLDT_UINT64, &p.job_exp,          sizeof p.job_exp,          NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 8,  SQLDT_INT,    &p.zeny,             sizeof p.zeny,             NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 9,  SQLDT_SHORT,  &p.str,              sizeof p.str,              NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 10, SQLDT_SHORT,  &p.agi,              sizeof p.agi,              NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 11, SQLDT_SHORT,  &p.vit,              sizeof p.vit,              NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 12, SQLDT_SHORT,  &p.int_,             sizeof p.int_,             NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 13, SQLDT_SHORT,  &p.dex,              sizeof p.dex,              NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 14, SQLDT_SHORT,  &p.luk,              sizeof p.luk,              NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 15, SQLDT_INT,    &p.max_hp,           sizeof p.max_hp,           NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 16, SQLDT_INT,    &p.hp,               sizeof p.hp,               NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 17, SQLDT_INT,    &p.max_sp,           sizeof p.max_sp,           NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 18, SQLDT_INT,    &p.sp,               sizeof p.sp,               NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 19, SQLDT_INT,    &p.status_point,     sizeof p.status_point,     NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 20, SQLDT_INT,    &p.skill_point,      sizeof p.skill_point,      NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 21, SQLDT_UINT,   &p.option,           sizeof p.option,           NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 22, SQLDT_UCHAR,  &p.karma,            sizeof p.karma,            NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 23, SQLDT_SHORT,  &p.manner,           sizeof p.manner,           NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 24, SQLDT_SHORT,  &p.hair,             sizeof p.hair,             NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 25, SQLDT_SHORT,  &p.hair_color,       sizeof p.hair_color,       NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 26, SQLDT_SHORT,  &p.clothes_color,    sizeof p.clothes_color,    NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 27, SQLDT_INT,    &p.body,             sizeof p.body,             NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 28, SQLDT_INT,    &p.look.weapon,      sizeof p.look.weapon,      NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 29, SQLDT_INT,    &p.look.shield,      sizeof p.look.shield,      NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 30, SQLDT_INT,    &p.look.head_top,    sizeof p.look.head_top,    NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 31, SQLDT_INT,    &p.look.head_mid,    sizeof p.look.head_mid,    NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 32, SQLDT_INT,    &p.look.head_bottom, sizeof p.look.head_bottom, NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 33, SQLDT_STRING, &last_map,           sizeof last_map,           NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 34, SQLDT_USHORT, &p.rename,           sizeof p.rename,           NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 35, SQLDT_TIME,   &p.delete_date,      sizeof p.delete_date,      NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 36, SQLDT_INT,    &p.look.robe,        sizeof p.look.robe,        NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 37, SQLDT_USHORT, &p.slotchange,       sizeof p.slotchange,       NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 38, SQLDT_TIME,   &unban_time,         sizeof unban_time,         NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 39, SQLDT_ENUM,   &sex,                sizeof sex,                NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 40, SQLDT_INT,    &p.title_id,         sizeof p.title_id,         NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 41, SQLDT_INT,    &p.inventorySize,    sizeof p.inventorySize,    NULL, NULL)
	) {
		SqlStmt_ShowDebug(stmt);
		SQL->StmtFree(stmt);
		return 0;
	}

	int tmpCount = 0;
	for (i = 0; i < MAX_CHARS && SQL_SUCCESS == SQL->StmtNextRow(stmt); i++) {
		if (p.slot >= MAX_CHARS)
			continue;
		if (p.inventorySize <= 0 || p.inventorySize > MAX_INVENTORY) {
			ShowError("Wrong inventorySize field: %d. Must be in range 1 to %d. Character %s (CID: %d, AID: %d)\n",
			          p.inventorySize, MAX_INVENTORY, p.name, p.char_id, p.account_id);
			Assert_report(0);
			p.inventorySize = FIXED_INVENTORY_SIZE;
		}
		p.last_point.map = mapindex->name2id(last_map);
		sd->found_char[p.slot] = p.char_id;
		sd->unban_time[p.slot] = unban_time;
		p.sex = chr->mmo_gender(sd, &p, sex[0]);
		j += chr->mmo_char_tobuf(WBUFP(buf, j), &p);
		tmpCount ++;
	}

	sd->rename = NULL;

	SQL->StmtFree(stmt);
	if (count)
		*count = tmpCount;
	return j;
}

//=====================================================================================================


/**
 * Loads character data from the database.
 *
 * @param char_id    Id to be loaded
 * @param load_flag  Bitmask of data to be loaded (@see char_save_flag)
 * @param out        Pointer to object to be filled (ignored when cache_data is not 0)
 * @param cache_data 0 Don't change cache, load data to `out`
 * @param cache_data 1 Insert into cache - @writelock db_lock(chr->char_db_)
 * @param cache_data 2 Update cache      - @writelock db_lock(chr->char_db_)
 * @retval cache_data is 0 returns pointer to out
 * @retval cache_data is 1 or 2 returns pointer to object in cache
 * @retval NULL failed
 *
 * Acquires skillid2idx_lock when load_flag&CHARSAVE_SKILL
 **/
static struct mmo_charstatus *char_mmo_char_fromsql(int char_id, int load_flag, struct mmo_charstatus *out, enum e_char_cache cache_data)
{
	int i = 0;
	char t_msg[128] = "";
	struct mmo_charstatus* cp;
	struct SqlStmt *stmt;
	char last_map[MAP_NAME_LENGTH_EXT];
	char save_map[MAP_NAME_LENGTH_EXT];
	char point_map[MAP_NAME_LENGTH_EXT];

	unsigned int opt;
	int account_id;
	char sex[2];

	struct Sql *sql_handle = inter->sql_handle_get();

	// Temporary data holder, used when the data will be inserted into cache (cache_data == 1)
	struct mmo_charstatus temp = {0};
	struct mmo_charstatus *data = NULL;

	switch(cache_data) {
		case CHARCACHE_IGNORE_NOLOCK: // Don't change cache
			Assert_retr(NULL, out && "When cache_data is 0 out can't be NULL!");
			load_flag |= CHARSAVE_STATUS;
			data = out;
			memset(data, 0, sizeof(*data));
			break;
		case CHARCACHE_INSERT: // Insert loaded data into cache
			load_flag |= CHARSAVE_STATUS;
			data = &temp;
			break;
		case CHARCACHE_UPDATE: // Update cache
			data = idb_ensure(chr->char_db_, char_id, chr->create_charstatus);
			break;
		default:
			Assert_report("Invalid cache_data!");
			return NULL;
	}

	if(chr->show_save_log)
		ShowInfo("Char load request (%d)\n", char_id);

	stmt = SQL->StmtMalloc(sql_handle);
	if(stmt == NULL) {
		SqlStmt_ShowDebug(stmt);
		return NULL;
	}

	// Read char data CHARSAVE_STATUS_LONG / CHARSAVE_STATUS_SHORT
	if((load_flag&CHARSAVE_STATUS_LONG || load_flag&CHARSAVE_STATUS_SHORT)
	&& (
		SQL_ERROR == SQL->StmtPrepare(stmt, "SELECT "
		"`char_id`,`account_id`,`char_num`,`name`,`class`,`base_level`,`job_level`,`base_exp`,`job_exp`,`zeny`,"
		"`str`,`agi`,`vit`,`int`,`dex`,`luk`,`max_hp`,`hp`,`max_sp`,`sp`,"
		"`status_point`,`skill_point`,`option`,`karma`,`manner`,`party_id`,`guild_id`,`pet_id`,`homun_id`,`elemental_id`,`hair`,"
		"`hair_color`,`clothes_color`,`body`,`weapon`,`shield`,`head_top`,`head_mid`,`head_bottom`,`last_map`,`last_x`,`last_y`,"
		"`save_map`,`save_x`,`save_y`,`partner_id`,`father`,`mother`,`child`,`fame`,`rename`,`delete_date`,`robe`,`slotchange`,"
		"`char_opt`,`font`,`uniqueitem_counter`,`sex`,`hotkey_rowshift`,`hotkey_rowshift2`,`clan_id`,`last_login`,"
		"`title_id`, `inventory_size`"
		" FROM `%s` WHERE `char_id`=? LIMIT 1", char_db)
	 || SQL_ERROR == SQL->StmtBindParam(stmt, 0, SQLDT_INT, &char_id, sizeof char_id)
	 || SQL_ERROR == SQL->StmtExecute(stmt)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 0,  SQLDT_INT,    &data->char_id,            sizeof data->char_id,            NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 1,  SQLDT_INT,    &data->account_id,         sizeof data->account_id,         NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 2,  SQLDT_UCHAR,  &data->slot,               sizeof data->slot,               NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 3,  SQLDT_STRING, &data->name,               sizeof data->name,               NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 4,  SQLDT_INT,    &data->class,              sizeof data->class,              NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 5,  SQLDT_INT,    &data->base_level,         sizeof data->base_level,         NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 6,  SQLDT_INT,    &data->job_level,          sizeof data->job_level,          NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 7,  SQLDT_UINT64, &data->base_exp,           sizeof data->base_exp,           NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 8,  SQLDT_UINT64, &data->job_exp,            sizeof data->job_exp,            NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 9,  SQLDT_INT,    &data->zeny,               sizeof data->zeny,               NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 10, SQLDT_SHORT,  &data->str,                sizeof data->str,                NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 11, SQLDT_SHORT,  &data->agi,                sizeof data->agi,                NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 12, SQLDT_SHORT,  &data->vit,                sizeof data->vit,                NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 13, SQLDT_SHORT,  &data->int_,               sizeof data->int_,               NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 14, SQLDT_SHORT,  &data->dex,                sizeof data->dex,                NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 15, SQLDT_SHORT,  &data->luk,                sizeof data->luk,                NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 16, SQLDT_INT,    &data->max_hp,             sizeof data->max_hp,             NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 17, SQLDT_INT,    &data->hp,                 sizeof data->hp,                 NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 18, SQLDT_INT,    &data->max_sp,             sizeof data->max_sp,             NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 19, SQLDT_INT,    &data->sp,                 sizeof data->sp,                 NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 20, SQLDT_INT,    &data->status_point,       sizeof data->status_point,       NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 21, SQLDT_INT,    &data->skill_point,        sizeof data->skill_point,        NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 22, SQLDT_UINT,   &data->option,             sizeof data->option,             NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 23, SQLDT_UCHAR,  &data->karma,              sizeof data->karma,              NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 24, SQLDT_SHORT,  &data->manner,             sizeof data->manner,             NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 25, SQLDT_INT,    &data->party_id,           sizeof data->party_id,           NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 26, SQLDT_INT,    &data->guild_id,           sizeof data->guild_id,           NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 27, SQLDT_INT,    &data->pet_id,             sizeof data->pet_id,             NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 28, SQLDT_INT,    &data->hom_id,             sizeof data->hom_id,             NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 29, SQLDT_INT,    &data->ele_id,             sizeof data->ele_id,             NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 30, SQLDT_SHORT,  &data->hair,               sizeof data->hair,               NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 31, SQLDT_SHORT,  &data->hair_color,         sizeof data->hair_color,         NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 32, SQLDT_SHORT,  &data->clothes_color,      sizeof data->clothes_color,      NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 33, SQLDT_INT,    &data->body,               sizeof data->body,               NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 34, SQLDT_INT,    &data->look.weapon,        sizeof data->look.weapon,        NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 35, SQLDT_INT,    &data->look.shield,        sizeof data->look.shield,        NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 36, SQLDT_INT,    &data->look.head_top,      sizeof data->look.head_top,      NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 37, SQLDT_INT,    &data->look.head_mid,      sizeof data->look.head_mid,      NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 38, SQLDT_INT,    &data->look.head_bottom,   sizeof data->look.head_bottom,   NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 39, SQLDT_STRING, &last_map,                 sizeof last_map,                 NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 40, SQLDT_INT16,  &data->last_point.x,       sizeof data->last_point.x,       NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 41, SQLDT_INT16,  &data->last_point.y,       sizeof data->last_point.y,       NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 42, SQLDT_STRING, &save_map,                 sizeof save_map,                 NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 43, SQLDT_INT16,  &data->save_point.x,       sizeof data->save_point.x,       NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 44, SQLDT_INT16,  &data->save_point.y,       sizeof data->save_point.y,       NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 45, SQLDT_INT,    &data->partner_id,         sizeof data->partner_id,         NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 46, SQLDT_INT,    &data->father,             sizeof data->father,             NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 47, SQLDT_INT,    &data->mother,             sizeof data->mother,             NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 48, SQLDT_INT,    &data->child,              sizeof data->child,              NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 49, SQLDT_INT,    &data->fame,               sizeof data->fame,               NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 50, SQLDT_USHORT, &data->rename,             sizeof data->rename,             NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 51, SQLDT_TIME,   &data->delete_date,        sizeof data->delete_date,        NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 52, SQLDT_INT,    &data->look.robe,          sizeof data->look.robe,          NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 53, SQLDT_USHORT, &data->slotchange,         sizeof data->slotchange,         NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 54, SQLDT_UINT,   &opt,                      sizeof opt,                      NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 55, SQLDT_UCHAR,  &data->font,               sizeof data->font,               NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 56, SQLDT_UINT32, &data->uniqueitem_counter, sizeof data->uniqueitem_counter, NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 57, SQLDT_ENUM,   &sex,                      sizeof sex,                      NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 58, SQLDT_UCHAR,  &data->hotkey_rowshift,    sizeof data->hotkey_rowshift,    NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 59, SQLDT_UCHAR,  &data->hotkey_rowshift2,   sizeof data->hotkey_rowshift2,   NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 60, SQLDT_INT,    &data->clan_id,            sizeof data->clan_id,            NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 61, SQLDT_INT64,  &data->last_login,         sizeof data->last_login,         NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 62, SQLDT_INT,    &data->title_id,           sizeof data->title_id,           NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 63, SQLDT_INT,    &data->inventorySize,      sizeof data->inventorySize,      NULL, NULL)
	)
	) {
		SqlStmt_ShowDebug(stmt);
		// When inserting or just loading data, status load can't fail
		if(cache_data != CHARCACHE_UPDATE) {
			SQL->StmtFree(stmt);
			return NULL;
		}
		load_flag &= ~(CHARSAVE_STATUS);
	}
	if(SQL_SUCCESS != SQL->StmtNextRow(stmt)) {
		ShowError("Requested non-existant character id: %d!\n", char_id);
		SQL->StmtFree(stmt);
		return NULL;
	}
	if(load_flag&CHARSAVE_STATUS_LONG || load_flag&CHARSAVE_STATUS_SHORT) {
		/* load options into proper vars */
		if(opt & OPT_ALLOW_PARTY)
			data->allow_party = true;
		if(opt & OPT_SHOW_EQUIP)
			data->show_equip = true;
		if(opt & OPT_ALLOW_CALL)
			data->allow_call = true;
	}

	data->sex = chr->mmo_gender(NULL, data, sex[0]);

	account_id = data->account_id;

	data->last_point.map = mapindex->name2id(last_map);
	data->save_point.map = mapindex->name2id(save_map);

	if(data->last_point.map == 0) {
		data->last_point.map = (unsigned short)mapindex->default_id();
		data->last_point.x = mapindex->default_x;
		data->last_point.y = mapindex->default_y;
	}

	if(data->save_point.map == 0) {
		data->save_point.map = (unsigned short)mapindex->default_id();
		data->save_point.x = mapindex->default_x;
		data->save_point.y = mapindex->default_y;
	}

	if(data->inventorySize <= 0 || data->inventorySize > MAX_INVENTORY) {
		ShowError("Wrong inventorySize field: %d. Must be in range 1 to %d. "
			      "Character %s (CID: %d, AID: %d)\n",
		          data->inventorySize, MAX_INVENTORY, data->name, data->char_id, data->account_id);
		Assert_report(0);
		data->inventorySize = FIXED_INVENTORY_SIZE;
	}

	//read memo data
	//`memo` (`memo_id`,`char_id`,`map`,`x`,`y`)
	if(load_flag&CHARSAVE_MEMO) {
		struct point tmp_point = {0};

		if(SQL_ERROR == SQL->StmtPrepare(stmt,
			"SELECT `map`,`x`,`y` FROM `%s` WHERE `char_id`=? ORDER by `memo_id` LIMIT %d",
			memo_db, MAX_MEMOPOINTS)
		|| SQL_ERROR == SQL->StmtBindParam(stmt, 0, SQLDT_INT, &char_id, sizeof char_id)
		|| SQL_ERROR == SQL->StmtExecute(stmt)
		|| SQL_ERROR == SQL->StmtBindColumn(stmt, 0, SQLDT_STRING, &point_map,   sizeof point_map,   NULL, NULL)
		|| SQL_ERROR == SQL->StmtBindColumn(stmt, 1, SQLDT_INT16,  &tmp_point.x, sizeof tmp_point.x, NULL, NULL)
		|| SQL_ERROR == SQL->StmtBindColumn(stmt, 2, SQLDT_INT16,  &tmp_point.y, sizeof tmp_point.y, NULL, NULL)
		) {
			SqlStmt_ShowDebug(stmt);
			load_flag &= ~CHARSAVE_MEMO;
		} else {
			for(i = 0; i < MAX_MEMOPOINTS && SQL_SUCCESS == SQL->StmtNextRow(stmt); ++i) {
				tmp_point.map = mapindex->name2id(point_map);
				memcpy(&data->memo_point[i], &tmp_point, sizeof(tmp_point));
			}
		}
	}

	/* read inventory [Smokexyz/Hercules] */
	if(load_flag&CHARSAVE_INVENTORY &&
	   chr->getitemdata_from_sql(data->inventory, MAX_INVENTORY, data->char_id, TABLE_INVENTORY) < 0
	)
		load_flag &= ~CHARSAVE_INVENTORY;

	/* read cart [Smokexyz/Hercules] */
	if(load_flag&CHARSAVE_CART &&
	   chr->getitemdata_from_sql(data->cart, MAX_CART, data->char_id, TABLE_CART) < 0
	)
		load_flag &= ~CHARSAVE_CART;

	//read skill
	//`skill` (`char_id`, `id`, `lv`)
	if(load_flag&CHARSAVE_SKILL) {
		struct s_skill tmp_skill = {0};
		if (SQL_ERROR == SQL->StmtPrepare(stmt, "SELECT `id`, `lv`,`flag` FROM `%s` WHERE `char_id`=? LIMIT %d", skill_db, MAX_SKILL_DB)
		 || SQL_ERROR == SQL->StmtBindParam(stmt, 0, SQLDT_INT, &char_id, sizeof char_id)
		 || SQL_ERROR == SQL->StmtExecute(stmt)
		 || SQL_ERROR == SQL->StmtBindColumn(stmt, 0, SQLDT_USHORT, &tmp_skill.id,   sizeof tmp_skill.id,   NULL, NULL)
		 || SQL_ERROR == SQL->StmtBindColumn(stmt, 1, SQLDT_UCHAR,  &tmp_skill.lv,   sizeof tmp_skill.lv,   NULL, NULL)
		 || SQL_ERROR == SQL->StmtBindColumn(stmt, 2, SQLDT_UCHAR,  &tmp_skill.flag, sizeof tmp_skill.flag, NULL, NULL)
		) {
			SqlStmt_ShowDebug(stmt);
			load_flag &= ~CHARSAVE_SKILL;
		} else {
			if (tmp_skill.flag != SKILL_FLAG_PERM_GRANTED)
				tmp_skill.flag = SKILL_FLAG_PERMANENT;

			rwlock->read_lock(skillid2idx_lock);
			for (i = 0; i < MAX_SKILL_DB && SQL_SUCCESS == SQL->StmtNextRow(stmt); ++i) {
				if( skillid2idx[tmp_skill.id] )
					memcpy(&data->skill[skillid2idx[tmp_skill.id]], &tmp_skill, sizeof(tmp_skill));
				else
					ShowWarning("chr->mmo_char_fromsql: ignoring invalid skill (id=%u,lv=%u) of "
						"character %s (AID=%d,CID=%d)\n", tmp_skill.id, tmp_skill.lv, data->name,
						data->account_id, data->char_id);
			}
			rwlock->read_unlock(skillid2idx_lock);
		}
	}

	//read friends
	//`friends` (`char_id`, `friend_account`, `friend_id`)
	if(load_flag&CHARSAVE_FRIENDS) {
		struct s_friend tmp_friend = {0};
		if(SQL_ERROR == SQL->StmtPrepare(stmt,
			"SELECT c.`account_id`, c.`char_id`, c.`name` FROM `%s` c LEFT JOIN `%s` f ON f.`friend_account` = c.`account_id` AND f.`friend_id` = c.`char_id` WHERE f.`char_id`=? LIMIT %d",
			char_db, friend_db, MAX_FRIENDS)
		|| SQL_ERROR == SQL->StmtBindParam(stmt, 0, SQLDT_INT, &char_id, sizeof char_id)
		|| SQL_ERROR == SQL->StmtExecute(stmt)
		|| SQL_ERROR == SQL->StmtBindColumn(stmt, 0, SQLDT_INT,    &tmp_friend.account_id, sizeof tmp_friend.account_id, NULL, NULL)
		|| SQL_ERROR == SQL->StmtBindColumn(stmt, 1, SQLDT_INT,    &tmp_friend.char_id,    sizeof tmp_friend.char_id,    NULL, NULL)
		|| SQL_ERROR == SQL->StmtBindColumn(stmt, 2, SQLDT_STRING, &tmp_friend.name,       sizeof tmp_friend.name,       NULL, NULL)
		) {
			SqlStmt_ShowDebug(stmt);
			load_flag &= ~CHARSAVE_FRIENDS;
		} else {
			for(i = 0; i < MAX_FRIENDS && SQL_SUCCESS == SQL->StmtNextRow(stmt); ++i)
				memcpy(&data->friends[i], &tmp_friend, sizeof(tmp_friend));
		}
	}

#ifdef HOTKEY_SAVING
	//read hotkeys
	//`hotkey` (`char_id`, `hotkey`, `type`, `itemskill_id`, `skill_lvl`
	if(load_flag&CHARSAVE_HOTKEYS) {
		struct hotkey tmp_hotkey = {0};
		int hotkey_num = 0;
		memset(&tmp_hotkey, 0, sizeof(tmp_hotkey));
		if(SQL_ERROR == SQL->StmtPrepare(stmt, "SELECT `hotkey`, `type`, `itemskill_id`, `skill_lvl` FROM `%s` WHERE `char_id`=?", hotkey_db)
		|| SQL_ERROR == SQL->StmtBindParam(stmt, 0, SQLDT_INT, &char_id, sizeof char_id)
		|| SQL_ERROR == SQL->StmtExecute(stmt)
		|| SQL_ERROR == SQL->StmtBindColumn(stmt, 0, SQLDT_INT,    &hotkey_num,      sizeof hotkey_num,      NULL, NULL)
		|| SQL_ERROR == SQL->StmtBindColumn(stmt, 1, SQLDT_UCHAR,  &tmp_hotkey.type, sizeof tmp_hotkey.type, NULL, NULL)
		|| SQL_ERROR == SQL->StmtBindColumn(stmt, 2, SQLDT_UINT,   &tmp_hotkey.id,   sizeof tmp_hotkey.id,   NULL, NULL)
		|| SQL_ERROR == SQL->StmtBindColumn(stmt, 3, SQLDT_USHORT, &tmp_hotkey.lv,   sizeof tmp_hotkey.lv,   NULL, NULL)
		) {
			SqlStmt_ShowDebug(stmt);
			load_flag &= ~CHARSAVE_HOTKEYS;
		}

		while(SQL_SUCCESS == SQL->StmtNextRow(stmt) && load_flag&CHARSAVE_HOTKEYS) {
			if( hotkey_num >= 0 && hotkey_num < MAX_HOTKEYS_DB )
				memcpy(&data->hotkeys[hotkey_num], &tmp_hotkey, sizeof(tmp_hotkey));
			else
				ShowWarning("chr->mmo_char_fromsql: ignoring invalid hotkey "
				"(hotkey=%d,type=%u,id=%u,lv=%u) of character %s (AID=%d,CID=%d)\n",
					hotkey_num, tmp_hotkey.type, tmp_hotkey.id, tmp_hotkey.lv,
					data->name, data->account_id, data->char_id);
		}
	}
#endif

	/* Mercenary Owner DataBase */
	if(load_flag&CHARSAVE_MERCENARY && !inter_mercenary->owner_fromsql(char_id, data))
		load_flag &= ~CHARSAVE_MERCENARY;

	if(load_flag&CHARSAVE_ACCDATA) {
		/* default */
		data->mod_exp = data->mod_drop = data->mod_death = 100;

		//`account_data` (`account_id`,`bank_vault`,`base_exp`,`base_drop`,`base_death`,`attendance_count`, `attendance_timer`)
		if (SQL_ERROR == SQL->StmtPrepare(stmt, "SELECT `bank_vault`,`base_exp`,`base_drop`,`base_death`,`attendance_count`, `attendance_timer` FROM `%s` WHERE `account_id`=? LIMIT 1", account_data_db)
		 || SQL_ERROR == SQL->StmtBindParam(stmt, 0, SQLDT_INT, &account_id, sizeof account_id)
		 || SQL_ERROR == SQL->StmtExecute(stmt)
		 || SQL_ERROR == SQL->StmtBindColumn(stmt, 0, SQLDT_INT,    &data->bank_vault, sizeof data->bank_vault, NULL, NULL)
		 || SQL_ERROR == SQL->StmtBindColumn(stmt, 1, SQLDT_USHORT, &data->mod_exp,    sizeof data->mod_exp,    NULL, NULL)
		 || SQL_ERROR == SQL->StmtBindColumn(stmt, 2, SQLDT_USHORT, &data->mod_drop,   sizeof data->mod_drop,   NULL, NULL)
		 || SQL_ERROR == SQL->StmtBindColumn(stmt, 3, SQLDT_USHORT, &data->mod_death,  sizeof data->mod_death,  NULL, NULL)
		 || SQL_ERROR == SQL->StmtBindColumn(stmt, 4, SQLDT_SHORT,  &data->attendance_count, sizeof data->attendance_count, NULL, NULL)
		 || SQL_ERROR == SQL->StmtBindColumn(stmt, 5, SQLDT_INT64,  &data->attendance_timer, sizeof data->attendance_timer, NULL, NULL)
		) {
			SqlStmt_ShowDebug(stmt);
		}

		if(SQL_ERROR == SQL->StmtNextRow(stmt))
			load_flag &= ~CHARSAVE_ACCDATA;
	}

	if(chr->show_save_log) {
		char load_status[128];
		ShowInfo("Loaded char (%d - %s): %s\n", char_id, data->name,
			chr->mmo_flag2str(load_status, sizeof(load_status), load_flag));
	}
	SQL->StmtFree(stmt);

	if(cache_data == CHARCACHE_INSERT) { // Insert to cache
		cp = idb_ensure(chr->char_db_, char_id, chr->create_charstatus);
		memcpy(cp, data, sizeof(struct mmo_charstatus));
		data = cp;
	}
	return data;
}

//==========================================================================================================
static int char_mmo_char_sql_init(void)
{
	chr->char_db_= idb_alloc(DB_OPT_RELEASE_DATA);

	//the 'set offline' part is now in check_login_conn ...
	//if the server connects to loginserver
	//it will dc all off players
	//and send the loginserver the new state....

	// Force all users offline in sql when starting char-server
	// (useful when servers crashes and don't clean the database)
	chr->set_all_offline_sql();

	return 0;
}

/* [Ind/Hercules] - special thanks to Yommy for providing the packet structure/data */
static bool char_char_slotchange(struct char_session_data *sd, struct socket_data *session, unsigned short from, unsigned short to)
{
	struct mmo_charstatus char_dat;
	int from_id = 0;

	nullpo_ret(sd);
	if( from >= MAX_CHARS || to >= MAX_CHARS || ( sd->char_slots && to > sd->char_slots ) || sd->found_char[from] <= 0 )
		return false;

	if(!chr->mmo_char_fromsql(sd->found_char[from], CHARSAVE_STATUS, // Only the short data is needed.
	    &char_dat, CHARCACHE_IGNORE_NOLOCK)
	)
		return false;

	if( char_dat.slotchange == 0 )
		return false;

	from_id = sd->found_char[from];
	struct Sql *sql_handle = inter->sql_handle_get();

	if( sd->found_char[to] > 0 ) {/* moving char to occupied slot */
		bool result = false;
		/* update both at once */
		if( SQL_SUCCESS != SQL->QueryStr(sql_handle, "START TRANSACTION")
		   ||  SQL_SUCCESS != SQL->Query(sql_handle, "UPDATE `%s` SET `char_num`='%d' WHERE `char_id`='%d' LIMIT 1", char_db, from, sd->found_char[to])
		   ||  SQL_SUCCESS != SQL->Query(sql_handle, "UPDATE `%s` SET `char_num`='%d' WHERE `char_id`='%d' LIMIT 1", char_db, to, sd->found_char[from])
		)
			Sql_ShowDebug(sql_handle);
		else
			result = true;

		if( SQL_ERROR == SQL->QueryStr(sql_handle, (result == true) ? "COMMIT" : "ROLLBACK") ) {
			Sql_ShowDebug(sql_handle);
			result = false;
		}
		if( !result )
			return false;
	} else {/* slot is free. */
		if( SQL_ERROR == SQL->Query(sql_handle, "UPDATE `%s` SET `char_num`='%d' WHERE `char_id`='%d' LIMIT 1", char_db, to, sd->found_char[from] ) ) {
			Sql_ShowDebug(sql_handle);
			return false;
		}
	}

	/* update count */
	if( SQL_ERROR == SQL->Query(sql_handle, "UPDATE `%s` SET `slotchange`=`slotchange`-1 WHERE `char_id`='%d' LIMIT 1", char_db, from_id ) ) {
		Sql_ShowDebug(sql_handle);
		return false;
	}

	return true;
}

/**
 * Changes the provided character name using sd::rename data
 *
 * @return Change charname result code (success CRR_SUCCESS)
 * @see enum change_charname_result
 *
 * @remarks
 * Assumes that the data in sd::rename is already validated
 * (i.e. the name is valid and escaped)
 **/
static enum change_charname_result char_rename_char_sql(struct char_session_data *sd, int char_id)
{
	struct mmo_charstatus char_dat;

	nullpo_retr(CRR_INCORRECT_USER, sd);
	if(!sd->rename || sd->rename->new_name[0] == '\0') // Not ready for rename
		return CRR_INCORRECT_USER;

	if(!chr->mmo_char_fromsql(char_id, CHARSAVE_STATUS,
		&char_dat, CHARCACHE_IGNORE_NOLOCK)) // Only the short data is needed.
		return CRR_INCORRECT_USER;

	if(sd->account_id != char_dat.account_id) // Tried to rename not owned char
		return CRR_INCORRECT_USER;

	if(char_dat.rename == 0)
		return CRR_ALREADY_CHANGED;

	if(char_aegis_rename) {
		if(char_dat.guild_id > 0)
			return CRR_BELONGS_TO_GUILD;
		if(char_dat.party_id > 0)
			return CRR_BELONGS_TO_PARTY;
	}

	struct Sql *sql_handle = inter->sql_handle_get();
	/**
	 * There's no need to check if the name is in use when performing the update, the 
	 * `name` field is defined as UNIQUE, so the query will simply fail if there's
	 * a duplicate. This way we avoid possible data-races of multiple simultaneous writes.
	 **/
	int sql_result = 
	SQL->Query(sql_handle,
		"UPDATE `%s` SET `name` = '%s', `rename` = '%d' WHERE `char_id` = '%d'",
		char_db, sd->rename->new_name, --char_dat.rename, char_id);
	if(SQL_ERROR == sql_result) {
		Sql_ShowDebug(sql_handle);
		return CRR_FAILED;
	}
	if(SQL->NumAffectedRows(sql_handle) <= 0)
		return CRR_DUPLICATE;

	// Change character's name into guild_db.
	if(char_dat.guild_id)
		inter_guild->charname_changed(char_dat.guild_id, char_id, sd->rename->new_name);

	safestrncpy(char_dat.name, sd->rename->new_name, NAME_LENGTH);
	aFree(sd->rename);
	sd->rename = NULL;

	// log change
	if (chr->enable_logs) {
		if (SQL_ERROR == SQL->Query(sql_handle,
					"INSERT INTO `%s` ("
					" `time`, `char_msg`, `account_id`, `char_id`, `char_num`, `class`, `name`,"
					" `str`, `agi`, `vit`, `int`, `dex`, `luk`,"
					" `hair`, `hair_color`"
					") VALUES ("
					" NOW(), 'change char name', '%d', '%d', '%d', '%d', '%s',"
					" '%d', '%d', '%d', '%d', '%d', '%d',"
					" '%d', '%d'"
					")",
					charlog_db,
					// char_data.name is escaped.
					sd->account_id, char_dat.char_id, char_dat.slot, char_dat.class, char_dat.name,
					char_dat.str, char_dat.agi, char_dat.vit, char_dat.int_, char_dat.dex, char_dat.luk,
					char_dat.hair, char_dat.hair_color
					))
			Sql_ShowDebug(sql_handle);
	}

	return 0;
}

/**
 * Checks if the given name exists in the database.
 *
 * @param name The name to check.
 * @param esc_name Escaped version of the name, optional for faster processing.
 * @retval true if the character name already exists.
 */
static bool char_name_exists(const char *name, const char *esc_name)
{
	char esc_name2[ESC_NAME_LENGTH];
	struct Sql *sql_handle = inter->sql_handle_get();

	nullpo_retr(true, name);

	if (esc_name == NULL) {
		SQL->EscapeStringLen(sql_handle, esc_name2, name, strnlen(name, NAME_LENGTH));
		esc_name = esc_name2;
	}

	if (name_ignoring_case) {
		if (SQL_ERROR == SQL->Query(sql_handle, "SELECT 1 FROM `%s` WHERE BINARY `name` = '%s' LIMIT 1", char_db, esc_name)) {
			Sql_ShowDebug(sql_handle);
			return true;
		}
	} else {
		if (SQL_ERROR == SQL->Query(sql_handle, "SELECT 1 FROM `%s` WHERE `name` = '%s' LIMIT 1", char_db, esc_name)) {
			Sql_ShowDebug(sql_handle);
			return true;
		}
	}
	if (SQL->NumRows(sql_handle) > 0)
		return true;

	return false;
}

/**
 * Checks if provided name has any control characters or unauthorized letters/symbols
 * @retval true There are invalid characters
 * @retval false No invalid characters
 **/
static bool char_check_symbols(const char *name)
{
	int i;

	// check content of character name
	char *name_copy = aStrdup(name);
	if(remove_control_chars(name_copy)) {
		aFree(name_copy);
		return true; // control chars in name
	}
	aFree(name_copy);

	// Check Authorized letters/symbols in the name of the character
	if( char_name_option == 1 )
	{ // only letters/symbols in char_name_letters are authorized
		for( i = 0; i < NAME_LENGTH && name[i]; i++ )
			if( strchr(char_name_letters, name[i]) == NULL )
				return true;
	}
	else if( char_name_option == 2 )
	{ // letters/symbols in char_name_letters are forbidden
		for( i = 0; i < NAME_LENGTH && name[i]; i++ )
			if( strchr(char_name_letters, name[i]) != NULL )
				return true;
	}
	return false;
}

/**
 * Checks if the given name is valid for a new character.
 *
 * @param name The name to check.
 * @param esc_name Escaped version of the name, optional for faster processing.
 * @retval RMCE_CREATED        Name is valid.
 * @retval RMCE_ALREADY_EXISTS Name already exists or is reserved
 * @retval RMCE_INVALID        Name is too short or contains special characters.
 * @retval RMCE_SYMBOLS        Name contains forbidden characters.
 * @remarks
 *  Before any database access the name is escaped.
 */
static enum refuse_make_char_errorcode char_check_char_name(const char *name, const char *esc_name)
{
	nullpo_retr(RMCE_DENIED, name);

	// check length of character name
	if( name[0] == '\0' )
		return RMCE_INVALID; // empty character name
	/**
	 * The client does not allow you to create names with less than 4 characters, however,
	 * the use of WPE can bypass this, and this fixes the exploit.
	 **/
	if( strlen( name ) < 4 )
		return RMCE_INVALID;

	if( chr->check_symbols(name) )
		return RMCE_SYMBOLS; // Invalid characters in name

	// check for reserved names
	if( strcmpi(name, wisp_server_name) == 0 )
		return RMCE_ALREADY_EXISTS; // nick reserved for internal server messages

	if( chr->name_exists(name, esc_name) )
		return RMCE_ALREADY_EXISTS;

	return RMCE_CREATED;
}

/**
 * Normalizes provided string and then sql escapes it.
 * @param name     Buffer to be encoded (it's safe to pass non-strings)
 * @param esc_name Buffer for the encoded string, its length must be ESC_NAME_LENGTH
 **/
void char_escape_normalize_name(const char *name, char *esc_name)
{
	SQL->EscapeStringLen(inter->sql_handle_get(), esc_name, name, strnlen(name, NAME_LENGTH));
	normalize_name(esc_name, TRIM_CHARS);
}

/**
 * Creates a new character
 * @param out_char_id Filled when a character is successfuly created
 * @return error code, when successful RMCE_CREATED
 * @see enum refuse_make_char_errorcode
 **/
enum refuse_make_char_errorcode char_make_new_char_sql(struct char_session_data *sd,
	const char *name_,
	int str, int agi, int vit, int int_, int dex, int luk,
	int slot, int hair_color, int hair_style, int starting_class, uint8 sex,
	int *out_char_id
) {
	char name[NAME_LENGTH];
	char esc_name[ESC_NAME_LENGTH];
	int char_id, i;
	enum refuse_make_char_errorcode flag;

	nullpo_retr(RMCE_DENIED, sd);
	nullpo_retr(RMCE_DENIED, name_);
	if(!enable_char_creation)
		return RMCE_DENIED; //turn character creation on/off [Kevin]

	safestrncpy(name, name_, NAME_LENGTH);
	chr->escape_normalize_name(name, esc_name);

	flag = chr->check_char_name(name,esc_name);
	if(flag != RMCE_CREATED)
		return flag;

	switch (starting_class) {
		case JOB_SUMMONER:
		case JOB_NOVICE:
			break;
		default:
			return RMCE_DENIED;
	}

	//check other inputs
#if PACKETVER >= 20120307
	if(slot < 0 || slot >= sd->char_slots)
#else
	if((slot < 0 || slot >= sd->char_slots) // slots
	|| (str + agi + vit + int_ + dex + luk != 6*5 ) // stats
	|| (str < 1 || str > 9 || agi < 1 || agi > 9 || vit < 1 || vit > 9 || int_ < 1 || int_ > 9 || dex < 1 || dex > 9 || luk < 1 || luk > 9) // individual stat values
	|| (str + int_ != 10 || agi + luk != 10 || vit + dex != 10) ) // pairs
#endif
#if PACKETVER >= 20100413
		return RMCE_NOT_ELIGIBLE; // invalid slot
#else
		return RMCE_DENIED; // invalid input
#endif

	// check char slot
	if( sd->found_char[slot] != -1 )
		return RMCE_NOT_ELIGIBLE; /* character account limit exceeded */

	struct Sql *sql_handle = inter->sql_handle_get();
#if PACKETVER >= 20120307
	// Insert the new char entry to the database
	if (SQL_ERROR == SQL->Query(sql_handle, "INSERT INTO `%s` (`account_id`, `char_num`, `name`, `class`, `zeny`, `status_point`,`str`, `agi`, `vit`, `int`, `dex`, `luk`, `max_hp`, `hp`,"
		"`max_sp`, `sp`, `hair`, `hair_color`, `last_map`, `last_x`, `last_y`, `save_map`, `save_x`, `save_y`, `sex`, `inventory_size`) VALUES ("
		"'%d', '%d', '%s', '%d', '%d', '%d', '%d', '%d', '%d', '%d', '%d', '%d', '%d', '%d','%d', '%d','%d', '%d', '%s', '%d', '%d', '%s', '%d', '%d', '%c', '%d')",
		char_db, sd->account_id , slot, esc_name, starting_class, start_zeny, 48, str, agi, vit, int_, dex, luk,
		(40 * (100 + vit)/100) , (40 * (100 + vit)/100 ),  (11 * (100 + int_)/100), (11 * (100 + int_)/100), hair_style, hair_color,
		mapindex_id2name(start_point.map), start_point.x, start_point.y, mapindex_id2name(start_point.map), start_point.x, start_point.y, sex, FIXED_INVENTORY_SIZE)) {
			Sql_ShowDebug(sql_handle);
			return RMCE_DENIED; //No, stop the procedure!
	}
#else
	//Insert the new char entry to the database
	if( SQL_ERROR == SQL->Query(sql_handle, "INSERT INTO `%s` (`account_id`, `char_num`, `name`, `class`, `zeny`, `str`, `agi`, `vit`, `int`, `dex`, `luk`, `max_hp`, `hp`,"
							   "`max_sp`, `sp`, `hair`, `hair_color`, `last_map`, `last_x`, `last_y`, `save_map`, `save_x`, `save_y`, `inventory_size`) VALUES ("
							   "'%d', '%d', '%s', '%d',  '%d', '%d', '%d', '%d', '%d', '%d', '%d', '%d', '%d','%d', '%d','%d', '%d', '%s', '%d', '%d', '%s', '%d', '%d', '%d')",
							   char_db, sd->account_id , slot, esc_name, starting_class, start_zeny, str, agi, vit, int_, dex, luk,
							   (40 * (100 + vit)/100) , (40 * (100 + vit)/100 ),  (11 * (100 + int_)/100), (11 * (100 + int_)/100), hair_style, hair_color,
							   mapindex_id2name(start_point.map), start_point.x, start_point.y, mapindex_id2name(start_point.map), start_point.x, start_point.y, FIXED_INVENTORY_SIZE) )
	{
		Sql_ShowDebug(sql_handle);
		return RMCE_DENIED; //No, stop the procedure!
	}
#endif
	//Retrieve the newly auto-generated char id
	char_id = (int)SQL->LastInsertId(sql_handle);

	if(!char_id)
		return RMCE_DENIED;

	// Validation success, log result
	if (chr->enable_logs) {
		if (SQL_ERROR == SQL->Query(sql_handle,
					"INSERT INTO `%s` (`time`, `char_msg`, `account_id`, `char_id`, `char_num`, `class`, `name`, `str`, `agi`, `vit`, `int`, `dex`, `luk`, `hair`, `hair_color`)"
					"VALUES (NOW(), '%s', '%d', '%d', '%d', '%d', '%s', '%d', '%d', '%d', '%d', '%d', '%d', '%d', '%d')",
					charlog_db, "make new char", sd->account_id, char_id, slot, starting_class, esc_name, str, agi, vit, int_, dex, luk, hair_style, hair_color))
			Sql_ShowDebug(sql_handle);
	}

	//Give the char the default items
	for (i = 0; i < VECTOR_LENGTH(start_items); i++) {
		struct start_item_s *item = &VECTOR_INDEX(start_items, i);
		if (item->stackable) {
			if (SQL_ERROR == SQL->Query(sql_handle,
			                            "INSERT INTO `%s` (`char_id`,`nameid`, `amount`, `identify`) VALUES ('%d', '%d', '%d', '%d')",
			                            inventory_db, char_id, item->id, item->amount, 1))
				Sql_ShowDebug(sql_handle);
		} else {
			// Non-stackable items should have their own entries (issue: 7279)
			int l, loc = item->loc;
			for (l = 0; l < item->amount; l++) {
				if (SQL_ERROR == SQL->Query(sql_handle,
				                            "INSERT INTO `%s` (`char_id`,`nameid`, `amount`, `equip`, `identify`) VALUES ('%d', '%d', '%d', '%d', '%d')",
				                            inventory_db, char_id, item->id, 1, loc, 1))
					Sql_ShowDebug(sql_handle);
			}
		}
	}

	ShowInfo("Created char: account: %d, char: %d, slot: %d, name: %s, sex: %c\n",
		sd->account_id, char_id, slot, name, sex);
	*out_char_id = char_id;
	return RMCE_CREATED;
}

/*----------------------------------------------------------------------------------------------------------*/
/* Divorce Players */
/*----------------------------------------------------------------------------------------------------------*/
static int char_divorce_char_sql(int partner_id1, int partner_id2)
{
	unsigned char buf[64];
	struct Sql *sql_handle = inter->sql_handle_get();

	if( SQL_ERROR == SQL->Query(sql_handle, "UPDATE `%s` SET `partner_id`='0' WHERE `char_id`='%d' OR `char_id`='%d' LIMIT 2", char_db, partner_id1, partner_id2) )
		Sql_ShowDebug(sql_handle);
	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE (`nameid`='%d' OR `nameid`='%d') AND (`char_id`='%d' OR `char_id`='%d') LIMIT 2", inventory_db, WEDDING_RING_M, WEDDING_RING_F, partner_id1, partner_id2) )
		Sql_ShowDebug(sql_handle);

	WBUFW(buf,0) = 0x2b12;
	WBUFL(buf,2) = partner_id1;
	WBUFL(buf,6) = partner_id2;
	mapif->sendall(buf,10);

	return 0;
}

/*----------------------------------------------------------------------------------------------------------*/
/* Delete char - davidsiaw */
/*----------------------------------------------------------------------------------------------------------*/
/* Returns 0 if successful
 * Returns < 0 for error
 */
static int char_delete_char_sql(int char_id)
{
	char name[NAME_LENGTH];
	char esc_name[ESC_NAME_LENGTH]; //Name needs be escaped.
	int account_id, party_id, guild_id, hom_id, partner_id, father_id, mother_id, elemental_id;
	char *data;
	size_t len;
	struct Sql *sql_handle = inter->sql_handle_get();

	if(SQL_ERROR == SQL->Query(sql_handle,
		"SELECT `name`,`account_id`,`party_id`,`guild_id`,`homun_id`,"
		"`partner_id`,`father`,`mother`,`elemental_id` "
		"FROM `%s` WHERE `char_id`='%d'", char_db, char_id)
	)
		Sql_ShowDebug(sql_handle);

	if( SQL_SUCCESS != SQL->NextRow(sql_handle) )
	{
		ShowError("chr->delete_char_sql: Unable to fetch character data, deletion aborted.\n");
		SQL->FreeResult(sql_handle);
		return -1;
	}

	SQL->GetData(sql_handle, 0, &data, &len); safestrncpy(name, data, NAME_LENGTH);
	SQL->GetData(sql_handle, 1, &data, NULL); account_id = atoi(data);
	SQL->GetData(sql_handle, 2, &data, NULL); party_id = atoi(data);
	SQL->GetData(sql_handle, 3, &data, NULL); guild_id = atoi(data);
	SQL->GetData(sql_handle, 4, &data, NULL); hom_id = atoi(data);
	SQL->GetData(sql_handle, 5, &data, NULL); partner_id = atoi(data);
	SQL->GetData(sql_handle, 6, &data, NULL); father_id = atoi(data);
	SQL->GetData(sql_handle, 7, &data, NULL); mother_id = atoi(data);
	SQL->GetData(sql_handle, 8, &data, NULL); elemental_id = atoi(data);

	SQL->EscapeStringLen(sql_handle, esc_name, name, min(len, NAME_LENGTH));
	SQL->FreeResult(sql_handle);

	/* Divorce [Wizputer] */
	if( partner_id )
		chr->divorce_char_sql(char_id, partner_id);

	/* De-addopt [Zephyrus] */
	if( father_id || mother_id )
	{ // Char is Baby
		unsigned char buf[64];

		if( SQL_ERROR == SQL->Query(sql_handle, "UPDATE `%s` SET `child`='0' WHERE `char_id`='%d' OR `char_id`='%d'", char_db, father_id, mother_id) )
			Sql_ShowDebug(sql_handle);
		if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `id` = '410'AND (`char_id`='%d' OR `char_id`='%d')", skill_db, father_id, mother_id) )
			Sql_ShowDebug(sql_handle);

		WBUFW(buf,0) = 0x2b25;
		WBUFL(buf,2) = father_id;
		WBUFL(buf,6) = mother_id;
		WBUFL(buf,10) = char_id; // Baby
		mapif->sendall(buf,14);
	}

	//Make the character leave the party [Skotlex]
	if (party_id)
		inter_party->leave(party_id, account_id, char_id);

	/* delete char's pet */
	//Delete the hatched pet if you have one...
	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `char_id`='%d' AND `incubate` = '0'", pet_db, char_id) )
		Sql_ShowDebug(sql_handle);

	//Delete all pets that are stored in eggs (inventory + cart)
	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` USING `%s` JOIN `%s` ON `pet_id` = `card1`|`card2`<<16 WHERE `%s`.char_id = '%d' AND card0 = -256", pet_db, pet_db, inventory_db, inventory_db, char_id) )
		Sql_ShowDebug(sql_handle);
	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` USING `%s` JOIN `%s` ON `pet_id` = `card1`|`card2`<<16 WHERE `%s`.char_id = '%d' AND card0 = -256", pet_db, pet_db, cart_db, cart_db, char_id) )
		Sql_ShowDebug(sql_handle);

	/* remove homunculus */
	if( hom_id )
		inter_homunculus->delete(hom_id);

	/* remove elemental */
	if (elemental_id)
		inter_elemental->delete(elemental_id);

	/* remove mercenary data */
	inter_mercenary->owner_delete(char_id);

	/* delete char's friends list */
	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `char_id` = '%d'", friend_db, char_id) )
		Sql_ShowDebug(sql_handle);

	/* delete char from other's friend list */
	//NOTE: Won't this cause problems for people who are already online? [Skotlex]
	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `friend_id` = '%d'", friend_db, char_id) )
		Sql_ShowDebug(sql_handle);

#ifdef HOTKEY_SAVING
	/* delete hotkeys */
	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `char_id`='%d'", hotkey_db, char_id) )
		Sql_ShowDebug(sql_handle);
#endif

	/* delete inventory */
	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `char_id`='%d'", inventory_db, char_id) )
		Sql_ShowDebug(sql_handle);

	/* delete cart inventory */
	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `char_id`='%d'", cart_db, char_id) )
		Sql_ShowDebug(sql_handle);

	/* delete memo areas */
	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `char_id`='%d'", memo_db, char_id) )
		Sql_ShowDebug(sql_handle);

	/* delete character registry */
	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `char_id`='%d'", char_reg_str_db, char_id) )
		Sql_ShowDebug(sql_handle);
	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `char_id`='%d'", char_reg_num_db, char_id) )
		Sql_ShowDebug(sql_handle);

	/* delete skills */
	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `char_id`='%d'", skill_db, char_id) )
		Sql_ShowDebug(sql_handle);

	/* delete mails (only received) */
	if (SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `dest_id`='%d'", mail_db, char_id))
		Sql_ShowDebug(sql_handle);

#ifdef ENABLE_SC_SAVING
	/* status changes */
	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `account_id` = '%d' AND `char_id`='%d'", scdata_db, account_id, char_id) )
		Sql_ShowDebug(sql_handle);
#endif

	/* delete character */
	if (SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `char_id`='%d'", char_db, char_id)) {
		Sql_ShowDebug(sql_handle);
	} else if (chr->enable_logs) {
		if (SQL_ERROR == SQL->Query(sql_handle,
					"INSERT INTO `%s`(`time`, `account_id`, `char_id`, `char_num`, `char_msg`, `name`)"
					" VALUES (NOW(), '%d', '%d', '%d', 'Deleted character', '%s')",
					charlog_db, account_id, char_id, 0, esc_name))
			Sql_ShowDebug(sql_handle);
	}

	/* No need as we used inter_guild->leave [Skotlex]
	// Also delete info from guildtables.
	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `char_id`='%d'", guild_member_db, char_id) )
		Sql_ShowDebug(sql_handle);
	*/

	if( SQL_ERROR == SQL->Query(sql_handle, "SELECT `guild_id` FROM `%s` WHERE `char_id` = '%d'", guild_db, char_id) )
		Sql_ShowDebug(sql_handle);
	else if( SQL->NumRows(sql_handle) > 0 )
		inter_guild->disband(guild_id);
	else if( guild_id )
		inter_guild->leave(guild_id, account_id, char_id, 0, "** Character Deleted **", NULL);// Leave your guild.
	return 0;
}

//---------------------------------------------------------------------
// This function return the number of online players in all map-servers
//---------------------------------------------------------------------
/**
 * Returns the total number of online players.
 * Acquires chr->map_list_lock (read)
 **/
static int char_count_users(void)
{
	int i, users;

	users = 0;
	struct mmo_map_server *server;
	INDEX_MAP_ITER_DECL(iter);
	INDEX_MAP_ITER(chr->map_server_list, iter);
	while((i = INDEX_MAP_NEXT(chr->map_server_list, iter)) != -1) {
		server = INDEX_MAP_INDEX(chr->map_server_list, i);
		if(!server)
			continue;
		users += InterlockedExchangeAdd(&server->user_count, 0);
	}
	INDEX_MAP_ITER_FREE(iter);
	return users;
}

// Writes char data to the buffer in the format used by the client.
// Used in packets 0x6b (chars info) and 0x6d (new char info)
// Returns the size
#define MAX_CHAR_BUF (PACKET_LEN_0x006d - 2)
static int char_mmo_char_tobuf(uint8 *buffer, struct mmo_charstatus *p)
{
	unsigned short offset = 0;
	uint8* buf;

	if( buffer == NULL || p == NULL )
		return 0;

	buf = WBUFP(buffer,0);

	WBUFL(buf,0) = p->char_id;
#if PACKETVER >= 20170830
	WBUFQ(buf,4) = min(p->base_exp, INT64_MAX);
	offset += 4;
	buf = WBUFP(buffer, offset);
#else
	WBUFL(buf,4) = min((uint32)(p->base_exp), INT32_MAX);
#endif
	WBUFL(buf,8) = p->zeny;
#if PACKETVER >= 20170830
	WBUFQ(buf,12) = min(p->job_exp, INT64_MAX);
	offset += 4;
	buf = WBUFP(buffer, offset);
#else
	WBUFL(buf,12) = min((uint32)(p->job_exp), INT32_MAX);
#endif
	WBUFL(buf,16) = p->job_level;
	WBUFL(buf,20) = 0; // probably opt1
	WBUFL(buf,24) = 0; // probably opt2
	WBUFL(buf,28) = (p->option &~ 0x40);
	WBUFL(buf,32) = p->karma;
	WBUFL(buf,36) = p->manner;
	WBUFW(buf,40) = min(p->status_point, INT16_MAX);
#if PACKETVER > 20081217
	WBUFL(buf,42) = p->hp;
	WBUFL(buf,46) = p->max_hp;
	offset+=4;
	buf = WBUFP(buffer,offset);
#else
	WBUFW(buf,42) = min(p->hp, INT16_MAX);
	WBUFW(buf,44) = min(p->max_hp, INT16_MAX);
#endif
	WBUFW(buf,46) = min(p->sp, INT16_MAX);
	WBUFW(buf,48) = min(p->max_sp, INT16_MAX);
	WBUFW(buf,50) = DEFAULT_WALK_SPEED; // p->speed;
	WBUFW(buf,52) = p->class;
	WBUFW(buf,54) = p->hair;
#if PACKETVER >= 20141022
	WBUFW(buf,56) = p->body;
	offset+=2;
	buf = WBUFP(buffer,offset);
#endif

	//When the weapon is sent and your option is riding, the client crashes on login!?
	// FIXME[Haru]: is OPTION_HANBOK intended to be part of this list? And if it is, should the list also include other OPTION_ costumes?
	WBUFW(buf,56) = (p->option&(OPTION_RIDING|OPTION_DRAGON|OPTION_WUG|OPTION_WUGRIDER|OPTION_MADOGEAR|OPTION_HANBOK)) ? 0 : p->look.weapon;

	WBUFW(buf,58) = p->base_level;
	WBUFW(buf,60) = min(p->skill_point, INT16_MAX);
	WBUFW(buf,62) = p->look.head_bottom;
	WBUFW(buf,64) = p->look.shield;
	WBUFW(buf,66) = p->look.head_top;
	WBUFW(buf,68) = p->look.head_mid;
	WBUFW(buf,70) = p->hair_color;
	WBUFW(buf,72) = p->clothes_color;
	memcpy(WBUFP(buf,74), p->name, NAME_LENGTH);
	WBUFB(buf,98) = min(p->str, UINT8_MAX);
	WBUFB(buf,99) = min(p->agi, UINT8_MAX);
	WBUFB(buf,100) = min(p->vit, UINT8_MAX);
	WBUFB(buf,101) = min(p->int_, UINT8_MAX);
	WBUFB(buf,102) = min(p->dex, UINT8_MAX);
	WBUFB(buf,103) = min(p->luk, UINT8_MAX);
	WBUFW(buf,104) = p->slot;
#if PACKETVER >= 20061023
	WBUFW(buf,106) = ( p->rename > 0 ) ? 0 : 1;
	offset += 2;
#endif
#if (PACKETVER >= 20100720 && PACKETVER <= 20100727) || PACKETVER >= 20100803
	mapindex->getmapname_ext(mapindex_id2name(p->last_point.map), WBUFP(buf,108));
	offset += MAP_NAME_LENGTH_EXT;
#endif
#if PACKETVER >= 20100803
	WBUFL(buf,124) = (int)p->delete_date;
	offset += 4;
#endif
#if PACKETVER >= 20110111
	WBUFL(buf,128) = p->look.robe;
	offset += 4;
#endif
#if PACKETVER != 20111116 //2011-11-16 wants 136, ask gravity.
	#if PACKETVER >= 20110928
		WBUFL(buf,132) = ( p->slotchange > 0 ) ? 1 : 0;  // change slot feature (0 = disabled, otherwise enabled)
		offset += 4;
	#endif
	#if PACKETVER >= 20111025
		WBUFL(buf,136) = ( p->rename > 0 ) ? 1 : 0;  // (0 = disabled, otherwise displays "Add-Ons" sidebar)
		offset += 4;
	#endif
	#if PACKETVER >= 20141016
		WBUFB(buf,140) = p->sex;// sex - (0 = female, 1 = male, 99 = logindefined)
		offset += 1;
	#endif
#endif

	if (106 + offset != MAX_CHAR_BUF)
		Assert_report("Wrong buffer size in char_mmo_char_tobuf");
	return 106 + offset;
}

/* Made Possible by Yommy~! <3 */
static void char_send_HC_ACK_CHARINFO_PER_PAGE(struct socket_data *session, struct char_session_data *sd)
{
#if PACKETVER_MAIN_NUM >= 20130522 || PACKETVER_RE_NUM >= 20130327 || defined(PACKETVER_ZERO)
	WFIFOHEAD(session,
		sizeof(struct PACKET_HC_ACK_CHARINFO_PER_PAGE) + (MAX_CHARS * MAX_CHAR_BUF), true);
	struct PACKET_HC_ACK_CHARINFO_PER_PAGE *p = WFIFOP(session, 0);
	int count = 0;
	p->packetId = HEADER_HC_ACK_CHARINFO_PER_PAGE;
	p->packetLen = chr->mmo_chars_fromsql(sd, WFIFOP(session, 4), &count) + sizeof(struct PACKET_HC_ACK_CHARINFO_PER_PAGE);
	WFIFOSET(session, p->packetLen);
	// send empty packet if chars count is 3, for trigger final code in client
	if (count == 3) {
		chr->send_HC_ACK_CHARINFO_PER_PAGE_tail(session, sd);
	}
#endif
}

static void char_send_HC_ACK_CHARINFO_PER_PAGE_tail(struct socket_data *session, struct char_session_data *sd)
{
#if PACKETVER_MAIN_NUM >= 20130522 || PACKETVER_RE_NUM >= 20130327 || defined(PACKETVER_ZERO)
	WFIFOHEAD(session, sizeof(struct PACKET_HC_ACK_CHARINFO_PER_PAGE), true);
	struct PACKET_HC_ACK_CHARINFO_PER_PAGE *p = WFIFOP(session, 0);
	p->packetId = HEADER_HC_ACK_CHARINFO_PER_PAGE;
	p->packetLen = sizeof(struct PACKET_HC_ACK_CHARINFO_PER_PAGE);
	WFIFOSET(session, p->packetLen);
#endif
}

/* Sends character ban list */
/* Made Possible by Yommy~! <3 */
static void char_mmo_char_send_ban_list(struct socket_data *session, struct char_session_data *sd)
{
	int i;
	time_t now = time(NULL);

	nullpo_retv(sd);
	ARR_FIND(0, MAX_CHARS, i, sd->unban_time[i]);
	if( i != MAX_CHARS ) {
		int c;

		WFIFOHEAD(session, 4 + (MAX_CHARS*24), true);

		WFIFOW(session, 0) = 0x20d;

		struct Sql *sql_handle = inter->sql_handle_get();
		for(i = 0, c = 0; i < MAX_CHARS; i++) {
			if( sd->unban_time[i] ) {
				timestamp2string(WFIFOP(session,8 + (28*c)), 20, sd->unban_time[i], "%Y-%m-%d %H:%M:%S");

				if( sd->unban_time[i] > now )
					WFIFOL(session, 4 + (24*c)) = sd->found_char[i];
				else {
					/* reset -- client keeps this information even if you logout so we need to clear */
					WFIFOL(session, 4 + (24*c)) = 0;
					/* also update on mysql */
					sd->unban_time[i] = 0;
					if( SQL_ERROR == SQL->Query(sql_handle,
						"UPDATE `%s` SET `unban_time`='0' WHERE `char_id`='%d' LIMIT 1",
						char_db, sd->found_char[i])
					)
						Sql_ShowDebug(sql_handle);
				}
				c++;
			}
		}

		WFIFOW(session, 2) = 4 + (24*c);

		WFIFOSET(session, WFIFOW(session, 2));
	}
}

//----------------------------------------
// [Ind/Hercules] notify client about charselect window data
//----------------------------------------
static void char_mmo_char_send_slots_info(struct socket_data *session, struct char_session_data *sd)
{
// also probably supported client 2013-02-15aRagexe but not 2013-02-15bRagexe [4144]
#if PACKETVER_MAIN_NUM >= 20130612 || PACKETVER_RE_NUM >= 20130115 || defined(PACKETVER_ZERO)
	nullpo_retv(sd);
	WFIFOHEAD(session, 29, true);
	WFIFOW(session, 0) = 0x82d;
	WFIFOW(session, 2) = 29;
	WFIFOB(session, 4) = sd->char_slots;
	WFIFOB(session, 5) = MAX_CHARS - sd->char_slots;
	WFIFOB(session, 6) = 0;
	WFIFOB(session, 7) = sd->char_slots;
	WFIFOB(session, 8) = sd->char_slots;
	memset(WFIFOP(session, 9), 0, 20); // unused bytes
	WFIFOSET(session, 29);
#endif
}
//----------------------------------------
// Function to send characters to a player
//----------------------------------------
static int char_mmo_char_send_characters(struct socket_data *session, struct char_session_data *sd)
{
	int j, offset = 0;
	nullpo_ret(sd);
#if PACKETVER >= 20100413
	offset += 3;
#endif
	if (chr->show_save_log)
		ShowInfo("Loading Char Data ("CL_BOLD"%d"CL_RESET")\n",sd->account_id);

	j = 24 + offset; // offset
	WFIFOHEAD(session,j + MAX_CHARS*MAX_CHAR_BUF,true);
	WFIFOW(session,0) = 0x6b;
#if PACKETVER >= 20100413
	WFIFOB(session,4) = MAX_CHARS; // Max slots.
	WFIFOB(session,5) = sd->char_slots; // Available slots. (aka PremiumStartSlot)
	WFIFOB(session,6) = MAX_CHARS; // Premium slots. AKA any existent chars past sd->char_slots but within MAX_CHARS will show a 'Premium Service' in red
#endif
	memset(WFIFOP(session,4 + offset), 0, 20); // unknown bytes
	j += chr->mmo_chars_fromsql(sd, WFIFOP(session, j), NULL);
	WFIFOW(session,2) = j; // packet len
	WFIFOSET(session,j);

	return 0;
}

/**
 * Verifies if players are married to eachother
 **/
static bool char_char_married(int char_id1, int char_id2)
{
	struct Sql *sql_handle = inter->sql_handle_get();
	if( SQL_ERROR == SQL->Query(sql_handle,
		"SELECT `partner_id` FROM `%s` WHERE `char_id` = '%d'", char_db, char_id1)
	)
		Sql_ShowDebug(sql_handle);
	else if( SQL_SUCCESS == SQL->NextRow(sql_handle) )
	{
		char* data;

		SQL->GetData(sql_handle, 0, &data, NULL);
		if( char_id2 == atoi(data) )
		{
			SQL->FreeResult(sql_handle);
			return true;
		}
	}
	SQL->FreeResult(sql_handle);
	return false;
}

/**
 * Verifies if there's a parent relationship
 **/
static bool char_char_child(int parent_id, int child_id)
{
	if (parent_id == 0 || child_id == 0) // Failsafe, avoild querys and fix EXP bug dividing with lower level chars
		return false;

	struct Sql *sql_handle = inter->sql_handle_get();

	if( SQL_ERROR == SQL->Query(sql_handle, "SELECT `child` FROM `%s` WHERE `char_id` = '%d'", char_db, parent_id) )
		Sql_ShowDebug(sql_handle);
	else if( SQL_SUCCESS == SQL->NextRow(sql_handle) )
	{
		char* data;

		SQL->GetData(sql_handle, 0, &data, NULL);
		if( child_id == atoi(data) )
		{
			SQL->FreeResult(sql_handle);
			return true;
		}
	}
	SQL->FreeResult(sql_handle);
	return false;
}

/**
 * Verifies if provided characters are a family
 * @return child id
 **/
static int char_char_family(int cid1, int cid2, int cid3)
{
	//Failsafe, and avoid querys where there is no sense to keep executing if any of the inputs are 0
	if (cid1 == 0 || cid2 == 0 || cid3 == 0)
		return 0;

	struct Sql *sql_handle = inter->sql_handle_get();

	if( SQL_ERROR == SQL->Query(sql_handle,
		"SELECT `char_id`,`partner_id`,`child` FROM `%s` WHERE `char_id` IN ('%d','%d','%d')",
		char_db, cid1, cid2, cid3)
	)
		Sql_ShowDebug(sql_handle);
	else while( SQL_SUCCESS == SQL->NextRow(sql_handle) )
	{
		int charid;
		int partnerid;
		int childid;
		char* data;

		SQL->GetData(sql_handle, 0, &data, NULL); charid = atoi(data);
		SQL->GetData(sql_handle, 1, &data, NULL); partnerid = atoi(data);
		SQL->GetData(sql_handle, 2, &data, NULL); childid = atoi(data);

		if( (cid1 == charid    && ((cid2 == partnerid && cid3 == childid  ) || (cid2 == childid   && cid3 == partnerid))) ||
			(cid1 == partnerid && ((cid2 == charid    && cid3 == childid  ) || (cid2 == childid   && cid3 == charid   ))) ||
			(cid1 == childid   && ((cid2 == charid    && cid3 == partnerid) || (cid2 == partnerid && cid3 == charid   ))) )
		{
			SQL->FreeResult(sql_handle);
			return childid;
		}
	}
	SQL->FreeResult(sql_handle);
	return 0;
}

/**
 * Forces disconnection of a player that's connected to the char-server
 *
 * Acquires db_lock(chr->online_char_db)
 **/
static void char_disconnect_player(int account_id)
{
	db_lock(chr->online_char_db, WRITE_LOCK);
	struct online_char_data *character = idb_get(chr->online_char_db, account_id);
	struct socket_data *session = socket_io->session_from_id(character->session_id);
	db_unlock(chr->online_char_db);

	/**
	 * session_disconnect marks the session for removal and when the next
	 * action queue of this session is dequeued and processed in chclif_parse
	 * chr->disconnect will be called and then this account_id will be removed
	 **/
	if(session)
		socket_io->session_disconnect_guard(session);
}

/**
 * Notifies a failure in server connection
 * @param error_code @see enum notify_ban_errorcode
 **/
static void char_authfail_fd(struct socket_data *session, enum notify_ban_errorcode flag)
{
	WFIFOHEAD(session, 3, true);
	WFIFOW(session,0) = HEADER_SC_NOTIFY_BAN;
	WFIFOB(session,2) = (uint8)flag;
	WFIFOSET(session,3);
}

/**
 * Verifies if the provided online_char_data corresponds to an online player,
 * if so kicks and forces disconnection.
 *
 * @param session Character session
 * @param character Character data to be checked, can be NULL
 * @return true Character kicked
 * @see char_auth_ok
 * @see online_char_db
 * @lock db_lock(chr->online_char_db)
 * Acquires map_server_list_lock
 **/
static bool char_auth_kick_online(struct socket_data *session, struct online_char_data *character)
{
	if(!character)
		return false;

	// check if character is not online already. [Skotlex]
	if(character->server > -1) {
		//Character already online. KICK KICK KICK
		struct mmo_map_server *server;
		rwlock->read_lock(chr->map_server_list_lock);
		server = INDEX_MAP_INDEX(chr->map_server_list, character->server);
		if(server)
			mapif->disconnectplayer(server->session, character->account_id,
				character->char_id, NBE_DUPLICATE_ID);
		rwlock->read_unlock(chr->map_server_list_lock);
		if(character->waiting_disconnect == INVALID_TIMER)
			character->waiting_disconnect = timer->add(timer->gettick()+20000,
				chr->waiting_disconnect, character->account_id, 0);
		character->pincode_enable = -1;
		chr->authfail_fd(session, NBE_DUPLICATE_ID);
		return true;
	} else if(character->session_id && character->session_id != session->id) {
		//There's already a connection from this account that hasn't picked a char yet.
		chr->authfail_fd(session, NBE_DUPLICATE_ID);
		return true;
	}
	ShowDebug("char_auth_kick_online: Session attached to an account_id reauthenticating (AID %d)\n",
		character->account_id);
	character->session_id = session->id;
	return false;
}

/**
 * Successful character authentication.
 * Performs check to find if player is already connected to a map-server and kicks if necessary
 *
 * @param session Character session
 * @see online_char_db
 * Acquires chr->map_server_list_lock
 * Acquires db_lock(chr->online_char_db)
 **/
static void char_auth_ok(struct socket_data *session, struct char_session_data *sd)
{
	struct online_char_data *character;

	nullpo_retv(sd);

	bool kicked;
	db_lock(chr->online_char_db, WRITE_LOCK);
	character = idb_get(chr->online_char_db, sd->account_id);
	kicked = chr->auth_kick_online(session, character);
	db_unlock(chr->online_char_db);
	if(kicked)
		return; // This account was already online, kicked.

	if(chr->login_session)
		loginif->request_account_data(sd->account_id);

	// mark session as 'authed'
	sd->auth = true;

	// set char online on charserver
	chr->set_char_charselect(sd->account_id);

	/**
	 * Continues when account data is received via AW_REQUEST_ACCOUNT_ACK
	 * @see loginif_parse_account_data
	 **/
}

/**
 * HC_REFUSE_ENTER
 * Denial of authentication
 **/
static void char_auth_error(struct socket_data *session, unsigned char flag)
{
	WFIFOHEAD(session, 3, true);
	WFIFOW(session, 0) = HEADER_HC_REFUSE_ENTER;
	WFIFOB(session, 2) = flag;
	WFIFOSET(session, sizeof(struct PACKET_HC_REFUSE_ENTER));
}

/**
 * Performs the necessary operations when changing a character's gender,
 * such as correcting the job class and unequipping items,
 * and propagating the information to the guild data.
 *
 * @param sex The character's new gender (SEX_MALE or SEX_FEMALE).
 * @param acc The character's account ID.
 * @param char_id The character ID.
 * @param class The character's current job class.
 * @param guild_id The character's guild ID.
 *
 **/
static void char_change_sex_sub(int sex, int acc, int char_id, int class, int guild_id)
{
	struct Sql *sql_handle = inter->sql_handle_get();
	struct SqlStmt *stmt = SQL->StmtMalloc(sql_handle);

	/** If we can't save the data, there's nothing to do. **/
	if (stmt == NULL) {
		SqlStmt_ShowDebug(stmt);
		return;
	}

	const char *query_inv = "UPDATE `%s` SET `equip`='0' WHERE `char_id`=?";

	/** Don't change gender if resetting the view data fails to prevent character from being unable to login. **/
	if (SQL_ERROR == SQL->StmtPrepare(stmt, query_inv, inventory_db)
	    || SQL_ERROR == SQL->StmtBindParam(stmt, 0, SQLDT_INT32, &char_id, sizeof(char_id))
	    || SQL_ERROR == SQL->StmtExecute(stmt)) {
		SqlStmt_ShowDebug(stmt);
		SQL->StmtFree(stmt);
		return;
	}

	/** Correct the job class for gender specific jobs according to the passed gender. **/
	if (class == JOB_BARD || class == JOB_DANCER)
		class = (sex == SEX_MALE ? JOB_BARD : JOB_DANCER);
	else if (class == JOB_CLOWN || class == JOB_GYPSY)
		class = (sex == SEX_MALE ? JOB_CLOWN : JOB_GYPSY);
	else if (class == JOB_BABY_BARD || class == JOB_BABY_DANCER)
		class = (sex == SEX_MALE ? JOB_BABY_BARD : JOB_BABY_DANCER);
	else if (class == JOB_MINSTREL || class == JOB_WANDERER)
		class = (sex == SEX_MALE ? JOB_MINSTREL : JOB_WANDERER);
	else if (class == JOB_MINSTREL_T || class == JOB_WANDERER_T)
		class = (sex == SEX_MALE ? JOB_MINSTREL_T : JOB_WANDERER_T);
	else if (class == JOB_BABY_MINSTREL || class == JOB_BABY_WANDERER)
		class = (sex == SEX_MALE ? JOB_BABY_MINSTREL : JOB_BABY_WANDERER);
	else if (class == JOB_KAGEROU || class == JOB_OBORO)
		class = (sex == SEX_MALE ? JOB_KAGEROU : JOB_OBORO);
	else if (class == JOB_BABY_KAGEROU || class == JOB_BABY_OBORO)
		class = (sex == SEX_MALE ? JOB_BABY_KAGEROU : JOB_BABY_OBORO);

#if PACKETVER >= 20141016
	char gender = (sex == SEX_MALE) ? 'M' : ((sex == SEX_FEMALE) ? 'F' : 'U');
#else
	char gender = 'U';
#endif

	const char *query_char = "UPDATE `%s` SET `class`=?, `weapon`='0', `shield`='0', `head_top`='0', "
		"`head_mid`='0', `head_bottom`='0', `robe`='0', `sex`=? WHERE `char_id`=?";

	/** Don't update guild data if changing gender fails to prevent data de-synchronisation. **/
	if (SQL_ERROR == SQL->StmtPrepare(stmt, query_char, char_db)
	    || SQL_ERROR == SQL->StmtBindParam(stmt, 0, SQLDT_INT32, &class, sizeof(class))
	    || SQL_ERROR == SQL->StmtBindParam(stmt, 1, SQLDT_ENUM, &gender, sizeof(gender))
	    || SQL_ERROR == SQL->StmtBindParam(stmt, 2, SQLDT_INT32, &char_id, sizeof(char_id))
	    || SQL_ERROR == SQL->StmtExecute(stmt)) {
		SqlStmt_ShowDebug(stmt);
		SQL->StmtFree(stmt);
		return;
	}

	SQL->StmtFree(stmt);

	/** Update guild member data if a guild ID was passed. **/
	if (guild_id != 0)
		inter_guild->sex_changed(guild_id, acc, char_id, sex);
}

/**
 * Loads fame list from SQL to memory
 *
 * @mutex fame_list_mutex
 **/
static void char_read_fame_list(void)
{
	int i;
	char* data;
	size_t len;
	struct Sql *sql_handle = inter->sql_handle_get();

	// Empty ranking lists
	memset(smith_fame_list, 0, sizeof(smith_fame_list));
	memset(chemist_fame_list, 0, sizeof(chemist_fame_list));
	memset(taekwon_fame_list, 0, sizeof(taekwon_fame_list));
	// Build Blacksmith ranking list
	if( SQL_ERROR == SQL->Query(sql_handle, "SELECT `char_id`,`fame`,`name` FROM `%s` WHERE `fame`>0 AND (`class`='%d' OR `class`='%d' OR `class`='%d' OR `class`='%d' OR `class`='%d' OR `class`='%d') ORDER BY `fame` DESC LIMIT 0,%d", char_db, JOB_BLACKSMITH, JOB_WHITESMITH, JOB_BABY_BLACKSMITH, JOB_MECHANIC, JOB_MECHANIC_T, JOB_BABY_MECHANIC, fame_list_size_smith) )
		Sql_ShowDebug(sql_handle);
	for( i = 0; i < fame_list_size_smith && SQL_SUCCESS == SQL->NextRow(sql_handle); ++i )
	{
		// char_id
		SQL->GetData(sql_handle, 0, &data, NULL);
		smith_fame_list[i].id = atoi(data);
		// fame
		SQL->GetData(sql_handle, 1, &data, &len);
		smith_fame_list[i].fame = atoi(data);
		// name
		SQL->GetData(sql_handle, 2, &data, &len);
		memcpy(smith_fame_list[i].name, data, min(len, NAME_LENGTH));
	}
	// Build Alchemist ranking list
	if( SQL_ERROR == SQL->Query(sql_handle, "SELECT `char_id`,`fame`,`name` FROM `%s` WHERE `fame`>0 AND (`class`='%d' OR `class`='%d' OR `class`='%d' OR `class`='%d' OR `class`='%d' OR `class`='%d') ORDER BY `fame` DESC LIMIT 0,%d", char_db, JOB_ALCHEMIST, JOB_CREATOR, JOB_BABY_ALCHEMIST, JOB_GENETIC, JOB_GENETIC_T, JOB_BABY_GENETIC, fame_list_size_chemist) )
		Sql_ShowDebug(sql_handle);
	for( i = 0; i < fame_list_size_chemist && SQL_SUCCESS == SQL->NextRow(sql_handle); ++i )
	{
		// char_id
		SQL->GetData(sql_handle, 0, &data, NULL);
		chemist_fame_list[i].id = atoi(data);
		// fame
		SQL->GetData(sql_handle, 1, &data, &len);
		chemist_fame_list[i].fame = atoi(data);
		// name
		SQL->GetData(sql_handle, 2, &data, &len);
		memcpy(chemist_fame_list[i].name, data, min(len, NAME_LENGTH));
	}
	// Build Taekwon ranking list
	if( SQL_ERROR == SQL->Query(sql_handle, "SELECT `char_id`,`fame`,`name` FROM `%s` WHERE `fame`>0 AND (`class` in('%d', '%d')) ORDER BY `fame` DESC LIMIT 0,%d", char_db, JOB_TAEKWON, JOB_BABY_TAEKWON, fame_list_size_taekwon) )
		Sql_ShowDebug(sql_handle);
	for( i = 0; i < fame_list_size_taekwon && SQL_SUCCESS == SQL->NextRow(sql_handle); ++i )
	{
		// char_id
		SQL->GetData(sql_handle, 0, &data, NULL);
		taekwon_fame_list[i].id = atoi(data);
		// fame
		SQL->GetData(sql_handle, 1, &data, &len);
		taekwon_fame_list[i].fame = atoi(data);
		// name
		SQL->GetData(sql_handle, 2, &data, &len);
		memcpy(taekwon_fame_list[i].name, data, min(len, NAME_LENGTH));
	}
	SQL->FreeResult(sql_handle);
}

//Loads a character's name and stores it in the buffer given (must be NAME_LENGTH in size) and not NULL
//Returns 1 on found, 0 on not found (buffer is filled with Unknown char name)
static int char_loadName(int char_id, char *name)
{
	char* data;
	size_t len;
	struct Sql *sql_handle = inter->sql_handle_get();

	if( SQL_ERROR == SQL->Query(sql_handle, "SELECT `name` FROM `%s` WHERE `char_id`='%d'", char_db, char_id) )
		Sql_ShowDebug(sql_handle);
	else if( SQL_SUCCESS == SQL->NextRow(sql_handle) )
	{
		SQL->GetData(sql_handle, 0, &data, &len);
		safestrncpy(name, data, NAME_LENGTH);
		return 1;
	}
	else
	{
		safestrncpy(name, unknown_char_name, NAME_LENGTH);
	}
	return 0;
}

/**
 * ZW_DATASYNC
 * Verifies if map-server and char-server have the same basic data structures.
 * @see socket_io->datasync
 **/
static void char_parse_frommap_datasync(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	socket_io->datasync(act, false);
}

/**
 * ZW_SKILLID2IDX
 * Updates char-server skill-id to skill index according to the map-server
 *
 * TODO: Send new skillid2idx to other map-servers so they can check if the
 * skill indices are still in sync [Panikon]
 *
 * Acquires write skillid2idx_lock
 **/
static void char_parse_frommap_skillid2idx(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	int i;
	int j = RFIFOW(act, 2) - 4;

	rwlock->write_lock(skillid2idx_lock);

	memset(&skillid2idx, 0, sizeof(skillid2idx));
	if( j )
		j /= 4;
	for(i = 0; i < j; i++) {
		if (RFIFOW(act, 4 + (i*4)) >= MAX_SKILL_ID) {
			ShowWarning("Error skillid2dx[%d] = %d failed, %d is higher than "
				"MAX_SKILL_ID (%d)\n",
				RFIFOW(act, 4 + (i*4)), RFIFOW(act, 6 + (i*4)),
				RFIFOW(act, 4 + (i*4)), MAX_SKILL_ID);
			continue;
		}
		skillid2idx[RFIFOW(act, 4 + (i*4))] = RFIFOW(act, 6 + (i*4));
	}

	rwlock->write_unlock(skillid2idx_lock);
}

/**
 * ZW_OWNED_MAP_LIST
 * Receives list of indices owned by this map-server
 *
 * Acquires fame_list_mutex
 **/
static void char_parse_frommap_map_names(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	int i;

	rwlock->read_unlock(chr->map_server_list_lock);
	rwlock->write_lock(chr->map_server_list_lock);

	VECTOR_CLEAR(server->maps);
	VECTOR_ENSURE(server->maps, (RFIFOW(act, 2) - 4) / 4, 1);
	for(i = 4; i < RFIFOW(act,2); i += 4) {
		VECTOR_PUSH(server->maps, RFIFOW(act,i));
	}

	ShowStatus("Map-Server %d connected: %d maps, from IP %u.%u.%u.%u port %d.\n",
			server->pos, (int)VECTOR_LENGTH(server->maps),
			CONVIP(server->ip), server->port);
	ShowStatus("Map-server %d loading complete.\n", server->pos);

	mapif->map_received(act->session, wisp_server_name, 0);
	mutex->lock(fame_list_mutex);
	mapif->fame_list(server, smith_fame_list, fame_list_size_smith,
	                         chemist_fame_list, fame_list_size_chemist,
	                         taekwon_fame_list, fame_list_size_taekwon);
	mutex->unlock(fame_list_mutex);
	mapif->send_maps(server, RFIFOP(act, 4));

	rwlock->write_unlock(chr->map_server_list_lock);
	rwlock->read_lock(chr->map_server_list_lock);
}

/**
 * Loads and sends requested status change data, then deletes it.
 **/
static void char_send_scdata(struct socket_data *session, int aid, int cid)
{
#ifdef ENABLE_SC_SAVING
	struct Sql *sql_handle = inter->sql_handle_get();

	if(SQL_ERROR == SQL->Query(sql_handle, "SELECT `type`, `tick`, `total_tick`, `val1`, `val2`, `val3`, `val4` "
		"FROM `%s` WHERE `account_id` = '%d' AND `char_id`='%d'",
		scdata_db, aid, cid)
	) {
		Sql_ShowDebug(sql_handle);
		return;
	}
	uint64 expected_count = SQL->NumRows(sql_handle);
	mapif->scdata_head(session, aid, cid, min((int)expected_count, 50));
	if(expected_count > 0 ) {
		struct status_change_data scdata;
		int count;
		char* data;

		memset(&scdata, 0, sizeof(scdata));
		for(count = 0; count < 50 && SQL_SUCCESS == SQL->NextRow(sql_handle); ++count) {
			SQL->GetData(sql_handle, 0, &data, NULL); scdata.type = atoi(data);
			SQL->GetData(sql_handle, 1, &data, NULL); scdata.tick = atoi(data);
			SQL->GetData(sql_handle, 2, &data, NULL); scdata.total_tick = atoi(data);
			SQL->GetData(sql_handle, 3, &data, NULL); scdata.val1 = atoi(data);
			SQL->GetData(sql_handle, 4, &data, NULL); scdata.val2 = atoi(data);
			SQL->GetData(sql_handle, 5, &data, NULL); scdata.val3 = atoi(data);
			SQL->GetData(sql_handle, 6, &data, NULL); scdata.val4 = atoi(data);
			mapif->scdata_data(session, &scdata);
		}
		if(count >= 50)
			ShowWarning("Too many status changes for %d:%d, some of them were not loaded.\n",
				aid, cid);
		if(count > 0) {
			//Clear the data once loaded.
			if(SQL_ERROR == SQL->Query(sql_handle,
				"DELETE FROM `%s` WHERE `account_id` = '%d' AND `char_id`='%d'",
				scdata_db, aid, cid))
				Sql_ShowDebug(sql_handle);
		}
	}
	mapif->scdata_send(session);
	SQL->FreeResult(sql_handle);
#endif
}

/**
 * ZW_REQUEST_SCDATA
 * Request of status change data of a character
 **/
static void char_parse_frommap_request_scdata(struct s_receive_action_data *act, struct mmo_map_server *server)
{
#ifdef ENABLE_SC_SAVING
	int aid = RFIFOL(act,2);
	int cid = RFIFOL(act,6);
	chr->send_scdata(act->session, aid, cid);
#endif
}

/**
 * ZW_SEND_USERS_COUNT
 * User count of a map-server
 **/
static void char_parse_frommap_set_users_count(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	if(RFIFOW(act,2) != server->user_count) {
		server->user_count = RFIFOW(act,2);
		ShowInfo("User Count: %d (Server: %d)\n",
			server->user_count, server->pos);
	}
}

/**
 * ZW_USER_LIST
 * Current online characters in map-server
 *
 * Acquires db_lock(chr->online_char_db)
 **/
static void char_parse_frommap_set_users(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	//TODO: When data mismatches memory, update guild/party online/offline states.
	int i;

	server->user_count = RFIFOW(act,4);

	db_lock(chr->online_char_db, WRITE_LOCK);
	chr->online_char_db->foreach(chr->online_char_db,chr->db_setoffline,
		server->pos); //Set all chars from this server as 'unknown'
	/**
	 * Unlock db_lock(chr->online_char_db) after all operations so no timer can
	 * mess with the database while we're loading the data.
	 **/

	for(i = 0; i < server->user_count; i++) {
		int aid = RFIFOL(act,6+i*8);
		int cid = RFIFOL(act,6+i*8+4);
		struct online_char_data *character = idb_ensure(chr->online_char_db,
			aid, chr->create_online_char_data);
		if(character->server > -1 && character->server != server->pos) {
			ShowNotice("Set map user: Character (%d:%d) marked on map server %d,"
				"but map server %d claims to have (%d:%d) online!\n",
				character->account_id, character->char_id, character->server,
				server->pos, aid, cid);
			mapif->disconnectplayer(act->session, character->account_id,
				character->char_id, 2); // 2: Already connected to server
		}
		character->server = server->pos;
		character->char_id = cid;
	}
	db_unlock(chr->online_char_db);
	//If any chars remain in -2, they will be cleaned in the cleanup timer.
}

/**
 * ZW_SAVE_CHARACTER
 * Save character request
 *
 * Acquires db_lock(chr->online_char_db)
 * Acquires db_lock(chr->char_db_)
 **/
static void char_parse_frommap_save_character(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	int16 size = RFIFOW(act, 2);
	int32 aid = RFIFOL(act, 4);
	int32 cid = RFIFOL(act, 8);
	struct online_char_data* character;

	if(size - 13 != sizeof(struct mmo_charstatus)) {
		ShowError("parse_from_map (save-char): Size mismatch! %d != %"PRIuS"\n",
			size-13, sizeof(struct mmo_charstatus));
		return;
	}
	/**
	 * Check account only if this ain't final save. Final-save goes through because
	 * of the char-map reconnect.
	 **/
	db_lock(chr->online_char_db, WRITE_LOCK);
	if(RFIFOB(act, 12)
	 || ( (character = idb_get(chr->online_char_db, aid)) != NULL
	    && character->char_id == cid)
	) {
		db_unlock(chr->online_char_db);
		// TODO/FIXME: Copy of a padded struct
		struct mmo_charstatus char_dat;
		memcpy(&char_dat, RFIFOP(act, 13), sizeof(struct mmo_charstatus));
		int save_flag = chr->mmo_char_tosql(cid, &char_dat);
		if(save_flag > 0) {
			// Cache wasn't updated, try to reload changed data from db
			db_lock(chr->char_db_, WRITE_LOCK);
			chr->mmo_char_fromsql(cid, save_flag, NULL, CHARCACHE_UPDATE);
			db_unlock(chr->char_db_);
		}
	} else {
		db_unlock(chr->online_char_db);
		// set_char_online acquires db_lock(chr->online_char_db)
		/**
		 * This may be valid on char-server reconnection, when re-sending
		 * characters that already logged off.
		 **/
		ShowError("parse_from_map (save-char): Received data for "
			"non-existing/offline character (%d:%d).\n", aid, cid);
		chr->set_char_online(server->pos, cid, aid);
	}

	if(RFIFOB(act, 12)) {
		//Flag, set character offline after saving. [Skotlex]
		db_lock(chr->online_char_db, WRITE_LOCK);
		chr->set_char_offline(cid, aid);
		db_unlock(chr->online_char_db);
		mapif->save_character_ack(act->session, aid, cid);
	}
}

/**
 * ZW_CHAR_SELECT_REQ
 * Notification of client request to select another character
 **/
static void char_parse_frommap_char_select_req(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	int account_id   = RFIFOL(act,2);
	uint32 login_id1 = RFIFOL(act,6);
	uint32 login_id2 = RFIFOL(act,10);
	uint32 ip        = RFIFOL(act,14);
	int32 group_id   = RFIFOL(act,18);

	if(core->runflag != CHARSERVER_ST_RUNNING) {
		mapif->char_select_ack(act->session, account_id, 0);
		return;
	}
	struct char_session_data sd = { // Dummy session data for a new node
		.account_id = account_id,
		.login_id1 = login_id1,
		.login_id2 = login_id2,
		.group_id = group_id,
		.expiration_time = 0, // unlimited/unknown time by default (not display in map-server)
	};
	chr->create_auth_entry(&sd, 0, ntohl(ip), false);

	//Set char to "@ char select" in online db [Kevin]
	chr->set_char_charselect(account_id);
	mapif->char_select_ack(act->session, account_id, 1);
}

/**
 * ZW_CHANGE_SERVER_REQUEST
 * Request to move a character between map-servers
 *
 * Acquires db_lock(chr->online_char_db)
 * Acquires db_lock(chr->char_db_)
 **/
static void char_parse_frommap_change_map_server(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	int map_id;
	struct mmo_map_server *new_server;
	struct mmo_charstatus *char_data;

	int32 account_id = RFIFOL(act, 2);
	int32 login_id1  = RFIFOL(act, 6);
	int32 login_id2  = RFIFOL(act, 10);
	int32 char_id    = RFIFOL(act, 14);
	int16 mapindex   = RFIFOW(act, 18);
	int16 x          = RFIFOW(act, 20);
	int16 y          = RFIFOW(act, 22);
	int32 ipl        = ntohl(RFIFOL(act, 24));
	int16 port       = ntohs(RFIFOW(act, 28));
	uint8 sex        = RFIFOB(act, 30);
	int32 client_addr= ntohl(RFIFOL(act, 31));
	int32 group_id   = RFIFOL(act, 35);

	map_id = chr->search_mapserver(mapindex, ipl, port); //Locate mapserver by ip and port.
	if(map_id >= 0)
		new_server = INDEX_MAP_INDEX(chr->map_server_list, map_id);

	//Char should just had been saved before this packet, so this should be safe. [Skotlex]
	db_lock(chr->char_db_, WRITE_LOCK);
	char_data = uidb_get(chr->char_db_, char_id);
	if(char_data == NULL) { //Really shouldn't happen.
		ShowDebug("char_parse_frommap_change_map_server: AID %d CID %d from "
			"map-server %d without cached data!\n",
			account_id, char_id, server->pos);
		char_data = chr->mmo_char_fromsql(char_id, CHARSAVE_ALL, NULL, CHARCACHE_INSERT);
		if(!char_data) {
			db_unlock(chr->char_db_);
			ShowError("char_parse_frommap_change_map_server: Failed to cache data "
				"(AID %d CID %d)\n", account_id, char_id);
			return;
		}
	}

	if (core->runflag == CHARSERVER_ST_RUNNING && new_server && char_data) {
		//Send the map server the auth of this player.
		struct online_char_data* data;

		//Update the "last map" as this is where the player must be spawned on the new map server.
		char_data->last_point.map = mapindex;
		char_data->last_point.x = x;
		char_data->last_point.y = y;
		char_data->sex = sex;
		db_unlock(chr->char_db_);

		struct char_session_data sd = { // Dummy session data for auth entry
			.account_id = account_id,
			.login_id1 = login_id1,
			.login_id2 = login_id2,
			.sex = sex,
			.expiration_time = 0,
			.group_id = group_id,
		};
		chr->create_auth_entry(&sd, char_id, client_addr, true);

		db_lock(chr->online_char_db, WRITE_LOCK);
		data = idb_ensure(chr->online_char_db, account_id, chr->create_online_char_data);
		data->char_id = char_data->char_id;
		data->server = map_id; //Update server where char is.
		db_unlock(chr->online_char_db);

		//Reply with an ack.
		mapif->change_map_server_ack(server->session, RFIFOP(act, 2), true);
	} else { //Reply with nak
		db_unlock(chr->char_db_);
		mapif->change_map_server_ack(server->session, RFIFOP(act, 2), false);
	}
}

/**
 * ZW_REMOVE_FRIEND
 * Remove friend from char_id friend list
 * @author Ind
 **/
static void char_parse_frommap_remove_friend(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	int char_id = RFIFOL(act,2);
	int friend_id = RFIFOL(act,6);
	struct Sql *sql_handle = inter->sql_handle_get();
	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `char_id`='%d' AND `friend_id`='%d' LIMIT 1",
		friend_db, char_id, friend_id) ) {
		Sql_ShowDebug(sql_handle);
	}
}

/**
 * ZW_CHARNAME_REQUEST
 * Character name request
 **/
static void char_parse_frommap_char_name_request(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	mapif->char_name_ack(act->session, RFIFOL(act,2));
}

/**
 * ZW_REQUEST_CHANGE_EMAIL
 * Map server send information to change an email of an account -> login-server
 **/
static void char_parse_frommap_change_email(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	if(chr->login_session) { // don't send request if no login-server
		int account_id = RFIFOL(act, 2);
		const char *current_email = RFIFOP(act, 6);
		loginif->request_change_email(account_id, RFIFOP(act, 6), RFIFOP(act, 46));
	}
}

/**
 * Kicks an account, if the character is in the map-server notifies it.
 * @see loginif->parse_kick
 *
 * Acquires map_server_list_lock
 * Acquires db_lock(chr->online_char_db)
 * Acquires db_lock(auth_db)
 **/
static void char_kick(int account_id)
{
	struct online_char_data *character;

	db_lock(chr->online_char_db, WRITE_LOCK);
	character = idb_get(chr->online_char_db, account_id);
	if(!character) {
		db_unlock(chr->online_char_db);
		goto remove_auth_db; // Account not marked as online
	}
	
	if(character->server > -1) {
		//Kick it from the map server it is on.
		struct mmo_map_server *server;
		rwlock->read_lock(chr->map_server_list_lock);
		server = INDEX_MAP_INDEX(chr->map_server_list, character->server);
		if(server) {
			mapif->disconnectplayer(server->session,
				character->account_id, character->char_id, NBE_DUPLICATE_ID);
		}
		rwlock->read_unlock(chr->map_server_list_lock);
		if(character->waiting_disconnect == INVALID_TIMER) {
			character->waiting_disconnect = timer->add(timer->gettick()+AUTH_TIMEOUT,
				chr->waiting_disconnect, character->account_id, 0);
		}
	} else {
		// Manual kick from char server.
		struct socket_data *client_session;
		client_session = socket_io->session_from_id(character->session_id);
		if(client_session) {
			mutex->lock(client_session->mutex);
			bool marked_removal = socket_io->session_marked_removal(client_session);
			mutex->unlock(client_session->mutex);
		
			if(marked_removal)
				client_session = NULL;
		}
		if(client_session) {
			chr->authfail_fd(client_session, NBE_SERVER_CLOSED);
			socket_io->session_disconnect_guard(client_session);
		} else { // still moving to the map-server
			chr->set_char_offline(-1, account_id);
		}
	}
	db_unlock(chr->online_char_db);
	// Fall-through
remove_auth_db:
	db_lock(auth_db, WRITE_LOCK);
	idb_remove(auth_db, account_id); // reject auth attempts from map-server
	db_unlock(auth_db);
}

static void char_ban(int account_id, int char_id, time_t *unban_time, short year, short month, short day, short hour, short minute, short second)
{
	time_t timestamp;
	struct tm *tmtime;
	struct SqlStmt *stmt = SQL->StmtMalloc(inter->sql_handle_get());

	nullpo_retv(unban_time);

	if (*unban_time == 0 || *unban_time < time(NULL))
		timestamp = time(NULL); // new ban
	else
		timestamp = *unban_time; // add to existing ban

	tmtime = localtime(&timestamp);
	tmtime->tm_year = tmtime->tm_year + year;
	tmtime->tm_mon  = tmtime->tm_mon + month;
	tmtime->tm_mday = tmtime->tm_mday + day;
	tmtime->tm_hour = tmtime->tm_hour + hour;
	tmtime->tm_min  = tmtime->tm_min + minute;
	tmtime->tm_sec  = tmtime->tm_sec + second;
	timestamp = mktime(tmtime);

	if( SQL_SUCCESS != SQL->StmtPrepare(stmt,
		"UPDATE `%s` SET `unban_time` = ? WHERE `char_id` = ? LIMIT 1",
		char_db)
	   || SQL_SUCCESS != SQL->StmtBindParam(stmt, 0, SQLDT_TIME, &timestamp, sizeof timestamp)
	   || SQL_SUCCESS != SQL->StmtBindParam(stmt, 1, SQLDT_INT,  &char_id,   sizeof char_id)
	   || SQL_SUCCESS != SQL->StmtExecute(stmt)
	) {
		SqlStmt_ShowDebug(stmt);
	}

	SQL->StmtFree(stmt);

	// condition applies; send to all map-servers to disconnect the player
	if (timestamp > time(NULL)) {
		mapif->char_ban(char_id, timestamp);
		// disconnect player if online on char-server
		chr->disconnect_player(account_id);
	}
}

static void char_unban(int char_id, int *result)
{
	struct Sql *sql_handle = inter->sql_handle_get();
	/* handled by char server, so no redirection */
	if( SQL_ERROR == SQL->Query(sql_handle, "UPDATE `%s` SET `unban_time` = '0' WHERE `char_id` = '%d' LIMIT 1", char_db, char_id) ) {
		Sql_ShowDebug(sql_handle);
		if (result)
			*result = 1;
	}
}

/**
 * Changes the sex of all characters of an account.
 * @see loginif_parse_changesex_reply
 * @see char_change_sex_sub
 * Acquires db_lock(auth_db)
 **/
static void char_changecharsex_all(int account_id, int sex)
{
	int char_id = 0, class = 0, guild_id = 0;
	struct char_auth_node *node;
	struct SqlStmt *stmt;
	struct Sql *sql_handle = inter->sql_handle_get();

	db_lock(auth_db, WRITE_LOCK);
	node = idb_get(auth_db, account_id);
	if(node != NULL)
		node->sex = sex;
	db_unlock(auth_db);

	// get characters
	stmt = SQL->StmtMalloc(sql_handle);
	if (SQL_ERROR == SQL->StmtPrepare(stmt, "SELECT `char_id`,`class`,`guild_id` FROM `%s` WHERE `account_id` = '%d'", char_db, account_id)
	 || SQL_ERROR == SQL->StmtExecute(stmt)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 0, SQLDT_INT, &char_id,  sizeof char_id,  NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 1, SQLDT_INT, &class,    sizeof class,    NULL, NULL)
	 || SQL_ERROR == SQL->StmtBindColumn(stmt, 2, SQLDT_INT, &guild_id, sizeof guild_id, NULL, NULL)
	) {
		SqlStmt_ShowDebug(stmt);
		SQL->StmtFree(stmt);
		return;
	}

	for(int i = 0; i < MAX_CHARS && SQL_SUCCESS == SQL->StmtNextRow(stmt); ++i)
		char_change_sex_sub(sex, account_id, char_id, class, guild_id);

	SQL->StmtFree(stmt);

	chr->disconnect_player(account_id); // Disconnect player if online on char-server.
	mapif->change_sex(account_id, sex); // Notify all mapservers about this change.
}

/**
 * Changes a character's gender.
 * The information is updated on database, and the character is kicked if it currently is online.
 *
 * @param char_id The character ID
 * @param sex The character's new gender (SEX_MALE or SEX_FEMALE).
 * @retval 0 in case of success.
 * @retval 1 in case of failure.
 *
 **/
static int char_changecharsex(int char_id, int sex)
{
	struct Sql *sql_handle = inter->sql_handle_get();
	struct SqlStmt *stmt = SQL->StmtMalloc(sql_handle);

	/** If we can't load the data, there's nothing to do. **/
	if (stmt == NULL) {
		SqlStmt_ShowDebug(stmt);
		return 1;
	}

	const char *query = "SELECT `account_id`, `class`, `guild_id` FROM `%s` WHERE `char_id`=?";
	int account_id = 0;
	int class = 0;
	int guild_id = 0;

	/** Abort changing gender if there was an error while loading the data. **/
	if (SQL_ERROR == SQL->StmtPrepare(stmt, query, char_db)
	    || SQL_ERROR == SQL->StmtBindParam(stmt, 0, SQLDT_INT32, &char_id, sizeof(char_id))
	    || SQL_ERROR == SQL->StmtExecute(stmt)
	    || SQL_ERROR == SQL->StmtBindColumn(stmt, 0, SQLDT_INT32, &account_id, sizeof(account_id), NULL, NULL)
	    || SQL_ERROR == SQL->StmtBindColumn(stmt, 1, SQLDT_INT32, &class, sizeof(class), NULL, NULL)
	    || SQL_ERROR == SQL->StmtBindColumn(stmt, 2, SQLDT_INT32, &guild_id, sizeof(guild_id), NULL, NULL)) {
		SqlStmt_ShowDebug(stmt);
		SQL->StmtFree(stmt);
		return 1;
	}

	/** Abort changing gender if no character was found. **/
	if (SQL->StmtNumRows(stmt) < 1) {
		ShowError("char_changecharsex: Requested non-existant character! (ID: %d)\n", char_id);
		SQL->StmtFree(stmt);
		return 1;
	}

	/** Abort changing gender if more than one character was found. **/
	if (SQL->StmtNumRows(stmt) > 1) {
		ShowError("char_changecharsex: There are multiple characters with identical ID! (ID: %d)\n", char_id);
		SQL->StmtFree(stmt);
		return 1;
	}

	/** Abort changing gender if fetching the data fails. **/
	if (SQL_ERROR == SQL->StmtNextRow(stmt)) {
		SqlStmt_ShowDebug(stmt);
		SQL->StmtFree(stmt);
		return 1;
	}

	SQL->StmtFree(stmt);
	char_change_sex_sub(sex, account_id, char_id, class, guild_id);
	chr->disconnect_player(account_id); // Disconnect player if online on char-server.
	mapif->change_sex(account_id, sex); // Notify all mapservers about this change.

	return 0;
}

/**
 * ZW_UPDATE_ACCOUNT
 * Request from map-server to change an account's or character's status
 * (accounts will just be forwarded to login server)
 **/
static void char_parse_frommap_change_account(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	int result = 0; // 0-login-server request done, 1-player not found, 2-gm level too low, 3-login-server offline
	char esc_name[ESC_NAME_LENGTH];
	struct Sql *sql_handle = inter->sql_handle_get();

	int acc = RFIFOL(act,2); // account_id of who ask (-1 if server itself made this request)
	const char *name = RFIFOP(act,6); // name of the target character
	enum zh_char_ask_name_type type = RFIFOW(act,30); // type of operation: 1-block, 2-ban, 3-unblock, 4-unban, 5 changesex, 6 charban, 7 charunban
	short year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
	int sex = SEX_MALE;
	if(type == CHAR_ASK_NAME_BAN || type == CHAR_ASK_NAME_CHARBAN) {
		year   = RFIFOW(act, 32);
		month  = RFIFOW(act, 34);
		day    = RFIFOW(act, 36);
		hour   = RFIFOW(act, 38);
		minute = RFIFOW(act, 40);
		second = RFIFOW(act, 42);
	} else if(type == CHAR_ASK_NAME_CHANGECHARSEX) {
		sex = RFIFOB(act, 32);
		// CHAR_ASK_NAME_CHANGESEX inverts sex
	}

	SQL->EscapeStringLen(sql_handle, esc_name, name, strnlen(name, NAME_LENGTH));

	if(SQL_ERROR == SQL->Query(sql_handle, "SELECT `account_id`,`char_id`,`unban_time` FROM `%s` WHERE `name` = '%s'", char_db, esc_name)) {
		Sql_ShowDebug(sql_handle);
	} else if (SQL->NumRows(sql_handle) == 0) {
		SQL->FreeResult(sql_handle);
		result = 1; // 1-player not found
	} else if (SQL_SUCCESS != SQL->NextRow(sql_handle)) {
		Sql_ShowDebug(sql_handle);
		SQL->FreeResult(sql_handle);
		result = 1; // 1-player not found
	} else {
		int account_id, char_id;
		char *data;
		time_t unban_time;

		SQL->GetData(sql_handle, 0, &data, NULL); account_id = atoi(data);
		SQL->GetData(sql_handle, 1, &data, NULL); char_id = atoi(data);
		SQL->GetData(sql_handle, 2, &data, NULL); unban_time = atol(data);
		SQL->FreeResult(sql_handle);

		if(!chr->login_session) {
			result = 3; // 3-login-server offline
#if 0 //FIXME: need to move this check to login server [ultramage]
		} else if( acc != -1 && isGM(acc) < isGM(account_id) ) {
			result = 2; // 2-gm level too low
#endif // 0
		} else {
			switch (type) {
			case CHAR_ASK_NAME_BLOCK:
				loginif->update_state(account_id, ALE_LOGIN_UNAVAILABLE); // Permanent block
				break;
			case CHAR_ASK_NAME_BAN:
				loginif->ban_account(account_id, year, month, day, hour, minute, second);
				break;
			case CHAR_ASK_NAME_UNBLOCK:
				loginif->update_state(account_id, ALE_OK);
				break;
			case CHAR_ASK_NAME_UNBAN:
				loginif->unban_account(account_id);
				break;
			case CHAR_ASK_NAME_CHANGESEX:
				loginif->changesex(account_id);
				break;
			case CHAR_ASK_NAME_CHARBAN:
				/* handled by char server, so no redirection */
				chr->ban(account_id, char_id, &unban_time, year, month, day, hour, minute, second);
				break;
			case CHAR_ASK_NAME_CHARUNBAN:
				chr->unban(char_id, &result);
				break;
			case CHAR_ASK_NAME_CHANGECHARSEX:
				result = chr->changecharsex(char_id, sex);
				break;
			}
		}
	}

	// send answer if a player ask, not if the server ask
	if (acc != -1 && type != CHAR_ASK_NAME_CHANGESEX && type != CHAR_ASK_NAME_CHANGECHARSEX) { // Don't send answer for changesex
		mapif->change_account_ack(act->session, acc, name, type, result);
	}
}

/**
 * ZW_FAME_LIST_UPDATE
 * Fame list update request
 *
 * Acquires fame_list_mutex
 **/
static void char_parse_frommap_fame_list(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	int cid   = RFIFOL(act, 2);
	int fame  = RFIFOL(act, 6);
	char type = RFIFOB(act, 10);
	int size;
	struct fame_list* list;
	int player_pos;
	int fame_pos;

	mutex->lock(fame_list_mutex);

	switch(type) {
		case RANKTYPE_BLACKSMITH: size = fame_list_size_smith;   list = smith_fame_list;   break;
		case RANKTYPE_ALCHEMIST:  size = fame_list_size_chemist; list = chemist_fame_list; break;
		case RANKTYPE_TAEKWON:    size = fame_list_size_taekwon; list = taekwon_fame_list; break;
		default:                  size = 0;                      list = NULL;              break;
	}

	if(!list) {
		mutex->unlock(fame_list_mutex);
		return;
	}

	ARR_FIND(0, size, player_pos, list[player_pos].id == cid);// position of the player
	ARR_FIND(0, size, fame_pos, list[fame_pos].fame <= fame);// where the player should be

	if( player_pos == size && fame_pos == size )
		;// not on list and not enough fame to get on it
	else if( fame_pos == player_pos ) {
		// same position
		list[player_pos].fame = fame;
		mapif->fame_list_update(type, player_pos, fame);
	} else {
		// move in the list
		if( player_pos == size ) {
			// new ranker - not in the list
			ARR_MOVE(size - 1, fame_pos, list, struct fame_list);
			list[fame_pos].id = cid;
			list[fame_pos].fame = fame;
			chr->loadName(cid, list[fame_pos].name);
		} else {
			// already in the list
			if( fame_pos == size )
				--fame_pos;// move to the end of the list
			ARR_MOVE(player_pos, fame_pos, list, struct fame_list);
			list[fame_pos].fame = fame;
		}
		mapif->fame_list(NULL, smith_fame_list, fame_list_size_smith,
	           chemist_fame_list, fame_list_size_chemist,
	           taekwon_fame_list, fame_list_size_taekwon);
	}
	mutex->unlock(fame_list_mutex);
}

/**
 * ZW_DIVORCE
 * Divorces chracters
 **/
static void char_parse_frommap_divorce_char(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	chr->divorce_char_sql(RFIFOL(act,2), RFIFOL(act,6));
}

/**
 * ZW_RATES
 * Updates map-server rates
 **/
static void char_parse_frommap_ragsrvinfo(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	char esc_server_name[sizeof(chr->server_name)*2+1];
	struct Sql *sql_handle = inter->sql_handle_get();

	SQL->EscapeString(sql_handle, esc_server_name, chr->server_name);

	if( SQL_ERROR == SQL->Query(sql_handle,
		"INSERT INTO `%s` SET `index`='%d',`name`='%s',`exp`='%u',`jexp`='%u',`drop`='%u'",
		ragsrvinfo_db, act->session_id, esc_server_name, RFIFOL(act,2), RFIFOL(act,6), RFIFOL(act,10))
	) {
		Sql_ShowDebug(sql_handle);
	}
}

/**
 * ZW_SET_CHARACTER_OFFLINE
 * Sets character offline.
 **/
static void char_parse_frommap_set_char_offline(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	db_lock(chr->online_char_db, WRITE_LOCK);
	chr->set_char_offline(RFIFOL(act, 2), RFIFOL(act, 6));
	db_unlock(chr->online_char_db);
}

/**
 * ZW_SET_ALL_OFFLINE
 * Sets all characters offline.
 **/
static void char_parse_frommap_set_all_offline(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	chr->set_all_offline(server->pos);
}

/**
 * ZW_SET_CHARACTER_ONLINE
 * Sets character online.
 **/
static void char_parse_frommap_set_char_online(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	chr->set_char_online(server->pos, RFIFOL(act,2),RFIFOL(act,6));
}

/**
 * ZW_FAME_LIST_BUILD
 * Build and send fame ranking lists
 * @author DracoRPG
 *
 * Acquires fame_list_mutex
 **/
static void char_parse_frommap_build_fame_list(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	mutex->lock(fame_list_mutex);
	chr->read_fame_list();
	mapif->fame_list(NULL, smith_fame_list, fame_list_size_smith,
	       chemist_fame_list, fame_list_size_chemist,
	       taekwon_fame_list, fame_list_size_taekwon);
	mutex->unlock(fame_list_mutex);
}

/**
 * ZW_STATUS_CHANGE_SAVE
 * Request to save status change data
 * @author Skotlex
 **/
static void char_parse_frommap_save_status_change_data(struct s_receive_action_data *act, struct mmo_map_server *server)
{
#ifdef ENABLE_SC_SAVING
	int aid = RFIFOL(act, 4);
	int cid = RFIFOL(act, 8);
	int count = RFIFOW(act, 12);
	struct Sql *sql_handle = inter->sql_handle_get();

	/* clear; ensure no left overs e.g. permanent */
	if( SQL_ERROR == SQL->Query(sql_handle,
		"DELETE FROM `%s` WHERE `account_id` = '%d' AND `char_id`='%d'", scdata_db, aid, cid)
	)
		Sql_ShowDebug(sql_handle);

	if( count > 0 )
	{
		struct status_change_data data;
		StringBuf buf;
		int i;

		StrBuf->Init(&buf);
		StrBuf->Printf(&buf, "INSERT INTO `%s` (`account_id`, `char_id`, `type`, "
			"`tick`, `total_tick`, `val1`, `val2`, `val3`, `val4`) VALUES ",
			scdata_db);
		for( i = 0; i < count; ++i )
		{
			/**
			 * FIXME: This doesn't take into account the difference in padding
			 * between different systems [Panikon]
			 **/
			memcpy (&data, RFIFOP(act, 14+i*sizeof(struct status_change_data)),
				sizeof(struct status_change_data));
			if( i > 0 )
				StrBuf->AppendStr(&buf, ", ");
			StrBuf->Printf(&buf, "('%d','%d','%hu','%d','%d','%d','%d','%d','%d')", aid, cid,
				data.type, data.tick, data.total_tick, data.val1, data.val2, data.val3, data.val4);
		}
		if( SQL_ERROR == SQL->QueryStr(sql_handle, StrBuf->Value(&buf)) )
			Sql_ShowDebug(sql_handle);
		StrBuf->Destroy(&buf);
	}
#endif
}

/**
 * ZW_PING
 * Ping packet
 **/
static void char_parse_frommap_ping(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	mapif->pong(act->session);
}

/**
 * ZW_AUTH
 * Map-server account authentication request
 *
 * Acquires auth_db_mutex
 * Acquires db_lock(auth_db)
 **/
static void char_parse_frommap_auth_request(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	struct mmo_charstatus* cd;

	int account_id  = RFIFOL(act,2);
	int char_id     = RFIFOL(act,6);
	int login_id1   = RFIFOL(act,10);
	char sex        = RFIFOB(act,14);
	uint32 ip       = ntohl(RFIFOL(act,15));
	char standalone = RFIFOB(act, 19);

	/**
	 * We copy node data before acquiring chr->char_db_ so we can avoid
	 * potential deadlock situations.
	 **/
	struct char_auth_node copy;
	struct char_auth_node *cached_node = NULL;
	struct char_auth_node *node = NULL;
	if(!standalone) {
		// Don't try to acquire auth node if player is autotrading
		db_lock(auth_db, WRITE_LOCK);
		node = idb_get(auth_db, account_id);
		if(node) {
			node->read_flag = true; // Set so no thread can change this node
			memcpy(&copy, node, sizeof(copy));
			cached_node = node;
			node = &copy;
		}
		db_unlock(auth_db);
	}

	db_lock(chr->char_db_, READ_LOCK);
	cd = uidb_get(chr->char_db_,char_id);
	if(cd == NULL) { //Really shouldn't happen.
		db_unlock(chr->char_db_);
		ShowDebug("char_parse_frommap_auth_request: AID %d CID %d requesting  "
			"map-server %d without cached data! Denying auth\n",
			account_id, char_id, server->pos);
		mapif->auth_failed(act->session, account_id, char_id, login_id1, sex, ip);
		return;
	}

	if( core->runflag == CHARSERVER_ST_RUNNING && cd && standalone ) {
		// Autotrading
		cd->sex = sex;

		mapif->auth_ok(act->session, account_id, NULL, cd);
		db_unlock(chr->char_db_);

		chr->set_char_online(server->pos, char_id, account_id);
		return;
	}

	if( core->runflag == CHARSERVER_ST_RUNNING &&
		cd != NULL &&
		node != NULL &&
		node->account_id == account_id &&
		node->char_id == char_id &&
		node->login_id1 == login_id1 /*&&
		node->sex == sex &&
		node->ip == ip*/ )
	{// auth ok
		if( cd->sex == 99 )
			cd->sex = sex;

		mapif->auth_ok(act->session, account_id, node, cd);
		db_unlock(chr->char_db_);

		// only use the auth once and mark user online
		db_lock(auth_db, WRITE_LOCK);
		idb_remove(auth_db, account_id);
		db_unlock(auth_db);

		chr->set_char_online(server->pos, char_id, account_id);
	}
	else
	{// auth failed
		db_unlock(chr->char_db_);

		if(cached_node) {
			db_lock(auth_db, WRITE_LOCK);
			cached_node->read_flag = false;
			db_unlock(auth_db);
		}

		mapif->auth_failed(act->session, account_id, char_id, login_id1, sex, ip);
	}
}

/**
 * ZW_WAN_UPDATE
 * Request to update map-server WAN IP
 **/
static void char_parse_frommap_update_ip(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	server->ip = ntohl(RFIFOL(act, 2));
	ShowInfo("Updated IP address of map-server #%d to %u.%u.%u.%u.\n",
		server->pos, CONVIP(server->ip));
}

/**
 * ZW_STATUS_CHANGE_UPDATE
 * Individual SC data insertion/update
 **/
static void char_parse_frommap_scdata_update(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	struct Sql *sql_handle = inter->sql_handle_get();
	int account_id = RFIFOL(act, 2);
	int char_id = RFIFOL(act, 6);
	int val1 = RFIFOL(act, 12);
	int val2 = RFIFOL(act, 16);
	int val3 = RFIFOL(act, 20);
	int val4 = RFIFOL(act, 24);
	short type = RFIFOW(act, 10);

	if (SQL_ERROR == SQL->Query(sql_handle, "REPLACE INTO `%s`"
			" (`account_id`,`char_id`,`type`,`tick`,`total_tick`,`val1`,`val2`,`val3`,`val4`)"
			" VALUES ('%d','%d','%d','%d','%d','%d','%d','%d','%d')",
			scdata_db, account_id, char_id, type, INFINITE_DURATION, INFINITE_DURATION, val1, val2, val3, val4)
	) {
		Sql_ShowDebug(sql_handle);
	}
}

/**
 * ZW_STATUS_CHANGE_DELETE
 * Individual SC data delete
 **/
static void char_parse_frommap_scdata_delete(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	struct Sql *sql_handle = inter->sql_handle_get();
	int account_id = RFIFOL(act, 2);
	int char_id    = RFIFOL(act, 6);
	short type     = RFIFOW(act, 10);

	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE "
		"`account_id` = '%d' AND `char_id` = '%d' AND `type` = '%d' LIMIT 1",
								scdata_db, account_id, char_id, type)
	) {
		Sql_ShowDebug(sql_handle);
	}
}

/**
 * Parses packets of an authenticated map-server
 **/
static enum parsefunc_rcode char_parse_frommap(struct s_receive_action_data *act)
{
	struct mmo_map_server *server;

	rwlock->read_lock(chr->map_server_list_lock);
	server = mapif->server_find(act->session);
	if(!server) {// not a map server
		rwlock->read_unlock(chr->map_server_list_lock);
		mutex->lock(act->session->mutex);
		if(!socket_io->session_marked_removal(act->session))
			ShowDebug("chr->parse_frommap: Disconnecting invalid session #%d (is not a map-server)\n",
				act->session->id);
		socket_io->session_disconnect(act->session);
		mutex->unlock(act->session->mutex);
		return PACKET_VALID;
	}

	mutex->lock(act->session->mutex);
	if( socket_io->session_marked_removal(act->session) )
	{
		rwlock->read_unlock(chr->map_server_list_lock);
		// session_data is an integer
		//aFree(act->session->session_data);
		mutex->unlock(act->session->mutex);
		mapif->on_disconnect(server);
		return PACKET_VALID;
	}
	mutex->unlock(act->session->mutex);

	while(RFIFOREST(act) >= 2) {
		uint16 command = RFIFOW(act, 0);

		if(VECTOR_LENGTH(HPM->packets[hpParse_FromMap]) > 0) {
			int result = HPM->parse_packets(act,command,hpParse_FromMap);
			if (result == 1)
				continue;

			if (result == 2)
				goto unlock_list_return_incomplete;
		}
		struct mapif_packet_entry *packet_data;
		packet_data = idb_get(mapif->packet_db, command);
		if(!packet_data) {
			ShowError("char_parse_frommap: Unknown packet 0x%04x from a "
				"map-server! Disconnecting!\n", command);
			socket_io->session_disconnect_guard(act->session);
			goto unlock_list_return;
		}

		size_t packet_len;
		if(packet_data->len == -1)
			packet_len = (RFIFOREST(act) >= 4)?RFIFOW(act, 2):4;
		else
			packet_len = packet_data->len;

		if(RFIFOREST(act) < packet_len)
			goto unlock_list_return_incomplete;

		packet_data->pFunc(act, server);
		RFIFOSKIP(act, packet_len);
	} // while

unlock_list_return:
	rwlock->read_unlock(chr->map_server_list_lock);
	return PACKET_VALID;

unlock_list_return_incomplete:
	rwlock->read_unlock(chr->map_server_list_lock);
	return PACKET_INCOMPLETE;
}

/**
 * Searches for the mapserver that has a given map (and optionally ip/port, if not -1).
 * If found, returns the server's index in the 'server' array (otherwise returns -1).
 * Acquires chr->map_server_list_lock
 **/
static int char_search_mapserver(unsigned short map, uint32 ip, uint16 port)
{
	int i, j;
	int retval = -1;

	rwlock->read_lock(chr->map_server_list_lock);
	INDEX_MAP_ITER_DECL(iter);
	INDEX_MAP_ITER(chr->map_server_list, iter);
	while((i = INDEX_MAP_NEXT(chr->map_server_list, iter)) != -1) {
		struct mmo_map_server *server = INDEX_MAP_INDEX(chr->map_server_list, i);
		if(!server)
			continue;
		if((ip == (uint32)-1 || server->ip == ip)
		&& (port == (uint16)-1 || server->port == port)
		) {
			ARR_FIND(0, VECTOR_LENGTH(server->maps), j, VECTOR_INDEX(server->maps, j) == map);
			if(j != VECTOR_LENGTH(server->maps)) {
				retval = i;
				break;
			}
		}
	}
	rwlock->read_unlock(chr->map_server_list_lock);
	return retval;
}

/**
 * Called upon successful authentication of a map-server
 * (currently only initialization inter_mapif)
 **/
static int char_mapif_init(struct socket_data *session)
{
	return inter->mapif_init(session);
}

/**
 * Checks whether the given IP comes from LAN or WAN.
 *
 * @param ip IP address to check.
 * @retval 0 if it is a WAN IP.
 * @return the appropriate LAN server address to send, if it is a LAN IP.
 */
static uint32 char_lan_subnet_check(uint32 ip)
{
	struct s_subnet lan = {0};
	if (socket_io->lan_subnet_check(ip, &lan)) {
		ShowInfo("Subnet check [%u.%u.%u.%u]: Matches "CL_CYAN"%u.%u.%u.%u/%u.%u.%u.%u"
			CL_RESET"\n", CONVIP(ip), CONVIP(lan.ip & lan.mask), CONVIP(lan.mask));
		return lan.ip;
	}
	ShowInfo("Subnet check [%u.%u.%u.%u]: "CL_CYAN"WAN"CL_RESET"\n", CONVIP(ip));
	return 0;
}


/// Answers to deletion request (HC_DELETE_CHAR3_RESERVED)
/// @param result
/// 0 (0x718): An unknown error has occurred.
/// 1: none/success
/// 3 (0x719): A database error occurred.
/// 4 (0x71a): To delete a character you must withdraw from the guild.
/// 5 (0x71b): To delete a character you must withdraw from the party.
/// Any (0x718): An unknown error has occurred.
static void char_delete2_ack(struct socket_data *session, int char_id, uint32 result, time_t delete_date)
{// HC: <0828>.W <char id>.L <Msg:0-5>.L <deleteDate>.L
	WFIFOHEAD(session,14,true);
	WFIFOW(session,0) = 0x828;
	WFIFOL(session,2) = char_id;
	WFIFOL(session,6) = result;
#if PACKETVER >= 20130000
	WFIFOL(session,10) = (int)(delete_date - time(NULL));
#else
	WFIFOL(session,10) = (int)delete_date;

#endif
	WFIFOSET(session,14);
}

static void char_delete2_accept_actual_ack(struct socket_data *session, int char_id, uint32 result)
{
	WFIFOHEAD(session,10,true);
	WFIFOW(session,0) = 0x82a;
	WFIFOL(session,2) = char_id;
	WFIFOL(session,6) = result;
	WFIFOSET(session,10);
}

/// @param result
/// 0 (0x718): An unknown error has occurred.
/// 1: none/success
/// 2 (0x71c): Due to system settings can not be deleted.
/// 3 (0x719): A database error occurred.
/// 4 (0x71d): Deleting not yet possible time.
/// 5 (0x71e): Date of birth do not match.
/// Any (0x718): An unknown error has occurred.
static void char_delete2_accept_ack(struct socket_data *session, int char_id, uint32 result)
{// HC: <082a>.W <char id>.L <Msg:0-5>.L
#if PACKETVER_MAIN_NUM >= 20130522 || PACKETVER_RE_NUM >= 20130327 || defined(PACKETVER_ZERO)
	if( result == 1 ) {
		struct char_session_data* sd = (struct char_session_data*)session->session_data;
		chr->send_HC_ACK_CHARINFO_PER_PAGE(session, sd);
	}
#endif
	chr->delete2_accept_actual_ack(session, char_id, result);
}

/// @param result
/// 1 (0x718): none/success, (if char id not in deletion process): An unknown error has occurred.
/// 2 (0x719): A database error occurred.
/// Any (0x718): An unknown error has occurred.
static void char_delete2_cancel_ack(struct socket_data *session, int char_id, uint32 result)
{// HC: <082c>.W <char id>.L <Msg:1-2>.L
	WFIFOHEAD(session,10, true);
	WFIFOW(session,0) = 0x82c;
	WFIFOL(session,2) = char_id;
	WFIFOL(session,6) = result;
	WFIFOSET(session,10);
}

/**
 * Verifies if the player has enough level to delete
 *
 * @param out_delete_date Optional, pointer to be filled with `delete_date`
 * @return chr->delete2_accept_ack result
 * @retval 1 Success
 **/
static int char_can_delete(int char_id, int *out_delete_date)
{
	char *data;
	int base_level;
	int delete_date;
	struct Sql *sql_handle = inter->sql_handle_get();

	if(SQL_SUCCESS != SQL->Query(sql_handle,
		"SELECT `base_level`,`delete_date` FROM `%s` WHERE `char_id`='%d'",
		char_db, char_id)
	|| SQL_SUCCESS != SQL->NextRow(sql_handle)
	) {// data error
		Sql_ShowDebug(sql_handle);
		return 3; // 3: Database error
	}

	SQL->GetData(sql_handle, 0, &data, NULL); base_level = atoi(data);
	SQL->GetData(sql_handle, 1, &data, NULL); delete_date = strtoul(data, NULL, 10);
	if(out_delete_date)
		*out_delete_date = delete_date;

	if((char_del_level > 0 && base_level >= char_del_level)
	|| (char_del_level < 0 && base_level <= -char_del_level)
	) {
		// character level config restriction
		return 2; // 2: Due to system settings can not be deleted
	}
	return 1;
}

/**
 * Removes character from deletion queue.
 * @return bool success
 **/
static bool char_delete_remove_queue(int char_id)
{
	struct Sql *sql_handle = inter->sql_handle_get();
	if(SQL_SUCCESS != SQL->Query(sql_handle,
		"UPDATE `%s` SET `delete_date`='0' WHERE `char_id`='%d'", char_db, char_id)
	) {
		Sql_ShowDebug(sql_handle);
		return false;
	}
	return true;
}

/**
 * Inserts character in deletion queue.
 * @return chr->delete2_ack result
 **/
static int char_delete_insert_queue(int char_id, time_t *delete_timestamp)
{
	char *data;
	time_t delete_date;
	struct Sql *sql_handle = inter->sql_handle_get();

	if(SQL_SUCCESS != SQL->Query(sql_handle,
		"SELECT `delete_date` FROM `%s` WHERE `char_id`='%d'", char_db, char_id)
	|| SQL_SUCCESS != SQL->NextRow(sql_handle)
	) {
		Sql_ShowDebug(sql_handle);
		return 3; // 3: A database error occurred
	}

	SQL->GetData(sql_handle, 0, &data, NULL);
	delete_date = strtoul(data, NULL, 10);
	if(delete_date) {// character already queued for deletion
		SQL->FreeResult(sql_handle);
		return 0; // 0: An unknown error occurred
	}

	// This check is imposed by Aegis to avoid dead entries in databases
	// _it is not needed_ as we clear data properly
	// see issue: 7338
	if(char_aegis_delete) {
		int party_id = 0, guild_id = 0;
		if(SQL_SUCCESS != SQL->Query(sql_handle,
			"SELECT `party_id`, `guild_id` FROM `%s` WHERE `char_id`='%d'", char_db, char_id)
		|| SQL_SUCCESS != SQL->NextRow(sql_handle)
		) {
			Sql_ShowDebug(sql_handle);
			return 3; // 3: A database error occurred
		}
		SQL->GetData(sql_handle, 0, &data, NULL); party_id = atoi(data);
		SQL->GetData(sql_handle, 1, &data, NULL); guild_id = atoi(data);
		SQL->FreeResult(sql_handle);
		if(guild_id)
			return 4; // 4: To delete a character you must withdraw from the guild
		if(party_id)
			return 5; // 5: To delete a character you must withdraw from the party
	}

	// Success
	delete_date = time(NULL)+char_del_delay;

	if(SQL_SUCCESS != SQL->Query(sql_handle,
		"UPDATE `%s` SET `delete_date`='%lu' WHERE `char_id`='%d'",
		char_db, (unsigned long)delete_date, char_id)
	) {
		Sql_ShowDebug(sql_handle);
		return 3; // 3: A database error occurred
	}
	*delete_timestamp = delete_date;
	return 1;
}

static void char_send_account_id(struct socket_data *session, int account_id)
{
	WFIFOHEAD(session, 4, true);
	WFIFOL(session, 0) = account_id;
	WFIFOSET2(session, 4);
}

/**
 * Authenticates a connection request from a client
 *
 * @see chclif_parse_enter
 * @retval NBE_SUCCESS successful first step of authentication
 *
 * Acquires db_lock(auth_db);
 **/
static enum notify_ban_errorcode char_auth(struct socket_data *session, struct char_session_data *sd,
	int ipl
) {
	db_lock(auth_db, WRITE_LOCK);
	struct char_auth_node *node = idb_get(auth_db, sd->account_id);
	if(!node) {
		db_unlock(auth_db);
		// Authentication not found (coming from login server)
		if(!chr->login_session)
			return NBE_SERVER_CLOSED;
		loginif->auth(session->id, sd, ipl);
	} else {
		if(node->read_flag == true) { // This node is in another auth step
			db_unlock(auth_db);
			return NBE_TIME_GAP;
		}
		// Coming from map-server (after ZW_CHAR_SELECT_REQ)
		if(node->account_id != sd->account_id
		|| node->login_id1  != sd->login_id1
		|| node->login_id2  != sd->login_id2
		|| node->ip         != ipl
		) {
			// Authentication mismatch, deny connection
			db_unlock(auth_db);
			return NBE_DISCONNECTED;
		}
		enum notify_ban_errorcode temp_code = NBE_SUCCESS;
		/* restrictions apply */
		if( chr->server_type == CST_MAINTENANCE && node->group_id < char_maintenance_min_group_id )
			temp_code = NBE_SERVER_CLOSED;
		/* the client will already deny this request, this check is to avoid someone bypassing. */
		else if( chr->server_type == CST_PAYING && (time_t)node->expiration_time < time(NULL) )
			temp_code = NBE_NO_PAYING_TIME;

		idb_remove(auth_db, sd->account_id);
		db_unlock(auth_db);

		if(temp_code != NBE_SUCCESS)
			return temp_code;
		chr->auth_ok(session, sd);
	}

	mutex->lock(session->mutex);
	socket_io->session_update_parse(session, chclif->parse);
	mutex->unlock(session->mutex);
	return NBE_SUCCESS;
}

/**
 * PACKET_HC_NOTIFY_ZONESVR
 * Notifies client of the map-server available for connection (after character selection)
 **/
static void char_send_map_info(struct socket_data *session,
	uint32 subnet_map_ip, uint32 map_ip, uint16 map_port,
	int char_id, const struct point *last_point, char *dnsHost
) {
#if PACKETVER < 20170329
	const int cmd = 0x71;
	const int len = 28;
#else
	const int cmd = 0xac5;
	const int len = 156;
#endif
	WFIFOHEAD(session, len, true);
	WFIFOW(session, 0) = cmd;
	WFIFOL(session, 2) = char_id;
	mapindex->getmapname_ext(mapindex_id2name(last_point->map), WFIFOP(session, 6));
	WFIFOL(session, 22) = htonl((subnet_map_ip) ? subnet_map_ip : map_ip);
	WFIFOW(session, 26) = socket_io->ntows(htons(map_port)); // [!] LE byte order here [!]
#if PACKETVER >= 20170329
	if (dnsHost != NULL) {
		safestrncpy(WFIFOP(session, 28), dnsHost, 128);
	} else {
		memset(WFIFOP(session, 28), 0, 128);
	}
#endif
	WFIFOSET(session, len);
}

/**
 * HC_NOTIFY_ACCESSIBLE_MAPNAME
 * Forces char-selection window respawn
 **/
static void char_send_wait_char_server(struct socket_data *session)
{
	WFIFOHEAD(session, 24, true);
	WFIFOW(session, 0) = 0x840;
	WFIFOW(session, 2) = 24;
	safestrncpy(WFIFOP(session,4), "0", 20);/* we can't send empty (otherwise the list will pop up) */
	WFIFOSET(session, 24);
}

/**
 * Returns the first map-server found with a major city
 * @return map-server id
 **/
static int char_search_default_maps_mapserver(struct point *last_point)
{
	int i;
	int j;

	if ((i = chr->search_mapserver((j=mapindex->name2id(MAP_PRONTERA)),-1,-1)) >= 0) {
		last_point->x = 273;
		last_point->y = 354;
	} else if ((i = chr->search_mapserver((j=mapindex->name2id(MAP_GEFFEN)),-1,-1)) >= 0) {
		last_point->x = 120;
		last_point->y = 100;
	} else if ((i = chr->search_mapserver((j=mapindex->name2id(MAP_MORROC)),-1,-1)) >= 0) {
		last_point->x = 160;
		last_point->y = 94;
	} else if ((i = chr->search_mapserver((j=mapindex->name2id(MAP_ALBERTA)),-1,-1)) >= 0) {
		last_point->x = 116;
		last_point->y = 57;
	} else if ((i = chr->search_mapserver((j=mapindex->name2id(MAP_PAYON)),-1,-1)) >= 0) {
		last_point->x = 87;
		last_point->y = 117;
	} else if ((i = chr->search_mapserver((j=mapindex->name2id(MAP_IZLUDE)),-1,-1)) >= 0) {
		last_point->x = 94;
		last_point->y = 103;
	}
	if (i >= 0)
	{
		last_point->map = j;
		ShowWarning("Unable to find map-server for '%s', sending to major city '%s'.\n",
			mapindex_id2name(last_point->map), mapindex_id2name(j));
	}
	return i;
}

/**
 * Returns appropriate map-server id for the provided character
 *  When the owner of the last_map is not online an owner of a major city is returned.
 * @realock chr->map_server_list_lock
 * @retval -1 No map-server found.
 * @retval -2 No map-server with a major city found.
 **/
static int char_get_map_server(struct point *last_point)
{
	int server_id;

	server_id = chr->search_mapserver(last_point->map, -1, -1);
	if(server_id != -1)
		return server_id;
	if(!INDEX_MAP_COUNT(chr->map_server_list))
		return -1;

	server_id = chr->search_default_maps_mapserver(last_point);
	if(server_id == -1)
		return -2;

	return server_id;
}

/**
 * Logs selection of provided character in database
 *
 * @remarks Only inserts if logging is enabled
 **/
static void char_log_select(struct mmo_charstatus *cd, int slot)
{
	if(!chr->enable_logs)
		return;

	struct Sql *sql_handle = inter->sql_handle_get();

	if(SQL_ERROR == SQL->Query(sql_handle,
				"INSERT INTO `%s`("
				" `time`, `char_msg`, `account_id`, `char_id`, `char_num`, `class`, `name`,"
				" `str`, `agi`, `vit`, `int`, `dex`, `luk`,"
				" `hair`, `hair_color`"
				") VALUES ("
				" NOW(), 'char select', '%d', '%d', '%d', '%d', '%s',"
				" '%d', '%d', '%d', '%d', '%d', '%d',"
				" '%d', '%d')",
				charlog_db,
				cd->account_id, cd->char_id, slot, cd->class, cd->name,
				cd->str, cd->agi, cd->vit, cd->int_, cd->dex, cd->luk,
				cd->hair, cd->hair_color
				))
		Sql_ShowDebug(sql_handle);
}

/**
 * Converts selected slot to a valid character id.
 *
 * @retval -1 Not found
 **/
static int char_slot2id(int account_id, int slot)
{
	char *data;
	int char_id;
	struct Sql *sql_handle = inter->sql_handle_get();

	if(SQL_SUCCESS != SQL->Query(sql_handle,
		"SELECT `char_id` FROM `%s` WHERE `account_id`='%d' AND `char_num`='%d'",
		char_db, account_id, slot)
	 || SQL_SUCCESS != SQL->NextRow(sql_handle)
	 || SQL_SUCCESS != SQL->GetData(sql_handle, 0, &data, NULL)
	) {
		Sql_ShowDebug(sql_handle);
		char_id = -1;
	} else
		char_id = atoi(data);
	SQL->FreeResult(sql_handle);
	return char_id;
}

/**
 * Creates an authentication entry in 'auth_db'
 *
 * @see auth_db
 **/
static void char_create_auth_entry(struct char_session_data *sd, int char_id, int ipl, bool changing_map_servers)
{
	struct char_auth_node *node;
	CREATE(node, struct char_auth_node, 1);
	node->account_id           = sd->account_id;
	node->char_id              = char_id;
	node->login_id1            = sd->login_id1;
	node->login_id2            = sd->login_id2;
	node->sex                  = sd->sex;
	node->expiration_time      = sd->expiration_time;
	node->group_id             = sd->group_id;
	node->ip                   = ipl;
	node->changing_mapservers  = changing_map_servers;
	node->read_flag            = false;

	db_lock(auth_db, WRITE_LOCK);
	idb_put(auth_db, sd->account_id, node);
	db_unlock(auth_db);
}

static void char_creation_failed(struct socket_data *session, enum refuse_make_char_errorcode result)
{
	WFIFOHEAD(session, 3, true);
	WFIFOW(session, 0) = 0x6e;
	WFIFOB(session, 2) = (uint8)result;
	WFIFOSET(session,3);
}

static void char_creation_ok(struct socket_data *session, struct mmo_charstatus *char_dat)
{
	int len;

	// send to player
	WFIFOHEAD(session,2+MAX_CHAR_BUF, true);
	WFIFOW(session,0) = 0x6d;
	len = 2 + chr->mmo_char_tobuf(WFIFOP(session,2), char_dat);
	WFIFOSET(session,len);
}

// flag:
// 0 = Incorrect Email address
static void char_delete_char_failed(struct socket_data *session, int flag)
{
	WFIFOHEAD(session,3,true);
	WFIFOW(session,0) = 0x70;
	WFIFOB(session,2) = flag;
	WFIFOSET(session,3);
}

static void char_delete_char_ok(struct socket_data *session)
{
	WFIFOHEAD(session,2, true);
	WFIFOW(session,0) = 0x6f;
	WFIFOSET(session,2);
}

static void char_parse_char_ping(struct s_receive_action_data *act)
{
	RFIFOSKIP(act,6);
}

static void char_allow_rename(struct socket_data *session, int flag)
{
	WFIFOHEAD(session, 4, true);
	WFIFOW(session,0) = 0x28e;
	WFIFOW(session,2) = flag;
	WFIFOSET(session,4);
}

static void char_rename_char_ack(struct socket_data *session, int flag)
{
	WFIFOHEAD(session, 4, true);
	WFIFOW(session,0) = 0x290;
	WFIFOW(session,2) = flag;
	WFIFOSET(session,4);
}

static void char_captcha_notsupported(struct socket_data *session)
{
	WFIFOHEAD(session,5,true);
	WFIFOW(session,0) = 0x7e9;
	WFIFOW(session,2) = 5;
	WFIFOB(session,4) = 1;
	WFIFOSET(session,5);
}

STATIC_ASSERT(sizeof(int32) >= sizeof(void*),
	"Map-server id is defined in session->session_data without allocating any "
	"memory via a direct assignment and this relies in the sizeof(void*) being "
	"at least the same as sizeof(int32), if your compiler doesn't support it "
	"then an allocation should be made. See char_parse_char_login_map_server "
	"and mapif_server_find.");

/**
 * 0x2af8 ZW_MAP_AUTH
 * Parses map-server authentication request
 **/
static void char_parse_char_login_map_server(struct s_receive_action_data *act, uint32 ipl)
{
	char l_user[24], l_pass[24];
	safestrncpy(l_user, RFIFOP(act,2), 24);
	safestrncpy(l_pass, RFIFOP(act,26), 24);


	if (core->runflag != CHARSERVER_ST_RUNNING ||
		strcmp(l_user, chr->userid) != 0 ||
		strcmp(l_pass, chr->passwd) != 0 ||
		!socket_io->allowed_ip_check(ipl))
	{
		mapif->login_map_server_ack(act->session, 3); // Failure
		socket_io->session_disconnect_guard(act->session);
		return;
	}
	mapif->login_map_server_ack(act->session, 0); // Success

	struct mmo_map_server *server = mapif->on_connect(act->session, 
	                                                  ntohl(RFIFOL(act,54)),
	                                                  ntohs(RFIFOW(act,58)));
	chr->mapif_init(act->session);

	mutex->lock(act->session->mutex);

	socket_io->session_update_parse(act->session, chr->parse_frommap);
	act->session->flag.server = 1;
	act->session->flag.validate = 0;
	action->queue_set(act->session, server->queue_index);

	act->session->session_data = aMalloc(sizeof(server->pos));

	act->session->session_data = (void*)server->pos;

	mutex->unlock(act->session->mutex);

	socket_io->datasync(act, true);

	RFIFOSKIP(act,60);
}

static void char_change_character_slot_ack(struct socket_data *session, bool ret)
{
	WFIFOHEAD(session, 8, true);
	WFIFOW(session, 0) = 0x8d5;
	WFIFOW(session, 2) = 8;
	WFIFOW(session, 4) = ret?0:1;
	WFIFOW(session, 6) = 0;/* we enforce it elsewhere, go 0 */
	WFIFOSET(session, 8);
}

static void char_parse_char_move_character(struct s_receive_action_data *act, struct char_session_data *sd)
{
	bool ret = chr->char_slotchange(sd, act->session, RFIFOW(act, 2), RFIFOW(act, 4));
	chr->change_character_slot_ack(act->session, ret);
	/* for some stupid reason it requires the char data again (gravity -_-) */
	if( ret )
#if PACKETVER_MAIN_NUM >= 20130522 || PACKETVER_RE_NUM >= 20130327 || defined(PACKETVER_ZERO)
		chr->send_HC_ACK_CHARINFO_PER_PAGE(act->session, sd);
#else
		chr->mmo_char_send_characters(act->session, sd);
#endif
	RFIFOSKIP(act, 8);
}

/**
 * Performs player disconnection.
 * Removes character from online_char_db and sets offline for all map-servers, 
 * then marks session for removal via socket_io->session_disconnect.
 * Called before processing a new action.
 * @mutex session->mutex
 * @see chclif->parse
 * Acquires db_lock(chr->online_char_db)
 **/
static void char_disconnect(struct socket_data *session, struct char_session_data *sd)
{
	if(sd != NULL && sd->auth) {
		// already authed client
		db_lock(chr->online_char_db, WRITE_LOCK);
		struct online_char_data* data = idb_get(chr->online_char_db, sd->account_id);
		if( data != NULL && data->session_id == session->id)
			data->session_id = -1;
		if( data == NULL || data->server == -1) //If it is not in any server, send it offline. [Skotlex]
			chr->set_char_offline(-1, sd->account_id);
		db_unlock(chr->online_char_db);
	}
	if(sd && sd->rename)
		aFree(sd->rename);

	socket_io->session_disconnect(session);
}

/**
 * Parses new connections to the server (main processing entry point)
 **/
static enum parsefunc_rcode char_parse_entry(struct s_receive_action_data *act)
{
	mutex->lock(act->session->mutex);
	uint32 ipl = act->session->client_addr;
	if(socket_io->session_marked_removal(act->session)
	|| !chr->login_session // Deny any new connection authentication requests if no login-server
	) {
		socket_io->session_disconnect(act->session);
		mutex->unlock(act->session->mutex);
		return PACKET_VALID;
	}
	mutex->unlock(act->session->mutex);

	if(RFIFOREST(act) < 2)
		return PACKET_INCOMPLETE;

	unsigned short cmd = RFIFOW(act, 0);
	// Only authentication packets
	switch(cmd) {
		// Client connection request
		case 0x065:
			if(RFIFOREST(act) < 17)
				return PACKET_INCOMPLETE;
			chclif->parse_enter(act, ipl);
			break;
		// Map-server connection request
		case 0x2af8:
			if(RFIFOREST(act) < 60)
				return PACKET_INCOMPLETE;
			chr->parse_char_login_map_server(act, ipl);
			break;
		default:
			ShowError("char_parse_entry: Received unknown packet "
				CL_WHITE"0x%x"CL_RESET" from ip '"CL_WHITE"%s"CL_RESET"'! "
				"Disconnecting!\n", cmd, ipl);
			socket_io->session_disconnect_guard(act->session);
			return PACKET_UNKNOWN;
	}
	// Avoid processing of follow-up packets here
	if(RFIFOREST(act) != 0)
		return PACKET_INCOMPLETE;
	return PACKET_VALID;
}

/**
 * Broadcasts current online count to login-server
 * @see TimerFunc
 * @see loginif->send_users_count
 * @see mapif->send_users_count
 **/
static int char_broadcast_user_count(struct timer_interface *tm, int tid, int64 tick, int id, intptr_t data)
{
	int users = chr->count_users();

	// only send an update when needed
	static int prev_users = 0;
	if( prev_users == users )
		return 0;
	prev_users = users;

	if(chr->login_session) {
		loginif->send_users_count(users);
	}

	mapif->send_users_count(users);

	return 0;
}

/**
 * Checks if login-server is connected, if not tries to connect and authenticate
 * @see loginif->connect_to_server
 * @see TimerFunc
 **/
static int char_check_connect_login_server(struct timer_interface *tm, int tid, int64 tick, int id, intptr_t data)
{
	if(chr->login_session)
		return 0;

	ShowInfo("Attempt to connect to login-server...\n");

	chr->login_session = socket_io->make_connection(login_ip, login_port, NULL);
	if(!chr->login_session)
		return 0;

	socket_io->session_update_parse(chr->login_session, loginif->parse);
	chr->login_session->flag.server = 1;
	chr->login_session->flag.validate = 0;

	loginif->connect_to_server(); // Ask nicely for authentication
	mutex->unlock(chr->login_session->mutex);

	return 1;
}

/* ==================================
 * Configuration parsing
 */

/**
 * Reads the 'inter_configuration' config file and initializes required variables.
 *
 * @param filename Path to configuration file
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool char_sql_config_read(const char *filename, bool imported)
{
	struct config_t config;
	const struct config_setting_t *setting = NULL;
	const char *import = NULL;
	bool retval = true;

	nullpo_retr(false, filename);

	if (!libconfig->load_file(&config, filename))
		return false; // Error message is already shown by libconfig->load_file

	if ((setting = libconfig->lookup(&config, "inter_configuration/database_names")) == NULL) {
		libconfig->destroy(&config);
		if (imported)
			return true;
		ShowError("sql_config_read: inter_configuration/database_names was not found in %s!\n", filename);
		return false;
	}
	libconfig->setting_lookup_mutable_string(setting, "char_db", char_db, sizeof(char_db));
	libconfig->setting_lookup_mutable_string(setting, "interlog_db", interlog_db, sizeof(interlog_db));
	libconfig->setting_lookup_mutable_string(setting, "ragsrvinfo_db", ragsrvinfo_db, sizeof(ragsrvinfo_db));

	if (!chr->sql_config_read_registry(filename, &config, imported))
		retval = false;
	if (!chr->sql_config_read_pc(filename, &config, imported))
		retval = false;
	if (!chr->sql_config_read_guild(filename, &config, imported))
		retval = false;

	ShowInfo("Done reading %s.\n", filename);
	// import should overwrite any previous configuration, so it should be called last
	if (libconfig->lookup_string(&config, "import", &import) == CONFIG_TRUE) {
		if (strcmp(import, filename) == 0 || strcmp(import, chr->SQL_CONF_NAME) == 0) {
			ShowWarning("sql_config_read: Loop detected in %s! Skipping 'import'...\n", filename);
		} else {
			if (!chr->sql_config_read(import, true))
				retval = false;
		}
	}

	if (!HPM->parse_conf(&config, filename, HPCT_CHAR_INTER, imported))
		retval = false;

	libconfig->destroy(&config);
	return retval;
}

/**
 * Reads the 'inter_configuration/database_names/registry' config entry and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool char_sql_config_read_registry(const char *filename, const struct config_t *config, bool imported)
{
	const struct config_setting_t *setting = NULL;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "inter_configuration/database_names/registry")) == NULL) {
		if (imported)
			return true;
		ShowError("sql_config_read: inter_configuration/database_names/registry was not found in %s!\n", filename);
		return false;
	}
	// Not all registries are read by char-server
	libconfig->setting_lookup_mutable_string(setting, "char_reg_num_db", char_reg_num_db, sizeof(char_reg_num_db));
	libconfig->setting_lookup_mutable_string(setting, "char_reg_str_db", char_reg_str_db, sizeof(char_reg_str_db));
	libconfig->setting_lookup_mutable_string(setting, "acc_reg_str_db", acc_reg_str_db, sizeof(acc_reg_str_db));
	libconfig->setting_lookup_mutable_string(setting, "acc_reg_num_db", acc_reg_num_db, sizeof(acc_reg_num_db));

	return true;
}

/**
 * Reads the 'inter_configuration/database_names/pc' config entry and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool char_sql_config_read_pc(const char *filename, const struct config_t *config, bool imported)
{
	const struct config_setting_t *setting = NULL;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "inter_configuration/database_names/pc")) == NULL) {
		if (imported)
			return true;
		ShowError("sql_config_read: inter_configuration/database_names/pc was not found in %s!\n", filename);
		return false;
	}
	libconfig->setting_lookup_mutable_string(setting, "hotkey_db", hotkey_db, sizeof(hotkey_db));
	libconfig->setting_lookup_mutable_string(setting, "scdata_db", scdata_db, sizeof(scdata_db));
	libconfig->setting_lookup_mutable_string(setting, "inventory_db", inventory_db, sizeof(inventory_db));
	libconfig->setting_lookup_mutable_string(setting, "achievement_db", char_achievement_db, sizeof(char_achievement_db));
	libconfig->setting_lookup_mutable_string(setting, "cart_db", cart_db, sizeof(cart_db));
	libconfig->setting_lookup_mutable_string(setting, "charlog_db", charlog_db, sizeof(charlog_db));
	libconfig->setting_lookup_mutable_string(setting, "storage_db", storage_db, sizeof(storage_db));
	libconfig->setting_lookup_mutable_string(setting, "skill_db", skill_db, sizeof(skill_db));
	libconfig->setting_lookup_mutable_string(setting, "memo_db", memo_db, sizeof(memo_db));
	libconfig->setting_lookup_mutable_string(setting, "party_db", party_db, sizeof(party_db));
	libconfig->setting_lookup_mutable_string(setting, "pet_db", pet_db, sizeof(pet_db));
	libconfig->setting_lookup_mutable_string(setting, "friend_db", friend_db, sizeof(friend_db));
	libconfig->setting_lookup_mutable_string(setting, "mail_db", mail_db, sizeof(mail_db));
	libconfig->setting_lookup_mutable_string(setting, "auction_db", auction_db, sizeof(auction_db));
	libconfig->setting_lookup_mutable_string(setting, "quest_db", quest_db, sizeof(quest_db));
	libconfig->setting_lookup_mutable_string(setting, "homunculus_db", homunculus_db, sizeof(homunculus_db));
	libconfig->setting_lookup_mutable_string(setting, "skill_homunculus_db", skill_homunculus_db, sizeof(skill_homunculus_db));
	libconfig->setting_lookup_mutable_string(setting, "mercenary_db", mercenary_db, sizeof(mercenary_db));
	libconfig->setting_lookup_mutable_string(setting, "mercenary_owner_db", mercenary_owner_db, sizeof(mercenary_owner_db));
	libconfig->setting_lookup_mutable_string(setting, "elemental_db", elemental_db, sizeof(elemental_db));
	libconfig->setting_lookup_mutable_string(setting, "account_data_db", account_data_db, sizeof(account_data_db));

	return true;
}

/**
 * Reads the 'inter_configuration/database_names/guild' config entry and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool char_sql_config_read_guild(const char *filename, const struct config_t *config, bool imported)
{
	const struct config_setting_t *setting = NULL;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "inter_configuration/database_names/guild")) == NULL) {
		if (imported)
			return true;
		ShowError("sql_config_read: inter_configuration/database_names/guild was not found in %s!\n", filename);
		return false;
	}

	libconfig->setting_lookup_mutable_string(setting, "main_db", guild_db, sizeof(guild_db));
	libconfig->setting_lookup_mutable_string(setting, "alliance_db", guild_alliance_db, sizeof(guild_alliance_db));
	libconfig->setting_lookup_mutable_string(setting, "castle_db", guild_castle_db, sizeof(guild_castle_db));
	libconfig->setting_lookup_mutable_string(setting, "expulsion_db", guild_expulsion_db, sizeof(guild_expulsion_db));
	libconfig->setting_lookup_mutable_string(setting, "member_db", guild_member_db, sizeof(guild_member_db));
	libconfig->setting_lookup_mutable_string(setting, "skill_db", guild_skill_db, sizeof(guild_skill_db));
	libconfig->setting_lookup_mutable_string(setting, "position_db", guild_position_db, sizeof(guild_position_db));
	libconfig->setting_lookup_mutable_string(setting, "storage_db", guild_storage_db, sizeof(guild_storage_db));

	return true;
}

/**
 * Reads the 'char_configuration' config file and initializes required variables.
 *
 * @param filename Path to configuration file.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool char_config_read(const char *filename, bool imported)
{
	struct config_t config;
	const char *import = NULL;
	bool retval = true;

	nullpo_retr(false, filename);

	if (!libconfig->load_file(&config, filename))
		return false; // Error message is already shown by libconfig->load_file

	if (!chr->config_read_top(filename, &config, imported))
		retval = false;
	if (!chr->config_read_inter(filename, &config, imported))
		retval = false;
	if (!chr->config_read_permission(filename, &config, imported))
		retval = false;
	if (!chr->config_read_player(filename, &config, imported))
		retval = false;
	if (!chr->config_read_console(filename, &config, imported))
		retval = false;
	if (!chr->config_read_database(filename, &config, imported))
		retval = false;
	if (!inter->config_read_connection(filename, &config, imported))
		retval = false;
	if (!pincode->config_read(filename, &config, imported))
		retval = false;

	if (!HPM->parse_conf(&config, filename, HPCT_CHAR, imported))
		retval = false;

	ShowInfo("Done reading %s.\n", filename);

	// import should overwrite any previous configuration, so it should be called last
	if (libconfig->lookup_string(&config, "import", &import) == CONFIG_TRUE) {
		if (strcmp(import, filename) == 0 || strcmp(import, chr->CHAR_CONF_NAME) == 0) {
			ShowWarning("char_config_read: Loop detected in %s! Skipping 'import'...\n", filename);
		} else {
			if (!chr->config_read(import, true))
				retval = false;
		}
	}

	libconfig->destroy(&config);
	return retval;
}

/**
 * Reads the 'char_configuration' top level config entry and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool char_config_read_top(const char *filename, const struct config_t *config, bool imported)
{
	const struct config_setting_t *setting = NULL;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "char_configuration")) == NULL) {
		if (imported)
			return true;
		ShowError("char_config_read: char_configuration was not found in %s!\n", filename);
		return false;
	}

	// char_configuration/server_name
	if (libconfig->setting_lookup_mutable_string(setting, "server_name", chr->server_name, sizeof(chr->server_name)) == CONFIG_TRUE) {
		ShowInfo("server name %s\n", chr->server_name);
	} else if (!imported) {
		ShowWarning("char_config_read: server_name was not set! Defaulting to 'Hercules'.\n");
		safestrncpy(chr->server_name, "Hercules", sizeof(chr->server_name));
	}
	// char_configuration/wisp_server_name
	if (libconfig->setting_lookup_mutable_string(setting, "wisp_server_name", wisp_server_name, sizeof(wisp_server_name)) == CONFIG_TRUE) {
		// wisp_server_name should _always_ be equal or bigger than 4 characters!
		if (strlen(wisp_server_name) < 4) { // TODO: This length should be a #define (i.e. MIN_NAME_LENGTH)
			ShowWarning("char_config_read: char_configuration/wisp_server_name is too small! Defaulting to: Server.\n");
			safestrncpy(chr->server_name, "Server", sizeof(chr->server_name));
		}
	}
	// char_configuration/guild_exp_rate
	libconfig->setting_lookup_int(setting, "guild_exp_rate", &guild_exp_rate);

	return true;
}

/**
 * Reads the 'char_configuration/inter' config entry and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool char_config_read_inter(const char *filename, const struct config_t *config, bool imported)
{
	const struct config_setting_t *setting = NULL;
	const char *str = NULL;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "char_configuration/inter")) == NULL) {
		if (imported)
			return true;
		ShowError("char_config_read: char_configuration/inter was not found in %s!\n", filename);
		return false;
	}

	// Login information
	libconfig->setting_lookup_mutable_string(setting, "userid", chr->userid, sizeof(chr->userid));
	libconfig->setting_lookup_mutable_string(setting, "passwd", chr->passwd, sizeof(chr->passwd));

	// Login-server and character-server information
	if (libconfig->setting_lookup_string(setting, "login_ip", &str) == CONFIG_TRUE)
		chr->config_set_ip("Login server", str, &login_ip, login_ip_str);

	if (libconfig->setting_lookup_string(setting, "char_ip", &str) == CONFIG_TRUE)
		chr->config_set_ip("Character server", str, &chr->ip, char_ip_str);

	if (libconfig->setting_lookup_string(setting, "bind_ip", &str) == CONFIG_TRUE)
		chr->config_set_ip("Character server binding", str, &bind_ip, bind_ip_str);

	libconfig->setting_lookup_uint16(setting, "login_port", &login_port);
	libconfig->setting_lookup_uint16(setting, "char_port", &chr->port);

	return true;
}

/**
 * Reads the 'char_configuration/database' config entry and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool char_config_read_database(const char *filename, const struct config_t *config, bool imported)
{
	const struct config_setting_t *setting = NULL;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "char_configuration/database")) == NULL) {
		if (imported)
			return true;
		ShowError("char_config_read: char_configuration/database was not found in %s!\n", filename);
		return false;
	}
	if (libconfig->setting_lookup_int(setting, "autosave_time", &autosave_interval) == CONFIG_TRUE) {
		autosave_interval *= 1000;
		if (autosave_interval <= 0)
			autosave_interval = DEFAULT_AUTOSAVE_INTERVAL;
	}
	libconfig->setting_lookup_mutable_string(setting, "db_path", chr->db_path, sizeof(chr->db_path));
	libconfig->set_db_path(chr->db_path);
	libconfig->setting_lookup_bool_real(setting, "log_char", &chr->enable_logs);
	return true;
}

/**
 * Reads the 'char_configuration/console' config entry and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool char_config_read_console(const char *filename, const struct config_t *config, bool imported)
{
	const struct config_setting_t *setting;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "char_configuration/console")) == NULL) {
		if (imported)
			return true;
		ShowError("char_config_read: char_configuration/console was not found in %s!\n", filename);
		return false;
	}
	libconfig->setting_lookup_bool_real(setting, "stdout_with_ansisequence", &showmsg->stdout_with_ansisequence);
	libconfig->setting_lookup_bool_real(setting, "save_log", &chr->show_save_log);
	if (libconfig->setting_lookup_int(setting, "console_silent", &showmsg->silent) == CONFIG_TRUE) {
		if (showmsg->silent) // only bother if its actually enabled
			ShowInfo("Console Silent Setting: %d\n", showmsg->silent);
	}
	libconfig->setting_lookup_mutable_string(setting, "timestamp_format", showmsg->timestamp_format, sizeof(showmsg->timestamp_format));

	return true;
}

/**
 * Reads the 'char_configuration/player' config entry and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool char_config_read_player(const char *filename, const struct config_t *config, bool imported)
{
	bool retval = true;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if (!chr->config_read_player_new(filename, config, imported))
		retval = false;
	if (!chr->config_read_player_name(filename, config, imported))
		retval = false;
	if (!chr->config_read_player_deletion(filename, config, imported))
		retval = false;
	if (!chr->config_read_player_fame(filename, config, imported))
		retval = false;

	return retval;
}

/**
 * Reads the 'char_configuration/player/fame' config entry and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool char_config_read_player_fame(const char *filename, const struct config_t *config, bool imported)
{
	const struct config_setting_t *setting = NULL;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "char_configuration/player/fame")) == NULL) {
		if (imported)
			return true;
		ShowError("char_config_read: char_configuration/player/fame was not found in %s!\n", filename);
		return false;
	}

	libconfig->setting_lookup_int(setting, "alchemist", &fame_list_size_chemist);
	if (fame_list_size_chemist > MAX_FAME_LIST) {
		ShowWarning("Max fame list size is %d (fame_list_alchemist)\n", MAX_FAME_LIST);
		fame_list_size_chemist = MAX_FAME_LIST;
	}

	libconfig->setting_lookup_int(setting, "blacksmith", &fame_list_size_smith);
	if (fame_list_size_smith > MAX_FAME_LIST) {
		ShowWarning("Max fame list size is %d (fame_list_blacksmith)\n", MAX_FAME_LIST);
		fame_list_size_smith = MAX_FAME_LIST;
	}

	libconfig->setting_lookup_int(setting, "taekwon", &fame_list_size_taekwon);
	if (fame_list_size_taekwon > MAX_FAME_LIST) {
		ShowWarning("Max fame list size is %d (fame_list_taekwon)\n", MAX_FAME_LIST);
		fame_list_size_taekwon = MAX_FAME_LIST;
	}

	return true;
}

/**
 * Reads the 'char_configuration/player/deletion' config entry and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool char_config_read_player_deletion(const char *filename, const struct config_t *config, bool imported)
{
	const struct config_setting_t *setting = NULL;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "char_configuration/player/deletion")) == NULL) {
		if (imported)
			return true;
		ShowError("char_config_read: char_configuration/player/deletion was not found in %s!\n", filename);
		return false;
	}
	libconfig->setting_lookup_int(setting, "level", &char_del_level);
	libconfig->setting_lookup_int(setting, "delay", &char_del_delay);
	libconfig->setting_lookup_bool_real(setting, "use_aegis_delete", &char_aegis_delete);

	return true;
}

/**
 * Reads the 'char_configuration/player/name' config entry and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool char_config_read_player_name(const char *filename, const struct config_t *config, bool imported)
{
	const struct config_setting_t *setting = NULL;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "char_configuration/player/name")) == NULL) {
		if (imported)
			return true;
		ShowError("char_config_read: char_configuration/player/name was not found in %s!\n", filename);
		return false;
	}
	libconfig->setting_lookup_mutable_string(setting, "unknown_char_name", unknown_char_name, sizeof(unknown_char_name));
	libconfig->setting_lookup_mutable_string(setting, "name_letters", char_name_letters, sizeof(char_name_letters));
	libconfig->setting_lookup_int(setting, "name_option", &char_name_option);
	libconfig->setting_lookup_bool_real(setting, "name_ignoring_case", &name_ignoring_case);
	libconfig->setting_lookup_bool_real(setting, "use_aegis_rename", &char_aegis_rename);

	return true;
}

/**
 * Defines start_items based on '(...)/player/new/start_item'.
 *
 * @param setting The already retrieved start_item setting.
 */
static void char_config_set_start_item(const struct config_setting_t *setting)
{
	int i, count;

	nullpo_retv(setting);

	VECTOR_CLEAR(start_items);

	count = libconfig->setting_length(setting);
	if (!count)
		return;

	VECTOR_ENSURE(start_items, count, 1);

	for (i = 0; i < count; i++) {
		const struct config_setting_t *t = libconfig->setting_get_elem(setting, i);
		struct start_item_s start_item = { 0 };

		if (t == NULL)
			continue;

		if (libconfig->setting_lookup_int(t, "id", &start_item.id) != CONFIG_TRUE) {
			ShowWarning("char_config_read: entry (%d) is missing id! Ignoring...\n", i);
			continue;
		}
		if (libconfig->setting_lookup_int(t, "amount", &start_item.amount) != CONFIG_TRUE) {
			ShowWarning("char_config_read: entry (%d) is missing amount! Defaulting to 1...\n", i);
			start_item.amount = 1;
		}
		if (libconfig->setting_lookup_bool_real(t, "stackable", &start_item.stackable) != CONFIG_TRUE) {
			// Without knowing if the item is stackable or not we can't add it!
			ShowWarning("char_config_read: entry (%d) is missing stackable! Ignoring...\n", i);
			continue;
		}
		if (libconfig->setting_lookup_int(t, "loc", &start_item.loc) != CONFIG_TRUE)
			start_item.loc = 0;
		VECTOR_PUSH(start_items, start_item);
	}
}

/**
 * Reads the 'char_configuration/player/new' config entry and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool char_config_read_player_new(const char *filename, const struct config_t *config, bool imported)
{
	const struct config_setting_t *setting = NULL, *setting2 = NULL;
#ifdef RENEWAL
	const char *start_point_setting = "start_point_re";
#else
	const char *start_point_setting = "start_point_pre";
#endif
	int64 i64 = 0;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "char_configuration/player/new")) == NULL) {
		if (imported)
			return true;
		ShowError("char_config_read: char_configuration/player/new was not found in %s!\n", filename);
		return false;
	}

	if (libconfig->setting_lookup_int64(setting, "zeny", &i64) == CONFIG_TRUE) {
		if (i64 > MAX_ZENY) {
			ShowWarning("char_config_read: player/new/zeny is too big! Capping to MAX_ZENY.\n");
			start_zeny = MAX_ZENY;
		} else {
			start_zeny = (int)i64;
		}
	}

	if ((setting2 = libconfig->setting_get_member(setting, "start_items")))
		chr->config_set_start_item(setting2);

	// start_point / start_point_pre
	if ((setting2 = libconfig->setting_get_member(setting, start_point_setting))) {
		const char *str = NULL;
		if (libconfig->setting_lookup_string(setting2, "map", &str) == CONFIG_TRUE) {
			start_point.map = mapindex->name2id(str);
			if (start_point.map == 0)
				ShowError("char_config_read_player_new: Specified start_point %s not found in map-index cache.\n", str);
			libconfig->setting_lookup_int16(setting2, "x", &start_point.x);
			libconfig->setting_lookup_int16(setting2, "y", &start_point.y);
		}
	}

	return true;
}

/**
 * Reads the 'char_configuration/permission' config entry and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool char_config_read_permission(const char *filename, const struct config_t *config, bool imported)
{
	const struct config_setting_t *setting = NULL;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "char_configuration/permission")) == NULL) {
		if (imported)
			return true;
		ShowError("char_config_read: char_configuration/permission was not found in %s!\n", filename);
		return false;
	}

	libconfig->setting_lookup_bool_real(setting, "enable_char_creation", &enable_char_creation);
	if (libconfig->setting_lookup_int16(setting, "display_new", &chr->new_display) != CONFIG_TRUE) {
		// While normally true/false makes sense, we may accept any int16 here (it's passed as is to the client)
		int i32 = 0;
		if (libconfig->setting_lookup_bool(setting, "display_new", &i32) == CONFIG_TRUE)
			chr->new_display = i32 == 0 ? 0 : 1;
	}
	libconfig->setting_lookup_int(setting, "max_connect_user", &max_connect_user);
	libconfig->setting_lookup_int(setting, "gm_allow_group", &gm_allow_group);
	libconfig->setting_lookup_int(setting, "maintenance_min_group_id", &char_maintenance_min_group_id);
	if (libconfig->setting_lookup_int(setting, "server_type", &chr->server_type) == CONFIG_TRUE) {
		if (chr->server_type < CST_NORMAL || chr->server_type >= CST_MAX) {
			ShowWarning("char_config_read: Invalid permission/server_type %d, defaulting to CST_NORMAL.\n", chr->server_type);
			chr->server_type = CST_NORMAL;
		}
	}

	return true;
}

/**
 * Loads an IP into 'out_ip' and shows status.
 *
 * @param type[in]           String containing the type of IP being set (for logging purposes).
 * @param value[in]          New ip value to parse.
 * @param out_ip[in]         Pointer to numeric value that will be changed.
 * @param out_ip_str[in,out] Pointer to str value that will be changed (expected to be already initialized, to display previous value, if any).
 *
 * @retval false in case of error.
 */
static bool char_config_set_ip(const char *type, const char *value, uint32 *out_ip, char *out_ip_str)
{
	uint32 ip = 0;

	nullpo_retr(false, type);
	nullpo_retr(false, value);
	nullpo_retr(false, out_ip);
	nullpo_retr(false, out_ip_str);

	if ((ip = socket_io->host2ip(value)) == 0)
		return false;
	*out_ip = ip;

	ShowStatus("%s IP address : %s -> %s\n", type,
		out_ip_str[0] != '\0' ? out_ip_str : "0.0.0.0",
		socket_io->ip2str(ip, NULL));
	safestrncpy(out_ip_str, value, sizeof *out_ip_str);
	return true;
}

/**
 * Verifies if the configuration ip matches the actual server ip, for both
 * login and char-server. Corrects any difference.
 * @see loginif->parse_update_ip
 **/
static void char_config_update_ip(void)
{
	uint32 new_ip = 0;
	new_ip = socket_io->host2ip(login_ip_str);
	if(new_ip && new_ip != login_ip)
		login_ip = new_ip; //Update login ip, too.

	new_ip = socket_io->host2ip(char_ip_str);
	if(new_ip && new_ip != chr->ip) {
		//Update ip.
		chr->ip = new_ip;
		ShowInfo("Updating IP for [%s].\n", char_ip_str);
		// notify login server about the change
		chr->update_ip(chr->login_session);
	}
}

static int char_gm_allow_group_get(void)
{
	return gm_allow_group;
}

static int char_max_connect_user_get(void)
{
	return max_connect_user;
}

static int char_maintenance_min_group_id_get(void)
{
	return char_maintenance_min_group_id;
}

int do_final(void)
{
	ShowStatus("Terminating...\n");

	HPM->event(HPET_FINAL);

	chr->set_all_offline(-1);
	chr->set_all_offline_sql();

	inter->final();

	socket_io->wfifoflush_all();

	rwlock->write_lock(chr->map_server_list_lock);
	INDEX_MAP_ITER_DECL(iter);
	INDEX_MAP_ITER(chr->map_server_list, iter);
	int i;
	while((i = INDEX_MAP_NEXT(chr->map_server_list, iter)) != -1) {
		struct mmo_map_server *server;
		server = INDEX_MAP_INDEX(chr->map_server_list, i);
		if(!server)
			continue;
		mapif->server_destroy(server, false);
		aFree(server);
	}
	INDEX_MAP_ITER_FREE(iter);
	INDEX_MAP_DESTROY(chr->map_server_list);

	rwlock->write_unlock(chr->map_server_list_lock);
	rwlock->destroy(chr->map_server_list_lock);

	chclif->final();
	loginif->final();
	mapif->final();
	pincode->final();

	struct Sql *sql_handle = inter->sql_handle_get();
	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s`", ragsrvinfo_db) )
		Sql_ShowDebug(sql_handle);

	db_lock(chr->char_db_, WRITE_LOCK);
	chr->char_db_->destroy(chr->char_db_, NULL);

	db_lock(chr->online_char_db, WRITE_LOCK);
	chr->online_char_db->destroy(chr->online_char_db, NULL);

	db_lock(auth_db, WRITE_LOCK);
	auth_db->destroy(auth_db, NULL);

	mutex->destroy(fame_list_mutex);
	HPM_char_do_final();

	mapindex->final();
	inter->sql_handle_close();

	VECTOR_CLEAR(start_items);

	aFree(chr->CHAR_CONF_NAME);
	aFree(chr->NET_CONF_NAME);
	aFree(chr->SQL_CONF_NAME);
	aFree(chr->INTER_CONF_NAME);

	rwlock->destroy(skillid2idx_lock);

	HPM->event(HPET_POST_FINAL);

	ShowStatus("Finished.\n");
	return EXIT_SUCCESS;
}

//------------------------------
// Function called when the server
// has received a crash signal.
//------------------------------
void do_abort(void)
{
}

void set_server_type(void)
{
	SERVER_TYPE = SERVER_TYPE_CHAR;
}

/// Called when a terminate signal is received.
static void do_shutdown(void)
{
	if( core->runflag != CHARSERVER_ST_SHUTDOWN )
	{
		int i;
		core->runflag = CHARSERVER_ST_SHUTDOWN;
		ShowStatus("Shutting down...\n");
		// TODO proper shutdown procedure; wait for acks?, kick all characters, ... [FlavioJS]
		INDEX_MAP_ITER_DECL(iter);
		INDEX_MAP_ITER(chr->map_server_list, iter);
		while((i = INDEX_MAP_NEXT(chr->map_server_list, iter)) != -1) {
			struct mmo_map_server *cur = INDEX_MAP_INDEX(chr->map_server_list, i);
			if(!cur)
				continue;
			mapif->server_reset(cur);
		}
		INDEX_MAP_ITER_FREE(iter);

		loginif->check_shutdown();
		socket_io->wfifoflush_all();
		core->runflag = CORE_ST_STOP;
	}
}

/**
 * --char-config handler
 *
 * Overrides the default char configuration file.
 * @see cmdline->exec
 */
static CMDLINEARG(charconfig)
{
	aFree(chr->CHAR_CONF_NAME);
	chr->CHAR_CONF_NAME = aStrdup(params);
	return true;
}
/**
 * --inter-config handler
 *
 * Overrides the default inter-server configuration file.
 * @see cmdline->exec
 */
static CMDLINEARG(interconfig)
{
	aFree(chr->INTER_CONF_NAME);
	chr->INTER_CONF_NAME = aStrdup(params);
	return true;
}
/**
 * --net-config handler
 *
 * Overrides the default network configuration file.
 * @see cmdline->exec
 */
static CMDLINEARG(netconfig)
{
	aFree(chr->NET_CONF_NAME);
	chr->NET_CONF_NAME = aStrdup(params);
	return true;
}

/**
 * --run-once handler
 *
 * Causes the server to run its loop once, and shutdown. Useful for testing.
 * @see cmdline->exec
 */
static CMDLINEARG(runonce)
{
	core->runflag = CORE_ST_STOP;
	return true;
}

/**
 * Initializes the command line arguments handlers.
 */
void cmdline_args_init_local(void)
{
	CMDLINEARG_DEF2(run-once, runonce, "Closes server after loading (testing).", CMDLINE_OPT_NORMAL);
	CMDLINEARG_DEF2(char-config, charconfig, "Alternative char-server configuration.", CMDLINE_OPT_PARAM);
	CMDLINEARG_DEF2(inter-config, interconfig, "Alternative inter-server configuration.", CMDLINE_OPT_PARAM);
	CMDLINEARG_DEF2(net-config, netconfig, "Alternative network configuration.", CMDLINE_OPT_PARAM);
}

/**
 * Last function executed by each action worker.
 **/
void char_action_final(void *param) {
	inter->sql_handle_close();
}

/**
 * First function executed by each action worker.
 **/
void char_action_init(void *param) {
	inter->sql_handle_open();
}

/**
 * Character-server entry-point
 **/
int do_init(int argc, char **argv)
{
	memset(&skillid2idx, 0, sizeof(skillid2idx));
	skillid2idx_lock = rwlock->create();
	if(!skillid2idx_lock)
		exit(EXIT_FAILURE);

	char_load_defaults();

	chr->ers_collection = ers_collection_create(MEMORYTYPE_SHARED);
	if(!chr->ers_collection)
		exit(EXIT_FAILURE);

	INDEX_MAP_CREATE(chr->map_server_list, MAP_SERVER_LIST_INITIAL_LENGTH, MEMORYTYPE_SHARED);
	chr->map_server_list_lock = rwlock->create();
	if(!chr->map_server_list_lock) {
		ShowFatalError("Failed to setup map server list!\n");
		exit(EXIT_FAILURE);
	}

	chr->action_information_mutex = mutex->create();
	if(!chr->map_server_list_lock) {
		ShowFatalError("Failed to setup action information mutex!\n");
		exit(EXIT_FAILURE);
	}
	/**
	 * Read configuration information before creating first action thread,
	 * chr->action_init can rely in loaded information.
	 **/
	inter->load_config(chr->INTER_CONF_NAME);
	inter->sql_handle_open();

	// Create first queue, the other queues are created upon map-server connections at mapif.c
	struct s_action_queue *queue = action->queue_create(10, chr->ers_collection,
		chr->action_init, NULL, chr->action_final, NULL);

	struct s_action_information *ainfo = aMalloc(sizeof(*ainfo));
	ainfo->index = action->queue_get_index(queue);
	ainfo->server = NULL;
	linkdb_insert(&chr->action_information, NULL, ainfo);
	// TODO/FIXME: do final
	VECTOR_INIT(start_items);

	HPM_char_do_init();
	cmdline->exec(argc, argv, CMDLINE_OPT_PREINIT);
	HPM->config_read();
	HPM->event(HPET_PRE_INIT);

	mapindex->init();
	pincode->init();

	#ifdef RENEWAL
		start_point.map = mapindex->name2id("iz_int");
	#else
		start_point.map = mapindex->name2id("new_1-1");
	#endif

	safestrncpy(chr->userid, "s1", sizeof(chr->userid));
	safestrncpy(chr->passwd, "p1", sizeof(chr->passwd));

	cmdline->exec(argc, argv, CMDLINE_OPT_NORMAL);
	chr->config_read(chr->CHAR_CONF_NAME, false);
	socket_io->net_config_read(chr->NET_CONF_NAME);
	chr->sql_config_read(chr->SQL_CONF_NAME, false);

#ifndef BUILDBOT
	if (strcmp(chr->userid, "s1")==0 && strcmp(chr->passwd, "p1")==0) {
		ShowWarning("Using the default user/password s1/p1 is NOT RECOMMENDED.\n");
		ShowNotice("Please edit your 'login' table to create a proper inter-server user/password (gender 'S')\n");
		ShowNotice("And then change the user/password to use in conf/char/char-server.conf (or conf/import/char-server.conf)\n");
	}
#endif

	inter->init_sql();

	auth_db = idb_alloc(DB_OPT_RELEASE_DATA);
	chr->online_char_db = idb_alloc(DB_OPT_RELEASE_DATA);

	HPM->event(HPET_INIT);

	chr->mmo_char_sql_init();

	if(!(fame_list_mutex = mutex->create()))
		exit(EXIT_FAILURE);
	chr->read_fame_list(); //Read fame lists.

	if ((socket_io->naddr_ != 0) && (!login_ip || !chr->ip)) {
		char ip_str[16];
		socket_io->ip2str(socket_io->addr_[0], ip_str);

		if (socket_io->naddr_ > 1)
			ShowStatus("Multiple interfaces detected..  using %s as our IP address\n", ip_str);
		else
			ShowStatus("Defaulting to %s as our IP address\n", ip_str);
		if (!login_ip) {
			safestrncpy(login_ip_str, ip_str, sizeof(login_ip_str));
			login_ip = socket_io->str2ip(login_ip_str);
		}
		if (!chr->ip) {
			safestrncpy(char_ip_str, ip_str, sizeof(char_ip_str));
			chr->ip = socket_io->str2ip(char_ip_str);
		}
	}

	chclif->init();
	loginif->init();
	mapif->init();

	// periodically update the overall user count on all mapservers + login server
	timer->add_func_list(chr->broadcast_user_count, "chr->broadcast_user_count");
	timer->add_interval(timer->gettick() + 1000, chr->broadcast_user_count, 0, 0, 5 * 1000);

	// Timer to clear (chr->online_char_db)
	timer->add_func_list(chr->waiting_disconnect, "chr->waiting_disconnect");

	// Online Data timers (checking if char still connected)
	timer->add_func_list(chr->online_data_cleanup, "chr->online_data_cleanup");
	timer->add_interval(timer->gettick() + 1000, chr->online_data_cleanup, 0, 0, 600 * 1000);

	struct Sql *sql_handle = inter->sql_handle_get();
	//Cleaning the tables for NULL entries @ startup [Sirius]
	//Chardb clean
	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `account_id` = '0'", char_db) )
		Sql_ShowDebug(sql_handle);

	//guilddb clean
	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `guild_lv` = '0' AND `max_member` = '0' AND `exp` = '0' AND `next_exp` = '0' AND `average_lv` = '0'", guild_db) )
		Sql_ShowDebug(sql_handle);

	//guildmemberdb clean
	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `guild_id` = '0' AND `account_id` = '0' AND `char_id` = '0'", guild_member_db) )
		Sql_ShowDebug(sql_handle);

	socket_io->set_defaultparse(chr->parse_entry);
	socket_io->validate = true;

	if(!socket_io->make_listen_bind(bind_ip,chr->port)) {
		ShowFatalError("Failed to bind to port '"CL_WHITE"%d"CL_RESET"'\n",chr->port);
		exit(EXIT_FAILURE);
	}

	Sql_HerculesUpdateCheck(sql_handle);
#ifdef CONSOLE_INPUT
	console->input->setSQL(sql_handle);
	console->display_gplnotice();
#endif
	ShowStatus("The char-server is "CL_GREEN"ready"CL_RESET" (Server is listening on the port %d).\n\n", chr->port);

	if( core->runflag != CORE_ST_STOP )
	{
		core->shutdown_callback = do_shutdown;
		core->runflag = CHARSERVER_ST_RUNNING;
	}

	HPM->event(HPET_READY);

	return 0;
}

void char_load_defaults(void)
{
	mapindex_defaults();
	pincode_defaults();
	char_defaults();
	chclif_defaults();
	loginif_defaults();
	mapif_defaults();
	inter_auction_defaults();
	inter_clan_defaults();
	inter_elemental_defaults();
	inter_guild_defaults();
	inter_homunculus_defaults();
	inter_mail_defaults();
	inter_mercenary_defaults();
	inter_party_defaults();
	inter_pet_defaults();
	inter_quest_defaults();
	inter_storage_defaults();
	inter_rodex_defaults();
	inter_achievement_defaults();
	inter_defaults();
	geoip_defaults();
}

/**
 * Sets up chr interface and initializes default values
 **/
void char_defaults(void)
{
	chr = &char_s;

	chr->ers_collection = NULL;

	chr->map_server_list = (struct s_mmo_map_server_list)INDEX_MAP_STATIC_INITIALIZER(MEMORYTYPE_SHARED);
	chr->map_server_list_lock = NULL;

	chr->action_information = NULL;
	chr->action_information_mutex = NULL;

	sprintf(chr->db_path, "db");
	libconfig->set_db_path(chr->db_path);

	chr->login_session = NULL;

	chr->online_char_db = NULL;
	chr->char_db_ = NULL;

	memset(chr->userid, 0, sizeof(chr->userid));
	memset(chr->passwd, 0, sizeof(chr->passwd));
	memset(chr->server_name, 0, sizeof(chr->server_name));

	chr->CHAR_CONF_NAME = aStrdup("conf/char/char-server.conf");
	chr->NET_CONF_NAME = aStrdup("conf/network.conf");
	chr->SQL_CONF_NAME = aStrdup("conf/common/inter-server.conf");
	chr->INTER_CONF_NAME = aStrdup("conf/common/inter-server.conf");

	chr->ip = 0;
	chr->port = 6121;
	chr->server_type = 0;
	chr->new_display = 0;

	chr->show_save_log = true;
	chr->enable_logs = true;

	chr->parse_entry = char_parse_entry;
	chr->action_init  = char_action_init;
	chr->action_final = char_action_final;
	chr->escape_normalize_name = char_escape_normalize_name;
	chr->create_auth_entry = char_create_auth_entry;
	chr->waiting_disconnect = char_waiting_disconnect;
	chr->delete_char_sql = char_delete_char_sql;
	chr->create_online_char_data = char_create_online_char_data;
	chr->set_char_charselect = char_set_char_charselect;
	chr->set_char_online = char_set_char_online;
	chr->set_char_offline = char_set_char_offline;
	chr->db_setoffline = char_db_setoffline;
	chr->db_kickoffline = char_db_kickoffline;
	chr->set_all_offline = char_set_all_offline;
	chr->set_all_offline_sql = char_set_all_offline_sql;
	chr->create_charstatus = char_create_charstatus;
	chr->mmo_flag2str = char_mmo_flag2str;
	chr->mmo_char_compare = char_mmo_char_compare;
	chr->mmo_char_tosql = char_mmo_char_tosql;
	chr->memitemdata_to_sql = char_memitemdata_to_sql;
	chr->getitemdata_from_sql = char_getitemdata_from_sql;
	chr->mmo_gender = char_mmo_gender;
	chr->mmo_chars_fromsql = char_mmo_chars_fromsql;
	chr->mmo_char_fromsql = char_mmo_char_fromsql;
	chr->mmo_char_sql_init = char_mmo_char_sql_init;
	chr->char_slotchange = char_char_slotchange;
	chr->rename_char_sql = char_rename_char_sql;
	chr->name_exists = char_name_exists;
	chr->check_char_name = char_check_char_name;
	chr->make_new_char_sql = char_make_new_char_sql;
	chr->divorce_char_sql = char_divorce_char_sql;
	chr->count_users = char_count_users;
	chr->mmo_char_tobuf = char_mmo_char_tobuf;
	chr->send_HC_ACK_CHARINFO_PER_PAGE = char_send_HC_ACK_CHARINFO_PER_PAGE;
	chr->send_HC_ACK_CHARINFO_PER_PAGE_tail = char_send_HC_ACK_CHARINFO_PER_PAGE_tail;
	chr->mmo_char_send_ban_list = char_mmo_char_send_ban_list;
	chr->mmo_char_send_slots_info = char_mmo_char_send_slots_info;
	chr->mmo_char_send_characters = char_mmo_char_send_characters;
	chr->char_married = char_char_married;
	chr->char_child = char_char_child;
	chr->char_family = char_char_family;
	chr->disconnect_player = char_disconnect_player;
	chr->authfail_fd = char_authfail_fd;
	chr->auth_kick_online = char_auth_kick_online;
	chr->auth_ok = char_auth_ok;
	chr->auth_error = char_auth_error;
	chr->read_fame_list = char_read_fame_list;
	chr->loadName = char_loadName;
	chr->auth = char_auth;
	chr->disconnect = char_disconnect;
	chr->parse_frommap_datasync = char_parse_frommap_datasync;
	chr->parse_frommap_skillid2idx = char_parse_frommap_skillid2idx;
	chr->parse_frommap_map_names = char_parse_frommap_map_names;
	chr->send_scdata = char_send_scdata;
	chr->parse_frommap_request_scdata = char_parse_frommap_request_scdata;
	chr->parse_frommap_set_users_count = char_parse_frommap_set_users_count;
	chr->parse_frommap_set_users = char_parse_frommap_set_users;
	chr->parse_frommap_save_character = char_parse_frommap_save_character;
	chr->parse_frommap_char_select_req = char_parse_frommap_char_select_req;
	chr->parse_frommap_change_map_server = char_parse_frommap_change_map_server;
	chr->parse_frommap_remove_friend = char_parse_frommap_remove_friend;
	chr->parse_frommap_char_name_request = char_parse_frommap_char_name_request;
	chr->parse_frommap_change_email = char_parse_frommap_change_email;
	chr->kick = char_kick;
	chr->ban = char_ban;
	chr->unban = char_unban;
	chr->changecharsex_all = char_changecharsex_all;
	chr->changecharsex = char_changecharsex;
	chr->parse_frommap_change_account = char_parse_frommap_change_account;
	chr->parse_frommap_fame_list = char_parse_frommap_fame_list;
	chr->parse_frommap_divorce_char = char_parse_frommap_divorce_char;
	chr->parse_frommap_ragsrvinfo = char_parse_frommap_ragsrvinfo;
	chr->parse_frommap_set_char_offline = char_parse_frommap_set_char_offline;
	chr->parse_frommap_set_all_offline = char_parse_frommap_set_all_offline;
	chr->parse_frommap_set_char_online = char_parse_frommap_set_char_online;
	chr->parse_frommap_build_fame_list = char_parse_frommap_build_fame_list;
	chr->parse_frommap_save_status_change_data = char_parse_frommap_save_status_change_data;
	chr->parse_frommap_ping = char_parse_frommap_ping;
	chr->parse_frommap_auth_request = char_parse_frommap_auth_request;
	chr->parse_frommap_update_ip = char_parse_frommap_update_ip;
	chr->parse_frommap_scdata_update = char_parse_frommap_scdata_update;
	chr->parse_frommap_scdata_delete = char_parse_frommap_scdata_delete;
	chr->parse_frommap = char_parse_frommap;
	chr->search_mapserver = char_search_mapserver;
	chr->mapif_init = char_mapif_init;
	chr->lan_subnet_check = char_lan_subnet_check;
	chr->delete2_ack = char_delete2_ack;
	chr->delete2_accept_actual_ack = char_delete2_accept_actual_ack;
	chr->delete2_accept_ack = char_delete2_accept_ack;
	chr->delete2_cancel_ack = char_delete2_cancel_ack;
	chr->send_account_id = char_send_account_id;
	chr->send_map_info = char_send_map_info;
	chr->send_wait_char_server = char_send_wait_char_server;
	chr->search_default_maps_mapserver = char_search_default_maps_mapserver;
	chr->creation_failed = char_creation_failed;
	chr->creation_ok = char_creation_ok;
	chr->delete_char_failed = char_delete_char_failed;
	chr->delete_char_ok = char_delete_char_ok;
	chr->parse_char_ping = char_parse_char_ping;
	chr->allow_rename = char_allow_rename;
	chr->rename_char_ack = char_rename_char_ack;
	chr->captcha_notsupported = char_captcha_notsupported;
	chr->parse_char_login_map_server = char_parse_char_login_map_server;
	chr->change_character_slot_ack = char_change_character_slot_ack;
	chr->parse_char_move_character = char_parse_char_move_character;
	chr->broadcast_user_count = char_broadcast_user_count;
	chr->check_connect_login_server = char_check_connect_login_server;
	chr->online_data_cleanup_sub = char_online_data_cleanup_sub;
	chr->online_data_cleanup = char_online_data_cleanup;
	chr->sql_config_read = char_sql_config_read;
	chr->sql_config_read_registry = char_sql_config_read_registry;
	chr->sql_config_read_pc = char_sql_config_read_pc;
	chr->sql_config_read_guild = char_sql_config_read_guild;
	chr->config_read = char_config_read;
	chr->config_read_database = char_config_read_database;
	chr->config_read_console = char_config_read_console;
	chr->config_read_player_fame = char_config_read_player_fame;
	chr->config_read_player_deletion = char_config_read_player_deletion;
	chr->config_read_player_name = char_config_read_player_name;
	chr->config_set_start_item = char_config_set_start_item;
	chr->config_read_player_new = char_config_read_player_new;
	chr->config_read_player = char_config_read_player;
	chr->config_read_permission = char_config_read_permission;
	chr->config_set_ip = char_config_set_ip;
	chr->config_read_inter = char_config_read_inter;
	chr->config_read_top = char_config_read_top;

	chr->config_update_ip = char_config_update_ip;
	chr->max_connect_user_get = char_max_connect_user_get;
	chr->gm_allow_group_get = char_gm_allow_group_get;
	chr->maintenance_min_group_id_get = char_maintenance_min_group_id_get;
}
