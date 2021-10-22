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
#ifndef CHAR_CHAR_H
#define CHAR_CHAR_H

#include "common/hercules.h"
#include "common/core.h" // CORE_ST_LAST
#include "common/db.h"
#include "common/mmo.h"

/* Forward Declarations */
struct config_setting_t; // common/conf.h
struct config_t; // common/conf.h

enum E_CHARSERVER_ST {
	CHARSERVER_ST_RUNNING = CORE_ST_LAST,
	CHARSERVER_ST_SHUTDOWN,
	CHARSERVER_ST_LAST
};

/**
 * Character session data
 *
 * This data is only used while the player is logged only in the char-server,
 * so all access to its members is sequential in a single Action Worker. Thus
 * There's no need to use any mutexes to access it.
 **/
struct char_session_data {
	bool auth; // Authentication state inside the char-server
	int account_id, login_id1, login_id2, sex;
	int found_char[MAX_CHARS]; // ids of chars on this account
	time_t unban_time[MAX_CHARS]; // char unban time array
	char email[40]; // e-mail (default: a@a.com) by [Yor]
	time_t expiration_time; // # of seconds 1/1/1970 (timestamp): Validity limit of the account (0 = unlimited)
	int group_id; // permission
	uint8 char_slots;
	uint32 version;
	uint8 clienttype;
	char pincode[4+1];
	uint32 pincode_seed;
	uint16 pincode_try;
	uint32 pincode_change;
	char birthdate[10+1];  // YYYY-MM-DD
	/**
	 * Rename process data.
	 **/
	struct {
		/**
		 * New character name, used when there's a renaming process.
		 *
		 * The client sends the desired name and after server confirmation that
		 * the name is valid the player needs to reconfirm that the change is
		 * still desired.
		 * @see chclif_parse_rename
		 **/
		char new_name[ESC_NAME_LENGTH];
		int char_id;
	} *rename;
};

/**
 * Online character information
 * Objects of this struct are stored in chr->online_char_db
 *
 * @param account_id         Account id
 * @param char_id            Selected character (-1 when in char selection)
 * @param session_id         Session connected to char-server (-1 when in map-server)
 * @oaram waiting_disconnect Timeout timer id when moving to map-server (chr->waiting_disconnect)
 * @param server             -2 Unknown server
 * @param server             -1 Not connected
 * @param server             Index position of server
 * @param pincode_enable     Should the player be queried for the pincode? (2: true)
 * @see pincode_handle
 * @see chr->online_char_db
 **/
struct online_char_data {
	int account_id;
	int char_id;
	int session_id;
	int waiting_disconnect;
	short server;
	int pincode_enable;
};

/**
 * Map-server information
 **/
struct mmo_map_server {
	uint32 pos; // Position in list (@see char_interface::map_server_list)
	int32 queue_index; // Index of the queue of this map-server

	struct socket_data *session;
	uint32 ip;
	uint16 port;

	int user_count; // Current user count (accessed via InterLocked)
	VECTOR_DECL(uint16) maps; // Maps owned by this map-server
	/**
	 * TODO: This map list is searched for several times (everytime a player
	 * changes server or logs in), this should be a hashtable.
	 **/
};
INDEX_MAP_STRUCT_DECL(s_mmo_map_server_list, struct mmo_map_server);
#define MAP_SERVER_LIST_INITIAL_LENGTH 1 // Initial length of map-server list (multiplied by 32) @see do_init

/**
 * deprecated feature, multi map been a dangerous in-complete feature for so long and going to be removed.
 * USE IT AT YOUR OWN RISK!
 */
#define MAX_MAP_SERVERS 1

/**
 * Linked list of all action workers active in this server with the
 * map-server that's attached.
 **/
struct s_action_information {
	uint32_t index;
	struct mmo_map_server *server;
};

#define DEFAULT_AUTOSAVE_INTERVAL (300*1000)

enum inventory_table_type {
	TABLE_INVENTORY,
	TABLE_CART,
	TABLE_STORAGE,
	TABLE_GUILD_STORAGE,
};

struct char_auth_node {
	int account_id;
	int char_id;
	uint32 login_id1;
	uint32 login_id2;
	uint32 ip;
	int sex;
	time_t expiration_time; // # of seconds 1/1/1970 (timestamp): Validity limit of the account (0 = unlimited)
	int group_id;
	unsigned changing_mapservers : 1;

	bool read_flag; // When set to true this node is being read
};

/**
 * HC_REFUSE_MAKECHAR Error Codes
 * @see char_creation_failed
 **/
enum refuse_make_char_errorcode {
	RMCE_CREATED = -1,  // Character successfuly created (internal)
	RMCE_ALREADY_EXISTS,// "Character Name already exists"
	RMCE_UNDERAGED,     // "You are underaged"
	RMCE_SYMBOLS,       // "Symbols in Character Names are forbidden"
	RMCE_NOT_ELIGIBLE,  // "You are not eligible to open the Character Slot"
	RMCE_DENIED,        // "Character Creation is denied"
	// 5 - 10 RMCE_DENIED
	RMCE_PREMIUM = 11,  // "This service is only available for premium users"
	RMCE_INVALID,       // "Character name is invalid"
	// 12 - 129 RMCE_DENIED
};

/**
 * HC_ACK_CHANGE_CHARNAME Result list
 * @see chr->rename_char_ack
 **/
enum change_charname_result {
	CRR_SUCCESS = 0,      // Success
	CRR_ALREADY_CHANGED,  // The Character Name was changed before. You can not change the name more than once
	CRR_INCORRECT_USER,   // User information is not correct
	CRR_FAILED,           // Changing character name has failed
	CRR_DUPLICATE,        // Other user already selected the character name. Please use other name.
	CRR_BELONGS_TO_GUILD, // MSG_FAILED_RENAME_BELONGS_TO_GUILD
	CRR_BELONGS_TO_PARTY, // MSG_FAILED_RENAME_BELONGS_TO_PARTY
};

/**
 * Flags used to mark which members have changed in a mmo_charstatus object
 * @see char_mmo_compare
 * @see char_mmo_char_save
 **/
enum char_save_flag {
	CHARSAVE_NONE         = 0x0,
	CHARSAVE_INVENTORY    = 0x1,
	CHARSAVE_CART         = 0x2,
	CHARSAVE_STATUS_LONG  = 0x4,
	CHARSAVE_ACCDATA      = 0x8,
	CHARSAVE_STATUS_SHORT = 0x10,
	CHARSAVE_MERCENARY    = 0x20,
	CHARSAVE_MEMO         = 0x40,
	CHARSAVE_SKILL        = 0x80,
	CHARSAVE_FRIENDS      = 0x100,
	CHARSAVE_HOTKEYS      = 0x200,

	CHARSAVE_STATUS       = CHARSAVE_STATUS_LONG|CHARSAVE_STATUS_SHORT,
	CHARSAVE_ALL          = 0x3FF
};

/**
 * Parameter of char_mmo_char_fromsql
 * @see char_mmo_char_fromsql
 **/
enum e_char_cache {
	CHARCACHE_IGNORE_NOLOCK, // Don't change cache
	CHARCACHE_INSERT,        // Insert data to cache
	CHARCACHE_UPDATE         // Update cache
};

/**
 * char interface
 **/
struct char_interface {
	struct ers_collection_t *ers_collection;

	/**
	 * List of all connected map-servers
	 **/
	struct s_mmo_map_server_list map_server_list;
	struct rwlock_data *map_server_list_lock;

	/**
	 * Action queue information
	 * Used to find which queue is being used to process each server.
	 * Login-server uses any of the available workers.
	 **/
	struct linkdb_node *action_information; // <server> <s_action_information>
	struct mutex_data *action_information_mutex;

	struct socket_data *login_session;

	/**
	 * Online character db
	 *
	 * Players currently connected either to the char-server (in char selection
	 * screen) or to a map-server. When a new entry is added a cleanup timer is
	 * started (online_char_data::waiting_disconnect, char_waiting_disconnect).
	 * The table is also cleaned up periodically via chr->online_data_cleanup
	 *
	 * @see char_set_char_charselect
	 * @see char_set_char_online
	 * @see char_online_data_cleanup_sub
	 *
	 * int account_id -> struct online_char_data*
	 * @see online_char_data
	 **/
	struct DBMap *online_char_db;
	struct mutex_data *online_char_db_mutex;

	/**
	 * Character status database
	 *
	 * All currently loaded characters have an active entry in this table,
	 * these entries are set up via chr->create_charstatus that is usually
	 * triggered by chr->mmo_char_fromsql in the authentication process
	 * after char selection (chclif_parse_select_char, CH_SELECT_CHAR).
	 *
	 * int char_id -> struct mmo_charstatus*
	 * @see mmo_charstatus
	 **/
	struct DBMap *char_db_;
	struct rwlock_data *char_db_lock;

	char userid[NAME_LENGTH];
	char passwd[NAME_LENGTH];
	char server_name[20];
	uint32 ip;
	uint16 port;
	int server_type;
	int16 new_display; ///< Display 'New' in the server list.

	char *CHAR_CONF_NAME;
	char *NET_CONF_NAME; ///< Network config filename
	char *SQL_CONF_NAME;
	char *INTER_CONF_NAME;

	bool show_save_log; ///< Show loading/saving messages.
	bool enable_logs;   ///< Whether to log char server operations.

	char db_path[256]; //< Database directory (db)

	void (*action_init) (void *param);
	void (*action_final) (void *param);

	struct DBData (*create_online_char_data) (const struct DBKey_s *key, va_list args);
	int (*db_setoffline) (const struct DBKey_s *key, struct DBData *data, va_list args);
	int (*db_kickoffline) (const struct DBKey_s *key, struct DBData *data, va_list args);
	struct DBData (*create_charstatus) (const struct DBKey_s *key, va_list args);
	int (*online_data_cleanup_sub) (const struct DBKey_s *key, struct DBData *data, va_list args);

	int (*online_data_cleanup) (struct timer_interface *tm, int tid, int64 tick, int id, intptr_t data);

	void (*escape_normalize_name)(const char *name, char *esc_name);
	int (*waiting_disconnect) (struct timer_interface *tm, int tid, int64 tick, int id, intptr_t data);
	int (*delete_char_sql) (int char_id);

	void (*set_char_charselect) (int account_id);
	void (*set_char_online) (int map_id, int char_id, int account_id);
	void (*set_char_offline) (int char_id, int account_id);

	void (*set_login_all_offline) (void);
	void (*set_all_offline) (int id);
	void (*set_all_offline_sql) (void);

	char *(*mmo_flag2str)(char *save_status, size_t len, int32 save_flag);
	int (*mmo_char_tosql) (int char_id, struct mmo_charstatus* p);
	int (*getitemdata_from_sql) (struct item *items, int max, int guid, enum inventory_table_type table);
	int (*memitemdata_to_sql) (const struct item items[], int current_size, int guid, enum inventory_table_type table);
	int (*mmo_gender) (const struct char_session_data *sd, const struct mmo_charstatus *p, char sex);
	int (*mmo_chars_fromsql) (struct char_session_data* sd, uint8* buf, int *count);
	uint32 (*mmo_char_compare) (const struct mmo_charstatus *cp, const struct mmo_charstatus *p);
	struct mmo_charstatus *(*mmo_char_fromsql) (int char_id, int load_flag, struct mmo_charstatus *out, enum e_char_cache cache_data);
	int (*mmo_char_sql_init) (void);
	int (*get_map_server)(struct point *last_point);
	void (*log_select) (const struct mmo_charstatus *cd, int slot);
	bool (*char_slotchange) (struct char_session_data *sd, struct socket_data *session, unsigned short from, unsigned short to);
	enum change_charname_result (*rename_char_sql) (struct char_session_data *sd, int char_id);
	bool (*name_exists) (const char *name, const char *esc_name);
	bool (*check_symbols)(const char *name);
	enum refuse_make_char_errorcode (*check_char_name) (const char *name, const char *esc_name);
	enum refuse_make_char_errorcode (*make_new_char_sql) (struct char_session_data *sd, const char *name_, int str, int agi, int vit, int int_, int dex, int luk, int slot, int hair_color, int hair_style, int starting_job, uint8 sex, int *out_char_id);
	int (*divorce_char_sql) (int partner_id1, int partner_id2);
	int (*count_users) (void);
	int (*mmo_char_tobuf) (uint8* buffer, struct mmo_charstatus* p);

	void (*send_HC_ACK_CHARINFO_PER_PAGE) (struct socket_data *session, struct char_session_data *sd);
	void (*send_HC_ACK_CHARINFO_PER_PAGE_tail) (struct socket_data *session, struct char_session_data *sd);
	void (*mmo_char_send_ban_list) (struct socket_data *session, struct char_session_data *sd);
	void (*mmo_char_send_slots_info) (struct socket_data *session, struct char_session_data* sd);
	int (*mmo_char_send_characters) (struct socket_data *session, struct char_session_data* sd);

	bool (*char_married) (int pl1, int pl2);
	bool (*char_child) (int parent_id, int child_id);
	int (*char_family) (int cid1, int cid2, int cid3);
	void (*disconnect_player) (int account_id);
	void (*authfail_fd) (struct socket_data *session, enum notify_ban_errorcode flag);
	bool (*auth_kick_online) (struct socket_data *session, struct online_char_data *character);
	void (*auth_ok) (struct socket_data *session, struct char_session_data *sd);
	void (*ping_login_server) (struct socket_data *session);
	void (*auth_error) (struct socket_data *session, unsigned char flag);
	void (*update_ip) (struct socket_data *session);
	void (*read_fame_list) (void);
	int (*loadName) (int char_id, char* name);
	void (*parse_frommap_datasync) (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_frommap_skillid2idx) (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_frommap_map_names) (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*send_scdata) (struct socket_data *session, int aid, int cid);
	void (*parse_frommap_request_scdata)    (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_frommap_set_users_count)   (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_frommap_set_users)         (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_frommap_save_character)    (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_frommap_char_select_req)   (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_frommap_change_map_server) (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_frommap_remove_friend)     (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_frommap_char_name_request) (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_frommap_change_email)      (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*kick) (int account_id);
	void (*ban) (int account_id, int char_id, time_t *unban_time, short year, short month, short day, short hour, short minute, short second);
	void (*unban) (int char_id, int *result);
	void (*changecharsex_all) (int account_id, int sex);
	int (*changecharsex) (int char_id, int sex);
	void (*parse_frommap_change_account)          (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_frommap_fame_list)               (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_frommap_divorce_char)            (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_frommap_ragsrvinfo)              (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_frommap_set_char_offline)        (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_frommap_set_all_offline)         (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_frommap_set_char_online)         (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_frommap_build_fame_list)         (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_frommap_save_status_change_data) (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_frommap_ping)                    (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_frommap_auth_request)            (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_frommap_update_ip)               (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_frommap_scdata_update)           (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_frommap_scdata_delete)           (struct s_receive_action_data *act, struct mmo_map_server *server);
	enum parsefunc_rcode (*parse_frommap) (struct s_receive_action_data *act);
	int (*search_mapserver) (unsigned short map, uint32 ip, uint16 port);
	int (*mapif_init) (struct socket_data *session);
	uint32 (*lan_subnet_check) (uint32 ip);
	int (*can_delete) (int char_id, int *out_delete_date);
	bool (*delete_remove_queue) (int char_id);
	int (*delete_insert_queue) (int char_id, time_t *delete_timestamp);
	void (*delete2_ack) (struct socket_data *session, int char_id, uint32 result, time_t delete_date);
	void (*delete2_accept_actual_ack) (struct socket_data *session, int char_id, uint32 result);
	void (*delete2_accept_ack) (struct socket_data *session, int char_id, uint32 result);
	void (*delete2_cancel_ack) (struct socket_data *session, int char_id, uint32 result);

	void (*send_account_id) (struct socket_data *session, int account_id);
	void (*send_map_info) (struct socket_data *session, uint32 subnet_map_ip, uint32 map_ip, uint16 map_port, int char_id, const struct point *last_point, char *dnsHost);
	void (*create_auth_entry)(struct char_session_data *sd, int char_id, int ipl, bool changing_map_servers);
	void (*send_wait_char_server) (struct socket_data *session);
	int (*search_default_maps_mapserver) (struct point *last_point);
	void (*creation_failed) (struct socket_data *session, enum refuse_make_char_errorcode result);
	void (*creation_ok) (struct socket_data *session, struct mmo_charstatus *char_dat);
	void (*delete_char_failed) (struct socket_data *session, int flag);
	void (*delete_char_ok) (struct socket_data *session);
	void (*parse_char_ping) (struct s_receive_action_data *act);
	void (*allow_rename) (struct socket_data *session, int flag);
	void (*rename_char_ack) (struct socket_data *session, int flag);
	void (*captcha_notsupported) (struct socket_data *session);
	void (*parse_char_login_map_server) (struct s_receive_action_data *act, uint32 ipl);
	void (*change_character_slot_ack) (struct socket_data *session, bool ret);
	void (*parse_char_move_character) (struct s_receive_action_data *act, struct char_session_data* sd);

	int (*slot2id)(int account_id, int slot);
	enum notify_ban_errorcode (*auth)(struct socket_data *session, struct char_session_data *sd, int ipl);
	void (*disconnect)(struct socket_data *session, struct char_session_data *sd);
	enum parsefunc_rcode (*parse_entry) (struct s_receive_action_data *act);

	int (*broadcast_user_count) (struct timer_interface *tm, int tid, int64 tick, int id, intptr_t data);
	int (*check_connect_login_server) (struct timer_interface *tm, int tid, int64 tick, int id, intptr_t data);

	bool (*sql_config_read) (const char *filename, bool imported);
	bool (*sql_config_read_registry) (const char *filename, const struct config_t *config, bool imported);
	bool (*sql_config_read_pc) (const char *filename, const struct config_t *config, bool imported);
	bool (*sql_config_read_guild) (const char *filename, const struct config_t *config, bool imported);
	bool (*config_read) (const char *filename, bool imported);
	bool (*config_read_database) (const char *filename, const struct config_t *config, bool imported);
	bool (*config_read_console) (const char *filename, const struct config_t *config, bool imported);
	bool (*config_read_player_fame) (const char *filename, const struct config_t *config, bool imported);
	bool (*config_read_player_deletion) (const char *filename, const struct config_t *config, bool imported);
	bool (*config_read_player_name) (const char *filename, const struct config_t *config, bool imported);
	void (*config_set_start_item) (const struct config_setting_t *setting);
	bool (*config_read_player_new) (const char *filename, const struct config_t *config, bool imported);
	bool (*config_read_player) (const char *filename, const struct config_t *config, bool imported);
	bool (*config_read_permission) (const char *filename, const struct config_t *config, bool imported);
	bool (*config_set_ip) (const char *type, const char *value, uint32 *out_ip, char *out_ip_str);
	bool (*config_read_inter) (const char *filename, const struct config_t *config, bool imported);
	bool (*config_read_top) (const char *filename, const struct config_t *config, bool imported);
	void (*config_update_ip) (void);

	int (*gm_allow_group_get) (void);
	int (*max_connect_user_get) (void);
	int (*maintenance_min_group_id_get) (void);
};

#ifdef HERCULES_CORE
extern int char_name_option;
extern char char_name_letters[];
extern bool char_gm_read;
extern int autosave_interval;
extern char db_path[];
extern char char_db[256];
extern char scdata_db[256];
extern char cart_db[256];
extern char inventory_db[256];
extern char charlog_db[256];
extern char storage_db[256];
extern char interlog_db[256];
extern char skill_db[256];
extern char memo_db[256];
extern char guild_db[256];
extern char guild_alliance_db[256];
extern char guild_castle_db[256];
extern char guild_expulsion_db[256];
extern char guild_member_db[256];
extern char guild_position_db[256];
extern char guild_skill_db[256];
extern char guild_storage_db[256];
extern char party_db[256];
extern char pet_db[256];
extern char mail_db[256];
extern char auction_db[256];
extern char quest_db[256];
extern char rodex_db[256];
extern char rodex_item_db[256];
extern char homunculus_db[256];
extern char skill_homunculus_db[256];
extern char mercenary_db[256];
extern char mercenary_owner_db[256];
extern char ragsrvinfo_db[256];
extern char elemental_db[256];
extern char acc_reg_num_db[32];
extern char acc_reg_str_db[32];
extern char char_reg_str_db[32];
extern char char_reg_num_db[32];
extern char char_achievement_db[256];

extern int guild_exp_rate;

void char_load_defaults(void);
void char_defaults(void);
#endif // HERCULES_CORE

HPShared struct char_interface *chr;

#endif /* CHAR_CHAR_H */
