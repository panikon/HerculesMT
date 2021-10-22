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
#ifndef LOGIN_LOGIN_H
#define LOGIN_LOGIN_H

#include "common/hercules.h"
#include "common/core.h" // CORE_ST_LAST
#include "common/db.h"
#include "common/mmo.h" // NAME_LENGTH,SEX_*

/** @file
 * Login interface.
 */

struct mmo_account;
struct AccountDB;
struct config_t;
struct config_setting_t;

enum E_LOGINSERVER_ST
{
	LOGINSERVER_ST_RUNNING = CORE_ST_LAST,
	LOGINSERVER_ST_SHUTDOWN,
	LOGINSERVER_ST_LAST
};

enum password_enc {
	PWENC_NONE     = 0x0, ///< No encryption
	PWENC_ENCRYPT  = 0x1, ///< passwordencrypt
	PWENC_ENCRYPT2 = 0x2, ///< passwordencrypt2
	PWENC_BOTH = PWENC_ENCRYPT|PWENC_ENCRYPT2, ///< both the above
};

#define PASSWORDENC PWENC_BOTH

#define PASSWD_LEN (32+1) // 23+1 for plaintext, 32+1 for md5-ed passwords

struct login_session_data {
	int account_id;
	int login_id1; //< Id1 is position in server list for servers
	int login_id2;
	char sex;// 'F','M','S'

	char userid[NAME_LENGTH];
	char passwd[PASSWD_LEN];
	int passwdenc;
	char md5key[20];
	uint16 md5keylen;

	char lastlogin[24];
	uint8 group_id;
	uint8 clienttype;
	uint32 version;

	uint8 client_hash[16];
	int has_client_hash;

	time_t expiration_time;

	struct socket_data *session;
};

struct client_hash_node {
	int group_id;
	uint8 hash[16];
	struct client_hash_node *next;
};

struct Login_Config {

	uint32 login_ip;                                ///< the address to bind to
	uint16 login_port;                              ///< the port to bind to
	uint32 ipban_cleanup_interval;                  ///< interval (in seconds) to clean up expired IP bans
	uint32 ip_sync_interval;                        ///< interval (in minutes) to execute a DNS/IP update (for dynamic IPs)
	bool log_login;                                 ///< whether to log login server actions or not
	char date_format[32];                           ///< date format used in messages
	bool new_account_flag,new_acc_length_limit;     ///< auto-registration via _M/_F ? / if yes minimum length is 4?
	int start_limited_time;                         ///< new account expiration time (-1: unlimited)
	bool use_md5_passwds;                           ///< work with password hashes instead of plaintext passwords?
	int group_id_to_connect;                        ///< required group id to connect
	int min_group_id_to_connect;                    ///< minimum group id to connect
	bool check_client_version;                      ///< check the clientversion set in the clientinfo ?
	bool check_client_flags;                        ///< check the clientversion flags set in the clientinfo
	bool report_client_flags_error;                 ///< report the clientversion flags set errors
	uint32 client_version_to_connect;               ///< the client version needed to connect (if checking is enabled)
	int allowed_regs;                               ///< account registration flood protection [Kevin]
	int time_allowed;                               ///< time in seconds

	bool ipban;                                     ///< perform IP blocking (via contents of `ipbanlist`) ?
	bool dynamic_pass_failure_ban;                  ///< automatic IP blocking due to failed login attemps ?
	uint32 dynamic_pass_failure_ban_interval;       ///< how far to scan the loginlog for password failures
	uint32 dynamic_pass_failure_ban_limit;          ///< number of failures needed to trigger the ipban
	uint32 dynamic_pass_failure_ban_duration;       ///< duration of the ipban
	bool use_dnsbl;                                 ///< dns blacklist blocking ?
	VECTOR_DECL(char *) dnsbl_servers;              ///< dnsbl servers

	bool send_user_count_description;
	uint32 users_low;
	uint32 users_medium;
	uint32 users_high;

	bool client_hash_check;                         ///< flags for checking client md5
	// TODO: VECTOR candidate
	struct client_hash_node *client_hash_nodes;     ///< linked list containg md5 hash for each gm group
};

struct login_auth_node {
	int account_id;
	uint32 login_id1;
	uint32 login_id2;
	uint32 ip;
	char sex;
	uint32 version;
	uint8 clienttype;
	int group_id;
	time_t expiration_time;
};

/**
 * Online User Database
 * @author Wizputer
 **/
struct online_login_data {
	int account_id;
	/**
	 * Session timeout until confirmation by char-server that the client
	 * connected.
	 * @see login_auth_ok
	 * @see login_waiting_disconnect_timer
	 **/
	int waiting_disconnect;
	/**
	 * Server that currently owns this account.
	 * Server account id
	 **/
	enum {
		ACC_DISCONNECTED  = -2, //< Owner disconnected
		ACC_WAIT_TIMEOUT  = -1, //< Waiting timeout (didn't connect to char-server yet)
		ACC_CHAR_VALID    = 0   //< Greater than ACC_CHAR_VALID owner
	} char_server;
};

#define sex_num2str(num) ( ((num) ==  SEX_FEMALE) ? 'F' : ((num) ==  SEX_MALE) ? 'M' : 'S' )
#define sex_str2num(str) ( ((str) == 'F') ? SEX_FEMALE : ((str) == 'M') ? SEX_MALE : SEX_SERVER )

/**
 * Character server information
 *
 * This information is used in order to keep track of all authenticated
 * char-servers and to send the data via (lclif_send_server_list) to
 * the clients.
 * @see lclif_send_server_list
 * @see s_login_dbs::server
 * @see PACKET_AC_ACCEPT_LOGIN
 **/
struct mmo_char_server {
	uint32 pos; // Position in list
	char name[20];
	struct socket_data *session;
	uint32 ip;
	uint16 port;

	uint16 users; ///< user count on this server
	uint16 type;  ///< 0=normal, 1=maintenance, 2=over 18, 3=paying, 4=P2P (@see e_char_server_type in mmo.h)
	uint16 new_;  ///< should display as 'new'?
};
INDEX_MAP_STRUCT_DECL(s_mmo_char_server_list, struct mmo_char_server);

/**
 * Login.c Interface
 **/
struct login_interface {
	struct DBMap *auth_db;
	struct mutex_data *auth_db_mutex;

	struct DBMap *online_db;
	struct mutex_data *online_db_mutex;

	struct Login_Config *config;
	struct AccountDB* accounts;
	struct ers_collection_t *ers_collection;

	enum accept_login_errorcode (*mmo_auth) (struct login_session_data* sd, bool isServer);
	enum accept_login_errorcode (*mmo_auth_new) (const char* userid, const char* pass, const char sex, const char* last_ip);
	int (*waiting_disconnect_timer) (struct timer_interface *tm, int tid, int64 tick, int id, intptr_t data);
	struct DBData (*create_online_user) (const struct DBKey_s *key, va_list args);
	struct online_login_data* (*add_online_user) (int char_server, int account_id);
	void (*remove_online_user) (int account_id);
	int (*online_db_setoffline) (const struct DBKey_s *key, struct DBData *data, va_list ap);
	int (*online_data_cleanup_sub) (const struct DBKey_s *key, struct DBData *data, va_list ap);
	int (*online_data_cleanup) (struct timer_interface *tm, int tid, int64 tick, int id, intptr_t data);
	int (*sync_ip_addresses) (struct timer_interface *tm, int tid, int64 tick, int id, intptr_t data);
	bool (*account_load) (int account_id, struct mmo_account *out_acc);

	bool (*check_encrypted) (const char* str1, const char* str2, const char* passwd);
	bool (*check_password) (const char* md5key, int passwdenc, const char* passwd, const char* refpass);
	uint32 (*lan_subnet_check) (uint32 ip);

	void (*fromchar_accinfo_failure) (struct socket_data *session, int u_fd, int u_aid, int map_id);
	void (*fromchar_accinfo_success) (struct socket_data *session, int account_id, int u_fd, int u_aid, int u_group, int map_id, struct mmo_account *acc);

	void (*fromchar_account) (struct socket_data *session, int account_id, struct mmo_account *acc, int request_id);
	void (*fromchar_account_update_state) (int account_id, unsigned char flag, unsigned int state);
	void (*fromchar_auth_ack) (struct socket_data *session, int account_id, uint32 login_id1, uint32 login_id2, uint8 sex, int request_id, struct login_auth_node* node);
	void (*fromchar_change_sex_other) (int account_id, char sex);
	void (*fromchar_pong) (struct socket_data *session);

	void (*fromchar_parse_auth)                 (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_update_users)         (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_request_change_email) (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_account_data)         (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_ping)                 (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_change_email)         (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_account_update)       (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_ban)                  (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_change_sex)           (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_account_reg2)         (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_unban)                (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_account_online)       (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_account_offline)      (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_online_accounts)      (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_request_account_reg2) (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_update_wan_ip)        (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_all_offline)          (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_change_pincode)       (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_wrong_pincode)        (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_accinfo)              (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	enum parsefunc_rcode (*parse_fromchar) (struct s_receive_action_data *act);

	void (*kick) (struct login_session_data* sd);
	void (*auth_ok) (struct login_session_data* sd);
	void (*auth_failed) (struct login_session_data* sd, int result);

	bool (*client_login) (struct socket_data *session, struct login_session_data *sd);
	bool (*client_login_otp) (struct socket_data *session, struct login_session_data *sd);
	void (*client_login_mobile_otp_request) (struct socket_data *session, struct login_session_data *sd);
	void (*char_server_connection_status) (struct socket_data *session, struct login_session_data* sd, uint8 status);

	void (*parse_request_connection) (struct s_receive_action_data *act, struct login_session_data* sd, const char *ip, uint32 ipl);

	void (*config_set_defaults) (void);
	bool (*config_read) (const char *filename, bool included);
	bool (*config_read_inter) (const char *filename, struct config_t *config, bool imported);
	bool (*config_read_console) (const char *filename, struct config_t *config, bool imported);
	bool (*config_read_log) (const char *filename, struct config_t *config, bool imported);
	bool (*config_read_account) (const char *filename, struct config_t *config, bool imported);
	bool (*config_read_permission) (const char *filename, struct config_t *config, bool imported);
	bool (*config_read_permission_hash) (const char *filename, struct config_t *config, bool imported);
	bool (*config_read_permission_blacklist) (const char *filename, struct config_t *config, bool imported);
	bool (*config_read_users) (const char *filename, struct config_t *config, bool imported);
	void (*clear_dnsbl_servers) (void);
	void (*config_set_dnsbl_servers) (struct config_setting_t *setting);
	void (*clear_client_hash_nodes) (void);
	void (*config_set_md5hash) (struct config_setting_t *setting);
	uint16 (*convert_users_to_colors) (uint16 users);
	bool (*check_client_version) (struct login_session_data *sd);

	char *LOGIN_CONF_NAME;
	char *NET_CONF_NAME; ///< Network configuration filename
};

/**
 * Login inter-server parse function
 * @readlock g_char_server_list_lock
 * @see login_parse_fromchar
 **/
typedef void (LoginInterParseFunc)(struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);

/**
 * Login inter-server packet information
 * @see lchrif_init
 **/
struct login_inter_packet_entry {
	int16 len;
	LoginInterParseFunc *pFunc;
};

/**
 * lchrif Interface
 **/
struct lchrif_interface {
	/**
	 * Inter-server packet database
	 * This database doesn't have any locks because it's not meant to be edited
	 * after it's creation.
	 * @see lchrif->init
	 **/
	struct DBMap *packet_db; // int16 packet_id -> struct login_inter_packet_entry*
	struct login_inter_packet_entry *packet_list;

	void (*server_destroy) (struct mmo_char_server *server);
	void (*server_reset) (struct mmo_char_server *server);
	struct mmo_char_server *(*server_find) (struct socket_data *session);
	void (*on_disconnect) (struct mmo_char_server *server);

	void (*init) (void);
	void (*final) (void);
};

#ifdef HERCULES_CORE
void login_defaults(void);
void lchrif_defaults(void);
#endif // HERCULES_CORE

HPShared struct login_interface *login;
HPShared struct lchrif_interface *lchrif;

#endif /* LOGIN_LOGIN_H */
