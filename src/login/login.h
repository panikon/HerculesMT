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

/**
 * SC_NOTIFY_BAN Error code list
 * @see lclif_connection_error
 * @see login_auth_ok
 **/
enum notify_ban_errorcode {
	NBE_SUCCESS = -1,		// Internal use, success
	NBE_DISCONNECTED,		// "Disconnected from server"
	NBE_SERVER_CLOSED,		// "Server closed"
	NBE_DUPLICATE_ID,		// "Someone has logged in with this ID"
	NBE_TIME_GAP,			// "You've been disconected due to a time gap between you and the server."
	NBE_JAMMED_SHORTLY,		// "Server is jammed due to overpopulation. Please try again shortly."
	NBE_UNDERAGED,			// "You are underaged and cannot join this server"
	NBE_NO_PAY,				// "You didn't pay for this ID. Would you like to pay for it now? Opens window"
	NBE_JAMMED_MINUTES,		// "Server is jammed due to overpopulation. Please try again in a few minutes."
	NBE_RECOGNIZES,			// "Server still recognizes your last log-in. Please try again after a few minutes."
	NBE_IC_FULL,			// "IP capacity of this Internet Cafe is full. Would you like to pay the personal base?"
	NBE_NO_PAYING_TIME,		// "You are out of available paying time. Game will be shutdown automatically."
	NBE_ACCOUNT_POSTPONED,	// "Your account was postponed"
	NBE_POLICY_CHANGE,		// "Will be disconnected temporarily due to a change in payment policy. Please connect again."
	NBE_IP_MISMATCH,		// "Will be terminated because do not match between your IP address and approved IP in Account server."
	NBE_IC_OVERPAYMENT,		// "Will be terminated to prevent overpayment of meter-rate system in Internet Cafe.
							// Please connect with unaproved IP to use personal meter-rate system."
	//15 - Disconnected from server
	NBE_JPN_REJOIN = 16,	// "A message to the BETA users in Japan -> Let's rejoin kung-ho"
	NBE_JPN_BILLS,			// "A message to users terminated in Japan -> Pay bills, Pay twice"
	NBE_ALREADY_ON,			// "You already have been connected to another account server."
	//18-99 - Disconnected
	NBE_IC_2_ACCOUNTS = 100,// "There are more than 2 account connected to PC cafe payment system.
							// Please check this matter"
	NBE_30_PLAYERS_SAME_IP,	// "More than 30 players sharing the same IP have logged into the game for an hour.
							// Please check this matter."
	NBE_10_PLAYERS_SAME_IP,	// "More than 10 connections sharing the same IP have logged into the game for an hour.
							// Please check this matter."
	NBE_PRIVACY_POLICY,		// "You need to accept the Privacy Policy from gravity in order to use the service."
	NBE_USER_AGREEMENT,		// "You need to accept User Agreement in order to use the service."
	NBE_NONEXISTENT_ID,		// "Incorrect or nonexitent ID."
	//106 - DISCONNECTED
	NBE_IP_BLOCKED = 107,	// "Unavailable to access in your connected IP"
	NBE_IP_BLOCKED2,		// "Unavailable to access in your connected IP"
	NBE_BRUTE_FORCE,		// "Unable to access for a while due to errors on password 6 times"
	NBE_INVALID_TEST_CHAR,	// "Sorry. Do not access selected character for the test."
	//111 - 112 - DISCONNECTED
	NBE_KRN_LAW,			// "By the korean law, the under 16 age users will be limited to play games
							// until 0~6am and game will be closed."
	NBE_NO_MSG,				// "NO MSG"
	//115 - 225 - DISCONNECTED
	NBE_LAST = 255
};

/**
 * AC_REFUSE_LOGIN error code list
 * @see struct HEADER_AC_REFUSE_LOGIN / _R2 / R3
 * @see lclif_send_auth_failed
 * @see login_auth_failed
 * @see login_mmo_auth
 **/
enum accept_login_errorcode {
	/**
	 * These codes should hold the negative value of the equivalent code in
	 * notify_ban_error_code (PACKET_SC_NOTIFY_BAN)
	 **/
	ALE_BRUTE_FORCE = -109,				// Brute force attempt (NBE_BRUTE_FORCE)
	ALE_DUPLICATE_ID = -2,				// Already logged in   (NBE_DUPLICATE_ID)

	ALE_OK = -1,						// Authentication successful
	// Valid error codes for AC_REFUSE_LOGIN
	ALE_UNREGISTERED = 0,				// "Unregistered account"
	ALE_INCORRECT_PASS = 1,				// "Incorrect password"
	ALE_EXPIRED_ID = 2,					// "This ID is expired"
	ALE_REJECTED = 3,					// "Rejected from Server"
	ALE_LOGIN_UNAVAILABLE,				// "Login is currently unavailable"
	ALE_INVALID_VERSION,				// Invalid client version
	ALE_PROHIBITED,						// "Your are Prohibited to log in until %s"
	ALE_JAMMED,							// "Server is jammed due to overpopulation"
	ALE_SAKRAY,							// "You cannot access sakray with this user account"
	MSI_REFUSE_BAN_BY_DBA,				// "MSI_REFUSE_BAN_BY_DBA (9)"
	MSI_REFUSE_EMAIL_NOT_CONFIRMED,		// "MSI_REFUSE_EMAIL_NOT_CONFIRMED (10)"
	MSI_REFUSE_BAN_BY_GM,				// "MSI_REFUSE_BAN_BY_GM (11)"
	MSI_REFUSE_TEMP_BAN_FOR_DBWORK,		// "MSI_REFUSE_TEMP_BAN_FOR_DBWORK (12)"
	MSI_REFUSE_SELF_LOCK,				// "MSI_SELF_LOCK (13)"
	MSI_REFUSE_NOT_PERMITTED_GROUP,		// "MSI_REFUSE_NOT_PERMITTED_GROUP (14)"
	MSI_REFUSE_WAIT_FOR_SAKRAY_ACTIVE,	// "MSI_REFUSE_WAIT_FOR_SAKRAY_ACTIVE (15)"
	ALE_NO_WINDOW,						// Doesn't display anything (no window either)
	ALE_BAN_HACK,						// "This account has been used for illegal program or hacking program. Block time: %s"
	ALE_TAMPERED_CLIENT,				// "The possibility of exposure to illegal program, PC virus infection
										// or Hacking Tool has been detected. Please execute licensed client. Our team is
										// trying to make a best environment for Ro players. (18)"
	/**
	 * One-Time Password Security (OTP)
	 * Probably the client will send PACKET_CA_OTP_AUTH_REQ and then an OTP will be generated to
	 * username and then sent via some other service
	 * When OTP is not available ALE_NO_OTP should be the answer
	 * When the typed OTP is incorrect ALE_FAILED_OTP should be the answer and not ALE_INCORRED_PASS
	 **/
	ALE_NO_OTP,							// "There is no OTP information, contact administrator (19)"
	ALE_FAILED_OTP,						// "fail to recognizing OTP (20)"
	// 21 - 98 ALE_REJECTED
	ALE_ID_REMOVED = 99,				// "This ID has been removed" - closes client window
	ALE_LOGIN_INFO_REMAINS,				// "Login information remains at %s"
	ALE_HACKING_INVESTIGATION,			// "Account has been locked for a hacking investigation. Please contact the GM Team for more information"
	ALE_BUG_INVESTIGATION,				// "This account has been temporarily prohibited from login due to a bug-related investigation"
	ALE_DELETING_CHAR,					// "Login is temporarily unavailable while this character is being deleted"
	ALE_DELETING_SPOUSE,				// "Login is temporarily unavailable while your spouse character is being deleted"
	ALE_UNSAFE_COM_KEY,					// "This account has not confirmed by connecting to the safe communication key. Please connect
										// to the key first, and then login into the game"
	ALE_MOBILE_AUTHENTICATION,			// "Mobile Authentication"
	ALE_107,							// Rejected
	ALE_CANNOT_CONNECT_FREE_SERVER,		// "An user of this server cannot connect to free server"
	ALE_EXPIRED_PASS,					// "Your password has expired. Please log in again"
	ALE_NO_MSG,							// "NO MSG" - closes client window
	// 111 - 239 ALE_REJECTED
	ALE_OPEN_SITE = 240,				// Prompt asking something in korean, if OK opens ragnarok.co.kr
	// ... 255 with same message as ALE_REJECTED
	// 256 starts repeating the messages, i.e 256 = ALE_UNREGISTERED
	ALE_LAST = 255
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

	void (*fromchar_accinfo) (struct socket_data *session, int account_id, int u_fd, int u_aid, int u_group, int map_fd, struct mmo_account *acc);
	void (*fromchar_account) (struct socket_data *session, int account_id, struct mmo_account *acc);
	void (*fromchar_account_update_other) (int account_id, unsigned int state);
	void (*fromchar_auth_ack) (struct socket_data *session, int account_id, uint32 login_id1, uint32 login_id2, uint8 sex, int request_id, struct login_auth_node* node);
	void (*fromchar_ban) (int account_id, time_t timestamp);
	void (*fromchar_change_sex_other) (int account_id, char sex);
	void (*fromchar_pong) (struct socket_data *session);

	void (*fromchar_parse_auth) (struct s_receive_action_data *act, struct mmo_char_server *server);
	void (*fromchar_parse_update_users) (struct s_receive_action_data *act, struct mmo_char_server *server);
	void (*fromchar_parse_request_change_email) (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_account_data) (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_ping) (struct s_receive_action_data *act);
	void (*fromchar_parse_change_email) (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_account_update) (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_ban) (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_change_sex)      (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_account_reg2)    (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_unban)           (struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip);
	void (*fromchar_parse_account_online)  (struct s_receive_action_data *act, struct mmo_char_server *server);
	void (*fromchar_parse_account_offline) (struct s_receive_action_data *act);
	void (*fromchar_parse_online_accounts) (struct s_receive_action_data *act, struct mmo_char_server *server);
	void (*fromchar_parse_request_account_reg2) (struct s_receive_action_data *act);
	void (*fromchar_parse_update_wan_ip) (struct s_receive_action_data *act, struct mmo_char_server *server);
	void (*fromchar_parse_all_offline)   (struct s_receive_action_data *act, struct mmo_char_server *server);
	void (*fromchar_parse_change_pincode) (struct s_receive_action_data *act);
	bool (*fromchar_parse_wrong_pincode) (struct s_receive_action_data *act);
	void (*fromchar_parse_accinfo) (struct s_receive_action_data *act);
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
 * Login.c Interface
 **/
struct lchrif_interface {
	void (*server_destroy) (struct mmo_char_server *server);
	void (*server_reset) (struct mmo_char_server *server);
	struct mmo_char_server *(*server_find) (struct socket_data *session);
	void (*on_disconnect) (struct mmo_char_server *server);
};

#ifdef HERCULES_CORE
void login_defaults(void);
void lchrif_defaults(void);
#endif // HERCULES_CORE

HPShared struct login_interface *login;
HPShared struct lchrif_interface *lchrif;

#endif /* LOGIN_LOGIN_H */
