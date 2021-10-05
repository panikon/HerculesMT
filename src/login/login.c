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

#include "login.h"

#include "login/HPMlogin.h"
#include "login/account.h"
#include "login/ipban.h"
#include "login/loginlog.h"
#include "login/lclif.h"
#include "login/packets_ac_struct.h"
#include "common/HPM.h"
#include "common/cbasetypes.h"
#include "common/conf.h"
#include "common/core.h"
#include "common/ers.h"
#include "common/db.h"
#include "common/memmgr.h"
#include "common/md5calc.h"
#include "common/nullpo.h"
#include "common/packetsstatic_len.h"
#include "common/random.h"
#include "common/showmsg.h"
#include "common/socket.h"
#include "common/strlib.h"
#include "common/sysinfo.h"
#include "common/timer.h"
#include "common/utils.h"
#include "common/action.h"

#include "common/packets_wa_struct.h"
#include "common/packets_aw_struct.h"
#include "common/mutex.h"
#include "common/rwlock.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h> // stat()

/** @file
 * Implementation of the login interface.
 */

static struct login_interface login_s;
struct login_interface *login;
static struct lchrif_interface lchrif_s;
struct lchrif_interface *lchrif;
static struct Login_Config login_config_;

static struct Account_engine account_engine;

// account database
static AccountDB *accounts = NULL;

/**
 * List of all connected character servers
 **/
struct s_mmo_char_server_list g_char_server_list = INDEX_MAP_STATIC_INITIALIZER(MEMORYTYPE_SHARED);
struct rwlock_data *g_char_server_list_lock = NULL;
#define CHAR_SERVER_LIST_INITIAL_LENGTH 1 // Initial length of char-server list (multiplied by 32)

/**
 * Timeout in ms to remove an inactive account after login
 * (accounts that disconnect from login and don't connect to char)
 * @see online_db
 **/
#define AUTH_TIMEOUT 30000

/**
 * Linked list of all action workers active in this server with the
 * char-server that's attached.
 **/
struct s_action_information {
	uint32_t index;
	struct mmo_char_server *server;
};
struct linkdb_node *action_information = NULL; // <server> <s_action_information>
struct mutex_data *action_information_mutex = NULL;

/**
 * Creates a new entry in online_db
 *
 * @see login_add_online_user
 * @see DBCreateData
 */
static struct DBData login_create_online_user(const struct DBKey_s *key, va_list args)
{
	struct online_login_data* p;
	CREATE(p, struct online_login_data, 1);
	p->account_id = key->u.i;
	p->char_server = ACC_WAIT_TIMEOUT;
	p->waiting_disconnect = INVALID_TIMER;
	return DB->ptr2data(p);
}

/**
 * Adds account to online_db and attaches server to it.
 *
 * @param char_server Server position in list
 **/
static struct online_login_data* login_add_online_user(int char_server, int account_id)
{
	struct online_login_data* p;

	mutex->lock(login->online_db_mutex);
	p = idb_ensure(login->online_db, account_id, login->create_online_user);
	mutex->unlock(login->online_db_mutex);

	p->char_server = char_server;
	if( p->waiting_disconnect != INVALID_TIMER )
	{
		timer->delete(p->waiting_disconnect, login->waiting_disconnect_timer);
		p->waiting_disconnect = INVALID_TIMER;
	}
	return p;
}

/**
 * Removes account from online_db
 * @see login_online_data_cleanup_sub
 **/
static void login_remove_online_user(int account_id)
{
	struct online_login_data* p;

	mutex->lock(login->online_db_mutex);

	p = (struct online_login_data*)idb_get(login->online_db, account_id);
	if(p) {
		if( p->waiting_disconnect != INVALID_TIMER )
			timer->delete(p->waiting_disconnect, login->waiting_disconnect_timer);

		idb_remove(login->online_db, account_id);
	}

	mutex->unlock(login->online_db_mutex);
}

/**
 * Timeout between disconnection from login-server and reconnection to char-server
 * @see TimerFunc
 **/
static int login_waiting_disconnect_timer(struct timer_interface *tm, int tid, int64 tick, int id, intptr_t data)
{
	mutex->lock(login->online_db_mutex);
	struct online_login_data* p = (struct online_login_data*)idb_get(login->online_db, id);
	mutex->unlock(login->online_db_mutex);

	if( p != NULL && p->waiting_disconnect == tid && p->account_id == id )
	{
		p->waiting_disconnect = INVALID_TIMER;
		login->remove_online_user(id);

		mutex->lock(login->auth_db_mutex);
		idb_remove(login->auth_db, id);
		mutex->unlock(login->auth_db_mutex);
	}
	return 0;
}

/**
 * @see DBApply
 * @mutex login->online_db_mutex
 */
static int login_online_db_setoffline(const struct DBKey_s *key, struct DBData *data, va_list ap)
{
	struct online_login_data* p = DB->data2ptr(data);
	int server_id = va_arg(ap, int);
	nullpo_ret(p);
	if( server_id == ACC_WAIT_TIMEOUT )
	{
		p->char_server = ACC_WAIT_TIMEOUT;
		if( p->waiting_disconnect != INVALID_TIMER )
		{
			timer->delete(p->waiting_disconnect, login->waiting_disconnect_timer);
			p->waiting_disconnect = INVALID_TIMER;
		}
	}
	else if( p->char_server == server_id )
		p->char_server = ACC_DISCONNECTED; //Char server disconnected.
	return 0;
}

/**
 * Removes all online users that have an invalid char_server (ACC_DISCONNECTED)
 * @see DBApply (online_db)
 * @see login_online_data_cleanup
 * @mutex login->online_db_mutex
 */
static int login_online_data_cleanup_sub(const struct DBKey_s *key, struct DBData *data, va_list ap)
{
	struct online_login_data *character= DB->data2ptr(data);
	struct timer_interface *tm = NULL;

	tm = va_arg(ap, struct timer_interface *);
	/**
	 * We don't call login->remove_online_user because it'll try to reacquire the mutex
	 * and also we can't know if this function is being called from the timer thread
	 * (with all the heap locks) or from an action worker, so we need to use the
	 * timer interface provided by the system.
	 **/
	if(character->char_server == ACC_DISCONNECTED) {
		if(character->waiting_disconnect != INVALID_TIMER)
			tm->delete(character->waiting_disconnect, login->waiting_disconnect_timer);
		login->online_db->remove(login->online_db, *key, NULL);
	}

	return 0;
}

/**
 * Periodic removal of invalid entries in online_db
 * @see TimerFunc
 **/
static int login_online_data_cleanup(struct timer_interface *tm, int tid, int64 tick, int id, intptr_t data)
{
	mutex->lock(login->online_db_mutex);
	login->online_db->foreach(login->online_db, login->online_data_cleanup_sub, tm);
	mutex->unlock(login->online_db_mutex);
	return 0;
}


/**
 * Sends a packet to all connected char-servers except the provided one
 * (wos: without our self)
 *
 * @param self Server session to be excluded (if NULL ignored, sends to all)
 * @param buf  Packet data
 * @param len  buf len
 * @return c   Count of servers that were notified
 * Acquires mutexes of all server sessions
 **/
static int charif_sendallwos(struct socket_data *self, uint8 *buf, size_t len)
{
	int i, c;

	nullpo_ret(buf);

	rwlock->write_lock(g_char_server_list_lock);
	for (i = 0, c = 0; i < INDEX_MAP_LENGTH(g_char_server_list); ++i)
	{
		struct mmo_char_server *server = INDEX_MAP_INDEX(g_char_server_list, i);
		if(!server)
			continue;
		if(server->session == self)
			continue;

		mutex->lock(server->session->mutex);
		if(!socket_io->session_marked_removal(server->session)) {
			WFIFOHEAD(server->session,len, false);
			memcpy(WFIFOP(server->session,0), buf, len);
			WFIFOSET(server->session,len);
			++c;
		}
		mutex->unlock(server->session->mutex);
	}
	rwlock->write_unlock(g_char_server_list_lock);

	return c;
}

/**
 * Finds server object of given session
 *
 * @retval NULL Failed to find server
 * @readlock g_char_server_list_lock
 **/
static struct mmo_char_server *lchrif_server_find(struct socket_data *session)
{
	struct mmo_char_server *server;
	struct login_session_data *sd = session->session_data;

	if(sd->login_id1 < 0 && sd->login_id1 >= INDEX_MAP_LENGTH(g_char_server_list))
		return NULL;

	server = INDEX_MAP_INDEX(g_char_server_list, sd->login_id1);
	if(!server || server->session != session)
		return NULL;

	return server;
}

/**
 * Forces disconnection and then removes server from server list
 *
 * Acquires write lock
 **/
static void lchrif_server_destroy(struct mmo_char_server *server)
{
	rwlock->write_lock(g_char_server_list_lock);

	if(server) {
		INDEX_MAP_REMOVE(g_char_server_list, server->pos);
		socket_io->session_disconnect_guard(server->session);

		mutex->lock(action_information_mutex);
		struct s_action_information *data = linkdb_erase(&action_information, server);
		if(data) {
			data->server = NULL;
			linkdb_insert(&action_information, NULL, data);
		}
		mutex->unlock(action_information_mutex);

		aFree(server);
	}

	rwlock->write_unlock(g_char_server_list_lock);
}


/**
 * Notifies char-server of shutdown procedure and sets all characters offline
 * and then frees all data related to that server.
 *
 * Tries to acquire write lock (lchrif->server_destroy)
 * Tries to acquire session->mutex
 **/
static void lchrif_server_reset(struct mmo_char_server *server)
{
	struct login_session_data *sd = server->session->session_data;

	mutex->lock(login->online_db_mutex);
	login->online_db->foreach(login->online_db, login->online_db_setoffline, sd->account_id);
	mutex->unlock(login->online_db_mutex);

	lchrif->server_destroy(server);
}


/**
 * Called upon char-server disconnection
 *
 * Tries to acquire write lock (lchrif->server_destroy)
 * Tries to acquire session->mutex (lchrif->server_reset)
 **/
static void lchrif_on_disconnect(struct mmo_char_server *server)
{
	ShowStatus("Char-server '%s' has disconnected.\n",
		server->name);

	lchrif->server_reset(server);
}

/**
 * Finalizes lchrif
 **/
static void lchrif_final(void)
{
	db_clear(lchrif->packet_db);
	aFree(lchrif->packet_list);
}

/**
 * Initializes lchrif
 **/
static void lchrif_init(void)
{
	struct {
		int16 packet_id;
		int16 packet_len;
		LoginInterParseFunc *pFunc;
	} inter_packet[] = {
#define packet_def(name, fname) { HEADER_ ## name, sizeof(struct PACKET_ ## name), login->fromchar_parse_ ## fname }
#define packet_def2(name, fname, len) { HEADER_ ## name, (len), login->fromchar_parse_ ## fname }
		packet_def(WA_AUTH,                         auth),
		packet_def(WA_SEND_USERS_COUNT,             update_users),
		packet_def(WA_REQUEST_CHANGE_DEFAULT_EMAIL, request_change_email),
		packet_def(WA_REQUEST_ACCOUNT,              account_data),
		packet_def(WA_PING,                         ping),
		packet_def(WA_REQUEST_CHANGE_EMAIL,         change_email),
		packet_def(WA_UPDATE_STATE,                 account_update),
		packet_def(WA_BAN,                          ban),
		packet_def(WA_SEX_CHANGE,                   change_sex),
		packet_def2(WA_ACCOUNT_REG2,                account_reg2, -1),
		packet_def(WA_UNBAN,                        unban),
		packet_def(WA_ACCOUNT_ONLINE,               account_online),
		packet_def(WA_ACCOUNT_OFFLINE,              account_offline),
		packet_def2(WA_ACCOUNT_LIST,                online_accounts, -1),
		packet_def(WA_ACCOUNT_REG2_REQ,             request_account_reg2),
		packet_def(WA_WAN_UPDATE,                   update_wan_ip),
		packet_def(WA_SET_ALL_OFFLINE,              all_offline),
		packet_def(WA_PINCODE_UPDATE,               change_pincode),
		packet_def(WA_PINCODE_FAILED,               wrong_pincode),
		packet_def(WA_ACCOUNT_INFO_REQUEST,         accinfo),
#undef packet_def
#undef packet_def2
	};
	size_t length = ARRAYLENGTH(inter_packet);

	lchrif->packet_list = aMalloc(sizeof(*lchrif->packet_list)*length);
	lchrif->packet_db = idb_alloc(DB_OPT_BASE);

	for(size_t i = 0; i < length; i++) {
		int exists;
		lchrif->packet_list[i].len = inter_packet[i].packet_len;
		lchrif->packet_list[i].pFunc = inter_packet[i].pFunc;
		exists = idb_put(lchrif->packet_db,
			inter_packet[i].packet_id, &lchrif->packet_list[i]);
		if(exists) {
			ShowWarning("lchrif_init: Packet 0x%x already in database, replacing...\n",
				inter_packet[i].packet_id);
		}
	}
}

//-----------------------------------------------------
// periodic ip address synchronization
//-----------------------------------------------------
static int login_sync_ip_addresses(struct timer_interface *tm, int tid, int64 tick, int id, intptr_t data)
{
	uint8 buf[2];
	ShowInfo("IP Sync in progress...\n");
	WBUFW(buf,0) = HEADER_AW_IP_UPDATE;
	charif_sendallwos(NULL, buf, 2);
	return 0;
}


//-----------------------------------------------------
// encrypted/unencrypted password check (from eApp)
//-----------------------------------------------------
static bool login_check_encrypted(const char *str1, const char *str2, const char *passwd)
{
	char tmpstr[64+1], md5str[32+1];

	nullpo_ret(str1);
	nullpo_ret(str2);
	nullpo_ret(passwd);
	safesnprintf(tmpstr, sizeof(tmpstr), "%s%s", str1, str2);
	md5->string(tmpstr, md5str);

	return (0==strcmp(passwd, md5str));
}

static bool login_check_password(const char *md5key, int passwdenc, const char *passwd, const char *refpass)
{
	nullpo_ret(passwd);
	nullpo_ret(refpass);
	if(passwdenc == PWENC_NONE) {
		return (0==strcmp(passwd, refpass));
	} else {
		// password mode set to PWENC_ENCRYPT  -> md5(md5key, refpass) enable with <passwordencrypt></passwordencrypt>
		// password mode set to PWENC_ENCRYPT2 -> md5(refpass, md5key) enable with <passwordencrypt2></passwordencrypt2>

		return ((passwdenc&PWENC_ENCRYPT) && login->check_encrypted(md5key, refpass, passwd)) ||
		       ((passwdenc&PWENC_ENCRYPT2) && login->check_encrypted(refpass, md5key, passwd));
	}
}

/**
 * Acquires account lock and then tries to load account with provided id.
 *
 * @param account_id Account to be loaded
 * @param out_acc    Object to be filled with account information
 * @return bool Account found
 **/
static bool login_account_load(int account_id, struct mmo_account *out_acc)
{
	accounts->lock(accounts);
	bool ret = accounts->load_num(accounts, out_acc, account_id);
	accounts->unlock(accounts);
	return ret;
}


/**
 * Checks whether the given IP comes from LAN or WAN.
 *
 * @param ip IP address to check.
 * @retval 0 if it is a WAN IP.
 * @return the appropriate LAN server address to send, if it is a LAN IP.
 */
static uint32 login_lan_subnet_check(uint32 ip)
{
	return socket_io->lan_subnet_check(ip, NULL);
}

/**
 * 0x2713 AW_AUTH_ACK
 * Answers char-server request to authenticate an account
 **/
static void login_fromchar_auth_ack(struct socket_data *session,
	int account_id, uint32 login_id1, uint32 login_id2, uint8 sex,
	int request_id, struct login_auth_node *node
) {
	WFIFOHEAD(session,33, true);
	WFIFOW(session,0) = HEADER_AW_AUTH_ACK;
	WFIFOL(session,2) = account_id;
	WFIFOL(session,6) = login_id1;
	WFIFOL(session,10) = login_id2;
	WFIFOB(session,14) = sex;
	if (node)
	{
		WFIFOB(session,15) = 0;// ok
		WFIFOL(session,16) = request_id;
		WFIFOL(session,20) = node->version;
		WFIFOB(session,24) = node->clienttype;
		WFIFOL(session,25) = node->group_id;
		WFIFOL(session,29) = (unsigned int)node->expiration_time;
	}
	else
	{
		WFIFOB(session,15) = 1;// auth failed
		WFIFOL(session,16) = request_id;
		WFIFOL(session,20) = 0;
		WFIFOB(session,24) = 0;
		WFIFOL(session,25) = 0;
		WFIFOL(session,29) = 0;
	}
	WFIFOSET(session,33);
}

/**
 * 0x2712 WA_AUTH
 * Authenticates an account
 * @see LoginInterParseFunc
 **/
static void login_fromchar_parse_auth(struct s_receive_action_data *act, struct mmo_char_server *server, const char *ip)
{
	struct login_auth_node* node;

	int account_id = RFIFOL(act,2);
	uint32 login_id1 = RFIFOL(act,6);
	uint32 login_id2 = RFIFOL(act,10);
	uint8 sex = RFIFOB(act,14);
	uint32 ipl = ntohl(RFIFOL(act,15));
	int request_id = RFIFOL(act,19);

	mutex->lock(login->auth_db_mutex);
	node = (struct login_auth_node*)idb_get(login->auth_db, account_id);
	mutex->unlock(login->auth_db_mutex);

	if( core->runflag == LOGINSERVER_ST_RUNNING &&
		node != NULL &&
		node->account_id == account_id &&
		node->login_id1  == login_id1 &&
		node->login_id2  == login_id2 &&
		node->sex        == sex_num2str(sex) &&
		node->ip         == ipl )
	{// found
		ShowStatus("Char-server '%s': authentication of the account %d accepted (ip: %s).\n",
			server->name, account_id, socket_io->ip2str(ipl, NULL));

		// send ack
		login->fromchar_auth_ack(act->session, account_id, login_id1, login_id2, sex, request_id, node);
		// each auth entry can only be used once
		mutex->lock(login->auth_db_mutex);
		idb_remove(login->auth_db, account_id);
		mutex->unlock(login->auth_db_mutex);
	}
	else
	{// authentication not found
		ShowStatus("Char-server '%s': authentication of the account %d REFUSED (ip: %s).\n",
			server->name, account_id, socket_io->ip2str(ipl, NULL));
		login->fromchar_auth_ack(act->session, account_id, login_id1, login_id2, sex, request_id, NULL);
	}
}

/**
 * 0x2714 WA_SEND_USERS_COUNT
 * Updates user count of a char-server with received value.
 * Character-server broadcasts this information at fixed intervals
 * @see chr->broadcast_user_count
 **/
static void login_fromchar_parse_update_users(struct s_receive_action_data *act,
	struct mmo_char_server *server, const char *ip
) {
	int users = RFIFOL(act,2);

	rwlock->read_unlock(g_char_server_list_lock);
	rwlock->write_lock(g_char_server_list_lock);
	if(server->users != users) {
		server->users = users;
		ShowStatus("set users %s : %d\n", server->name, users);
	}
	rwlock->write_unlock(g_char_server_list_lock);
	rwlock->read_lock(g_char_server_list_lock);
}

/**
 * 0x2715 WA_REQUEST_CHANGE_DEFAULT_EMAIL
 * Changes e-mail of provided account
 *
 * TODO: This packet is not implemented in the char-server, implement an ack as well.
 *       The ip that's being reported as being of the account is the ip of the char-server.
 **/
static void login_fromchar_parse_request_change_email(struct s_receive_action_data *act,
	struct mmo_char_server *server, const char *const ip
) {
	struct mmo_account acc;
	char email[40];

	int account_id = RFIFOL(act,2);
	safestrncpy(email, RFIFOP(act,6), 40);
	remove_control_chars(email);


	if( e_mail_check(email) == 0 ) {
		ShowNotice("Char-server '%s': Attempt to create an e-mail on an account with "
			"a default e-mail REFUSED - e-mail is invalid (account: %d, ip: %s)\n",
			server->name, account_id, ip);
		return;
	}
	if( !login->account_load(account_id, &acc) || strcmp(acc.email, "a@a.com") == 0 || acc.email[0] == '\0' ) {
		ShowNotice("Char-server '%s': Attempt to create an e-mail on an account with "
			"a default e-mail REFUSED - account doesn't exist or e-mail of account "
			"isn't default e-mail (account: %d, ip: %s).\n",
			server->name, account_id, ip);
		return;
	}

	memcpy(acc.email, email, sizeof(acc.email));
	ShowNotice("Char-server '%s': Create an e-mail on an account with a "
		"default e-mail (account: %d, new e-mail: %s, ip: %s).\n",
		server->name, account_id, email, ip);
	// Save
	accounts->lock(accounts);
	accounts->save(accounts, &acc);
	accounts->unlock(accounts);
}

/**
 * 0x2717 AW_REQUEST_ACCOUNT_ACK
 * Sends account data to char-server
 *
 * @param account_id Id of the data
 * @param acc Account data (when NULL no data was found)
 **/
static void login_fromchar_account(struct socket_data *session,
	int account_id, struct mmo_account *acc, int request_id
) {
	WFIFOHEAD(session, sizeof(struct PACKET_AW_REQUEST_ACCOUNT_ACK), true);
	WFIFOW(session, 0) = HEADER_AW_REQUEST_ACCOUNT_ACK;
	WFIFOL(session, 2) = account_id;
	WFIFOL(session, 6) = request_id;
	if(!acc) {
		WFIFOB(session, 10) = false;
		memset(WFIFOP(session, 11),
			0,
			sizeof(struct PACKET_AW_REQUEST_ACCOUNT_ACK)-11);
	} else {
		WFIFOB(session, 10) = true;
		safestrncpy(WFIFOP(session, 11), acc->email, sizeof(acc->email));
		WFIFOL(session, 51) = (uint32)acc->expiration_time;
		WFIFOL(session, 55) = acc->group_id;
		WFIFOB(session, 59) = acc->char_slots;
		if(acc->pincode[0] == '\0')
			memset(WFIFOP(session, 60),'\0',sizeof(acc->pincode));
		else
			safestrncpy(WFIFOP(session, 60), acc->pincode, sizeof(acc->pincode));
		safestrncpy(WFIFOP(session, 65), acc->birthdate, sizeof(acc->birthdate));
		WFIFOL(session, 76) = acc->pincode_change;
	}
	WFIFOSET(session, sizeof(struct PACKET_AW_REQUEST_ACCOUNT_ACK));
}

/**
 * 0x2716 WA_REQUEST_ACCOUNT
 * Char-server account data request
 **/
static void login_fromchar_parse_account_data(struct s_receive_action_data *act,
	struct mmo_char_server *server, const char *const ip
) {
	struct mmo_account acc;

	int account_id = RFIFOL(act,2);
	int request_id = RFIFOL(act,6);

	if( !login->account_load(account_id, &acc) )
	{
		ShowNotice("Char-server '%s': account %d NOT found (ip: %s).\n",
			server->name, account_id, ip);
		login->fromchar_account(act->session, account_id, NULL, request_id);
		return;
	}

	login->fromchar_account(act->session, account_id, &acc, request_id);
}

/**
 * 0x2718 AW_PONG
 **/
static void login_fromchar_pong(struct socket_data *session)
{
	WFIFOHEAD(session, 2, true);
	WFIFOW(session,0) = HEADER_AW_PONG;
	WFIFOSET(session,2);
}

/**
 * 0x2719 WA_PING
 **/
static void login_fromchar_parse_ping(struct s_receive_action_data *act,
	struct mmo_char_server *server, const char *const ip
) {
	login->fromchar_pong(act->session);
}

/**
 * 0x2722 WA_REQUEST_CHANGE_EMAIL
 * Map-server request through char-server to change e-mail of an account
 * TODO: Implement ack.
 *       The ip that's being reported as being of the account is the ip of the car-server.
 **/
static void login_fromchar_parse_change_email(struct s_receive_action_data *act,
	struct mmo_char_server *server, const char *const ip
) {
	struct mmo_account acc;
	char actual_email[40];
	char new_email[40];

	int account_id = RFIFOL(act,2);
	safestrncpy(actual_email, RFIFOP(act,6), 40);
	safestrncpy(new_email, RFIFOP(act,46), 40);

	if( e_mail_check(actual_email) == 0 ) {
		ShowNotice("Char-server '%s': Attempt to modify an e-mail on an account "
		"(@email GM command), but actual email is invalid (account: %d, ip: %s)\n",
			server->name, account_id, ip);
		return;
	}

	if( e_mail_check(new_email) == 0 ) {
		ShowNotice("Char-server '%s': Attempt to modify an e-mail on an account "
			"(@email GM command) with a invalid new e-mail (account: %d, ip: %s)\n",
			server->name, account_id, ip);
		return;
	}

	if( strcmpi(new_email, "a@a.com") == 0 ) {
		ShowNotice("Char-server '%s': Attempt to modify an e-mail on an account "
			"(@email GM command) with a default e-mail (account: %d, ip: %s)\n",
			server->name, account_id, ip);
		return;
	}

	if( !login->account_load(account_id, &acc) ) {
		ShowNotice("Char-server '%s': Attempt to modify an e-mail on an account "
			"(@email GM command), but account doesn't exist (account: %d, ip: %s).\n",
			server->name, account_id, ip);
		return;
	}

	if( strcmpi(acc.email, actual_email) != 0 )
		ShowNotice("Char-server '%s': Attempt to modify an e-mail on an account "
			"(@email GM command), but actual e-mail is incorrect "
			"(account: %d (%s), actual e-mail: %s, proposed e-mail: %s, ip: %s).\n",
			server->name, account_id, acc.userid, acc.email, actual_email, ip);
	else {
		safestrncpy(acc.email, new_email, sizeof(acc.email));
		ShowNotice("Char-server '%s': Modify an e-mail on an account "
			"(@email GM command) (account: %d (%s), new e-mail: %s, ip: %s).\n",
			server->name, account_id, acc.userid, new_email, ip);
		// Save
		accounts->lock(accounts);
		accounts->save(accounts, &acc);
		accounts->unlock(accounts);
	}

}

/**
 * 0x2731 AW_UPDATE_STATE <account_id>.L <flag>.B <state>.L
 *  Notifies all char-servers of a state change and then they relay to all map-servers via
 *  0xb214 WZ_UPDATE_STATE
 * @param id     account-id
 * @param flag   0 Account status change
 *               1 Account ban
 *               2 Character ban (not supported by login-server!)
 * @param state  timestamp of ban due date (flag 1)
 *               ALE_UNREGISTERED to ALE_UNAUTHORIZED +1 @see enum notify_ban_errorcode
 *               100: message 421 ("Your account has been totally erased")
 *               Other values: message 420 ("Your account is no longer authorized")
 **/
static void login_fromchar_account_update_state(int account_id, unsigned char flag, unsigned int state)
{
	uint8 buf[11];

	if(flag == 2) {
		ShowWarning("login_fromchar_account_update_state: Invalid flag, 2 is reserved "
			"for character update, login-server can only ask for account updates!\n");
		return;
	}
	WBUFW(buf,0) = HEADER_AW_UPDATE_STATE;
	WBUFL(buf,2) = account_id;
	WBUFB(buf,6) = flag;
	WBUFL(buf,7) = state;
	charif_sendallwos(NULL, buf, 11);
}

/**
 * 0x2724 WA_UPDATE_STATE
 * Char-server request to update state of an account
 **/
static void login_fromchar_parse_account_update(struct s_receive_action_data *act,
	struct mmo_char_server *server, const char *const ip
) {
	struct mmo_account acc;

	int account_id = RFIFOL(act,2);
	unsigned int state = RFIFOL(act,6);

	if( !login->account_load(account_id, &acc) ) {
		ShowNotice("Char-server '%s': Error of Status change (account: %d not found, "
			"suggested status %u, ip: %s).\n",
			server->name, account_id, state, ip);
		return;
	}

	if( acc.state == state ) {
		ShowNotice("Char-server '%s':  Error of Status change - actual status is "
			"already the good status (account: %d, status %u, ip: %s).\n",
			server->name, account_id, state, ip);
		return;
	}

	ShowNotice("Char-server '%s': Status change (account: %d, new status %u, "
		"ip: %s).\n", server->name, account_id, state, ip);

	acc.state = state;
	// Save
	accounts->lock(accounts);
	accounts->save(accounts, &acc);
	accounts->unlock(accounts);

	// notify other servers
	if (state != 0) {
		login->fromchar_account_update_state(account_id, 0, state);
	}
}

/**
 * 0x2725 WA_BAN
 * Ban request
 **/
static void login_fromchar_parse_ban(struct s_receive_action_data *act,
	struct mmo_char_server *server, const char *const ip
) {
	struct mmo_account acc;

	int account_id = RFIFOL(act,2);
	int year       = RFIFOW(act,6);
	int month      = RFIFOW(act,8);
	int mday       = RFIFOW(act,10);
	int hour       = RFIFOW(act,12);
	int min        = RFIFOW(act,14);
	int sec        = RFIFOW(act,16);

	if (!login->account_load(account_id, &acc)) {
		ShowNotice("Char-server '%s': Error of ban request (account: %d not found, ip: %s).\n",
			server->name, account_id, ip);
		return;
	}

	time_t timestamp;
	struct tm *tmtime;
	if (acc.unban_time == 0 || acc.unban_time < time(NULL))
		timestamp = time(NULL); // new ban
	else
		timestamp = acc.unban_time; // add to existing ban
	tmtime = localtime(&timestamp);
	tmtime->tm_year += year;
	tmtime->tm_mon  += month;
	tmtime->tm_mday += mday;
	tmtime->tm_hour += hour;
	tmtime->tm_min  += min;
	tmtime->tm_sec  += sec;
	timestamp = mktime(tmtime);
	if (timestamp == -1) {
		ShowNotice("Char-server '%s': Error of ban request (account: %d, invalid date, ip: %s).\n",
			server->name, account_id, ip);
	} else if( timestamp <= time(NULL) || timestamp == 0 ) {
		ShowNotice("Char-server '%s': Error of ban request (account: %d, new date unbans "
			"the account, ip: %s).\n", 
			server->name, account_id, ip);
	} else {
		char tmpstr[24];
		timestamp2string(tmpstr, sizeof(tmpstr), timestamp, login->config->date_format);
		ShowNotice("Char-server '%s': Ban request (account: %d, new final "
			"date of banishment: %ld (%s), ip: %s).\n",
		    server->name, account_id, (long)timestamp, tmpstr, ip);

		acc.unban_time = timestamp;

		// Save
		accounts->lock(accounts);
		accounts->save(accounts, &acc);
		accounts->unlock(accounts);

		login->fromchar_account_update_state(account_id, 1, (unsigned int)timestamp);
	}
}

/**
 * 0x2723 AW_SEX_BROADCAST
 * Sends new sex to all servers
 **/
static void login_fromchar_change_sex_other(int account_id, char sex)
{
	unsigned char buf[7];
	WBUFW(buf,0) = HEADER_AW_SEX_BROADCAST;
	WBUFL(buf,2) = account_id;
	WBUFB(buf,6) = sex_str2num(sex);
	charif_sendallwos(NULL, buf, 7);
}

/**
 * 0x2727 WA_SEX_CHANGE
 * Reverses sex of an account
 **/
static void login_fromchar_parse_change_sex(struct s_receive_action_data *act,
	struct mmo_char_server *server, const char *const ip
) {
	struct mmo_account acc;

	int account_id = RFIFOL(act,2);

	if( !login->account_load(account_id, &acc) ) {
		ShowNotice("Char-server '%s': Error of sex change (account: %d not found, ip: %s).\n",
			server->name, account_id, ip);
		return;
	}

	if( acc.sex == 'S' ) {
		ShowNotice("Char-server '%s': Error of sex change - account to change is a Server account "
		"(account: %d, ip: %s).\n",
			server->name, account_id, ip);
		return;
	}

	char sex = ( acc.sex == 'M' ) ? 'F' : 'M'; //Change gender

	ShowNotice("Char-server '%s': Sex change (account: %d, new sex %c, ip: %s).\n",
		server->name, account_id, sex, ip);

	acc.sex = sex;
	// Save
	accounts->lock(accounts);
	accounts->save(accounts, &acc);
	accounts->unlock(accounts);

	// announce to other servers
	login->fromchar_change_sex_other(account_id, sex);
}

/**
 * 0x2728 WA_ACCOUNT_REG2
 * Global account reg saving
 **/
static void login_fromchar_parse_account_reg2(struct s_receive_action_data *act,
	struct mmo_char_server *server, const char *const ip
) {
	struct mmo_account acc;

	int account_id = RFIFOL(act,4);

	accounts->lock(accounts);
	if( !accounts->load_num(accounts, &acc, account_id) )
		ShowStatus("Char-server '%s': receiving (from the char-server) of account_reg2 "
		"(account: %d not found, ip: %s).\n",
			server->name, account_id, ip);
	else {
		account->mmo_save_accreg2(accounts,act,account_id,RFIFOL(act, 8));
	}
	accounts->unlock(accounts);
}

/**
 * 0x272a WA_UNBAN
 * Unban request
 **/
static void login_fromchar_parse_unban(struct s_receive_action_data *act,
	struct mmo_char_server *server, const char *const ip
) {
	struct mmo_account acc;

	int account_id = RFIFOL(act,2);

	accounts->lock(accounts);
	if( !accounts->load_num(accounts, &acc, account_id) )
		ShowNotice("Char-server '%s': Error of Unban request "
			"(account: %d not found, ip: %s).\n",
			server->name, account_id, ip);
	else
	if( acc.unban_time == 0 )
		ShowNotice("Char-server '%s': Error of Unban request "
			"(account: %d, no change for unban date, ip: %s).\n",
			server->name, account_id, ip);
	else
	{
		ShowNotice("Char-server '%s': Unban request (account: %d, ip: %s).\n",
			server->name, account_id, ip);
		acc.unban_time = 0;
		accounts->save(accounts, &acc);
		// FIXME/TODO: Shouldn't this be broadcast as AW_BAN_BROADCAST is?
	}
	accounts->unlock(accounts);
}

/**
 * 0x272b WA_ACCOUNT_ONLINE
 * Char-server request to turn account online
 **/
static void login_fromchar_parse_account_online(struct s_receive_action_data *act,
	struct mmo_char_server *server, const char *ip
) {
	struct login_session_data *sd = server->session->session_data;
	login->add_online_user(sd->account_id, RFIFOL(act,2));
}

/**
 * 0x272c WA_ACCOUNT_OFFLINE
 * Char-server request to turn account offline
 **/
static void login_fromchar_parse_account_offline(struct s_receive_action_data *act,
	struct mmo_char_server *server, const char *ip
) {
	login->remove_online_user(RFIFOL(act,2));
}

/**
 * 0x272d WA_ACCOUNT_LIST
 * Receives list of all online accounts
 **/
static void login_fromchar_parse_online_accounts(struct s_receive_action_data *act,
	struct mmo_char_server *server, const char *ip
) {
	uint32 i, users;
	struct login_session_data *sd = server->session->session_data;
	int id = sd->account_id;

	mutex->lock(login->online_db_mutex);

	//Set all chars from this char-server offline first
	login->online_db->foreach(login->online_db, login->online_db_setoffline, id);
	users = RFIFOW(act,6);
	for (i = 0; i < users; i++) {
		int aid = RFIFOL(act,6+i*4);
		struct online_login_data *p = idb_ensure(login->online_db, aid, login->create_online_user);
		p->char_server = id;
		if (p->waiting_disconnect != INVALID_TIMER)
		{
			timer->delete(p->waiting_disconnect, login->waiting_disconnect_timer);
			p->waiting_disconnect = INVALID_TIMER;
		}
	}

	mutex->unlock(login->online_db_mutex);
}

/**
 * 0x272e WA_ACCOUNT_REG2_REQ
 * Request of a global account reg
 **/
static void login_fromchar_parse_request_account_reg2(struct s_receive_action_data *act,
	struct mmo_char_server *server, const char *const ip
) {
	int account_id = RFIFOL(act,2);
	int char_id = RFIFOL(act,6);

	accounts->lock(accounts);
	account->mmo_send_accreg2(accounts,act->session,account_id,char_id);
	accounts->unlock(accounts);
}

/**
 * 0x2736 WA_WAN_UPDATE
 * Parses request to update WAN IP
 **/
static void login_fromchar_parse_update_wan_ip(struct s_receive_action_data *act,
	struct mmo_char_server *server, const char *const ipl
) {
	uint32 ip = ntohl(RFIFOL(act,2));

	rwlock->read_unlock(g_char_server_list_lock);
	rwlock->write_lock(g_char_server_list_lock);
	server->ip = ip;
	ShowInfo("Updated IP of Server #%d to %u.%u.%u.%u.\n",
		server->pos, CONVIP(ip));
	rwlock->write_unlock(g_char_server_list_lock);
	rwlock->read_lock(g_char_server_list_lock);
}

/**
 * 0x2737 WA_SET_ALL_OFFLINE
 * Sets all accounts from provided char-server offline
 **/
static void login_fromchar_parse_all_offline(struct s_receive_action_data *act,
	struct mmo_char_server *server, const char *const ip
) {
	struct login_session_data *sd = server->session->session_data;
	ShowInfo("Setting accounts from char-server %d offline.\n", server->pos);

	mutex->lock(login->online_db_mutex);
	login->online_db->foreach(login->online_db, login->online_db_setoffline,
		sd->account_id);
	mutex->unlock(login->online_db_mutex);
}

/**
 * 0x2738 WA_PINCODE_UPDATE
 * Pincode update request
 **/
static void login_fromchar_parse_change_pincode(struct s_receive_action_data *act,
	struct mmo_char_server *server, const char *const ip
) {
	struct mmo_account acc;

	accounts->lock(accounts);
	if (accounts->load_num(accounts, &acc, RFIFOL(act,2))) {
		safestrncpy(acc.pincode, RFIFOP(act,6), sizeof(acc.pincode));
		acc.pincode_change = ((unsigned int)time(NULL));
		accounts->save(accounts, &acc);
	}
	accounts->unlock(accounts);
}

/**
 * 0x2739 WA_PINCODE_FAILED
 * Failed to provided valid pincode
 **/
static void login_fromchar_parse_wrong_pincode(struct s_receive_action_data *act,
	struct mmo_char_server *server, const char *const ip
) {
	struct mmo_account acc;

	if( login->account_load(RFIFOL(act,2), &acc) ) {
		mutex->lock(login->online_db_mutex);
		struct online_login_data* ld = (struct online_login_data*)idb_get(login->online_db,acc.account_id);
		mutex->unlock(login->online_db_mutex);

		if (ld == NULL)
			return;

		loginlog->log(socket_io->host2ip(acc.last_ip), acc.userid, 100, "PIN Code check failed");
	}

	login->remove_online_user(acc.account_id);
}

static void login_fromchar_accinfo_failure(struct socket_data *session,
	int u_fd, int u_aid, int map_id
) {
	WFIFOHEAD(session, sizeof(struct PACKET_AW_ACCOUNT_INFO_FAILURE), true);
	WFIFOW(session, 0) = HEADER_AW_ACCOUNT_INFO_FAILURE;
	WFIFOL(session, 2) = map_id;
	WFIFOL(session, 6) = u_fd;
	WFIFOL(session, 10) = u_aid;
	WFIFOSET(session, sizeof(struct PACKET_AW_ACCOUNT_INFO_FAILURE));
}

static void login_fromchar_accinfo_success(struct socket_data *session, int account_id,
	int u_fd, int u_aid, int u_group, int map_id, struct mmo_account *acc
) {
	size_t cur = 0;
	WFIFOHEAD(session, sizeof(struct PACKET_AW_ACCOUNT_INFO_SUCCESS), true);
	cur += sizeof((WFIFOW(session, cur) = HEADER_AW_ACCOUNT_INFO_SUCCESS));
	cur += sizeof((WFIFOL(session, cur) = map_id));
	cur += sizeof((WFIFOL(session, cur) = u_fd));
	cur += sizeof((WFIFOL(session, cur) = u_aid));
	cur += sizeof((WFIFOL(session, cur) = account_id));

	memcpy(WFIFOP(session, cur), acc->userid, NAME_LENGTH);
	cur += NAME_LENGTH;
	memcpy(WFIFOP(session, cur), acc->email, sizeof(acc->email));
	cur += sizeof(acc->email);
	cur += sizeof((WFIFOL(session, cur) = acc->group_id));
	memcpy(WFIFOP(session, cur), acc->lastlogin, sizeof(acc->lastlogin));
	cur += sizeof(acc->lastlogin);
	cur += sizeof((WFIFOL(session, cur) = acc->logincount));
	cur += sizeof((WFIFOL(session, cur) = acc->state));
	memcpy(WFIFOP(session, cur), acc->birthdate, sizeof(acc->birthdate));
	cur += sizeof(acc->birthdate);

	WFIFOSET(session, sizeof(struct PACKET_AW_ACCOUNT_INFO_SUCCESS));
}

/**
 * 0x2740 WA_ACCOUNT_INFO_REQUEST
 * Account info request from map server (relayed through char-server)
 * [Map]   0x3007 ZW_ACCINFO_REQUEST
 * [Char]  0x2740 WA_ACCOUNT_INFO_REQUEST
 * [Login] AW_ACCOUNT_INFO_SUCCESS / AW_ACCOUNT_INFO_FAILURE
 * [Char]  0x3807 WZ_MSG_TO_FD
 **/
static void login_fromchar_parse_accinfo(struct s_receive_action_data *act,
	struct mmo_char_server *server, const char *const ip
) {
	struct mmo_account acc;
	int32_t account_id = RFIFOL(act, 2);
	int32_t u_fd       = RFIFOL(act, 6);
	int32_t u_aid      = RFIFOL(act, 10);
	int32_t u_group    = RFIFOL(act, 14);
	int32_t map_fd     = RFIFOL(act, 18);
	if (login->account_load(account_id, &acc)) {
		login->fromchar_accinfo_success(act->session, account_id, u_fd, u_aid, u_group, map_fd, &acc);
	} else {
		login->fromchar_accinfo_failure(act->session, u_fd, u_aid, map_fd);
	}
}


/**
 * Default action parsing for char-servers
 *
 * A connection only uses this parser after PACKET_CA_CHARSERVERCONNECT
 **/
static enum parsefunc_rcode login_parse_fromchar(struct s_receive_action_data *act)
{
	rwlock->read_lock(g_char_server_list_lock);
	struct mmo_char_server *server = lchrif->server_find(act->session);

	if (!server)
	{// not a char server
		rwlock->read_unlock(g_char_server_list_lock);
		mutex->lock(act->session->mutex);
		if(!socket_io->session_marked_removal(act->session))
			ShowDebug("login_parse_fromchar: Disconnecting invalid session #%d (is not a char-server)\n",
				act->session->id);
		socket_io->session_disconnect(act->session);
		mutex->unlock(act->session->mutex);
		return PACKET_VALID;
	}

	mutex->lock(act->session->mutex);
	if( socket_io->session_marked_removal(act->session) )
	{
		rwlock->read_unlock(g_char_server_list_lock);
		mutex->unlock(act->session->mutex);
		lchrif->on_disconnect(server);
		return PACKET_VALID;
	}
	mutex->unlock(act->session->mutex);

	uint32 ipl;
	char ip[16];
	ipl = server->ip;
	socket_io->ip2str(ipl, ip);

	while (RFIFOREST(act) >= 2) {
		uint16 command = RFIFOW(act,0);

		if (VECTOR_LENGTH(HPM->packets[hpParse_FromChar]) > 0) {
			int result = HPM->parse_packets(act,command,hpParse_FromChar);
			if (result == 1)
				continue;

			if (result == 2)
				goto unlock_list_return_incomplete;
		}

		struct login_inter_packet_entry *packet_data;
		packet_data = DB->data2ptr(lchrif->packet_db->get_safe(lchrif->packet_db, DB->i2key(command)));
		if(!packet_data) {
			ShowError("login_parse_fromchar: Unknown packet 0x%x from a char-server! Disconnecting!\n", command);
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
		packet_data->pFunc(act, server, ip);
		RFIFOSKIP(act, packet_len);
	} // while
	// Fall-through
unlock_list_return:
	rwlock->read_unlock(g_char_server_list_lock);
	return PACKET_VALID;

unlock_list_return_incomplete:
	rwlock->read_unlock(g_char_server_list_lock);
	return PACKET_INCOMPLETE;
}


/**
 * Creates a new account
 *
 * @return Code to be used in login_auth_failed
 * @see login_mmo_auth
 **/
static enum accept_login_errorcode login_mmo_auth_new(const char *userid, const char *pass, const char sex, const char *last_ip)
{
	static int num_regs = 0; // registration counter
	static int64 new_reg_tick = 0;
	int64 tick = timer->gettick();
	struct mmo_account acc;

	nullpo_retr(3, userid);
	nullpo_retr(3, pass);
	nullpo_retr(3, last_ip);
	//Account Registration Flood Protection by [Kevin]
	if( new_reg_tick == 0 )
		new_reg_tick = timer->gettick();
	if (DIFF_TICK(tick, new_reg_tick) < 0 && num_regs >= login->config->allowed_regs) {
		ShowNotice("Account registration denied (registration limit exceeded)\n");
		return ALE_REJECTED;
	}

	if (login->config->new_acc_length_limit && (strlen(userid) < 4 || strlen(pass) < 4))
		return ALE_INCORRECT_PASS;

	// check for invalid inputs
	if( sex != 'M' && sex != 'F' )
		return ALE_UNREGISTERED;

	// check if the account doesn't exist already
	accounts->lock(accounts);
	bool acc_found = accounts->load_str(accounts, &acc, userid);
	accounts->unlock(accounts);
	if( acc_found ) {
		ShowNotice("Attempt of creation of an already existing account "
			"(account: %s_%c, pass: %s, received pass: %s)\n",
			userid, sex, acc.pass, pass);
		return ALE_INCORRECT_PASS;
	}

	memset(&acc, '\0', sizeof(acc));
	acc.account_id = -1; // assigned by account db
	safestrncpy(acc.userid, userid, sizeof(acc.userid));
	safestrncpy(acc.pass, pass, sizeof(acc.pass));
	acc.sex = sex;
	safestrncpy(acc.email, "a@a.com", sizeof(acc.email));
	acc.expiration_time = (login->config->start_limited_time != -1) ? time(NULL) + login->config->start_limited_time : 0;
	safestrncpy(acc.lastlogin, "(never)", sizeof(acc.lastlogin));
	safestrncpy(acc.last_ip, last_ip, sizeof(acc.last_ip));
	safestrncpy(acc.birthdate, "0000-00-00", sizeof(acc.birthdate));
	safestrncpy(acc.pincode, "\0", sizeof(acc.pincode));
	acc.pincode_change = 0;
	acc.char_slots = 0;

	accounts->lock(accounts);
	bool create = accounts->create(accounts, &acc);
	accounts->unlock(accounts);
	if( !create )
		return ALE_UNREGISTERED; // Failed to create an account

	ShowNotice("Account creation (account %s, id: %d, pass: %s, sex: %c)\n", acc.userid, acc.account_id, acc.pass, acc.sex);

	if( DIFF_TICK(tick, new_reg_tick) > 0 ) {// Update the registration check.
		num_regs = 0;
		new_reg_tick = tick + login->config->time_allowed*1000;
	}
	++num_regs;

	return ALE_OK;
}

/**
 * Checks if the version of the client is to be accepted by the server
 *
 * @return True client can connect
 **/
static bool login_check_client_version(struct login_session_data *sd)
{
	// if check flags enabled skip version check with flags pattern present in version field
	if (!login->config->check_client_flags || (sd->version & 0x80000000) == 0) {
		if (login->config->check_client_version && sd->version != login->config->client_version_to_connect)
			return false;
	}

	// check flags only if enabled and if client flags set to known value
	if (login->config->check_client_flags && (sd->version & 0x80000000) != 0) {
		const uint32 emulatorFlags = 0x80000000 | sysinfo->fflags();
		if (emulatorFlags != sd->version) {
			if (login->config->report_client_flags_error)
				ShowNotice("Wrong client flags detected (account: %s, received flags: 0x%x)\n", sd->userid, sd->version);
			return false;
		}
	}

	return true;
}


/**
 * Authenticates a new connection and fills session data with relevant information.
 *
 * @param sd       Session data to be filled
 * @param isServer Connection from a character-server
 * @return Code to be used in login_auth_failed
 **/
static enum accept_login_errorcode login_mmo_auth(struct login_session_data *sd, bool isServer)
{
	struct mmo_account acc;
	size_t len;

	char ip[16];
	nullpo_ret(sd);
	uint32 client_addr = sd->session->client_addr;
	socket_io->ip2str(client_addr, ip);

	// DNS Blacklist check
	if (login->config->use_dnsbl) {
		char r_ip[16];
		char ip_dnsbl[256];
		uint8* sin_addr = (uint8*)&client_addr;
		int i;

		sprintf(r_ip, "%u.%u.%u.%u", sin_addr[0], sin_addr[1], sin_addr[2], sin_addr[3]);

		for (i = 0; i < VECTOR_LENGTH(login->config->dnsbl_servers); i++) {
			char *dnsbl_server = VECTOR_INDEX(login->config->dnsbl_servers, i);
			sprintf(ip_dnsbl, "%s.%s", r_ip, trim(dnsbl_server));
			if (socket_io->host2ip(ip_dnsbl)) {
				ShowInfo("DNSBL: (%s) Blacklisted. User Kicked.\n", r_ip);
				return ALE_REJECTED;
			}
		}

	}

	//Client Version check
	if(!isServer && !login->check_client_version(sd))
		return ALE_INVALID_VERSION;

	len = strnlen(sd->userid, NAME_LENGTH);

	// Account creation with _M/_F
	if (login->config->new_account_flag) {
		if (len > 2 && sd->passwd[0] != '\0' && // valid user and password lengths
			sd->passwdenc == PWENC_NONE && // unencoded password
			sd->userid[len-2] == '_' && memchr("FfMm", sd->userid[len-1], 4)) // _M/_F suffix
		{
			int result;

			// remove the _M/_F suffix
			len -= 2;
			sd->userid[len] = '\0';

			result = login->mmo_auth_new(sd->userid, sd->passwd, TOUPPER(sd->userid[len+1]), ip);
			if(result != ALE_OK)
				return result;// Failed to make account. [Skotlex].
		}
	}

	if( len <= 0 ) { /** a empty password is fine, a userid is not. **/
		ShowNotice("Empty userid (received pass: '%s', ip: %s)\n", sd->passwd, ip);
		return ALE_UNREGISTERED;
	}

	accounts->lock(accounts);
	bool acc_found = accounts->load_str(accounts, &acc, sd->userid);
	accounts->unlock(accounts);
	if( !acc_found ) {
		ShowNotice("Unknown account (account: %s, received pass: %s, ip: %s)\n", sd->userid, sd->passwd, ip);
		return ALE_UNREGISTERED;
	}

	if( !login->check_password(sd->md5key, sd->passwdenc, sd->passwd, acc.pass) ) {
		ShowNotice("Invalid password (account: '%s', pass: '%s', received pass: '%s', ip: %s)\n", sd->userid, acc.pass, sd->passwd, ip);
		return ALE_INCORRECT_PASS;
	}

	if( acc.unban_time != 0 && acc.unban_time > time(NULL) ) {
		char tmpstr[24];
		timestamp2string(tmpstr, sizeof(tmpstr), acc.unban_time, login->config->date_format);
		ShowNotice("Connection refused (account: %s, pass: %s, banned until %s, ip: %s)\n", sd->userid, sd->passwd, tmpstr, ip);
		return ALE_PROHIBITED; // Your are Prohibited to log in until %s
	}

	if( acc.state != 0 ) {
		ShowNotice("Connection refused (account: %s, pass: %s, state: %u, ip: %s)\n",
			sd->userid, sd->passwd, acc.state, ip);
		return acc.state - 1;
	}

	if (login->config->client_hash_check && !isServer) {
		struct client_hash_node *node = NULL;
		bool match = false;

		for (node = login->config->client_hash_nodes; node; node = node->next) {
			if( acc.group_id < node->group_id )
				continue;
			if( *node->hash == '\0' // Allowed to login without hash
			 || (sd->has_client_hash && memcmp(node->hash, sd->client_hash, 16) == 0 ) // Correct hash
			) {
				match = true;
				break;
			}
		}

		if( !match ) {
			char smd5[33];
			int i;

			if( !sd->has_client_hash ) {
				ShowNotice("Client didn't send client hash (account: %s, pass: %s, ip: %s)\n", sd->userid, sd->passwd, ip);
				return ALE_INVALID_VERSION;
			}

			for( i = 0; i < 16; i++ )
				sprintf(&smd5[i * 2], "%02x", sd->client_hash[i]);
			smd5[32] = '\0';

			ShowNotice("Invalid client hash (account: %s, pass: %s, sent md5: %s, ip: %s)\n", sd->userid, sd->passwd, smd5, ip);
			return ALE_TAMPERED_CLIENT;
		}
	}

	ShowNotice("Authentication accepted (account: %s, id: %d, ip: %s)\n", sd->userid, acc.account_id, ip);

	// update session data
	sd->account_id = acc.account_id;
	sd->login_id1 = rnd() + 1;
	sd->login_id2 = rnd() + 1;
	safestrncpy(sd->lastlogin, acc.lastlogin, sizeof(sd->lastlogin));
	sd->sex = acc.sex;
	sd->group_id = (uint8)acc.group_id;
	sd->expiration_time = acc.expiration_time;

	// update account data
	timestamp2string(acc.lastlogin, sizeof(acc.lastlogin), time(NULL), "%Y-%m-%d %H:%M:%S");
	safestrncpy(acc.last_ip, ip, sizeof(acc.last_ip));
	acc.unban_time = 0;
	acc.logincount++;

	accounts->lock(accounts);
	accounts->save(accounts, &acc);
	accounts->unlock(accounts);

	if( sd->sex != 'S' && sd->account_id < START_ACCOUNT_NUM )
		ShowWarning("Account %s has account id %d! Account IDs must be over %d to work properly!\n", sd->userid, sd->account_id, START_ACCOUNT_NUM);

	return ALE_OK;
}

/**
 * 0x2734 AW_KICK
 * Requests char-server to kick an authenticated character
 **/
static void login_kick(struct login_session_data *sd)
{
	uint8 buf[6];
	nullpo_retv(sd);
	WBUFW(buf,0) = HEADER_AW_KICK;
	WBUFL(buf,2) = sd->account_id;
	charif_sendallwos(NULL, buf, 6);
}

/**
 * Sends notification of successful authentication to client
 * There are still fail states (e.g. no character server connected) that we notify via lclif->connection_error
 **/
static void login_auth_ok(struct login_session_data *sd)
{
	uint32 ip;
	struct login_auth_node* node;

	nullpo_retv(sd);

	ip = sd->session->client_addr;
	if( core->runflag != LOGINSERVER_ST_RUNNING )
	{
		// players can only login while running
		lclif->connection_error(sd->session, NBE_SERVER_CLOSED);
		return;
	}

	/**
	 * FIXME/TODO: Maybe change these checks from login to char-server
	 * and use HC_REFUSE_ENTER (0x006c) instead?
	 **/
	if (login->config->group_id_to_connect >= 0
		&& sd->group_id != login->config->group_id_to_connect
	) {
		ShowStatus("Connection refused: the required group id for connection is %d "
			"(account: %s, group: %d).\n",
			login->config->group_id_to_connect, sd->userid, sd->group_id);
		lclif->connection_error(sd->session, NBE_SERVER_CLOSED);
		return;
	} else if (login->config->min_group_id_to_connect >= 0
		&& login->config->group_id_to_connect == -1
		&& sd->group_id < login->config->min_group_id_to_connect
	) {
		ShowStatus("Connection refused: the minimum group id required for connection "
			"is %d (account: %s, group: %d).\n", login->config->min_group_id_to_connect,
			sd->userid, sd->group_id);
		lclif->connection_error(sd->session, NBE_SERVER_CLOSED);
		return;
	}

	mutex->lock(login->online_db_mutex);
	struct online_login_data* data = (struct online_login_data*)idb_get(login->online_db, sd->account_id);
	if( data )
	{// account is already marked as online!
		switch(data->char_server) {
			// Client already authenticated but did not access char-server yet
			case ACC_WAIT_TIMEOUT:
				mutex->unlock(login->online_db_mutex);
				// Do not let a new connection until auth_db timeout, this could be an attack.
				ShowNotice("User '%s' still waiting authentication timeout - Rejected\n",
					sd->userid);
				lclif->connection_error(sd->session, NBE_RECOGNIZES);
				return;
#if 0
				// wipe previous session
				mutex->lock(login->auth_db_mutex);
				idb_remove(login->auth_db, sd->account_id);
				mutex->unlock(login->auth_db_mutex);

				login->remove_online_user(sd->account_id);
				data = NULL;
				break;
#endif
			case ACC_DISCONNECTED:
			case ACC_CHAR_VALID:
			default: // Request char servers to kick this account out. [Skotlex]
				mutex->unlock(login->online_db_mutex);
				ShowNotice("User '%s' is already online - Rejected.\n", sd->userid);
				login->kick(sd);
				if( data->waiting_disconnect == INVALID_TIMER )
					data->waiting_disconnect = timer->add(timer->gettick()+AUTH_TIMEOUT,
						login->waiting_disconnect_timer, sd->account_id, 0);

				lclif->connection_error(sd->session, NBE_DUPLICATE_ID);
				return;
		}
	}
	mutex->unlock(login->online_db_mutex);

	rwlock->read_lock(g_char_server_list_lock);
	bool server_list = lclif->server_list(sd, &g_char_server_list);
	rwlock->read_unlock(g_char_server_list_lock);
	if (!server_list) {
		// if no char-server, don't send void list of servers, just disconnect the player with proper message
		ShowStatus("Connection refused: there is no char-server online (account: %s).\n",
			sd->userid);
		lclif->connection_error(sd->session, NBE_SERVER_CLOSED);
		return;
	}

	loginlog->log(ip, sd->userid, 100, "login ok");
	ShowStatus("Connection of the account '%s' accepted.\n", sd->userid);

	// create temporary auth entry
	CREATE(node, struct login_auth_node, 1);
	node->account_id = sd->account_id;
	node->login_id1 = sd->login_id1;
	node->login_id2 = sd->login_id2;
	node->sex = sd->sex;
	node->ip = ip;
	node->version = sd->version;
	node->clienttype = sd->clienttype;
	node->group_id = sd->group_id;
	node->expiration_time = sd->expiration_time;

	mutex->lock(login->auth_db_mutex);
	idb_put(login->auth_db, sd->account_id, node);
	mutex->unlock(login->auth_db_mutex);


	// mark client as 'online'
	data = login->add_online_user(ACC_WAIT_TIMEOUT, sd->account_id);

	// schedule deletion of this node
	data->waiting_disconnect = timer->add(timer->gettick()+AUTH_TIMEOUT, login->waiting_disconnect_timer, sd->account_id, 0);
}

/**
 * Logs failed attempt to login and then sends packet via lclif->auth_failed
 **/
static void login_auth_failed(struct login_session_data *sd, int result)
{
	uint32 ip;
	time_t ban_time = 0;
	nullpo_retv(sd);

	ip = sd->session->client_addr;
	if (login->config->log_login) {
		const char* error;
		// @see enum accept_login_errorcode
		switch( result ) {
		case   0: error = "Unregistered ID."; break; // 0 = Unregistered ID
		case   1: error = "Incorrect Password."; break; // 1 = Incorrect Password
		case   2: error = "Account Expired."; break; // 2 = This ID is expired
		case   3: error = "Rejected from server."; break; // 3 = Rejected from Server
		case   4: error = "Blocked by GM."; break; // 4 = You have been blocked by the GM Team
		case   5: error = "Not latest game EXE."; break; // 5 = Your Game's EXE file is not the latest version
		case   6: error = "Banned."; break; // 6 = Your are Prohibited to log in until %s
		case   7: error = "Server Over-population."; break; // 7 = Server is jammed due to over populated
		case   8: error = "Account limit from company"; break; // 8 = No more accounts may be connected from this company
		case   9: error = "Ban by DBA"; break; // 9 = MSI_REFUSE_BAN_BY_DBA
		case  10: error = "Email not confirmed"; break; // 10 = MSI_REFUSE_EMAIL_NOT_CONFIRMED
		case  11: error = "Ban by GM"; break; // 11 = MSI_REFUSE_BAN_BY_GM
		case  12: error = "Working in DB"; break; // 12 = MSI_REFUSE_TEMP_BAN_FOR_DBWORK
		case  13: error = "Self Lock"; break; // 13 = MSI_REFUSE_SELF_LOCK
		case  14: error = "Not Permitted Group"; break; // 14 = MSI_REFUSE_NOT_PERMITTED_GROUP
		case  15: error = "Not Permitted Group"; break; // 15 = MSI_REFUSE_NOT_PERMITTED_GROUP
		case  99: error = "Account gone."; break; // 99 = This ID has been totally erased
		case 100: error = "Login info remains."; break; // 100 = Login information remains at %s
		case 101: error = "Hacking investigation."; break; // 101 = Account has been locked for a hacking investigation. Please contact the GM Team for more information
		case 102: error = "Bug investigation."; break; // 102 = This account has been temporarily prohibited from login due to a bug-related investigation
		case 103: error = "Deleting char."; break; // 103 = This character is being deleted. Login is temporarily unavailable for the time being
		case 104: error = "Deleting spouse char."; break; // 104 = This character is being deleted. Login is temporarily unavailable for the time being
		default : error = "Unknown Error."; break;
		}

		loginlog->log(ip, sd->userid, result, error);
	}

	if (result == 1 && login->config->dynamic_pass_failure_ban && !socket_io->trusted_ip_check(ip))
		ipban->log(ip); // log failed password attempt

	if (result == 6) {
		struct mmo_account acc = { 0 };
		accounts->lock(accounts);
		if (accounts->load_str(accounts, &acc, sd->userid))
			ban_time = acc.unban_time;
		accounts->unlock(accounts);
	}
	lclif->auth_failed(sd->session, ban_time, result);
}

/**
 * CA_LOGIN_*
 **/
static bool login_client_login(struct socket_data *session, struct login_session_data *sd) __attribute__((nonnull (2)));
static bool login_client_login(struct socket_data *session, struct login_session_data *sd)
{
	enum accept_login_errorcode result;
	char ip[16];
	uint32 ipl = session->client_addr;
	socket_io->ip2str(ipl, ip);

	ShowStatus("Request for connection %sof %s (ip: %s).\n", sd->passwdenc == PASSWORDENC ? " (passwdenc mode)" : "", sd->userid, ip);

	if (sd->passwdenc != PWENC_NONE && login->config->use_md5_passwds) {
		login->auth_failed(sd, ALE_REJECTED);
		return true;
	}

	result = login->mmo_auth(sd, false);
	if(result == ALE_OK)
		login->auth_ok(sd);
	else
		login->auth_failed(sd, result);

	return false;
}

static bool login_client_login_otp(struct socket_data *session, struct login_session_data *sd) __attribute__((nonnull (2)));
static bool login_client_login_otp(struct socket_data *session, struct login_session_data *sd)
{
#if PACKETVER_MAIN_NUM >= 20170621 || PACKETVER_RE_NUM >= 20170621 || defined(PACKETVER_ZERO)
	// send ok response with fake token
	const int len = sizeof(struct PACKET_AC_LOGIN_OTP) + 6;  // + "token" string
	WFIFOHEAD(session, len, true);
	struct PACKET_AC_LOGIN_OTP *packet = WP2PTR(session);
	memset(packet, 0, len);
	packet->packet_id = HEADER_AC_LOGIN_OTP;
	packet->packet_len = len;
	packet->loginFlag = 0;  // normal login
#if PACKETVER_MAIN_NUM >= 20171213 || PACKETVER_RE_NUM >= 20171213 || PACKETVER_ZERO_NUM >= 20171123
	safestrncpy(packet->loginFlag2, "S1000", 6);
#endif  // PACKETVER_MAIN_NUM >= 20171213 || PACKETVER_RE_NUM >= 20171213 || PACKETVER_ZERO_NUM >= 20171123

	safestrncpy(packet->token, "token", 6);
	WFIFOSET(session, len);
	return true;
#else  // PACKETVER_MAIN_NUM >= 20170621 || PACKETVER_RE_NUM >= 20170621 || defined(PACKETVER_ZERO)
	return false;
#endif  // PACKETVER_MAIN_NUM >= 20170621 || PACKETVER_RE_NUM >= 20170621 || defined(PACKETVER_ZERO)
}

static void login_client_login_mobile_otp_request(struct socket_data *session, struct login_session_data *sd) __attribute__((nonnull (2)));
static void login_client_login_mobile_otp_request(struct socket_data *session, struct login_session_data *sd)
{
#if PACKETVER_MAIN_NUM >= 20181114 || PACKETVER_RE_NUM >= 20181114 || defined(PACKETVER_ZERO)
	WFIFOHEAD(session, sizeof(struct PACKET_AC_REQ_MOBILE_OTP), true);
	struct PACKET_AC_REQ_MOBILE_OTP *packet = WP2PTR(session);
	packet->packet_id = HEADER_AC_REQ_MOBILE_OTP;
	packet->aid = sd->account_id;
	WFIFOSET(session, sizeof(struct PACKET_AC_REQ_MOBILE_OTP));
#endif
}

/**
 * PACKET_AW_CHARSERVERCONNECT_ACK
 * Acknowledgment of connect-to-loginserver request
 * @see enum ac_charserverconnect_ack_status
 **/
static void login_char_server_connection_status(struct socket_data *session, struct login_session_data* sd, uint8 status) __attribute__((nonnull (2)));
static void login_char_server_connection_status(struct socket_data *session, struct login_session_data* sd, uint8 status)
{
	WFIFOHEAD(session, 3, true);
	WFIFOW(session, 0) = HEADER_AW_CHARSERVERCONNECT_ACK;
	WFIFOB(session, 2) = status;
	WFIFOSET2(session, 3);
}

/**
 * Processes information from a connection request from a character-server
 * The character server attempts connection via socket_io->connect and then sends
 * this packet in order to authenticate with us.
 *
 * @see lclif_parse_CA_CHARSERVERCONNECT
 * @see struct PACKET_CA_CHARSERVERCONNECT
 * @see enum ac_charserverconnect_ack_status
 **/
static void login_parse_request_connection(struct s_receive_action_data *act, struct login_session_data* sd, const char *const ip, uint32 ipl) __attribute__((nonnull (2, 3)));
static void login_parse_request_connection(struct s_receive_action_data *act, struct login_session_data* sd, const char *const ip, uint32 ipl)
{
	char server_name[20];
	char message[256];
	uint32 server_ip;
	uint16 server_port;
	uint16 type;
	uint16 new_;
	int result;

	safestrncpy(sd->userid, RFIFOP(act,2), NAME_LENGTH);
	safestrncpy(sd->passwd, RFIFOP(act,26), NAME_LENGTH);
	if(login->config->use_md5_passwds)
		md5->string(sd->passwd, sd->passwd);
	sd->passwdenc = PWENC_NONE;
	sd->version = login->config->client_version_to_connect; // hack to skip version check
	server_ip = ntohl(RFIFOL(act,54));
	server_port = ntohs(RFIFOW(act,58));
	safestrncpy(server_name, RFIFOP(act,60), 20);
	type = RFIFOW(act,82);
	new_ = RFIFOW(act,84);

	ShowInfo("Connection request of the char-server '%s' @ %u.%u.%u.%u:%u "
		"(account: '%s', pass: '%s', ip: '%s')\n",
		server_name, CONVIP(server_ip), server_port, sd->userid, sd->passwd, ip);
	sprintf(message, "charserver - %s@%u.%u.%u.%u:%u", server_name, CONVIP(server_ip), server_port);
	loginlog->log(act->session->client_addr, sd->userid, 100, message);

	if(!socket_io->allowed_ip_check(ipl)) {
		ShowNotice("Connection of the char-server '%s' REFUSED "
			"(IP not allowed).\n", server_name);
		login->char_server_connection_status(act->session, sd, CCA_IP_NOT_ALLOWED);
		return;
	}
	if(core->runflag != LOGINSERVER_ST_RUNNING) {
		ShowNotice("Connection of the char-server '%s' REFUSED "
			"(Login-server is not runnning).\n", server_name);
		login->char_server_connection_status(act->session, sd, CCA_INVALID_NOT_READY);
		return;
	}

	result = login->mmo_auth(sd, true);

	if(result != ALE_OK) {
		ShowNotice("Connection of the char-server '%s' REFUSED "
			"(Invalid credentials).\n", server_name);
		login->char_server_connection_status(act->session, sd, CCA_INVALID_CREDENTIAL);
		return;
	}
	if(sd->sex != 'S') {
		ShowNotice("Connection of the char-server '%s' REFUSED "
			"(Invalid sex).\n", server_name);
		login->char_server_connection_status(act->session, sd, CCA_INVALID_SEX);
		return;
	}
	if(sd->account_id < 0 && sd->account_id > START_ACCOUNT_NUM) {
		ShowNotice("Connection of the char-server '%s' REFUSED "
			"(Invalid account id).\n", server_name);
		login->char_server_connection_status(act->session, sd, CCA_INVALID_ACC_ID);
		return;
	}

	rwlock->read_lock(g_char_server_list_lock);
	struct mmo_char_server *server;
	int pos = -1;
	for(int i = 0; i < INDEX_MAP_LENGTH(g_char_server_list); i++) {
		struct login_session_data *server_sd;
		server = INDEX_MAP_INDEX(g_char_server_list, i);
		if(!server)
			continue;
		server_sd = server->session->session_data;
		if(server_sd->account_id == sd->account_id) {
			pos = 1;
			break; // Already connected
		}
	}
	rwlock->read_unlock(g_char_server_list_lock);

	if(pos != -1) {
		ShowNotice("Connection of the char-server '%s' REFUSED "
			"(This char account is already connected!).\n", server_name);
		login->char_server_connection_status(act->session, sd, CCA_ALREADY_CONNECTED);
		return;
	}

	ShowStatus("Connection of the char-server '%s' accepted.\n", server_name);
	server = aMalloc(sizeof(*server));
	safestrncpy(server->name, server_name, sizeof(server->name));
	server->session = act->session;
	server->ip = server_ip;
	server->port = server_port;
	server->users = 0;
	server->type = type;
	server->new_ = new_;

	rwlock->write_lock(g_char_server_list_lock);
	INDEX_MAP_ADD(g_char_server_list, server, server->pos);
	sd->login_id1 = server->pos;
	rwlock->write_unlock(g_char_server_list_lock);

	// Find proper action worker for this char-server
	mutex->lock(action_information_mutex);
	struct s_action_information *data = linkdb_search(&action_information, NULL);
	if(!data) { // Create a new action queue for this server
		struct s_action_queue *queue = action->queue_create(10, login->ers_collection);
		data = aMalloc(sizeof(*data));
		data->index = action->queue_get_index(queue);
		data->server = server;
	} else { // Remove and then reinsert with a server
		data->server = server;
		data = linkdb_erase(&action_information, NULL);
	}
	linkdb_insert(&action_information, server, data);
	mutex->unlock(action_information_mutex);

	mutex->lock(act->session->mutex);
	socket_io->session_update_parse(act->session, login->parse_fromchar);
	act->session->flag.server = 1;
	act->session->flag.validate = 0;
	action->queue_set(act->session, data->index);
	mutex->unlock(act->session->mutex);

	// send connection success
	login->char_server_connection_status(act->session, sd, CCA_ACCEPTED);
}

static void login_config_set_defaults(void)
{
	login->config->login_ip = INADDR_ANY;
	login->config->login_port = 6900;
	login->config->ipban_cleanup_interval = 60;
	login->config->ip_sync_interval = 0;
	login->config->log_login = true;
	safestrncpy(login->config->date_format, "%Y-%m-%d %H:%M:%S", sizeof(login->config->date_format));
	login->config->new_account_flag = true;
	login->config->new_acc_length_limit = true;
	login->config->use_md5_passwds = false;
	login->config->group_id_to_connect = -1;
	login->config->min_group_id_to_connect = -1;
	login->config->check_client_version = false;
	login->config->check_client_flags = true;
	login->config->report_client_flags_error = true;
	login->config->client_version_to_connect = 20;
	login->config->allowed_regs = 1;
	login->config->time_allowed = 10;

	login->config->ipban = true;
	login->config->dynamic_pass_failure_ban = true;
	login->config->dynamic_pass_failure_ban_interval = 5;
	login->config->dynamic_pass_failure_ban_limit = 7;
	login->config->dynamic_pass_failure_ban_duration = 5;
	login->config->use_dnsbl = false;
	VECTOR_INIT(login->config->dnsbl_servers);

	login->config->client_hash_check = 0;
	login->config->client_hash_nodes = NULL;
}

/**
 * Reads 'login_configuration/inter' and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool login_config_read_inter(const char *filename, struct config_t *config, bool imported)
{
	struct config_setting_t *setting = NULL;
	const char *str = NULL;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "login_configuration/inter")) == NULL) {
		if (imported)
			return true;
		ShowError("login_config_read: login_configuration/inter was not found in %s!\n", filename);
		return false;
	}

	libconfig->setting_lookup_uint16(setting, "login_port", &login->config->login_port);

	if (libconfig->setting_lookup_uint32(setting, "ip_sync_interval", &login->config->ip_sync_interval) == CONFIG_TRUE)
		login->config->ip_sync_interval *= 1000*60; // In minutes

	if (libconfig->setting_lookup_string(setting, "bind_ip", &str) == CONFIG_TRUE) {
		char old_ip_str[16];
		socket_io->ip2str(login->config->login_ip, old_ip_str);

		if ((login->config->login_ip = socket_io->host2ip(str)) != 0)
			ShowStatus("Login server binding IP address : %s -> %s\n", old_ip_str, str);
	}

	return true;
}

/**
 * Reads 'login_configuration.console' and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool login_config_read_console(const char *filename, struct config_t *config, bool imported)
{
	struct config_setting_t *setting = NULL;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "login_configuration/console")) == NULL) {
		if (imported)
			return true;
		ShowError("login_config_read: login_configuration/console was not found in %s!\n", filename);
		return false;
	}

	libconfig->setting_lookup_bool_real(setting, "stdout_with_ansisequence", &showmsg->stdout_with_ansisequence);
	if (libconfig->setting_lookup_int(setting, "console_silent", &showmsg->silent) == CONFIG_TRUE) {
		if (showmsg->silent) // only bother if its actually enabled
			ShowInfo("Console Silent Setting: %d\n", showmsg->silent);
	}
	libconfig->setting_lookup_mutable_string(setting, "timestamp_format", showmsg->timestamp_format, sizeof(showmsg->timestamp_format));

	return true;
}

/**
 * Reads 'login_configuration.log' and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool login_config_read_log(const char *filename, struct config_t *config, bool imported)
{
	struct config_setting_t *setting = NULL;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "login_configuration/log")) == NULL) {
		if (imported)
			return true;
		ShowError("login_config_read: login_configuration/log was not found in %s!\n", filename);
		return false;
	}

	libconfig->setting_lookup_bool_real(setting, "log_login", &login->config->log_login);
	libconfig->setting_lookup_mutable_string(setting, "date_format", login->config->date_format, sizeof(login->config->date_format));
	return true;
}

/**
 * Reads 'login_configuration.account' and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool login_config_read_account(const char *filename, struct config_t *config, bool imported)
{
	struct config_setting_t *setting = NULL;
	AccountDB *db = account_engine.db;
	bool retval = true;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "login_configuration/account")) == NULL) {
		if (imported)
			return true;
		ShowError("login_config_read: login_configuration/account was not found in %s!\n", filename);
		return false;
	}

	libconfig->setting_lookup_bool_real(setting, "new_account", &login->config->new_account_flag);
	libconfig->setting_lookup_bool_real(setting, "new_acc_length_limit", &login->config->new_acc_length_limit);

	libconfig->setting_lookup_int(setting, "allowed_regs", &login->config->allowed_regs);
	libconfig->setting_lookup_int(setting, "time_allowed", &login->config->time_allowed);
	libconfig->setting_lookup_int(setting, "start_limited_time", &login->config->start_limited_time);
	libconfig->setting_lookup_bool_real(setting, "use_MD5_passwords", &login->config->use_md5_passwds);

	if (!db->set_property(db, config, imported))
		retval = false;
	if (!ipban->config_read(filename, config, imported))
		retval = false;

	return retval;
}

/**
 * Frees login->config->client_hash_nodes
 **/
static void login_clear_client_hash_nodes(void)
{
	struct client_hash_node *node = login->config->client_hash_nodes;

	while (node != NULL) {
		struct client_hash_node *next = node->next;
		aFree(node);
		node = next;
	}

	login->config->client_hash_nodes = NULL;
}

/**
 * Reads information from login_configuration.permission.hash.md5_hashes (unused function)
 *
 * @param setting The setting to read from.
 */
static void login_config_set_md5hash(struct config_setting_t *setting)
{
	int i;
	int count = libconfig->setting_length(setting);

	login->clear_client_hash_nodes();

	// There's no need to parse if it's disabled or if there's no list
	if (count <= 0 || !login->config->client_hash_check)
		return;

	for (i = 0; i < count; i++) {
		int j;
		int group_id = 0;
		char md5hash[33];
		struct client_hash_node *nnode = NULL;
		struct config_setting_t *item = libconfig->setting_get_elem(setting, i);

		if (item == NULL)
			continue;

		if (libconfig->setting_lookup_int(item, "group_id", &group_id) != CONFIG_TRUE) {
			ShowWarning("login_config_set_md5hash: entry (%d) is missing group_id! Ignoring...\n", i);
			continue;
		}

		if (libconfig->setting_lookup_mutable_string(item, "hash", md5hash, sizeof(md5hash)) != CONFIG_TRUE) {
			ShowWarning("login_config_set_md5hash: entry (%d) is missing hash! Ignoring...\n", i);
			continue;
		}

		CREATE(nnode, struct client_hash_node, 1);
		if (strcmpi(md5hash, "disabled") == 0) {
			nnode->hash[0] = '\0';
		} else {
			for (j = 0; j < 32; j += 2) {
				char buf[3];
				unsigned int byte;

				memcpy(buf, &md5hash[j], 2);
				buf[2] = 0;

				sscanf(buf, "%x", &byte);
				nnode->hash[j / 2] = (uint8)(byte & 0xFF);
			}
		}
		nnode->group_id = group_id;
		nnode->next = login->config->client_hash_nodes; // login->config->client_hash_nodes is initialized before calling this function
		login->config->client_hash_nodes = nnode;
	}

	return;
}

/**
 * Reads 'login_configuration/permission/hash' and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool login_config_read_permission_hash(const char *filename, struct config_t *config, bool imported)
{
	struct config_setting_t *setting = NULL;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "login_configuration/permission/hash")) == NULL) {
		if (imported)
			return true;
		ShowError("login_config_read: login_configuration/permission/hash was not found in %s!\n", filename);
		return false;
	}

	libconfig->setting_lookup_bool_real(setting, "enabled", &login->config->client_hash_check);

	if ((setting = libconfig->lookup(config, "login_configuration/permission/hash/MD5_hashes")) != NULL)
		login->config_set_md5hash(setting);

	return true;
}

/**
 * Clears login->config->dnsbl_servers, freeing any allocated memory.
 */
static void login_clear_dnsbl_servers(void)
{
	while (VECTOR_LENGTH(login->config->dnsbl_servers) > 0) {
		aFree(VECTOR_POP(login->config->dnsbl_servers));
	}
	VECTOR_CLEAR(login->config->dnsbl_servers);
}

/**
 * Reads information from login_config/permission/DNS_blacklist/dnsbl_servers.
 *
 * @param setting The configuration setting to read from.
 */
static void login_config_set_dnsbl_servers(struct config_setting_t *setting)
{
	int i;
	int count = libconfig->setting_length(setting);

	login->clear_dnsbl_servers();

	// There's no need to parse if it's disabled
	if (count <= 0 || !login->config->use_dnsbl)
		return;

	VECTOR_ENSURE(login->config->dnsbl_servers, count, 1);

	for (i = 0; i < count; i++) {
		const char *string = libconfig->setting_get_string_elem(setting, i);

		if (string == NULL || string[0] == '\0')
			continue;

		VECTOR_PUSH(login->config->dnsbl_servers, aStrdup(string));
	}
}

/**
 * Reads 'login_configuration/permission/DNS_blacklist' and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool login_config_read_permission_blacklist(const char *filename, struct config_t *config, bool imported)
{
	struct config_setting_t *setting = NULL;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "login_configuration/permission/DNS_blacklist")) == NULL) {
		if (imported)
			return true;
		ShowError("login_config_read: login_configuration/permission/DNS_blacklist was not found in %s!\n", filename);
		return false;
	}

	libconfig->setting_lookup_bool_real(setting, "enabled", &login->config->use_dnsbl);

	if ((setting = libconfig->lookup(config, "login_configuration/permission/DNS_blacklist/dnsbl_servers")) != NULL)
		login->config_set_dnsbl_servers(setting);

	return true;
}

/**
 * Reads 'login_configuration.permission' and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool login_config_read_permission(const char *filename, struct config_t *config, bool imported)
{
	struct config_setting_t *setting = NULL;
	bool retval = true;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "login_configuration/permission")) == NULL) {
		if (imported)
			return true;
		ShowError("login_config_read: login_configuration/permission was not found in %s!\n", filename);
		return false;
	}

	libconfig->setting_lookup_int(setting, "group_id_to_connect", &login->config->group_id_to_connect);
	libconfig->setting_lookup_int(setting, "min_group_id_to_connect", &login->config->min_group_id_to_connect);
	libconfig->setting_lookup_bool_real(setting, "check_client_version", &login->config->check_client_version);
	libconfig->setting_lookup_bool_real(setting, "check_client_flags", &login->config->check_client_flags);
	libconfig->setting_lookup_bool_real(setting, "report_client_flags_error", &login->config->report_client_flags_error);
	libconfig->setting_lookup_uint32(setting, "client_version_to_connect", &login->config->client_version_to_connect);

	if (!login->config_read_permission_hash(filename, config, imported))
		retval = false;
	if (!login->config_read_permission_blacklist(filename, config, imported))
		retval = false;

	return retval;
}

/**
 * Reads 'login_configuration.users_count' and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool login_config_read_users(const char *filename, struct config_t *config, bool imported)
{
	struct config_setting_t *setting = NULL;
	bool retval = true;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "login_configuration/users_count")) == NULL) {
		if (imported)
			return true;
		ShowError("login_config_read: login_configuration/users_count was not found in %s!\n", filename);
		return false;
	}

	libconfig->setting_lookup_bool_real(setting, "send_user_count_description", &login->config->send_user_count_description);
	libconfig->setting_lookup_uint32(setting, "low", &login->config->users_low);
	libconfig->setting_lookup_uint32(setting, "medium", &login->config->users_medium);
	libconfig->setting_lookup_uint32(setting, "high", &login->config->users_high);

	return retval;
}

/**
 * Reads the 'login-config' configuration file and initializes required variables.
 *
 * @param filename Path to configuration file.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 **/
static bool login_config_read(const char *filename, bool imported)
{
	struct config_t config;
	const char *import = NULL;
	bool retval = true;

	nullpo_retr(false, filename);

	if (!libconfig->load_file(&config, filename))
		return false; // Error message is already shown by libconfig->load_file

	if (!login->config_read_inter(filename, &config, imported))
		retval = false;
	if (!login->config_read_console(filename, &config, imported))
		retval = false;
	if (!login->config_read_log(filename, &config, imported))
		retval = false;
	if (!login->config_read_account(filename, &config, imported))
		retval = false;
	if (!login->config_read_permission(filename, &config, imported))
		retval = false;
	if (!login->config_read_users(filename, &config, imported))
		retval = false;

	if (!loginlog->config_read("conf/common/inter-server.conf", imported)) // Only inter-server
		retval = false;

	if (!HPM->parse_conf(&config, filename, HPCT_LOGIN, imported))
		retval = false;

	ShowInfo("Finished reading %s.\n", filename);

	// import should overwrite any previous configuration, so it should be called last
	if (libconfig->lookup_string(&config, "import", &import) == CONFIG_TRUE) {
		if (strcmp(import, filename) == 0 || strcmp(import, login->LOGIN_CONF_NAME) == 0) {
			ShowWarning("login_config_read: Loop detected in %s! Skipping 'import'...\n", filename);
		} else {
			if (!login->config_read(import, true))
				retval = false;
		}
	}

	config_destroy(&config);
	return retval;
}

/**
 * Convert users count to colors.
 *
 * @param users Actual users count.
 *
 * @retval users count or color id.
 **/
static uint16 login_convert_users_to_colors(uint16 users)
{
#if PACKETVER >= 20170726
	if (!login->config->send_user_count_description)
		return 4;
	if (users <= login->config->users_low)
		return 0;
	else if (users <= login->config->users_medium)
		return 1;
	else if (users <= login->config->users_high)
		return 2;
	return 3;
#else
	return users;
#endif
}

//--------------------------------------
// Function called at exit of the server
//--------------------------------------
int do_final(void)
{
	ShowStatus("Terminating...\n");

	HPM->event(HPET_FINAL);

	login->clear_client_hash_nodes();
	login->clear_dnsbl_servers();

	loginlog->log(0, "login server", 100, "login server shutdown");

	if (login->config->log_login)
		loginlog->final();

	ipban->final();

	if (account_engine.db)
	{// destroy account engine
		account_engine.db->destroy(account_engine.db);
		account_engine.db = NULL;
	}
	login->accounts = NULL; // destroyed in account_engine
	accounts = NULL;
	login->online_db->destroy(login->online_db, NULL);
	login->auth_db->destroy(login->auth_db, NULL);
	mutex->destroy(login->online_db_mutex);
	mutex->destroy(login->auth_db_mutex);

	rwlock->destroy(g_char_server_list_lock);
	g_char_server_list_lock = NULL;
	INDEX_MAP_DESTROY(g_char_server_list);
	mutex->destroy(action_information_mutex);
	linkdb_final(&action_information); // TODO: free data

	lclif->final();
	lchrif->final();

	HPM_login_do_final();

	aFree(login->LOGIN_CONF_NAME);
	aFree(login->NET_CONF_NAME);

	ers_collection_destroy(login->ers_collection);
	// action->queue_final destroys all queues

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
	SERVER_TYPE = SERVER_TYPE_LOGIN;
}


/// Called when a terminate signal is received.
static void do_shutdown_login(void)
{
	if( core->runflag != LOGINSERVER_ST_SHUTDOWN )
	{
		core->runflag = LOGINSERVER_ST_SHUTDOWN;
		ShowStatus("Shutting down...\n");
		/**
		 * When lchrif->server_reset(id) is called and all characters are set to offline
		 * the character-server becomes responsible to properly kick and wait for acks.
		 **/
		for(int i = 0; i < INDEX_MAP_LENGTH(g_char_server_list); i++) {
			struct mmo_char_server *server = INDEX_MAP_INDEX(g_char_server_list, i);
			if(!server)
				continue;
			lchrif->server_reset(server);
			INDEX_MAP_REMOVE(g_char_server_list, i);
		}

		core->runflag = CORE_ST_STOP;
	}
}

/**
 * --login-config handler
 *
 * Overrides the default login configuration file.
 * @see cmdline->exec
 */
static CMDLINEARG(loginconfig)
{
	aFree(login->LOGIN_CONF_NAME);
	login->LOGIN_CONF_NAME = aStrdup(params);
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
 * --net-config handler
 *
 * Overrides the default subnet configuration file.
 * @see cmdline->exec
 */
static CMDLINEARG(netconfig)
{
	aFree(login->NET_CONF_NAME);
	login->NET_CONF_NAME = aStrdup(params);
	return true;
}
/**
 * Defines the local command line arguments
 */
void cmdline_args_init_local(void)
{
	CMDLINEARG_DEF2(run-once, runonce, "Closes server after loading (testing).", CMDLINE_OPT_NORMAL);
	CMDLINEARG_DEF2(login-config, loginconfig, "Alternative login-server configuration.", CMDLINE_OPT_PARAM);
	CMDLINEARG_DEF2(net-config, netconfig, "Alternative subnet configuration.", CMDLINE_OPT_PARAM);
}

//------------------------------
// Login server initialization
//------------------------------
int do_init(int argc, char **argv)
{
	account_defaults();
	login_defaults();

	login->ers_collection = ers_collection_create(MEMORYTYPE_SHARED);
	if(!login->ers_collection)
		exit(EXIT_FAILURE);

	// initialize engine (to accept config settings)
	account_engine.constructor = account->db_sql;
	account_engine.db = account_engine.constructor();
	accounts = account_engine.db;
	login->accounts = accounts;
	if( accounts == NULL ) {
		ShowFatalError("do_init: account engine 'sql' not found.\n");
		exit(EXIT_FAILURE);
	}

	ipban_defaults();
	lchrif_defaults();
	lclif_defaults();
	loginlog_defaults();

	// read login-server configuration
	login->config_set_defaults();

	login->LOGIN_CONF_NAME = aStrdup("conf/login/login-server.conf");
	login->NET_CONF_NAME   = aStrdup("conf/network.conf");

	lchrif->init();
	lclif->init();

	HPM_login_do_init();
	cmdline->exec(argc, argv, CMDLINE_OPT_PREINIT);
	HPM->config_read();
	HPM->event(HPET_PRE_INIT);

	cmdline->exec(argc, argv, CMDLINE_OPT_NORMAL);
	login->config_read(login->LOGIN_CONF_NAME, false);
	socket_io->net_config_read(login->NET_CONF_NAME);

	INDEX_MAP_CREATE(g_char_server_list, CHAR_SERVER_LIST_INITIAL_LENGTH, MEMORYTYPE_SHARED);
	g_char_server_list_lock = rwlock->create();
	if(!g_char_server_list_lock) {
		ShowFatalError("Failed to setup character server list!\n");
		exit(EXIT_FAILURE);
	}

	// initialize logging
	if (login->config->log_login)
		loginlog->init();

	// initialize static and dynamic ipban system
	ipban->init();

	// Online user database init
	login->online_db = idb_alloc(DB_OPT_RELEASE_DATA);
	login->online_db_mutex = mutex->create();
	if(!login->online_db_mutex) {
		ShowFatalError("Failed to initialize online db\n");
		exit(EXIT_FAILURE);
	}
	timer->add_func_list(login->waiting_disconnect_timer,
		"login->waiting_disconnect_timer");

	// Interserver auth init
	login->auth_db = idb_alloc(DB_OPT_RELEASE_DATA);
	login->auth_db_mutex = mutex->create();
	if(!login->auth_db_mutex) {
		ShowFatalError("Failed to initialize auth db\n");
		exit(EXIT_FAILURE);
	}

	// Create login queue
	struct s_action_queue *queue = action->queue_create(10, login->ers_collection);

	struct s_action_information *ainfo = aMalloc(sizeof(*ainfo));
	ainfo->index = action->queue_get_index(queue);
	ainfo->server = NULL;
	action_information_mutex = mutex->create();
	if(!action_information_mutex) {
		ShowFatalError("Failed to initialize action information list\n");
		exit(EXIT_FAILURE);
	}
	linkdb_insert(&action_information, NULL, ainfo);

	// set default parser as lclif->parse function
	socket_io->set_defaultparse(lclif->parse);
	socket_io->validate = true;

	// every 10 minutes cleanup online account db.
	timer->add_func_list(login->online_data_cleanup, "login->online_data_cleanup");
	timer->add_interval(timer->gettick() + 600*1000, login->online_data_cleanup,
		0, 0, 600*1000);

	// add timer to detect ip address change and perform update
	if (login->config->ip_sync_interval) {
		timer->add_func_list(login->sync_ip_addresses, "login->sync_ip_addresses");
		timer->add_interval(timer->gettick() + login->config->ip_sync_interval,
			login->sync_ip_addresses, 0, 0, login->config->ip_sync_interval);
	}

	// Account database init
	if(!accounts->init(accounts)) {
		ShowFatalError("do_init: Failed to initialize account engine 'sql'.\n");
		exit(EXIT_FAILURE);
	}

	HPM->event(HPET_INIT);

	// server port open & binding
	if(!socket_io->make_listen_bind(login->config->login_ip,login->config->login_port)) {
		ShowFatalError("Failed to bind to port '"CL_WHITE"%d"CL_RESET"'\n",
			login->config->login_port);
		exit(EXIT_FAILURE);
	}

	if( core->runflag != CORE_ST_STOP ) {
		core->shutdown_callback = do_shutdown_login;
		core->runflag = LOGINSERVER_ST_RUNNING;
	}

#ifdef CONSOLE_INPUT
	console->display_gplnotice();
#endif // CONSOLE_INPUT

	ShowStatus("The login-server is "CL_GREEN"ready"CL_RESET" (Server is listening on the port %u).\n\n", login->config->login_port);
	loginlog->log(0, "login server", 100, "login server started");

	HPM->event(HPET_READY);

	return 0;
}

void login_defaults(void)
{
	login = &login_s;

	login->config = &login_config_;
	login->accounts = accounts;

	login->mmo_auth = login_mmo_auth;
	login->mmo_auth_new = login_mmo_auth_new;
	login->waiting_disconnect_timer = login_waiting_disconnect_timer;
	login->create_online_user = login_create_online_user;
	login->add_online_user = login_add_online_user;
	login->remove_online_user = login_remove_online_user;
	login->online_db_setoffline = login_online_db_setoffline;
	login->online_data_cleanup_sub = login_online_data_cleanup_sub;
	login->online_data_cleanup = login_online_data_cleanup;
	login->sync_ip_addresses = login_sync_ip_addresses;
	login->check_encrypted = login_check_encrypted;
	login->check_password = login_check_password;
	login->lan_subnet_check = login_lan_subnet_check;
	login->account_load = login_account_load;

	login->fromchar_auth_ack = login_fromchar_auth_ack;
	login->fromchar_accinfo_failure = login_fromchar_accinfo_failure;
	login->fromchar_accinfo_success = login_fromchar_accinfo_success;
	login->fromchar_account = login_fromchar_account;
	login->fromchar_account_update_state = login_fromchar_account_update_state;
	login->fromchar_change_sex_other = login_fromchar_change_sex_other;
	login->fromchar_pong = login_fromchar_pong;
	login->fromchar_parse_auth = login_fromchar_parse_auth;
	login->fromchar_parse_update_users = login_fromchar_parse_update_users;
	login->fromchar_parse_request_change_email = login_fromchar_parse_request_change_email;
	login->fromchar_parse_account_data = login_fromchar_parse_account_data;
	login->fromchar_parse_ping = login_fromchar_parse_ping;
	login->fromchar_parse_change_email = login_fromchar_parse_change_email;
	login->fromchar_parse_account_update = login_fromchar_parse_account_update;
	login->fromchar_parse_ban = login_fromchar_parse_ban;
	login->fromchar_parse_change_sex = login_fromchar_parse_change_sex;
	login->fromchar_parse_account_reg2 = login_fromchar_parse_account_reg2;
	login->fromchar_parse_unban = login_fromchar_parse_unban;
	login->fromchar_parse_account_online = login_fromchar_parse_account_online;
	login->fromchar_parse_account_offline = login_fromchar_parse_account_offline;
	login->fromchar_parse_online_accounts = login_fromchar_parse_online_accounts;
	login->fromchar_parse_request_account_reg2 = login_fromchar_parse_request_account_reg2;
	login->fromchar_parse_update_wan_ip = login_fromchar_parse_update_wan_ip;
	login->fromchar_parse_all_offline = login_fromchar_parse_all_offline;
	login->fromchar_parse_change_pincode = login_fromchar_parse_change_pincode;
	login->fromchar_parse_wrong_pincode = login_fromchar_parse_wrong_pincode;
	login->fromchar_parse_accinfo = login_fromchar_parse_accinfo;

	login->parse_fromchar = login_parse_fromchar;
	login->client_login = login_client_login;
	login->client_login_otp = login_client_login_otp;
	login->client_login_mobile_otp_request = login_client_login_mobile_otp_request;
	login->parse_request_connection = login_parse_request_connection;
	login->auth_ok = login_auth_ok;
	login->auth_failed = login_auth_failed;
	login->char_server_connection_status = login_char_server_connection_status;
	login->kick = login_kick;
	login->check_client_version = login_check_client_version;

	login->config_set_defaults = login_config_set_defaults;
	login->config_read = login_config_read;
	login->config_read_inter = login_config_read_inter;
	login->config_read_console = login_config_read_console;
	login->config_read_log = login_config_read_log;
	login->config_read_account = login_config_read_account;
	login->config_read_permission = login_config_read_permission;
	login->config_read_permission_hash = login_config_read_permission_hash;
	login->config_read_permission_blacklist = login_config_read_permission_blacklist;
	login->config_read_users = login_config_read_users;
	login->config_set_dnsbl_servers = login_config_set_dnsbl_servers;

	login->clear_dnsbl_servers = login_clear_dnsbl_servers;
	login->clear_client_hash_nodes = login_clear_client_hash_nodes;
	login->config_set_md5hash = login_config_set_md5hash;
	login->convert_users_to_colors = login_convert_users_to_colors;
	login->LOGIN_CONF_NAME = NULL;
	login->NET_CONF_NAME = NULL;
}

void lchrif_defaults(void)
{
	lchrif = &lchrif_s;
	lchrif->packet_db = NULL;

	lchrif->init = lchrif_init;
	lchrif->final= lchrif_final;

	lchrif->server_destroy = lchrif_server_destroy;
	lchrif->server_reset = lchrif_server_reset;
	lchrif->server_find  = lchrif_server_find;
	lchrif->on_disconnect = lchrif_on_disconnect;
}
