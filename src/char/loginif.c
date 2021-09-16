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

#include "loginif.h"

#include "char/char.h"
#include "char/mapif.h"
#include "common/cbasetypes.h"
#include "common/core.h"
#include "common/db.h"
#include "common/nullpo.h"
#include "common/showmsg.h"
#include "common/socket.h"
#include "common/timer.h"

#include "common/rwlock.h"
#include "common/packets_wa_struct.h"
#include "common/packets_aw_struct.h"

#include <stdlib.h>
#include <string.h>

static struct loginif_interface loginif_s;
struct loginif_interface *loginif;

/**
 * Checks the conditions for the server to stop.
 * Releases the cookie when all characters are saved.
 * If all the conditions are met, it stops the core loop.
 **/
static void loginif_check_shutdown(void)
{
	if( core->runflag != CHARSERVER_ST_SHUTDOWN )
		return;
	core->runflag = CORE_ST_STOP;
}

/**
 * Called when the connection to Login Server is disconnected.
 * At this point chr->login_session is not valid.
 *
 * @see char_parse_fromlogin
 **/
static void loginif_on_disconnect(void)
{
	ShowWarning("Connection to Login Server lost.\n\n");
}

/**
 * Called after a successful authentication with the login-server.
 *
 * @see do_init_loginif
 * @see char_check_connect_login_server
 * @see char_parse_fromlogin_connection_state
 * Acquires map_server_list_lock read
 **/
static void loginif_on_ready(void)
{
	int i;

	loginif->check_shutdown();

	//Send online accounts to login server.
	loginif->account_list(timer, INVALID_TIMER, timer->gettick(), 0, 0);

	rwlock->read_lock(chr->map_server_list_lock);
	if(!INDEX_MAP_COUNT(chr->map_server_list))
		ShowStatus("Awaiting maps from map-server.\n");
	rwlock->read_unlock(chr->map_server_list_lock);
}

/**
 * Initializes initial loginif state, sets up periodic login-server packets
 **/
static void do_init_loginif(void)
{
	struct {
		int16 packet_id;
		int16 packet_len;
		LoginifParseFunc *pFunc;
	} inter_packet[] = {
#define packet_def(name, fname) { HEADER_ ## name, sizeof(struct PACKET_ ## name), chr->parse_fromlogin_ ## fname }
#define packet_def2(name, fname, len) { HEADER_ ## name, (len), chr->parse_fromlogin_ ## fname }
		packet_def(AW_CHARSERVERCONNECT_ACK, connection_state),
		packet_def(AW_AUTH_ACK,              auth_state),
		packet_def(AW_REQUEST_ACCOUNT_ACK,   account_data),
		packet_def(AW_PONG,                  login_pong),
		packet_def(AW_SEX_BROADCAST,         changesex_reply),
		packet_def(AW_UPDATE_STATE,          update_state),
		packet_def(AW_KICK,                  kick),
		packet_def(AW_IP_UPDATE,             update_ip),
		packet_def(AW_ACCOUNT_INFO_SUCCESS,  accinfo2_ok),
		packet_def(AW_ACCOUNT_INFO_FAILURE,  accinfo2_failed),
		packet_def(AW_ACCOUNT_REG2,          account_reg2),
#undef packet_def
#undef packet_def2
	};
	size_t length = ARRAYLENGTH(inter_packet);

	loginif->packet_list = aMalloc(sizeof(*loginif->packet_list)*length);
	loginif->packet_db = idb_alloc(DB_OPT_BASE);

	// Fill packet db
	for(size_t i = 0; i < length; i++) {
		int exists;
		loginif->packet_list[i].len = inter_packet[i].packet_len;
		loginif->packet_list[i].pFunc = inter_packet[i].pFunc;
		exists = idb_put(loginif->packet_db,
			inter_packet[i].packet_id, &loginif->packet_list[i]);
		if(exists) {
			ShowWarning("loginif_init: Packet 0x%x already in database, replacing...\n",
				inter_packet[i].packet_id);
		}
	}

	// establish char-login connection if not present
	timer->add_func_list(chr->check_connect_login_server, "chr->check_connect_login_server");
	timer->add_interval(timer->gettick() + 1000, chr->check_connect_login_server, 0, 0, 10 * 1000);

	// send a list of all online account IDs to login server
	timer->add_func_list(loginif->account_list, "loginif->send_accounts_tologin");
	timer->add_interval(timer->gettick() + 1000, loginif->account_list, 0, 0, 3600 * 1000); //Sync online accounts every hour
}

/**
 * Disconnects login-server if it's connected
 **/
static void do_final_loginif(void)
{
	if(chr->login_session) {
		socket_io->session_disconnect_guard(chr->login_session);
		// We need to wait all pending operations before unsetting login_session.
		// chr->login_session = NULL;
	}

	db_clear(loginif->packet_db);
	aFree(loginif->packet_list);
}

/**
 * WA_PING
 * Sends a ping packet to login server (expects AW_PONG)
 * @mutex chr->login_session->mutex
 * @see chr->parse_fromlogin
 **/
static void loginif_ping(void)
{
	nullpo_retv(chr->login_session);
	WFIFOHEAD(chr->login_session,2,false);
	WFIFOW(chr->login_session,0) = HEADER_WA_PING;
	WFIFOSET(chr->login_session,2);
}

/**
 * WA_PINCODE_UPDATE
 * Notifies login-server of the change of the pincode of an account
 **/
static void loginif_pincode_update(int account_id, const char *pin)
{
	nullpo_retv(chr->login_session);
	nullpo_retv(pin);

	WFIFOHEAD(chr->login_session, sizeof(struct PACKET_WA_PINCODE_UPDATE), true);
	WFIFOW(chr->login_session, 0) = HEADER_WA_PINCODE_UPDATE;
	WFIFOL(chr->login_session, 2) = account_id;
	safestrncpy(WFIFOP(chr->login_session, 6), pin, 5);
	WFIFOSET(chr->login_session, sizeof(struct PACKET_WA_PINCODE_UPDATE));
}

/**
 * WA_PINCODE_FAILED
 * Notifies login-server that the player failed too many attempts
 * @param account_id
 **/
static void loginif_pincode_failed(int account_id)
{
	nullpo_retv(chr->login_session);
	WFIFOHEAD(chr->login_session, sizeof(struct PACKET_WA_PINCODE_FAILED), true);
	WFIFOW(chr->login_session, 0) = HEADER_WA_PINCODE_FAILED;
	WFIFOL(chr->login_session, 2) = account_id;
	WFIFOSET(chr->login_session, sizeof(struct PACKET_WA_PINCODE_FAILED));
}

/**
 * WA_WAN_UPDATE
 * Sends current WAN IP to login-server
 **/
static void loginif_update_ip(void)
{
	Assert_retv(chr->login_session);
	WFIFOHEAD(chr->login_session, sizeof(struct PACKET_WA_WAN_UPDATE), true);
	WFIFOW(chr->login_session,0) = 0x2736;
	WFIFOL(chr->login_session,2) = htonl(chr->ip);
	WFIFOSET(chr->login_session, sizeof(struct PACKET_WA_WAN_UPDATE));
}

/**
 * Load this character's account id into the 'online accounts' packet
 * @see DBApply
 * @see loginif_account_list
 */
static int loginif_account_list_sub(const struct DBKey_s *key, struct DBData *data, va_list ap)
{
	struct online_char_data* character = DB->data2ptr(data);
	int* i = va_arg(ap, int*);

	nullpo_ret(character);
	if(character->server > -1)
	{
		WFIFOL(chr->login_session,8+(*i)*4) = character->account_id;
		(*i)++;
		return 1;
	}
	return 0;
}

/**
 * WA_ACCOUNT_INFO_REQUEST
 * Requests account information to login-server (relayed from map-server @see inter_accinfo)
 **/
static void loginif_accinfo_request(int account_id, int u_fd, int u_aid, int u_group, int map_fd)
{
	Assert_retv(chr->login_session);
	WFIFOHEAD(chr->login_session, sizeof(struct PACKET_WA_ACCOUNT_INFO_REQUEST), true);
	WFIFOW(chr->login_session, 0) = HEADER_WA_ACCOUNT_INFO_REQUEST;
	WFIFOL(chr->login_session, 2) = account_id;
	WFIFOL(chr->login_session, 6) = u_fd;
	WFIFOL(chr->login_session, 10) = u_aid;
	WFIFOL(chr->login_session, 14) = u_group;
	WFIFOL(chr->login_session, 18) = map_fd;
	WFIFOSET(chr->login_session, sizeof(struct PACKET_WA_ACCOUNT_INFO_REQUEST));
}

/**
 * WA_ACCOUNT_LIST
 * Periodic broadcast of logged user accounts to login-server
 * @see loginif_account_list_sub
 * @see TimerFunc
 **/
static int loginif_account_list(struct timer_interface *tm, int tid, int64 tick, int id, intptr_t data)
{
	if(!chr->login_session)
		return 0;

	int users = chr->online_char_db->size(chr->online_char_db);
	int i = 0;

	WFIFOHEAD(chr->login_session, 8+users*4, true);
	WFIFOW(chr->login_session,0) = HEADER_WA_ACCOUNT_LIST;
	chr->online_char_db->foreach(chr->online_char_db, loginif->account_list_sub, &i, users);
	WFIFOW(chr->login_session,2) = 8+ i*4; // length
	WFIFOL(chr->login_session,4) = i; // count
	WFIFOSET(chr->login_session,WFIFOW(chr->login_session,2));

	return 0;
}

/**
 * WA_REQUEST_ACCOUNT
 * Requests account data from login-server
 **/
static void loginif_request_account_data(int account_id)
{
	Assert_retv(chr->login_session);
	WFIFOHEAD(chr->login_session, sizeof(struct PACKET_WA_REQUEST_ACCOUNT), true);
	WFIFOW(chr->login_session,0) = HEADER_WA_REQUEST_ACCOUNT;
	WFIFOL(chr->login_session,2) = account_id;
	WFIFOSET(chr->login_session, sizeof(struct PACKET_WA_REQUEST_ACCOUNT));
}

/**
 * WA_SET_ALL_OFFLINE
 * Notifies login-server that all characters should be offline.
 **/
static void loginif_set_all_offline(void)
{
	Assert_retv(chr->login_session);
	WFIFOHEAD(chr->login_session, sizeof(struct PACKET_WA_SET_ALL_OFFLINE), true);
	WFIFOW(chr->login_session,0) = HEADER_WA_SET_ALL_OFFLINE;
	WFIFOSET(chr->login_session, sizeof(struct PACKET_WA_SET_ALL_OFFLINE));
}

/**
 * WA_ACCOUNT_ONLINE 
 * Notifies login-server that this account is online
 **/
static void loginif_set_account_online(int account_id)
{
	Assert_retv(chr->login_session);
	WFIFOHEAD(chr->login_session, sizeof(struct PACKET_WA_ACCOUNT_ONLINE), true);
	WFIFOW(chr->login_session,0) = HEADER_WA_ACCOUNT_ONLINE;
	WFIFOL(chr->login_session,2) = account_id;
	WFIFOSET(chr->login_session, sizeof(struct PACKET_WA_ACCOUNT_ONLINE));
}

/**
 * HEADER_WA_ACCOUNT_OFFLINE
 * Notifies login-server that this account is offline
 **/
static void loginif_set_account_offline(int account_id)
{
	Assert_retv(chr->login_session);
	WFIFOHEAD(chr->login_session, sizeof(struct PACKET_WA_ACCOUNT_OFFLINE), true);
	WFIFOW(chr->login_session,0) = HEADER_WA_ACCOUNT_OFFLINE;
	WFIFOL(chr->login_session,2) = account_id;
	WFIFOSET(chr->login_session, sizeof(struct PACKET_WA_ACCOUNT_OFFLINE));
}


/**
 * WA_REQUEST_CHANGE_EMAIL
 * Requests login-server to update the e-mail of an account (this is relayed from map-server)
 **/
static void loginif_request_change_email(int account_id, char current_email[40], char new_email[40])
{
	Assert_retv(chr->login_session);
	WFIFOHEAD(chr->login_session, sizeof(struct PACKET_WA_REQUEST_CHANGE_EMAIL), true);
	WFIFOW(chr->login_session, 0) = HEADER_WA_REQUEST_CHANGE_EMAIL;
	WFIFOL(chr->login_session, 2) = account_id;
	memcpy(WFIFOP(chr->login_session, 6), current_email, 40);
	memcpy(WFIFOP(chr->login_session, 46), new_email, 40);
	WFIFOSET(chr->login_session, sizeof(struct PACKET_WA_REQUEST_CHANGE_EMAIL));
}

/**
 * WA_ACCOUNT_REG2
 * Sends new registry information for saving.
 * @remarks This packet is separated in three functions, this function sets up the
 * header, while loginif_save_accreg2_entry fills entries and xxx
 * marks the buffer for sending.
 * @see loginif_save_accreg2_entry
 * @see PACKET_WA_ACCOUNT_REG2
 **/
static void loginif_save_accreg2_head(int account_id, int char_id)
{
	Assert_retv(chr->login_session);
	WFIFOHEAD(chr->login_session, 60000 + 300, true);
	WFIFOW(chr->login_session,0)  = HEADER_WA_ACCOUNT_REG2;
	WFIFOW(chr->login_session,2)  = 14; // Length without remaining data
	WFIFOL(chr->login_session,4)  = account_id;
	WFIFOL(chr->login_session,8)  = char_id;
	WFIFOW(chr->login_session,12) = 0; // Count
}

/**
 * Sends WA_ACCOUNT_REG2 packet that was started with loginif_save_accreg2_head.
 * @see PACKET_WA_ACCOUNT_REG2
 **/
static void loginif_save_accreg2_send(void)
{
	WFIFOSET(chr->login_session, WFIFOW(chr->login_session,2));
}

/**
 * Fills entry buffer of a WA_ACCOUNT_REG2 packet that was started with
 * loginif_save_accreg2_head.
 *
 * @param key        Key (c-string)
 * @param index      Database index
 * @param val        Value, when 0 the key is marked for deletion
 * @param is_string	 Value type (boolean)
 * @see PACKET_WA_ACCOUNT_REG2
 **/
static void loginif_save_accreg2_entry(const char *key, unsigned int index, intptr_t val, bool is_string)
{
	size_t count = WFIFOW(chr->login_session, 2);
	size_t key_len = strlen(key)+1;

	count += sizeof((WFIFOB(chr->login_session, count) = min(key_len, SCRIPT_VARNAME_LENGTH + 1)));

	safestrncpy(WFIFOP(chr->login_session, count), key, key_len);
	count += key_len;

	count += sizeof(WFIFOL(chr->login_session, count) = index);

	/**
	 * Set appropriate flag and value if necessary
	 * @see PACKET_WA_ACCOUNT_REG2::entry::flag
	 **/
	if( is_string ) {
		count += sizeof((WFIFOB(chr->login_session, count) = val ? 2 : 3));

		if(val) {
			char *sval = (char*)val;
			size_t val_len = strlen(sval)+1;

			count += sizeof(WFIFOB(chr->login_session, count) = min(val_len-1, 255));

			safestrncpy(WFIFOP(chr->login_session, count), sval, val_len);
			count += val_len;
		}
	} else {
		count += sizeof((WFIFOB(chr->login_session, count) = val ? 0 : 1));
		if(val)
			count += sizeof((WFIFOL(chr->login_session, count) = (int)val));
	}

	WFIFOW(chr->login_session,12) += 1; // Increase entry count

	WFIFOW(chr->login_session, 2) = count; // Update packet length
	if( WFIFOW(chr->login_session, 2) > 60000 ) {
		int account_id = WFIFOL(chr->login_session,4);
		int char_id = WFIFOL(chr->login_session,8);
		loginif->save_accreg2_send();
		loginif->save_accreg2_head(account_id,char_id);/* prepare next */
	}
}

/**
 * WA_ACCOUNT_REG2_REQ
 * Requests Account2 registry values to login-server
 **/
static void loginif_request_accreg2(int account_id, int char_id)
{
	if(!chr->login_session)
		return; // This can be called without having a login-server connected

	WFIFOHEAD(chr->login_session, sizeof(struct PACKET_WA_ACCOUNT_REG2_REQ), true);
	WFIFOW(chr->login_session,0) = HEADER_WA_ACCOUNT_REG2_REQ;
	WFIFOL(chr->login_session,2) = account_id;
	WFIFOL(chr->login_session,6) = char_id;
	WFIFOSET(chr->login_session, sizeof(struct PACKET_WA_ACCOUNT_REG2_REQ));
}

/**
 * WA_UPDATE_STATE
 * Requests login-server to update the block state of an account
 * @param state New account state from ALE_OK to ALE_UNAUTHORIZED
 * @see mmo_account::state
 **/
static void loginif_update_state(int account_id, enum accept_login_errorcode state)
{
	Assert_retv(chr->login_session);
	WFIFOHEAD(chr->login_session, sizeof(struct PACKET_WA_UPDATE_STATE), true);
	WFIFOW(chr->login_session,0) = HEADER_WA_UPDATE_STATE;
	WFIFOL(chr->login_session,2) = account_id;
	/**
	 * The state is increased by 1 in order to keep table backwards compatibility.
	 * Login-server handles the state taking this increasal into account.
	 * @see mmo_account::state
	 * @see accept_login_errorcode
	 **/
	WFIFOL(chr->login_session,6) = state+1;
	WFIFOSET(chr->login_session,sizeof(struct PACKET_WA_UPDATE_STATE));
}

/**
 * WA_BAN
 * Requests banishment for the provided account.
 **/
static void loginif_ban_account(int account_id, short year, short month, short day, short hour, short minute, short second)
{
	Assert_retv(chr->login_session);
	WFIFOHEAD(chr->login_session, sizeof(struct PACKET_WA_BAN), true);
	WFIFOW(chr->login_session, 0) = HEADER_WA_BAN;
	WFIFOL(chr->login_session, 2) = account_id;
	WFIFOW(chr->login_session, 6) = year;
	WFIFOW(chr->login_session, 8) = month;
	WFIFOW(chr->login_session,10) = day;
	WFIFOW(chr->login_session,12) = hour;
	WFIFOW(chr->login_session,14) = minute;
	WFIFOW(chr->login_session,16) = second;
	WFIFOSET(chr->login_session, sizeof(struct PACKET_WA_BAN));
}

/**
 * WA_UNBAN
 * Requests unblocking of an account
 **/
static void loginif_unban_account(int account_id)
{
	Assert_retv(chr->login_session);
	WFIFOHEAD(chr->login_session, sizeof(struct PACKET_WA_UNBAN), true);
	WFIFOW(chr->login_session,0) = HEADER_WA_UNBAN;
	WFIFOL(chr->login_session,2) = account_id;
	WFIFOSET(chr->login_session, sizeof(struct PACKET_WA_UNBAN));
}

/**
 * WA_SEX_CHANGE
 * Requests sex switch of an account
 **/
static void loginif_changesex(int account_id)
{
	Assert_retv(chr->login_session);
	WFIFOHEAD(chr->login_session, sizeof(struct PACKET_WA_SEX_CHANGE), true);
	WFIFOW(chr->login_session, 0) = HEADER_WA_SEX_CHANGE;
	WFIFOL(chr->login_session, 2) = account_id;
	WFIFOSET(chr->login_session, sizeof(struct PACKET_WA_SEX_CHANGE));
}

/**
 * PACKET_WA_AUTH
 * Asks login-server to authenticate an account (new connection)
 **/
static void loginif_auth(int session_id, struct char_session_data *sd, uint32 ipl)
{
	Assert_retv(chr->login_session);
	nullpo_retv(sd);
	WFIFOHEAD(chr->login_session, sizeof(struct PACKET_WA_AUTH), true);
	WFIFOW(chr->login_session,0) = HEADER_WA_AUTH;
	WFIFOL(chr->login_session,2) = sd->account_id;
	WFIFOL(chr->login_session,6) = sd->login_id1;
	WFIFOL(chr->login_session,10) = sd->login_id2;
	WFIFOB(chr->login_session,14) = sd->sex;
	WFIFOL(chr->login_session,15) = htonl(ipl);
	WFIFOL(chr->login_session,19) = session_id;
	WFIFOSET(chr->login_session, sizeof(struct PACKET_WA_AUTH));
}

/**
 * WA_SEND_USERS_COUNT
 * Sends user count to login-server
 **/
static void loginif_send_users_count(int users)
{
	Assert_retv(chr->login_session);
	WFIFOHEAD(chr->login_session, sizeof(struct PACKET_WA_SEND_USERS_COUNT), true);
	WFIFOW(chr->login_session,0) = HEADER_WA_SEND_USERS_COUNT;
	WFIFOL(chr->login_session,2) = users;
	WFIFOSET(chr->login_session, sizeof(struct PACKET_WA_SEND_USERS_COUNT));
}

/**
 * Asks for authentication to login-server
 *
 * CA_CHARSERVERCONNECT
 **/
static void loginif_connect_to_server(void)
{
	Assert_retv(chr->login_session);
	WFIFOHEAD(chr->login_session, sizeof(struct PACKET_CA_CHARSERVERCONNECT), true);
	WFIFOW(chr->login_session,0) = HEADER_CA_CHARSERVERCONNECT;
	memcpy(WFIFOP(chr->login_session,2), chr->userid, NAME_LENGTH);
	memcpy(WFIFOP(chr->login_session,26), chr->passwd, NAME_LENGTH);
	WFIFOL(chr->login_session,50) = 0;
	WFIFOL(chr->login_session,54) = htonl(chr->ip);
	WFIFOW(chr->login_session,58) = htons(chr->port);
	memcpy(WFIFOP(chr->login_session,60), chr->server_name, 20);
	WFIFOW(chr->login_session,80) = 0;
	WFIFOW(chr->login_session,82) = chr->server_type;
	WFIFOW(chr->login_session,84) = chr->new_display; //only display (New) if they want to [Kevin]
	WFIFOSET(chr->login_session, sizeof(struct PACKET_CA_CHARSERVERCONNECT));
}

void loginif_defaults(void) {
	loginif = &loginif_s;

	loginif->packet_db = NULL;
	loginif->packet_list = NULL;

	loginif->init = do_init_loginif;
	loginif->final = do_final_loginif;
	loginif->check_shutdown = loginif_check_shutdown;
	loginif->on_disconnect = loginif_on_disconnect;
	loginif->on_ready = loginif_on_ready;

	loginif->ping = loginif_ping;
	loginif->pincode_update = loginif_pincode_update;
	loginif->pincode_failed = loginif_pincode_failed;
	loginif->update_ip = loginif_update_ip;
	loginif->accinfo_request  = loginif_accinfo_request;
	loginif->account_list_sub = loginif_account_list_sub;
	loginif->account_list     = loginif_account_list;
	loginif->request_account_data = loginif_request_account_data;
	loginif->set_all_offline = loginif_set_all_offline;
	loginif->set_account_online  = loginif_set_account_online;
	loginif->set_account_offline = loginif_set_account_offline;
	loginif->request_change_email = loginif_request_change_email;
	loginif->save_accreg2_head  = loginif_save_accreg2_head;
	loginif->save_accreg2_entry = loginif_save_accreg2_entry;
	loginif->save_accreg2_send  = loginif_save_accreg2_send; 
	loginif->request_accreg2 = loginif_request_accreg2;
	loginif->update_state = loginif_update_state;
	loginif->ban_account = loginif_ban_account;
	loginif->unban_account = loginif_unban_account;
	loginif->changesex = loginif_changesex;
	loginif->auth = loginif_auth;
	loginif->send_users_count = loginif_send_users_count;
	loginif->connect_to_server = loginif_connect_to_server;
}
