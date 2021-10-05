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
#include "char/inter.h"
#include "char/pincode.h"

#include "common/HPM.h"
#include "common/cbasetypes.h"
#include "common/core.h"
#include "common/db.h"
#include "common/nullpo.h"
#include "common/showmsg.h"
#include "common/socket.h"
#include "common/timer.h"
#include "common/strlib.h"
#include "common/memmgr.h"

#include "common/rwlock.h"
#include "common/mutex.h"
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
#define packet_def(name, fname) { HEADER_ ## name, sizeof(struct PACKET_ ## name), loginif->parse_ ## fname }
#define packet_def2(name, fname, len) { HEADER_ ## name, (len), loginif->parse_ ## fname }
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
		packet_def2(AW_ACCOUNT_REG2,         account_reg2, -1),
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
static void loginif_request_change_email(int account_id, const char current_email[40], const char new_email[40])
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

	count += sizeof((WFIFOB(chr->login_session, count) = min((uint8)key_len, SCRIPT_VARNAME_LENGTH + 1)));

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

			count += sizeof(WFIFOB(chr->login_session, count) = min((uint8)val_len-1, 255));

			safestrncpy(WFIFOP(chr->login_session, count), sval, val_len);
			count += val_len;
		}
	} else {
		count += sizeof((WFIFOB(chr->login_session, count) = val ? 0 : 1));
		if(val)
			count += sizeof((WFIFOL(chr->login_session, count) = (int)val));
	}

	WFIFOW(chr->login_session,12) += 1; // Increase entry count

	WFIFOW(chr->login_session, 2) = (uint8)count; // Update packet length
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

/*======================================
 * Parsing functions
 *--------------------------------------*/

/**
 * AW_CHARSERVERCONNECT_ACK
 * Result of connection request
 * @see enum ac_charserverconnect_ack_status
 **/
static void loginif_parse_connection_state(struct s_receive_action_data *act)
{
	switch(RFIFOB(act,2)) {
		case CCA_ACCEPTED:
			ShowStatus("Connected to login-server (connection #%d).\n",
				act->session->id);
			loginif->on_ready();
			return;
		case CCA_INVALID_CREDENTIAL: // Invalid username/password
			ShowError(
				"Can not connect to login-server.\n"
				"The server communication passwords (default s1/p1) "
				"are probably invalid.\n"
				"Also, please make sure your login db has the correct "
				"communication username/passwords and the gender of the account is S.\n"
				"The communication passwords are set in "
				"/conf/map/map-server.conf and /conf/char/char-server.conf\n"
				);
			break;
		case CCA_IP_NOT_ALLOWED: // IP not allowed
			ShowError(
				"Can not connect to login-server.\n"
				"Please make sure your IP is allowed in conf/network.conf\n"
				);
			break;
		case CCA_INVALID_ACC_ID: // Account id out of range
			ShowError(
				"Can not connect to login-server.\n"
				"Character-server has an account id out of valid range.\n"
				);
			break;
		case CCA_INVALID_SEX: // Invalid sex for server credential
			ShowError(
				"Can not connect to login-server.\n"
				"Character-server has an account with an invalid sex type.\n"
				);
			break;
		case CCA_INVALID_NOT_READY: // Login-server is not ready
			ShowError(
				"Can not connect to login-server.\n"
				"Login-server is not yet ready for a new connection.\n"
				);
			break;
		case CCA_ALREADY_CONNECTED: // Someone already used these credentials
			ShowError(
				"Can not connect to login-server.\n"
				"Our credentials were already used in this server!\n"
				);
			break;
		default:
			ShowError("Invalid response from the login-server. Error code: %d\n",
				(int)RFIFOB(act, 2));
			break;
	}
	socket_io->session_disconnect_guard(act->session);
}

/**
 * Player authentication steps:
 *
 * New player connection (CH_ENTER (0x065) chr->parse_char_connect)
 * Request login-server for auth data (WA_AUTH)
 *
 * Receive authentication data (AW_AUTH_ACK loginif->parse_auth_state)
 * chr->auth_ok
 *   Notify that this account is in char-server (WA_ACCOUNT_ONLINE)
 *   Request login-server for account information (WA_REQUEST_ACCOUNT)
 * Receive account information (AW_REQUEST_ACCOUNT_ACK)
 * Send confirmation to player.
 **/

/**
 * AW_AUTH_ACK
 * Result of an account authentication request
 **/
static void loginif_parse_auth_state(struct s_receive_action_data *act)
{
	enum notify_ban_errorcode flag = NBE_SUCCESS;
	struct char_session_data* sd = NULL;

	int account_id               = RFIFOL(act,2);
	uint32 login_id1             = RFIFOL(act,6);
	uint32 login_id2             = RFIFOL(act,10);
	uint8 sex                    = RFIFOB(act,14);
	uint8 result                 = RFIFOB(act,15);
	int request_id               = RFIFOL(act,16);
	uint32 version               = RFIFOL(act,20);
	uint8 clienttype             = RFIFOB(act,24);
	int group_id                 = RFIFOL(act,25);
	unsigned int expiration_time = RFIFOL(act,29);

	struct socket_data *client_session = socket_io->session_from_id(request_id);
	if(!client_session)
		return;
	mutex->lock(client_session->mutex);
	bool marked_removal = socket_io->session_marked_removal(client_session);
	mutex->unlock(client_session->mutex);

	if(marked_removal)
		return; // Ignore this authentication

	sd = client_session->session_data;
	if(!sd) {
		// Invalid session. Force disconnection.
		flag = NBE_TIME_GAP;
		goto failed_auth;
	}
	if(sd->auth) {
		/**
		 * How was this session already authenticated? Has another worker 
		 * asked for the authentication or is the login-server resending
		 * us this packet? Disconnect the player.
		 **/
		ShowDebug("loginif_parse_auth_state: Tried to reauthenticate an already "
				  "authenticated account (aid %d), forcing disconnection.\n",
				  sd->account_id);
		/**
		 * The parsing entry-point will remove the session from the db when
		 * the disconnection request is dequeued
		 **/
		flag = NBE_TIME_GAP;
		goto failed_auth;
	}
	if(sd->account_id != account_id
	|| sd->login_id1 != login_id1
	|| sd->login_id2 != login_id2
	|| sd->sex != sex
	) {
		// Data mismatch. Is this 'session' memory being reused by the server?
		flag = NBE_IP_MISMATCH;
		goto failed_auth;
	}

	int client_fd = request_id;
	sd->version = version;
	sd->clienttype = clienttype;
	switch(result) {
		case 0:// ok
			/* restrictions apply */
			if(chr->server_type == CST_MAINTENANCE
			&& group_id < chr->maintenance_min_group_id_get()
			) {
				flag = NBE_SERVER_CLOSED;
				goto failed_auth;
			}
			/* the client will already deny this request, this check is to avoid someone bypassing. */
			if(chr->server_type == CST_PAYING
			&& (time_t)expiration_time < time(NULL)
			) {
				flag = NBE_DISCONNECTED;
				goto failed_auth;
			}
			chr->auth_ok(client_session, sd);
			break;
		case 1:// auth failed
			chr->auth_error(client_session, 0);
			break;
	}
	return;

failed_auth:
	chr->authfail_fd(client_session, flag);
	socket_io->session_disconnect_guard(client_session);
}

/**
 * AW_REQUEST_ACCOUNT_ACK
 * Parses requested account data, and sends connection acceptance to player.
 * @see char_auth_ok
 **/
static void loginif_parse_account_data(struct s_receive_action_data *act)
{
	struct char_session_data *sd;
	struct socket_data *client_session;
	enum notify_ban_errorcode flag = NBE_SUCCESS;

	int32 account_id = RFIFOL(act, 2);
	int32 request_id = RFIFOL(act, 6);
	uint8 result     = RFIFOB(act,10);

	client_session = socket_io->session_from_id(request_id);
	if(!client_session)
		return;

	mutex->lock(client_session->mutex);
	bool marked_removal = socket_io->session_marked_removal(client_session);
	mutex->unlock(client_session->mutex);

	if(marked_removal)
		return; // Ignore this authentication

	sd = client_session->session_data;
	if(!sd || !sd->auth) {
		// Invalid session. Force disconnection.
		flag = NBE_TIME_GAP;
		goto failed_auth;
	}
	if(!result) {
		// Login-server failed to find account data, disconnect
		flag = NBE_DISCONNECTED;
		goto failed_auth;
	}
	int max_connect_user = chr->max_connect_user_get();
	int gm_allow_group = chr->gm_allow_group_get();
	if((max_connect_user == 0 && sd->group_id != gm_allow_group)
	|| (max_connect_user > 0 && chr->count_users() >= max_connect_user && sd->group_id != gm_allow_group)
	) {
		// Refuse connection (over populated)
		flag = NBE_JAMMED_SHORTLY;
		goto failed_auth;
	}

	safestrncpy(sd->email, RFIFOP(act, 11), sizeof(sd->email));
	sd->expiration_time = RFIFOL(act, 51);
	sd->group_id        = RFIFOL(act, 55);
	sd->char_slots      = RFIFOB(act, 59);
	safestrncpy(sd->pincode,   RFIFOP(act, 60), sizeof(sd->pincode));
	safestrncpy(sd->birthdate, RFIFOP(act, 65), sizeof(sd->birthdate));
	sd->pincode_change  = RFIFOL(act, 76);

	if(sd->char_slots > MAX_CHARS) {
		ShowError("Account '%d' `character_slots` column is higher than "
				  "supported MAX_CHARS (%d), update MAX_CHARS in mmo.h! "
				  "Capping to MAX_CHARS...\n",
				  sd->account_id, sd->char_slots);
		sd->char_slots = MAX_CHARS;/* cap to maximum */
	} else if( sd->char_slots <= 0 )/* no value aka 0 in sql */
		sd->char_slots = MAX_CHARS;/* cap to maximum */

	/**
	 * Continued from chr->auth_ok...
	 * send characters to player
	 **/
	chr->mmo_char_send_slots_info(client_session, sd);
	chr->mmo_char_send_characters(client_session, sd);
#if PACKETVER >= 20060819
	chr->mmo_char_send_ban_list(client_session, sd);
#endif
#if PACKETVER >= 20110309
	pincode->handle(client_session, sd);
#endif
	return;

failed_auth:
	chr->authfail_fd(client_session, flag);
	socket_io->session_disconnect_guard(client_session);
}

/**
 * AW_PONG
 * Parses pong from login-server
 **/
static void loginif_parse_login_pong(struct s_receive_action_data *act)
{
	mutex->lock(act->session->mutex);
	act->session->flag.ping = 0;
	mutex->unlock(act->session->mutex);
}

/**
 * AW_SEX_BROADCAST
 * Parses login-server notification of a sex change
 **/
static void loginif_parse_changesex_reply(struct s_receive_action_data *act)
{
	int account_id = RFIFOL(act,2);
	int sex        = RFIFOB(act,6);

	// This should _never_ happen
	if(account_id <= 0) {
		ShowError("Received invalid account id from login server! (aid: %d)\n",
			account_id);
		return;
	}
	chr->changecharsex_all(account_id, sex);
}

/**
 * AW_ACCOUNT_REG2
 * Relays received account2 registry to map-servers
 **/
static void loginif_parse_account_reg2(struct s_receive_action_data *act)
{
	//Receive account_reg2 registry, forward to map servers.
	mapif->sendall(RFIFOP(act, 0), RFIFOW(act,2));
}

/**
 * AW_UPDATE_STATE
 * Parses login-server request to update an account state
 * @see mapif_update_state
 * @readlock chr->map_server_list_lock
 **/
static void loginif_parse_update_state(struct s_receive_action_data *act)
{
	int account_id = RFIFOL(act, 2);
	unsigned char flag = RFIFOB(act,6);
	unsigned int state = RFIFOL(act,7);

	if(flag == 2) {
		ShowWarning("loginif_parse_update_state: Invalid flag, 2 is reserved "
			"for character update, login-server can only ask for account updates!\n");
		return;
	}
	mapif->update_state(account_id, flag, state);
	// disconnect player if online on char-server
	chr->disconnect_player(account_id);
}

/**
 * AW_KICK
 * Kick request from login-server
 **/
static void loginif_parse_kick(struct s_receive_action_data *act)
{
	chr->kick(RFIFOL(act,2));
}

/**
 * AW_IP_UPDATE
 * Parse login-server ip synchronization request
 **/
static void loginif_parse_update_ip(struct s_receive_action_data *act)
{
	unsigned char buf[2];
	WBUFW(buf,0) = 0x2b1e;
	mapif->sendall(buf, 2);

	chr->config_update_ip();
}

/**
 * 0x2744 AW_ACCOUNT_INFO_FAILURE
 * Login-server couldn't find accinfo
 **/
static void loginif_parse_accinfo2_failed(struct s_receive_action_data *act)
{
	int32 map_id     = RFIFOL(act, 2);
	int32 u_fd       = RFIFOL(act, 6);
	int32 u_aid      = RFIFOL(act,10);
	int32 account_id = RFIFOL(act,14);
	inter->accinfo_ack(false, map_id, u_fd, u_aid, account_id,
		NULL, NULL, NULL, NULL, NULL, -1, 0, 0);
}

/**
 * 0x2743 AW_ACCOUNT_INFO_SUCCESS
 * Receive account information
 **/
static void loginif_parse_accinfo2_ok(struct s_receive_action_data *act)
{
	int32 map_id        = RFIFOL(act, 2);
	int32 u_fd          = RFIFOL(act, 6);
	int32 u_aid         = RFIFOL(act,10);
	int32 account_id    = RFIFOL(act,14);
	// userid.24B / email.40B / lastip.16B
	int32 group_id      = RFIFOL(act,98);
	// last_login.24B
	uint32 login_count  = RFIFOL(act,126);
	uint32 state        = RFIFOL(act,130);
	// birthdate.11B
	inter->accinfo_ack(false, map_id, u_fd, u_aid, account_id,
		RFIFOP(act,  18)/*userid*/,    RFIFOP(act, 42)/*email*/,
		RFIFOP(act,  82)/*last_ip*/,   RFIFOP(act, 102)/*last_login*/,
		RFIFOP(act, 134)/*birthdate*/, group_id,
		login_count, state);
}

/**
 * Entry-point of login-server packets
 **/
static enum parsefunc_rcode loginif_parse(struct s_receive_action_data *act)
{
	// only process data from the login-server
	if(!chr->login_session || act->session_id != chr->login_session->id) {
		mutex->lock(act->session->mutex);
		if(!socket_io->session_marked_removal(act->session))
			ShowDebug("loginif_parse: Disconnecting invalid session #%d (is not the login-server)\n",
				act->session->id);
		socket_io->session_disconnect(act->session);
		mutex->unlock(act->session->mutex);
		return PACKET_VALID;
	}

	mutex->lock(act->session->mutex);
	if(socket_io->session_marked_removal(act->session))	{
		mutex->unlock(act->session->mutex);
		chr->login_session = NULL;
		loginif->on_disconnect();
		return PACKET_VALID;
	}
	// @see session_timeout
	if(act->session->flag.ping) { /* we've reached stall time */
		if(DIFF_TICK(socket_io->last_tick, act->session->rdata_tick) > (socket_io->stall_time * 2)) {/* we can't wait any longer */
			socket_io->session_disconnect(act->session);
			mutex->unlock(act->session->mutex);
			return PACKET_VALID;
		}
		if(act->session->flag.ping != 2 ) { /* we haven't sent ping out yet */
			loginif->ping();
			act->session->flag.ping = 2;
		}
	}
	mutex->unlock(act->session->mutex);

	while(RFIFOREST(act) >= 2) {
		uint16 command = RFIFOW(act, 0);

		if (VECTOR_LENGTH(HPM->packets[hpParse_FromLogin]) > 0) {
			int result = HPM->parse_packets(act,command,hpParse_FromLogin);
			if (result == 1)
				continue;
			if (result == 2)
				return PACKET_INCOMPLETE;
		}

		struct loginif_packet_entry *packet_data;
		packet_data = DB->data2ptr(loginif->packet_db->get_safe(loginif->packet_db, DB->i2key(command)));
		if(!packet_data) {
			ShowError("loginif_parse: Unknown packet 0x%04x from a "
				"char-server! Disconnecting!\n", command);
			socket_io->session_disconnect_guard(act->session);
			return PACKET_UNKNOWN;
		}

		size_t packet_len;
		if(packet_data->len == -1)
			packet_len = (RFIFOREST(act) >= 4)?RFIFOW(act, 2):4;
		else
			packet_len = packet_data->len;

		if(RFIFOREST(act) < packet_len)
			return PACKET_INCOMPLETE;

		packet_data->pFunc(act);
		RFIFOSKIP(act, packet_len);
	}
	return PACKET_VALID;
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

	loginif->parse_connection_state = loginif_parse_connection_state;
	loginif->parse_auth_state       = loginif_parse_auth_state;
	loginif->parse_account_data     = loginif_parse_account_data;
	loginif->parse_login_pong       = loginif_parse_login_pong;
	loginif->parse_changesex_reply  = loginif_parse_changesex_reply;
	loginif->parse_account_reg2     = loginif_parse_account_reg2;
	loginif->parse_update_state     = loginif_parse_update_state;
	loginif->parse_kick             = loginif_parse_kick;
	loginif->parse_update_ip        = loginif_parse_update_ip;
	loginif->parse_accinfo2_failed  = loginif_parse_accinfo2_failed;
	loginif->parse_accinfo2_ok      = loginif_parse_accinfo2_ok;
	loginif->parse                  = loginif_parse;
}
