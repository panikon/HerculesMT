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

#include "chclif.h"
#include "char/char.h"
#include "char/pincode.h"
#include "char/packets_ch_struct.h"

#include "common/HPM.h"
#include "common/cbasetypes.h"
#include "common/memmgr.h"
#include "common/socket.h"
#include "common/strlib.h"
#include "common/mmo.h"

#include "common/rwlock.h"
#include "common/mutex.h"

static struct chclif_interface chclif_s;
struct chclif_interface *chclif;

/**
 * CH_REQ_CHANGE_CHARACTER_SLOT
 * Request to change character slot
 **/
static void chclif_parse_move_character(struct s_receive_action_data *act, struct char_session_data *sd, int ipl)
{
	bool ret = chr->char_slotchange(sd, act->session, RFIFOW(act, 2), RFIFOW(act, 4));
	chr->change_character_slot_ack(act->session, ret);
	/* for some stupid reason it requires the char data again (gravity -_-) */
	if(ret)
#if PACKETVER_MAIN_NUM >= 20130522 || PACKETVER_RE_NUM >= 20130327 || defined(PACKETVER_ZERO)
		chr->send_HC_ACK_CHARINFO_PER_PAGE(act->session, sd);
#else
		chr->mmo_char_send_characters(act->session, sd);
#endif
}

/**
 * CH_CHARLIST_REQ
 * Character-list request
 **/
static void chclif_parse_request_chars(struct s_receive_action_data *act, struct char_session_data *sd, int ipl)
{
	chr->send_HC_ACK_CHARINFO_PER_PAGE(act->session, sd);
}

/**
 * CH_ENTER_CHECKBOT
 * CH_CHECKBOT
 * Captcha system (not implemented) TODO
 **/
void chclif_parse_captcha_default(struct s_receive_action_data *act, struct char_session_data *sd, int ipl)
{
	chr->captcha_notsupported(act->session);
}

/**
 * CH_REQ_CHANGE_CHARNAME
 * Player confirms the request.
 **/
void chclif_parse_rename_confirm(struct s_receive_action_data *act, struct char_session_data *sd, int ipl)
{
	int char_id = RFIFOL(act, 2);
	if(!sd->rename) {
		ShowInfo("chclif_parse_rename_confirm: Trying to confirm name change "
			"without prior request, possible forged packet (AID %d target CID %d)",
			sd->account_id, char_id);
		socket_io->session_disconnect_guard(act->session);
		return;
	}
	if(sd->rename->char_id != char_id) {
		aFree(sd->rename);
		sd->rename = NULL;

		chr->rename_char_ack(act->session, CRR_INCORRECT_USER);
		return;
	}

	enum change_charname_result result;
	result = chr->rename_char_sql(sd, char_id);

	chr->rename_char_ack(act->session, result);
	if(result != CRR_DUPLICATE && result != CRR_FAILED) {
		aFree(sd->rename);
		sd->rename = NULL;
		// In other results the player may retry to change the name.
	}
}

/**
 * CH_REQ_IS_VALID_CHARNAME and CH_REQ_IS_VALID_CHARNAME2
 * Rename request.
 **/
void chclif_parse_rename(struct s_receive_action_data *act, struct char_session_data *sd, int ipl)
{
	int char_id;
	const char *name;

	if(RFIFOW(act, 0) == HEADER_CH_REQ_IS_VALID_CHARNAME) {
		char_id = RFIFOL(act, 2);
		name    = RFIFOP(act, 6);
	} else {
		int account_id = RFIFOL(act, 2);
		if(account_id != sd->account_id) {
			ShowInfo("chclif_parse_rename: incompatible provided account id (%d vs %d), "
				"forged packet?\n", account_id, sd->account_id);
			socket_io->session_disconnect_guard(act->session);
			return;
		}
		char_id = RFIFOL(act, 6);
		name    = RFIFOP(act,10);
	}
	int i;
	ARR_FIND(0, MAX_CHARS, i, sd->found_char[i] == char_id);
	if(i == MAX_CHARS) {
		chr->allow_rename(act->session, false);
		return; // Invalid character selection
	}
	if(sd->rename)
		sd->rename->new_name[0] = '\0';
	else
		sd->rename = aMalloc(sizeof(*sd->rename));
	sd->rename->char_id = char_id;

	/**
	 * It's safe to pass a buffer that can be non nul-terminated
	 * to escape_normalize_name, also the escaped name is guaranteed
	 * by the mysql API to be nul terminated.
	 **/
	chr->escape_normalize_name(name, sd->rename->new_name);
	if(chr->check_char_name(name, sd->rename->new_name) != RMCE_CREATED) {
		// Don't free rename data yet, the player probably will retry.
		chr->allow_rename(act->session, false);
		return;
	}
	chr->allow_rename(act->session, true);
	/** Character renaming process
	 * Asks if required name is valid or not
	 * R C CH_REQ_IS_VALID_CHARNAME (chclif_parse_rename)
	 * S C HC_ACK_IS_VALID_CHARNAME (chr->allow_rename)
	 * Confirms if player wants to change char name (if not confirmed no packet is sent)
	 * R C CH_REQ_CHANGE_CHARNAME   (chclif_parse_rename_confirm)
	 * S C HC_ACK_CHANGE_CHARNAME   (chr->rename_char_ack)
	 **/
}

/**
 * CH_PING
 * Keep-alive packet.
 **/
void chclif_parse_ping(struct s_receive_action_data *act, struct char_session_data *sd, int ipl)
{
	// Answer with the same packet
	WFIFOHEAD(act->session, sizeof(struct PACKET_CH_PING), true);
	WFIFOL(act->session, 0) = HEADER_CH_PING;
	WFIFOL(act->session, 2) = RFIFOL(act, 2);
	WFIFOSET(act->session, sizeof(struct PACKET_CH_PING));
	return;
}

/**
 * CH_DELETE_CHAR3_CANCEL
 * Player wishes to remove the character from deletion queue.
 **/
void chclif_parse_delete2_cancel(struct s_receive_action_data *act, struct char_session_data *sd, int ipl)
{
	int char_id = RFIFOL(act, 2);

	int i;
	ARR_FIND(0, MAX_CHARS, i, sd->found_char[i] == char_id);
	if(i == MAX_CHARS ) {// character not found
		chr->delete2_cancel_ack(act->session, char_id, 2); // 2: A database error occurred
		return;
	}

	// there is no need to check, whether or not the character was
	// queued for deletion, as the client prints an error message by
	// itself, if it was not the case (@see chr->delete2_cancel_ack)
	if(!chr->delete_remove_queue(char_id))
		chr->delete2_cancel_ack(act->session, char_id, 2); // 2: A database error occurred
	else
		chr->delete2_cancel_ack(act->session, char_id, 1); // 1: success
}

/**
 * CH_DELETE_CHAR3
 * Player confirms wish to delete the character.
 **/
void chclif_parse_delete2_accept(struct s_receive_action_data *act, struct char_session_data *sd, int ipl)
{
	int i;
	int char_id;
	char birthdate[8+1];

	char_id = RFIFOL(act, 2);
	// construct "YY-MM-DD"
	birthdate[0] = RFIFOB(act,6);
	birthdate[1] = RFIFOB(act,7);
	birthdate[2] = '-';
	birthdate[3] = RFIFOB(act,8);
	birthdate[4] = RFIFOB(act,9);
	birthdate[5] = '-';
	birthdate[6] = RFIFOB(act,10);
	birthdate[7] = RFIFOB(act,11);
	birthdate[8] = 0;

	ShowInfo(CL_RED"Request Char Deletion: "CL_GREEN"%d (%d)"CL_RESET"\n",
		sd->account_id, char_id);

	ARR_FIND(0, MAX_CHARS, i, sd->found_char[i] == char_id);
	if(i == MAX_CHARS) {// character not found
		chr->delete2_accept_ack(act->session, char_id, 3); // 3: A database error occurred
		return;
	}

	int delete_date = 0;
	int result = chr->can_delete(char_id, &delete_date);
	if(result != 1) {
		chr->delete2_accept_ack(act->session, char_id, result);
		return;
	}

	if(!delete_date || delete_date>time(NULL)) { // not queued or delay not yet passed
		// 4: Deleting not yet possible time
		chr->delete2_accept_ack(act->session, char_id, 4);
		return;
	}

	if(strcmp(sd->birthdate+2, birthdate)) { // +2 to cut off the century
		// 5: Date of birth do not match
		chr->delete2_accept_ack(act->session, char_id, 5);
		return;
	}

	if(chr->delete_char_sql(char_id) < 0 ) {
		chr->delete2_accept_ack(act->session, char_id, 3); // 3: A database error occurred
		return;
	}

	// Refresh character list cache
	sd->found_char[i] = -1;
	chr->delete2_accept_ack(act->session, char_id, 1); // 1: success
}

/**
 * CH_DELETE_CHAR3_RESERVED
 **/
void chclif_parse_delete2_req(struct s_receive_action_data *act, struct char_session_data *sd, int ipl)
{
	int char_id = RFIFOL(act, 2);

	int i;
	ARR_FIND(0, MAX_CHARS, i, sd->found_char[i] == char_id);
	if(i == MAX_CHARS ) {// character not found
		chr->delete2_ack(act->session, char_id, 3, 0); // 3: A database error occurred
		return;
	}
	time_t delete_date = 0;
	int result = chr->delete_insert_queue(char_id, &delete_date);
	chr->delete2_ack(act->session, char_id, result, delete_date);

	/**
	 ** New deletion process
	 * Asks to delete char (puts character in 'deletion queue')
	 * 	R C CH_DELETE_CHAR3_RESERVED (chclif_parse_delete2_req)
	 *  S C HC_DELETE_CHAR3_RESERVED (chr->delete2_ack)
	 * Deletion date arrives and player confirms deletion request
	 *  R C CH_DELETE_CHAR2 	   (chclif_parse_delete2_accept)
	 *  S C HC_ACCEPT_DELETECHAR   (chr->delete_char_ok)
	 * Asks to cancel deletion (remove from 'deletion_queue')
	 *  R C CH_DELETE_CHAR3_CANCEL (chclif_parse_delete2_cancel)
	 *  S C HC_DELETE_CHAR3_CANCEL (chr->delete2_cancel_ack)
	 ** Old deletion process
	 *  R C CH_DELETE_CHAR         (chclif_parse_delete_char)
	 *  S C HC_ACCEPT_DELETECHAR   (chr->delete_char_ok)
	 **/
}

/**
 * CH_DELETE_CHAR and CH_DELETE_CHAR2
 * Confirmation of a delete character request
 *
 * Acquires db_lock(chr->online_char_db)
 **/
void chclif_parse_delete_char(struct s_receive_action_data *act, struct char_session_data *sd, int ipl)
{
	/**
	 * Currently the server only supports keys (emails) up to 40 characters, so
	 * any exceeding characters are discarded.
	 **/
	char email[40];
	int char_id = RFIFOL(act, 2);

#if PACKETVER >= 20110309
	if(pincode->enabled) { // hack check
		struct online_char_data *character;

		int pincode_enable = 0;
		db_lock(chr->online_char_db, WRITE_LOCK);
		character = idb_get(chr->online_char_db, sd->account_id);
		pincode_enable = (character)?character->pincode_enable:0;
		db_unlock(chr->online_char_db);

		if(pincode_enable == -1) {
			chr->auth_error(act->session, 0);
			socket_io->session_disconnect_guard(act->session);
			return;
		}
	}
#endif
	ShowInfo(CL_RED"Request Char Deletion: "CL_GREEN"%d (%d)"CL_RESET"\n",
		sd->account_id, char_id);
	memcpy(email, RFIFOP(act,6), 40);
	email[39] = '\0';

	if(chr->can_delete(char_id, NULL) != 1) {
		chr->delete_char_failed(act->session, 3); // 3: Character deletion is denied
		return;
	}

	// Check if e-mail is correct
	if(strcmpi(email, sd->email) != 0  /* emails don't match */
	&& ( (strcmp("a@a.com", sd->email) != 0) /* it's not the default email */
	  || (strcmp("a@a.com", email) != 0 && strcmp("", email) != 0) /* sent email isn't the default */
	   )
	) {
		//Fail
		chr->delete_char_failed(act->session, 0);
		return;
	}

	// check if this char exists
	int i;
	ARR_FIND( 0, MAX_CHARS, i, sd->found_char[i] == char_id );
	if( i == MAX_CHARS )
	{ // Such a character does not exist in the account
		chr->delete_char_failed(act->session, 0);
		return;
	}

	// remove char from list and compact it
	sd->found_char[i] = -1;

	/* Delete character */
	if(chr->delete_char_sql(char_id) < 0){
		//can't delete the char
		//either SQL error or can't delete by some CONFIG conditions
		chr->delete_char_failed(act->session, 0);
		return;
	}
	/* Char successfully deleted.*/
	chr->delete_char_ok(act->session);
}

/**
 * CH_MAKE_CHAR
 * Parses character creation request.
 **/
void chclif_parse_make_char(struct s_receive_action_data *act, struct char_session_data *sd, int ipl)
{
	enum refuse_make_char_errorcode result;
	int char_id = -1;
#if PACKETVER >= 20151001
	uint8 sex = RFIFOB(act, 35);

	switch (sex) {
		case SEX_FEMALE:
			sex = 'F';
			break;
		case SEX_MALE:
			sex = 'M';
			break;
		default:
			chr->creation_failed(act->session, RMCE_DENIED);
			return;
	}

	result = chr->make_new_char_sql(sd, RFIFOP(act, 2), 1, 1, 1, 1, 1, 1,
		RFIFOB(act, 26), RFIFOW(act, 27), RFIFOW(act, 29), RFIFOL(act, 31),
		sex, &char_id);
#elif PACKETVER >= 20120307
	result = chr->make_new_char_sql(sd, RFIFOP(act, 2), 1, 1, 1, 1, 1, 1,
		RFIFOB(act, 26), RFIFOW(act, 27), RFIFOW(act, 29), JOB_NOVICE, 'U',
		&char_id);
#else
	result = chr->make_new_char_sql(sd, RFIFOP(act, 2), RFIFOB(act, 26),
		RFIFOB(act, 27), RFIFOB(act, 28), RFIFOB(act, 29), RFIFOB(act, 30),
		RFIFOB(act, 31), RFIFOB(act, 32), RFIFOW(act, 33), RFIFOW(act, 35),
		JOB_NOVICE, 'U', &char_id);
#endif
	if(result != RMCE_CREATED || char_id < 0) {
		chr->creation_failed(act->session, result);
		return;
	}
	/**
	 * Retrieve data from database, all passed strings are escaped before insertion so
	 * we can be sure that any access to the data in char_data is safe.
	 **/
	struct mmo_charstatus char_dat;
	if(!chr->mmo_char_fromsql(char_id, CHARSAVE_STATUS, &char_dat,
		CHARCACHE_IGNORE_NOLOCK)
	) { //Only the short data is needed.
		chr->creation_failed(act->session, RMCE_DENIED);
		return;
	}
	chr->creation_ok(act->session, &char_dat);

	// add new entry to the chars list
	sd->found_char[char_dat.slot] = char_id;
}

/**
 * CH_SELECT_CHAR
 * Parses character selection and notifies player of the available map-server.
 *
 * Acquires db_lock(chr->char_db_)
 **/
void chclif_parse_select_char(struct s_receive_action_data *act, struct char_session_data *sd, int ipl)
{
#if PACKETVER >= 20110309
	if(pincode->enabled) { // hack check
		struct online_char_data *character;

		int pincode_enable = 0;
		db_lock(chr->online_char_db, WRITE_LOCK);
		character = idb_get(chr->online_char_db, sd->account_id);
		pincode_enable = (character)?character->pincode_enable:0;
		db_unlock(chr->online_char_db);

		if(pincode_enable == -1) {
			chr->auth_error(act->session, 0);
			socket_io->session_disconnect_guard(act->session);
			return;
		}
	}
#endif

	rwlock->read_lock(chr->map_server_list_lock);
	bool is_map_available = INDEX_MAP_COUNT(chr->map_server_list);
	rwlock->read_unlock(chr->map_server_list_lock);
	/* not available, tell it to wait (client wont close; char select will respawn).
	 * magic response found by Ind thanks to Yommy <3 */
	if(!is_map_available) {
		chr->send_wait_char_server(act->session);
		return;
	}

	uint8 slot = RFIFOB(act, 2);
	int char_id = chr->slot2id(sd->account_id, slot);
	if(char_id == -1) {
		// Not found?? May be forged packet.
		chr->auth_error(act->session, 0);
		socket_io->session_disconnect_guard(act->session);
		return;
	}

	/* client doesn't let it get to this point if you're banned, so its a forged packet */
	if(sd->found_char[slot] == char_id && sd->unban_time[slot] > time(NULL)) {
		chr->auth_error(act->session, 0);
		socket_io->session_disconnect_guard(act->session);
		return;
	}

	/* set char as online prior to loading its data so 3rd party applications will
	 * realize the sql data is not reliable */
	chr->set_char_online(-2,char_id,sd->account_id);

	struct mmo_charstatus *cd;
	db_lock(chr->char_db_, WRITE_LOCK);
	cd = chr->mmo_char_fromsql(char_id, CHARSAVE_ALL, NULL, CHARCACHE_INSERT);
	if(!cd) {
		db_unlock(chr->char_db_);
		/* failed to load something. REJECT! */
		db_lock(chr->online_char_db, WRITE_LOCK);
		chr->set_char_offline(char_id, sd->account_id);
		db_unlock(chr->online_char_db);
		chr->auth_error(act->session, 0);
		socket_io->session_disconnect_guard(act->session);
		return;/* jump off this boat */
	}
	if(cd->sex == 99)
		cd->sex = sd->sex;
	chr->log_select(cd, slot);
	ShowInfo("Selected char: (Account %d: %d - %s)\n",
		sd->account_id, slot, cd->name);

	struct point last_point;
	memcpy(&last_point, &cd->last_point, sizeof(last_point));
	db_unlock(chr->char_db_);

	rwlock->read_lock(chr->map_server_list_lock);
	struct mmo_map_server *server;
	int server_id = chr->get_map_server(&last_point);
	if(server_id < 0 || !(server = INDEX_MAP_INDEX(chr->map_server_list, server_id))) {
		rwlock->read_unlock(chr->map_server_list_lock);
		ShowInfo("Connection Closed. %s.\n",
			(server_id == -1)?
				"No map servers available":
				"No map server available with a major city");
		chr->authfail_fd(act->session, NBE_SERVER_CLOSED);
		socket_io->session_disconnect_guard(act->session);
		return;
	}
	uint32 map_ip = server->ip;
	uint16 map_port = server->port;
	rwlock->read_unlock(chr->map_server_list_lock);

	int subnet_map_ip = chr->lan_subnet_check(ipl);

	// Send map information to client and then create a new auth entry
	chr->send_map_info(act->session, subnet_map_ip, map_ip,
		map_port, char_id, &last_point, NULL);
	chr->create_auth_entry(sd, cd->char_id, ipl, false);
}

/**
 * CH_ENTER
 * Parses connection request
 * Called from char_parse_entry
 **/
void chclif_parse_enter(struct s_receive_action_data *act, int ipl)
{
	struct char_session_data *sd;
	int account_id  = RFIFOL(act, 2);
	int login_id1   = RFIFOL(act, 6);
	int login_id2   = RFIFOL(act, 10);
	int client_type = RFIFOL(act, 14);
	char sex        = RFIFOL(act, 16);

	ShowInfo("Request connect - account_id:%d/login_id1:%u/login_id2:%u\n",
		account_id, login_id1, login_id2);
	if(act->session->session_data) {
		ShowDebug("chclif_parse_enter: Trying to authenticate a session with defined "
			"session data, this could mean that CH_ENTER is being parsed outside "
			"the proper parsing function (chr->parse_entry) and this packet is forged.\n");
		socket_io->session_disconnect_guard(act->session);
		return;
	}

	// Send back account_id
	chr->send_account_id(act->session, account_id);
	if(core->runflag != CHARSERVER_ST_RUNNING ) {
		chr->authfail_fd(act->session, NBE_SERVER_CLOSED);
		socket_io->session_disconnect_guard(act->session);
		return;
	}

	CREATE(act->session->session_data, struct char_session_data, 1);
	sd = act->session->session_data;
	sd->account_id = account_id;
	sd->login_id1 = login_id1;
	sd->login_id2 = login_id2;
	sd->sex = sex;
	sd->auth = false; // not authed yet

	enum notify_ban_errorcode flag = chr->auth(act->session, sd, ipl);
	if(flag == NBE_SUCCESS)
		return;
	chr->authfail_fd(act->session, flag);
	socket_io->session_disconnect_guard(act->session);
}

/**
 * Chclif parsing entry-point
 **/
enum parsefunc_rcode chclif_parse(struct s_receive_action_data *act)
{
	struct char_session_data* sd;

	mutex->lock(act->session->mutex);
	uint32 ipl = act->session->client_addr;
	sd = (struct char_session_data*)act->session->session_data;

	if(socket_io->session_marked_removal(act->session)
	|| !chr->login_session // Deny any new connection authentication requests if no login-server
	) {
		chr->disconnect(act->session, sd);
		mutex->unlock(act->session->mutex);
		return PACKET_VALID;
	}
	mutex->unlock(act->session->mutex);

	while(RFIFOREST(act) > 2) {
		unsigned short command = RFIFOL(act, 0);
		if(VECTOR_LENGTH(HPM->packets[hpParse_Char]) > 0) {
			int result = HPM->parse_packets(act,command,hpParse_Char);
			if(result == 1)
				continue;
			if(result == 2)
				return PACKET_INCOMPLETE;
		}

		struct chclif_packet_entry *packet_data;
		packet_data = idb_get(chclif->packet_db, command);
		if(!packet_data) {
			ShowError("chclif_parse: Unknown packet 0x%04x. Disconnecting!\n", command);
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

		packet_data->pFunc(act, sd, ipl);
		RFIFOSKIP(act, packet_len);
	}
	return PACKET_VALID;
}

/**
 * Finalizes chclif
 **/
void chclif_final(void)
{
	db_lock(chclif->packet_db, WRITE_LOCK);
	db_clear(chclif->packet_db);
	aFree(chclif->packet_list);
}

/**
 * Initializes chclif
 **/
void chclif_init(void)
{
	struct {
		int16 packet_id;
		int16 packet_len;
		ChclifParseFunc *pFunc;
	} inter_packet[] = {
#define packet_def(name, fname) { HEADER_ ## name, sizeof(struct PACKET_ ## name), chclif->parse_ ## fname }
#define packet_def2(name, fname, len) { HEADER_ ## name, (len), chclif->parse_ ## fname }
#define packet_def3(name, fname) { HEADER_ ## name, sizeof(struct PACKET_ ## name), ## fname }
		// packet_def(CH_ENTER, enter), Handled by chr->parse_entry
		packet_def(CH_SELECT_CHAR, select_char),
		packet_def(CH_MAKE_CHAR, make_char),
		packet_def(CH_DELETE_CHAR, delete_char),
		packet_def(CH_DELETE_CHAR2, delete_char),
		packet_def(CH_PING, ping),
		packet_def(CH_REQ_IS_VALID_CHARNAME, rename),
		packet_def(CH_REQ_IS_VALID_CHARNAME2, rename),
		packet_def(CH_REQ_CHANGE_CHARNAME, rename_confirm),
		packet_def(CH_ENTER_CHECKBOT, captcha),
		packet_def(CH_CHECKBOT, captcha),
		packet_def(CH_DELETE_CHAR3_RESERVED, delete2_req),
		packet_def(CH_DELETE_CHAR3, delete2_accept),
		packet_def(CH_DELETE_CHAR3_CANCEL, delete2_cancel),
		packet_def(CH_CHARLIST_REQ, request_chars),
		packet_def(CH_REQ_CHANGE_CHARACTER_SLOT, move_character),
		packet_def3(CH_SECOND_PASSWD_ACK,       pincode->check),
		packet_def3(CH_AVAILABLE_SECOND_PASSWD, pincode->window),
		packet_def3(CH_EDIT_SECOND_PASSWD,      pincode->change),
		packet_def3(CH_MAKE_SECOND_PASSWD,      pincode->setnew),
#undef packet_def
#undef packet_def2
#undef packet_def3
	};
	size_t length = ARRAYLENGTH(inter_packet);

	chclif->packet_list = aMalloc(sizeof(*chclif->packet_list)*length);
	chclif->packet_db = idb_alloc(DB_OPT_BASE|DB_OPT_DISABLE_LOCK); // packet_db is read-only

	// Fill packet db
	db_lock(chclif->packet_db, WRITE_LOCK);
	for(size_t i = 0; i < length; i++) {
		int exists;
		chclif->packet_list[i].len = inter_packet[i].packet_len;
		chclif->packet_list[i].pFunc = inter_packet[i].pFunc;
		exists = idb_put(chclif->packet_db,
			inter_packet[i].packet_id, &chclif->packet_list[i]);
		if(exists) {
			ShowWarning("chclif_init: Packet 0x%x already in database, replacing...\n",
				inter_packet[i].packet_id);
		}
	}
	db_unlock(chclif->packet_db);
}

/**
 * Sets up chclif interface
 **/
void chclif_defaults(void)
{
	chclif = &chclif_s;

	chclif->parse_captcha        = chclif_parse_captcha_default;
	chclif->parse_request_chars  = chclif_parse_request_chars;
	chclif->parse_move_character = chclif_parse_move_character;

	chclif->parse_delete2_req    = chclif_parse_delete2_req;
	chclif->parse_delete2_accept = chclif_parse_delete2_accept;
	chclif->parse_delete2_cancel = chclif_parse_delete2_cancel;
	chclif->parse_delete_char    = chclif_parse_delete_char;

	chclif->parse_rename         = chclif_parse_rename;
	chclif->parse_rename_confirm = chclif_parse_rename_confirm;
	chclif->parse_ping           = chclif_parse_ping;
	chclif->parse_make_char      = chclif_parse_make_char;

	chclif->parse_select_char = chclif_parse_select_char;
	chclif->parse_enter = chclif_parse_enter;

	chclif->parse = chclif_parse;
	chclif->init = chclif_init;
	chclif->final = chclif_final;
}
