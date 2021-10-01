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

#include "config/core.h" // GP_BOUND_ITEMS
#include "mapif.h"

#include "char/char.h"
#include "char/int_achievement.h"
#include "char/int_auction.h"
#include "char/int_clan.h"
#include "char/int_guild.h"
#include "char/int_homun.h"
#include "char/int_elemental.h"
#include "char/int_mail.h"
#include "char/int_mercenary.h"
#include "char/int_party.h"
#include "char/int_pet.h"
#include "char/int_quest.h"
#include "char/int_rodex.h"
#include "char/int_storage.h"
#include "char/inter.h"
#include "common/cbasetypes.h"
#include "common/memmgr.h"
#include "common/mmo.h"
#include "common/nullpo.h"
#include "common/utils.h"
#include "common/random.h"
#include "common/showmsg.h"
#include "common/socket.h"
#include "common/sql.h"
#include "common/strlib.h"

#include "common/rwlock.h"
#include "common/mutex.h"
#include "common/packets_zw_struct.h"
#include "common/packets_wz_struct.h"

#include <stdlib.h>

static struct mapif_interface mapif_s;
struct mapif_interface *mapif;

/**
 * Finds server object of given session
 *
 * @retval NULL Failed to find server
 * @readlock chr->map_server_list_lock
 **/
static struct mmo_map_server *mapif_server_find(struct socket_data *session)
{
	if(!session->session_data)
		return NULL;
	struct mmo_map_server *server;
	int32 server_pos = *(uint32*)session->session_data;

	if(server_pos >= INDEX_MAP_LENGTH(chr->map_server_list))
		return NULL;

	server = INDEX_MAP_INDEX(chr->map_server_list, server_pos);
	if(!server || server->session != session)
		return NULL;

	return server;
}

/**
 * Destroys a server structure.
 * Acquires map_server_list_lock write lock
 **/
static void mapif_server_destroy(struct mmo_map_server *server)
{
	if(!server || !server->session)
		return;
	rwlock->write_lock(chr->map_server_list_lock);
	INDEX_MAP_REMOVE(chr->map_server_list, server->pos);
	socket_io->session_disconnect_guard(server->session);

	mutex->lock(chr->action_information_mutex);
	struct s_action_information *data = linkdb_erase(&chr->action_information, server);
	if(data) {
		data->server = NULL;
		linkdb_insert(&chr->action_information, NULL, data);
	}
	mutex->unlock(chr->action_information_mutex);

	aFree(server);
	rwlock->write_unlock(chr->map_server_list_lock);
}

/**
 * Notifies other map-servers of the shutdown and also login-server, then
 * sets all of its characters offline and frees all data related to it.
 * Acquires map_server_list_lock
 **/
static void mapif_server_reset(struct mmo_map_server *server)
{
	int i, j;
	unsigned char buf[16384];

	rwlock->read_lock(chr->map_server_list_lock);

	/**
	 * 0x2b20 ZZ_SET_OFFLINE <len>.W <ip>.L <port>.W {<map-id>.W}*VECTOR_LENGTH(server->maps)
	 * Notify other map servers that this one is gone. [Skotlex]
	 * The notification is only made when the server owns at least one map.
	 **/
	WBUFW(buf, 0) = 0x2b20;
	WBUFL(buf, 4) = htonl(server->ip);
	WBUFW(buf, 8) = htons(server->port);
	j = 0;
	for (i = 0; i < VECTOR_LENGTH(server->maps); i++) {
		uint16 m = VECTOR_INDEX(server->maps, i);
		if (m != 0)
			WBUFW(buf, 10 + (j++) * 4) = m;
	}

	rwlock->read_unlock(chr->map_server_list_lock);

	if (j > 0) {
		WBUFW(buf, 2) = j * 4 + 10;
		mapif->sendallwos(server, buf, WBUFW(buf, 2));
	}
	if (SQL_ERROR == SQL->Query(inter->sql_handle, "DELETE FROM `%s` WHERE `index`='%d'",
		ragsrvinfo_db, server->session->id)
	)
		Sql_ShowDebug(inter->sql_handle);
	/**
	 * When setting these chars to disconnected in our database the login server will
	 * be notified via 0x272d WA_ACCOUNT_LIST (loginif->account_list)
	 * This information is broadcasted in fixed intervals
	 * @see do_init_loginif
	 **/
	chr->online_char_db->foreach(chr->online_char_db,
		chr->db_setoffline, server->pos); //Tag relevant chars as 'in disconnected' server.
	mapif->server_destroy(server);
}

/**
 * Called upon map-server disconnection
 * Acquires chr->map_server_list_lock
 **/
static void mapif_on_disconnect(struct mmo_map_server *server)
{
	ShowStatus("Map-server (id: %d) has disconnected.\n", server->session->id);
	mapif->server_reset(server);
}

/**
 * Called upon a successful map-server connection
 * Acquires chr->map_server_list_lock
 **/
static struct mmo_map_server *mapif_on_connect(struct socket_data *session, uint32 ip_, uint16 port_)
{
	struct mmo_map_server *server = aCalloc(1, sizeof(*server));
	server->ip = ip_;
	server->port = port_;
	server->session = session;
	VECTOR_INIT(server->maps);

	rwlock->write_lock(chr->map_server_list_lock);
	INDEX_MAP_ADD(chr->map_server_list, server, server->pos);
	rwlock->write_unlock(chr->map_server_list_lock);
	return server;
}

/**
 * Sends a buffer to all connected map-servers
 **/
static int mapif_sendall(const unsigned char *buf, unsigned int len)
{
	return mapif->sendallwos(NULL, buf, len);
}

/**
 * Sends a buffer to all connected map-servers except the provided one.
 * @param server Server to be excluded (if NULL sends message to all servers)
 * @return Number of messages sent
 * @readlock chr->map_server_list_lock
 **/
static int mapif_sendallwos(struct mmo_map_server *server, const unsigned char *buf, unsigned int len)
{
	int i, c;

	nullpo_ret(buf);
	c = 0;

	INDEX_MAP_ITER_DECL(iter);
	INDEX_MAP_ITER(chr->map_server_list, iter);
	while((i = INDEX_MAP_NEXT(chr->map_server_list, iter)) != -1) {
		struct mmo_map_server *cur = INDEX_MAP_INDEX(chr->map_server_list, i);
		if(cur->session && cur != server) {
			WFIFOHEAD(cur->session, len, true);
			memcpy(WFIFOP(cur->session, 0), buf, len);
			WFIFOSET(cur->session, len);
			c++;
		}
	}
	INDEX_MAP_ITER_FREE(iter);

	return c;
}

/**
 * Sends buffer to provided server
 * @return Number of copies sent
 * @readlock chr->map_server_list_lock
 **/
static int mapif_send(struct mmo_map_server *server, const unsigned char *buf, unsigned int len)
{
	nullpo_ret(buf);
	if(!server)
		return 0;

	WFIFOHEAD(server->session, len, true);
	memcpy(WFIFOP(server->session, 0), buf, len);
	WFIFOSET(server->session, len);

	return 1;
}

/**
 * 0xb214 WZ_UPDATE_STATE <id>.L <flag>.B <state>.W
 * Notifies all map-servers of a state change
 * @param id     account-id (flags 0 and 1), character-id (flag 2)
 * @param flag   0 Account status change
 *               1 Account ban
 *               2 Character ban
 * @param state  timestamp of ban due date (flags 1 and 2)
 *               ALE_UNREGISTERED to ALE_UNAUTHORIZED +1 @see enum notify_ban_errorcode
 *               100: message 421 ("Your account has been totally erased")
 *               Other values: message 420 ("Your account is no longer authorized")
 * @readlock chr->map_server_list_lock
 **/
static void mapif_update_state(int id, unsigned char flag, unsigned int state)
{
	unsigned char buf[11];
	WBUFW(buf, 0) = 0x2b14;
	WBUFL(buf, 2) = id;
	WBUFB(buf, 6) = flag;
	WBUFL(buf, 7) = state;
	mapif->sendall(buf, 11);
}

/**
 * Bans a character
 * Triggered by 0x2b0e with flag CHAR_ASK_NAME_CHARBAN
 * @see mapif_update_state
 * @readlock chr->map_server_list_lock
 **/
static void mapif_char_ban(int char_id, time_t timestamp)
{
	mapif->update_state(char_id, 2, (unsigned int)timestamp);
}

/**
 * 0x2b00 WZ_USER_COUNT <count>.L
 * Sends current user count to all map-servers
 * @readlock chr->map_server_list_lock
 **/
static void mapif_users_count(int users)
{
	uint8 buf[6];
	WBUFW(buf, 0) = HEADER_WZ_USER_COUNT;
	WBUFL(buf, 2) = users;
	mapif->sendall(buf, sizeof(struct PACKET_WZ_USER_COUNT));
}

/**
 * 0x2b0d WZ_CHANGE_SEX
 * Notifies all map-servers of a sex-change
 **/
static void mapif_change_sex(int account_id, int sex)
{
	unsigned char buf[7];

	WBUFW(buf,0) = HEADER_WZ_CHANGE_SEX;
	WBUFL(buf,2) = account_id;
	WBUFB(buf,6) = sex;
	mapif->sendall(buf, sizeof(struct PACKET_WZ_CHANGE_SEX));
}

/**
 * Writes list to buffer
 * @return Number of written bytes.
 **/
size_t mapif_fame_list_sub(uint8 *buf, struct fame_list *list, int len)
{
	size_t pos = 0;
	for(int i = 0; i < len && list[i].id; i++) {
		pos += sizeof((WBUFL(&buf, pos) = list[i].id));
		pos += sizeof((WBUFL(&buf, pos) = list[i].fame));
		memcpy(WBUFP(&buf, pos), list[i].name, sizeof(list[i].name));
		pos += sizeof(list[i].name);
	}
	return pos;
}

/**
 * Send map-servers the fame ranking lists
 *
 * @param session When set, sends list to only this server
 **/
static int mapif_fame_list(struct mmo_map_server *server,
	struct fame_list *smith, int smith_len,
	struct fame_list *chemist, int chemist_len,
	struct fame_list *taekwon, int taekwon_len
) {
	size_t len = sizeof(struct PACKET_WZ_FAME_LIST)-3*sizeof(intptr); // 3 dynamic lists

	size_t expected_len = len; 
	expected_len += sizeof(struct fame_list_packet_data)*smith_len;
	expected_len += sizeof(struct fame_list_packet_data)*chemist_len;
	expected_len += sizeof(struct fame_list_packet_data)*taekwon_len;
	/**
	 * The expected size of this packet when all lists are of the default
	 * length is 968 bytes, there's no need to use the stack to allocate
	 * 32000bytes as it was being done.
	 **/
	CREATE_BUFFER(buf, uint8, expected_len);

	WBUFW(buf,0) = HEADER_WZ_FAME_LIST;
	len += mapif_fame_list_sub(&buf[len], smith, smith_len);
	// add blacksmith's block length
	WBUFW(buf, 6) = (uint16)len;
	len += mapif_fame_list_sub(&buf[len], chemist, chemist_len);
	// add alchemist's block length
	WBUFW(buf, 4) = (uint16)len;
	len += mapif_fame_list_sub(&buf[len], taekwon, taekwon_len);
	// add total packet length
	WBUFW(buf, 2) = (uint16)len;
	assert(len == expected_len && "Buffer overflow");

	if(server)
		mapif->send(server, buf, len);
	else
		mapif->sendall(buf, len);

	DELETE_BUFFER(buf);
}

/**
 * Updates fame of a player
 *char_update_fame_list
 **/
static void mapif_fame_list_update(enum fame_list_type type, int index, int fame)
{
	unsigned char buf[8];
	WBUFW(buf,0) = HEADER_WZ_FAME_LIST_UPDATE;
	WBUFB(buf,2) = (uint8)type;
	WBUFB(buf,3) = index;
	WBUFL(buf,4) = fame;
	mapif->sendall(buf, 8);
}

/**
 * Notifies map of receival of maps
 * char_map_received_ok
 **/
static void mapif_map_received(struct socket_data *session, char *wisp_server_name, uint8 flag)
{
	WFIFOHEAD(session, sizeof(struct PACKET_WZ_SEND_MAP_ACK), true);
	WFIFOW(session,0) = HEADER_WZ_SEND_MAP_ACK;
	WFIFOB(session,2) = flag;
	memcpy(WFIFOP(session,3), wisp_server_name, NAME_LENGTH);
	WFIFOSET(session, sizeof(struct PACKET_WZ_SEND_MAP_ACK));
}

/**
 * Notifies map-server of maps owned by the other servers and other servers
 * of the maps owned by the former.
 *
 * @param server New server
 * @readlock map_server_list_lock
 **/
static void mapif_send_maps(struct mmo_map_server *server, int16 *map_list)
{
	int k,i;

	if(!VECTOR_LENGTH(server->maps)) {
		ShowWarning("Map-server %d has NO maps.\n", server->pos);
	} else {
		// Transmitting maps information to the other map-servers
		size_t expected_len = sizeof(struct PACKET_WZ_SEND_MAP)-sizeof(intptr);
		size_t list_len = VECTOR_LENGTH(server->maps) * sizeof(int16);
		expected_len += list_len;
		CREATE_BUFFER(buf, uint8, expected_len);

		WBUFW(buf,0) = HEADER_WZ_SEND_MAP;
		WBUFW(buf,2) = (uint16)expected_len;
		WBUFL(buf,4) = htonl(server->ip);
		WBUFW(buf,8) = htons(server->port);
		memcpy(WBUFP(buf,10), map_list, list_len);
		mapif->sendallwos(server, buf, WBUFW(buf,2));

		DELETE_BUFFER(buf);
	}

	// Transmitting the maps of the other map-servers to the new map-server
	INDEX_MAP_ITER_DECL(iter);
	INDEX_MAP_ITER(chr->map_server_list, iter);
	while((k = INDEX_MAP_NEXT(chr->map_server_list, iter)) != -1) {
		struct mmo_map_server *cur = INDEX_MAP_INDEX(chr->map_server_list, k);
		if(cur == server)
			continue;

		WFIFOHEAD(cur->session,10 + 4 * VECTOR_LENGTH(cur->maps), true);
		WFIFOW(cur->session,0) = HEADER_WZ_SEND_MAP;
		WFIFOL(cur->session,4) = htonl(cur->ip);
		WFIFOW(cur->session,8) = htons(cur->port);
		int j = 0;
		for(i = 0; i < VECTOR_LENGTH(cur->maps); i++) {
			uint16 m = VECTOR_INDEX(cur->maps, i);
			if (m != 0)
				WFIFOW(cur->session,10+(j++)*4) = m;
		}
		if (j > 0) {
			WFIFOW(cur->session,2) = j * 4 + 10;
			WFIFOSET(cur->session, WFIFOW(cur->session,2));
		}
	}
	INDEX_MAP_ITER_FREE(iter);
}

/**
 * Sends WZ_STATUS_CHANGE built by mapif_scdata_head and mapif_scdata_data
 **/
static void mapif_scdata_send(struct socket_data *session)
{
	size_t expected_len = sizeof(struct PACKET_WZ_STATUS_CHANGE)-sizeof(intptr);
	expected_len += WFIFOW(session, 12)*sizeof(struct status_change_packet_data);
	if(expected_len != WFIFOW(session, 2)) {
		ShowDebug("mapif_scdata_send: Expected length %zd, got %zd\n",
			WFIFOW(session, 2), expected_len);
		WFIFOW(session, 2) = (uint16)expected_len;
	}
	WFIFOSET(session, WFIFOW(session, 2));
}

/**
 * Adds status change data to WZ_STATUS_CHANGE initiated by mapif_scdata_head
 **/
static void mapif_scdata_data(struct socket_data *session, struct status_change_data *data)
{
	size_t pos = sizeof(struct PACKET_WZ_STATUS_CHANGE)-sizeof(intptr);
	size_t count = WFIFOW(session, 12);
	pos += count * sizeof(struct status_change_packet_data);

	pos += sizeof((WFIFOW(session,pos) = data->type));
	pos += sizeof((WFIFOL(session,pos) = data->val1));
	pos += sizeof((WFIFOL(session,pos) = data->val2));
	pos += sizeof((WFIFOL(session,pos) = data->val3));
	pos += sizeof((WFIFOL(session,pos) = data->val4));
	pos += sizeof((WFIFOL(session,pos) = data->tick));
	pos += sizeof((WFIFOL(session,pos) = data->total_tick));

	WFIFOW(session, 12) = (uint16)count + 1;
}

/**
 * Begins WZ_STATUS_CHANGE with requested SC data
 * This packet is completed by mapif_scdata_data and then mapif_scdata_send
 **/
static void mapif_scdata_head(struct socket_data *session, int aid, int cid, int count)
{
	size_t expected_len = sizeof(struct PACKET_WZ_STATUS_CHANGE)-sizeof(intptr);
	expected_len += sizeof(struct status_change_packet_data)*count;
	WFIFOHEAD(session, expected_len, true);
	WFIFOW(session, 0) = HEADER_WZ_STATUS_CHANGE;
	WFIFOW(session, 2) = (uint16)expected_len;
	WFIFOL(session,4)  = aid;
	WFIFOL(session,8)  = cid;
	WFIFOW(session,12) = 0;
}

/**
 * Notifies map-server that a character was saved
 * Only needed on final save.
 **/
static void mapif_save_character_ack(struct socket_data *session, int aid, int cid)
{
	WFIFOHEAD(session, sizeof(struct PACKET_WZ_SAVE_CHARACTER_ACK), true);
	WFIFOW(session,0) = HEADER_WZ_SAVE_CHARACTER_ACK;
	WFIFOL(session,2) = aid;
	WFIFOL(session,6) = cid;
	WFIFOSET(session,10);
}

/**
 * Notifies map-server of a request to receive a character to selection screen
 **/
static void mapif_char_select_ack(struct socket_data *session, int account_id, uint8 flag)
{
	WFIFOHEAD(session, sizeof(struct PACKET_WZ_CHAR_SELECT_ACK), true);
	WFIFOW(session,0) = HEADER_WZ_CHAR_SELECT_ACK;
	WFIFOL(session,2) = account_id;
	WFIFOB(session,6) = flag;
	WFIFOSET(session,7);
}

/**
 * Answer to map server change request
 * @param data Buffer containing the same data as ZW_CHANGE_SERVER_REQUEST[2]
 **/
static void mapif_change_map_server_ack(struct socket_data *session, const uint8 *data, bool ok)
{
	WFIFOHEAD(session, sizeof(struct PACKET_WZ_CHANGE_SERVER_REQUEST_ACK), true);
	WFIFOW(session,0) = HEADER_WZ_CHANGE_SERVER_REQUEST_ACK;
	memcpy(WFIFOP(session,2), data, 28);
	if(!ok)
		WFIFOL(session,6) = 0; //Set login1 to 0.
	WFIFOSET(session,30);
}

/**
 * Answer to a character name request
 **/
static void mapif_char_name_ack(struct socket_data *session, int char_id)
{
	WFIFOHEAD(session, sizeof(struct PACKET_WZ_CHARNAME_REQUEST_ACK), true);
	WFIFOW(session,0) = HEADER_WZ_CHARNAME_REQUEST_ACK;
	WFIFOL(session,2) = char_id;
	/**
	 * Map-server adds this name in the nickdb upon receival, even if it's not found.
	 * Clients older than 20180307 always expect a name when resolving, so we send 
	 * 'Unknown' to be added, newer clients have a flag in clif_solved_charname packet
	 * and NUL is sent instead, thus we send exactly what the map-server needs to
	 * send to the client here.
	 * @see clif_solved_charname (ZC_ACK_REQNAME_BYGID)
	 **/
#if PACKETVER_MAIN_NUM >= 20180307 || PACKETVER_RE_NUM >= 20180221 || PACKETVER_ZERO_NUM >= 20180328
	if (chr->loadName(char_id, WFIFOP(session,6)) == 0)
		WFIFOL(session, 6) = 0;
#else
	chr->loadName(char_id, WFIFOP(session,6));
#endif
	WFIFOSET(session, 30);
}

/**
 * Answer of an update account request
 * This is only sent when the original request was made by a player and
 * not only by map-server.
 **/
static void mapif_change_account_ack(struct socket_data *session, int acc,
	const char *name, enum zh_char_ask_name_type type, int result
) {
	nullpo_retv(name);
	WFIFOHEAD(session, sizeof(struct PACKET_ZW_UPDATE_ACCOUNT_ACK), true);
	WFIFOW(session, 0) = HEADER_ZW_UPDATE_ACCOUNT_ACK;
	WFIFOL(session, 2) = acc;
	safestrncpy(WFIFOP(session,6), name, NAME_LENGTH);
	WFIFOW(session,30) = type;
	WFIFOW(session,32) = result;
	WFIFOSET(session,34);
}

/**
 * Pong
 **/
static void mapif_pong(struct socket_data *session)
{
	WFIFOHEAD(session, 2,true);
	WFIFOW(session,0) = HEADER_ZW_PONG;
	WFIFOSET(session,2);
}

/**
 * Sends authentication data to map-server
 **/
static void mapif_auth_ok(struct socket_data *session, int account_id, struct char_auth_node *node, struct mmo_charstatus *cd)
{
	nullpo_retv(cd);
	WFIFOHEAD(session,25 + sizeof(struct mmo_charstatus), true);
	WFIFOW(session,0) = 0x2afd;
	WFIFOW(session,2) = 25 + sizeof(struct mmo_charstatus);
	WFIFOL(session,4) = account_id;
	if (node)
	{
		WFIFOL(session,8) = node->login_id1;
		WFIFOL(session,12) = node->login_id2;
		WFIFOL(session,16) = (uint32)node->expiration_time; // FIXME: will wrap to negative after "19-Jan-2038, 03:14:07 AM GMT"
		WFIFOL(session,20) = node->group_id;
		WFIFOB(session,24) = node->changing_mapservers;
	}
	else
	{
		WFIFOL(session,8) = 0;
		WFIFOL(session,12) = 0;
		WFIFOL(session,16) = 0;
		WFIFOL(session,20) = 0;
		WFIFOB(session,24) = 0;
	}
	/**
	 * TODO/FIXME: This just copies a padded struct, if the map-server doesn't have
	 * the same padding this could get messy... [Panikon]
	 **/
	memcpy(WFIFOP(session,25), cd, sizeof(struct mmo_charstatus));
	WFIFOSET(session, WFIFOW(session, 2));
}

/**
 * Notifies map-server of the failed authentication
 **/
static void char_auth_failed(struct socket_data *session, int account_id, int char_id, int login_id1, char sex, uint32 ip)
{
	WFIFOHEAD(session,sizeof(struct PACKET_ZW_AUTH_FAILED),true);
	WFIFOW(session,0) = HEADER_ZW_AUTH_FAILED;
	WFIFOL(session,2) = account_id;
	WFIFOL(session,6) = char_id;
	WFIFOL(session,10) = login_id1;
	WFIFOB(session,14) = sex;
	WFIFOL(session,15) = htonl(ip);
	WFIFOSET(session,19);
}

/**
 * WZ_MAP_AUTH_ACK
 * @param flag 0 Ok
 * @param flag 3 Error
 **/
static void mapif_login_map_server_ack(struct socket_data *session, uint8 flag)
{
	WFIFOHEAD(session, 3, true);
	WFIFOW(session, 0) = HEADER_WZ_MAP_AUTH_ACK;
	WFIFOB(session, 2) = flag;
	WFIFOSET2(session, 3);
}

/**
 * Parses an item_packet_data field of provided packet
 *
 * @param pos  Offset of item_packet_data in provided packet
 * @param item item object to be filled
 * @return Current buffer position
 **/
static int mapif_parse_item_data(struct s_receive_action_data *act, int pos, struct item *out)
{
	pos += sizeof((out->id        = RFIFOL(act, pos)));
	pos += sizeof((out->nameid    = RFIFOL(act, pos)));
	pos += sizeof((out->amount    = RFIFOW(act, pos)));
	pos += sizeof((out->equip     = RFIFOL(act, pos)));
	pos += sizeof((out->identify  = RFIFOB(act, pos)));
	pos += sizeof((out->refine    = RFIFOB(act, pos)));
	pos += sizeof((out->attribute = RFIFOB(act, pos)));
	memcpy(out->card, RFIFOP(act, pos),
		SIZEOF_MEMBER(struct item_packet_data, card));
	pos += SIZEOF_MEMBER(struct item_packet_data, card);
	pos += sizeof((out->expire_time = RFIFOL(act, pos)));
	pos += sizeof((out->favorite    = RFIFOB(act, pos)));
	pos += sizeof((out->bound       = RFIFOB(act, pos)));
	pos += sizeof((out->unique_id   = RFIFOQ(act, pos)));
	memcpy(out->option, RFIFOP(act, pos),
		SIZEOF_MEMBER(struct item_packet_data, option));
	pos += SIZEOF_MEMBER(struct item_packet_data, option);
}

/*======================================
 * MAPIF : AUCTION
 *--------------------------------------*/

/**
 * 0x3854 WZ_AUCTION_MESSAGE <char_id>.L <result>.B
 * Sends an auction message to the character via the map-server (clif->auction_message)
 * @see enum e_auction_result_message
 * @readlock chr->map_server_list_lock
 **/
static void mapif_auction_message(int char_id, enum e_auction_result_message result)
{
	unsigned char buf[7];

	WBUFW(buf, 0) = 0x3854;
	WBUFL(buf, 2) = char_id;
	WBUFB(buf, 6) = result;

	mapif->sendall(buf, 7);
}

/**
 * 0x3850 WZ_AUCTION_LIST <len>.W <char_id>.L <count>.W <pages>.W <struct auction_data>.<count>
 * Sends auction list to the map-server (answer of 0x3050 ZW_AUCTION_REQUEST_LIST)
 * @param session Map-server that requested
 **/
static void mapif_auction_sendlist(struct socket_data *session, int char_id, short count, short pages, unsigned char *buf)
{
	int len = (sizeof(struct auction_data) * count) + 12;

	nullpo_retv(buf);

	WFIFOHEAD(session, len, true);
	WFIFOW(session, 0) = 0x3850;
	WFIFOW(session, 2) = len;
	WFIFOL(session, 4) = char_id;
	WFIFOW(session, 8) = count;
	WFIFOW(session, 10) = pages;
	memcpy(WFIFOP(session, 12), buf, len - 12);
	WFIFOSET(session, len);
}

/**
 * 0x3050 ZW_AUCTION_REQUEST_LIST <char_id>.L <type>.W <price>.L <page>.W <search>[NAME_LENGTH].B
 * Map-server request of information of an auction list
 **/
static void mapif_parse_auction_requestlist(struct s_receive_action_data *act)
{
	char searchtext[NAME_LENGTH];

	int char_id = RFIFOL(act, 4);
	short type  = RFIFOW(act, 8); // enum e_auction_search_type
	int price   = RFIFOL(act, 10);
	short page  = max(1, RFIFOW(act, 14));
	memcpy(searchtext, RFIFOP(act, 16), NAME_LENGTH);

	int len = sizeof(struct auction_data);

	unsigned char buf[5 * sizeof(struct auction_data)];
	struct DBIterator *iter = db_iterator(inter_auction->db);
	struct auction_data *auction;
	short i = 0, j = 0, pages = 1;

	for (auction = dbi_first(iter); dbi_exists(iter); auction = dbi_next(iter)) {
		if ((type == AUCTIONSEARCH_ARMOR    && auction->type != IT_ARMOR && auction->type != IT_PETARMOR)
		 || (type == AUCTIONSEARCH_WEAPON   && auction->type != IT_WEAPON)
		 || (type == AUCTIONSEARCH_CARD     && auction->type != IT_CARD)
		 || (type == AUCTIONSEARCH_MISC     && auction->type != IT_ETC)
		 || (type == AUCTIONSEARCH_NAME     && !strstr(auction->item_name, searchtext))
		 || (type == AUCTIONSEARCH_ID       && auction->price > price)
		 || (type == AUCTIONSEARCH_OWN_SELL && auction->seller_id != char_id)
		 || (type == AUCTIONSEARCH_OWN_BIDS && auction->buyer_id != char_id))
			continue;

		i++;
		if (i > 5) {
			// Counting Pages of Total Results (5 Results per Page)
			pages++;
			i = 1; // First Result of This Page
		}

		if (page != pages)
			continue; // This is not the requested Page

		memcpy(WBUFP(buf, j * len), auction, len);
		j++; // Found Results
	}
	dbi_destroy(iter);

	mapif->auction_sendlist(act->session, char_id, j, pages, buf);
}

/**
 * 0x3851 WZ_AUCTION_REGISTER_ACK <auction_id>.L <auction_hours>.L <item_data>.*B
 * Notifies map-server of a successful registration of an auction (answer of 0x3051 ZW_AUCTION_REGISTER)
 *
 * @param auction_id    Generated id (when 0 the creation failed)
 * @param auction_hours Auction duration in hours
 * @param item_data     struct PACKET_ZW_AUCTION_REGISTER, data.item from received packet
 * @see mapif_parse_auction_register
 **/
static void mapif_auction_register(struct socket_data *session,
	unsigned int auction_id, unsigned int auction_hours, const uint8 *item_data
) {
	size_t len = SIZEOF_MEMBER(struct PACKET_ZW_AUCTION_REGISTER, data.item) + 10;
	WFIFOHEAD(session, len, true);
	WFIFOW(session, 0) = 0x3851;
	WFIFOL(session, 2) = auction_id;
	WFIFOL(session, 6) = auction_hours;
	memcpy(WFIFOP(session, 10), item_data,
		SIZEOF_MEMBER(struct PACKET_ZW_AUCTION_REGISTER, data.item));
	WFIFOSET(session, len);
}

/**
 * 0x3051 ZW_AUCTION_REGISTER
 * Parses map-server request to register an auction
 **/
static void mapif_parse_auction_register(struct s_receive_action_data *act)
{
	size_t pos = 2;
	struct auction_data a = {0};
	offsetof(struct PACKET_ZW_AUCTION_REGISTER, data.seller_id);
	pos += sizeof((a.seller_id  = RFIFOL(act, pos)));
	if(inter_auction->count(a.seller_id, false) < 5) {
		pos += sizeof((a.auction_id = RFIFOL(act, pos)));
		memcpy(a.seller_name, RFIFOP(act, pos), NAME_LENGTH);
		pos += NAME_LENGTH;
		pos += sizeof((a.buyer_id   = RFIFOL(act, pos)));
		memcpy(a.buyer_name, RFIFOP(act, pos), NAME_LENGTH);
		pos += NAME_LENGTH;
		pos += mapif->parse_item_data(act, pos, &a.item);
		memcpy(a.item_name, RFIFOP(act, pos),
			SIZEOF_MEMBER(struct PACKET_ZW_AUCTION_REGISTER,
				          data.item_name));
		pos += SIZEOF_MEMBER(struct PACKET_ZW_AUCTION_REGISTER,
			                 data.item_name);
		pos += sizeof((a.type             = RFIFOW(act, pos)));
		pos += sizeof((a.hours            = RFIFOW(act, pos)));
		pos += sizeof((a.price            = RFIFOL(act, pos)));
		pos += sizeof((a.buynow           = RFIFOL(act, pos)));
		pos += sizeof((a.timestamp        = RFIFOQ(act, pos)));
		pos += sizeof((a.auction_end_timer= RFIFOL(act, pos)));

		a.auction_id = inter_auction->create(&a);
	}

	mapif->auction_register(act->session,
		a.auction_id,
		// Other fields aren't always parsed from the packet
		RFIFOL(act, offsetof(struct PACKET_ZW_AUCTION_REGISTER, data.hours)),
		RFIFOP(act, offsetof(struct PACKET_ZW_AUCTION_REGISTER, data.item))
	);
}

/**
 * 0x3852 WZ_AUCTION_CANCEL_ACK <char_id>.L <result>.B
 * Sends an auction cancelation to the character via the map-server (clif->auction_close)
 * @see enum e_auction_cancel
 **/
static void mapif_auction_cancel(struct socket_data *session, int char_id, enum e_auction_cancel result)
{
	WFIFOHEAD(session, 7, true);
	WFIFOW(session, 0) = 0x3852;
	WFIFOL(session, 2) = char_id;
	WFIFOB(session, 6) = result;
	WFIFOSET(session, 7);
}

/**
 * 0x3052 ZW_AUCTION_CANCEL <char_id>.L <auction_id>.L
 * Parses cancelation request (CZ_AUCTION_ADD_CANCEL)
 **/
static void mapif_parse_auction_cancel(struct s_receive_action_data *act)
{
	int char_id    = RFIFOL(act, 2);
	int auction_id = RFIFOL(act, 6);
	struct auction_data *auction;

	if ((auction = (struct auction_data *)idb_get(inter_auction->db, auction_id)) == NULL) {
		mapif->auction_cancel(act->session, char_id, AUCTIONCANCEL_INCORRECT_ID);
		return;
	}

	if (auction->seller_id != char_id) {
		mapif->auction_cancel(act->session, char_id, AUCTIONCANCEL_FAILED);
		return;
	}

	if (auction->buyer_id > 0) {
		// An auction with at least one bidder cannot be canceled
		mapif->auction_message(char_id, AUCTIONRESULT_CANNOT_CANCEL);
		return;
	}

	inter_mail->sendmail(0, "Auction Manager", auction->seller_id,
		auction->seller_name, "Auction", "Auction canceled.", 0, &auction->item);
	inter_auction->delete_(auction);

	mapif->auction_cancel(act->session, char_id, AUCTIONCANCEL_SUCCESS);
}

/**
 * 0x3853 WZ_AUCTION_CLOSE_ACK <char_id>.L <result>.B
 **/
static void mapif_auction_close(struct socket_data *session, int char_id, enum e_auction_cancel result)
{
	WFIFOHEAD(session, 7, true);
	WFIFOW(session, 0) = 0x3853;
	WFIFOL(session, 2) = char_id;
	WFIFOB(session, 6) = result;
	WFIFOSET(session, 7);
}

/**
 * 0x3053 ZW_AUCTION_CLOSE <char_id>.L <result>.B
 * Parses close request (CZ_AUCTION_REQ_MY_SELL_STOP)
 **/
static void mapif_parse_auction_close(struct s_receive_action_data *act)
{
	int char_id    = RFIFOL(act, 2);
	int auction_id = RFIFOL(act, 6);
	struct auction_data *auction;

	if ((auction = (struct auction_data *)idb_get(inter_auction->db, auction_id)) == NULL) {
		mapif->auction_close(act->session, char_id, AUCTIONCANCEL_INCORRECT_ID); // Bid Number is Incorrect
		return;
	}

	if (auction->seller_id != char_id) {
		mapif->auction_close(act->session, char_id, AUCTIONCANCEL_FAILED); // You cannot end the auction
		return;
	}

	if (auction->buyer_id == 0) {
		mapif->auction_close(act->session, char_id, AUCTIONCANCEL_FAILED); // You cannot end the auction
		return;
	}

	// Send Money to Seller
	inter_mail->sendmail(0, "Auction Manager", auction->seller_id, auction->seller_name, "Auction", "Auction closed.", auction->price, NULL);
	// Send Item to Buyer
	inter_mail->sendmail(0, "Auction Manager", auction->buyer_id, auction->buyer_name, "Auction", "Auction winner.", 0, &auction->item);
	mapif->auction_message(auction->buyer_id, AUCTIONRESULT_WON); // You have won the auction
	inter_auction->delete_(auction);

	mapif->auction_close(act->session, char_id, AUCTIONCANCEL_SUCCESS); // You have ended the auction
}

/**
 * 0x3855 ZW_AUCTION_BID_ACK <char_id>.L <bid>.L <result>.B
 **/
static void mapif_auction_bid(struct socket_data *session, int char_id, int bid,
	enum e_auction_result_message result
) {
	WFIFOHEAD(session, 11, true);
	WFIFOW(session, 0) = 0x3855;
	WFIFOL(session, 2) = char_id;
	WFIFOL(session, 6) = bid; // To Return Zeny
	WFIFOB(session, 10) = result;
	WFIFOSET(session, 11);
}

/**
 * 0x3055 ZW_AUCTION_BID <char_id>.L <auction_id>.L <bid>.L <buyer_name>
 **/
static void mapif_parse_auction_bid(struct s_receive_action_data *act)
{
	int char_id             = RFIFOL(act, 4);
	unsigned int auction_id = RFIFOL(act, 8);
	int bid                 = RFIFOL(act, 12);
	struct auction_data *auction =
		(struct auction_data *)idb_get(inter_auction->db, auction_id);

	if(auction == NULL || auction->price >= bid || auction->seller_id == char_id) {
		mapif->auction_bid(act->session, char_id, bid, AUCTIONRESULT_BID_FAILED);
		return;
	}

	if(inter_auction->count(char_id, true) > 4
	&& bid < auction->buynow
	&& auction->buyer_id != char_id
	) {
		mapif->auction_bid(act->session, char_id, bid, AUCTIONRESULT_BID_EXCEEDED); // You cannot place more than 5 bids at a time
		return;
	}

	if(auction->buyer_id > 0) {
		// Send Money back to the previous Buyer
		if(auction->buyer_id != char_id) {
			inter_mail->sendmail(0, "Auction Manager", auction->buyer_id,
				auction->buyer_name,
				"Auction", "Someone has placed a higher bid.",
				auction->price, NULL);
			mapif->auction_message(auction->buyer_id, AUCTIONRESULT_LOSE); // You have failed to win the auction
		} else {
			inter_mail->sendmail(0, "Auction Manager", auction->buyer_id,
				auction->buyer_name,
				"Auction", "You have placed a higher bid.",
				auction->price, NULL);
		}
	}

	auction->buyer_id = char_id;
	safestrncpy(auction->buyer_name, RFIFOP(act, 16), NAME_LENGTH);
	auction->price = bid;

	if(bid >= auction->buynow) {
		// Automatic won the auction
		mapif->auction_bid(act->session, char_id, bid - auction->buynow, AUCTIONRESULT_BID_SUCCESS);

		inter_mail->sendmail(0, "Auction Manager", auction->buyer_id,
			auction->buyer_name,
			"Auction", "You have won the auction.", 0, &auction->item);
		mapif->auction_message(char_id, AUCTIONRESULT_WON); // You have won the auction
		inter_mail->sendmail(0, "Auction Manager", auction->seller_id,
			auction->seller_name,
			"Auction", "Payment for your auction!.", auction->buynow, NULL);

		inter_auction->delete_(auction);
		return;
	}

	inter_auction->save(auction);

	mapif->auction_bid(act->session, char_id, 0, AUCTIONRESULT_BID_SUCCESS); // You have successfully bid in the auction
}

/*======================================
 * MAPIF : ELEMENTAL
 *--------------------------------------*/

/**
 * WZ_ELEMENTAL_SEND
 * Sends elemental information to map-server
 **/
static void mapif_elemental_send(struct socket_data *session, unsigned char flag, const uint8_t *elemental_data)
{
	int size = sizeof(struct s_elemental) + 5;

	WFIFOHEAD(session, size, true);
	WFIFOW(session, 0) = 0x387c;
	WFIFOW(session, 2) = size;
	WFIFOB(session, 4) = flag;

	memcpy(WFIFOP(session, 5), elemental_data, sizeof(struct s_elemental_packet_data));
	WFIFOSET(session, size);
}

/**
 * ZW_ELEMENTAL_CREATE
 * Parses elemental creation request
 **/
static void mapif_parse_elemental_create(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	bool result;
	struct s_elemental ele = {
		.elemental_id = RFIFOL(act, 2),
		.char_id      = RFIFOL(act, 6),
		.class_       = RFIFOL(act, 10),
		.mode         = RFIFOL(act, 14),
		.hp           = RFIFOL(act, 18),
		.sp           = RFIFOL(act, 22),
		.max_hp       = RFIFOL(act, 26),
		.max_sp       = RFIFOL(act, 30),
		.matk         = RFIFOL(act, 14),
		.atk          = RFIFOL(act, 38),
		.atk2         = RFIFOL(act, 42),
		.hit          = RFIFOW(act, 46),
		.flee         = RFIFOW(act, 48),
		.amotion      = RFIFOW(act, 50),
		.def          = RFIFOW(act, 52),
		.mdef         = RFIFOW(act, 54),
		.life_time    = RFIFOL(act, 56),
	};

	result = inter_elemental->create(&ele);
	mapif->elemental_send(act->session, result, RFIFOP(act, 2));
}

/**
 * ZW_ELEMENTAL_LOAD
 * Load elemental request
 **/
static void mapif_parse_elemental_load(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	struct s_elemental ele;
	bool result = inter_elemental->load(RFIFOL(act,2), RFIFOL(act,6), &ele);
	mapif->elemental_send(act->session, result,
		(uint8_t*)&(struct s_elemental_packet_data) {
			.elemental_id = ele.elemental_id,
			.char_id      = ele.char_id,
			.class_       = ele.class_,
			.mode         = ele.mode,
			.hp           = ele.hp,
			.sp           = ele.sp,
			.max_hp       = ele.max_hp,
			.max_sp       = ele.max_sp,
			.matk         = ele.matk,
			.atk          = ele.atk,
			.atk2         = ele.atk2,
			.hit          = ele.hit,
			.flee         = ele.flee,
			.amotion      = ele.amotion,
			.def          = ele.def,
			.mdef         = ele.mdef,
			.life_time    = ele.life_time,
		}
	);
}

/**
 * WZ_ELEMENTAL_DELETE_ACK
 * @param flag (bool) success
 **/
static void mapif_elemental_deleted(struct socket_data *session, unsigned char flag)
{
	WFIFOHEAD(session, 3, true);
	WFIFOW(session, 0) = 0x387d;
	WFIFOB(session, 2) = flag;
	WFIFOSET(session, 3);
}

/**
 * ZW_ELEMENTAL_DELETE
 * Elemental delete request
 **/
static void mapif_parse_elemental_delete(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	bool result = inter_elemental->delete(RFIFOL(act, 2));
	mapif->elemental_deleted(act->session, result);
}

/**
 * WZ_ELEMENTAL_SAVE_ACK
 * @param flag (bool) success
 **/
static void mapif_elemental_saved(struct socket_data *session, unsigned char flag)
{
	WFIFOHEAD(session, 3, true);
	WFIFOW(session, 0) = 0x387e;
	WFIFOB(session, 2) = flag;
	WFIFOSET(session, 3);
}

/**
 * ZW_ELEMENTAL_SAVE
 * Elemental save request
 **/
static void mapif_parse_elemental_save(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	struct s_elemental ele = {
		.elemental_id = RFIFOL(act, 2),
		.char_id      = RFIFOL(act, 6),
		.class_       = RFIFOL(act, 10),
		.mode         = RFIFOL(act, 14),
		.hp           = RFIFOL(act, 18),
		.sp           = RFIFOL(act, 22),
		.max_hp       = RFIFOL(act, 26),
		.max_sp       = RFIFOL(act, 30),
		.matk         = RFIFOL(act, 14),
		.atk          = RFIFOL(act, 38),
		.atk2         = RFIFOL(act, 42),
		.hit          = RFIFOW(act, 46),
		.flee         = RFIFOW(act, 48),
		.amotion      = RFIFOW(act, 50),
		.def          = RFIFOW(act, 52),
		.mdef         = RFIFOW(act, 54),
		.life_time    = RFIFOL(act, 56),
	};
	bool result = inter_elemental->save(&ele);
	mapif->elemental_saved(act->session, result);
}

/*======================================
 * MAPIF : GUILD
 *--------------------------------------*/

/**
 * WZ_GUILD_CREATE_ACK
 **/
static int mapif_guild_created(struct socket_data *session, int account_id, struct guild *g)
{
	WFIFOHEAD(session, 10, true);
	WFIFOW(session, 0) = 0x3830;
	WFIFOL(session, 2) = account_id;
	if (g != NULL) {
		WFIFOL(session, 6) = g->guild_id;
		ShowInfo("int_guild: Guild created (%d - %s)\n", g->guild_id, g->name);
	} else {
		WFIFOL(session, 6) = 0;
	}

	WFIFOSET(session, 10);
	return 0;
}

/**
 * WZ_GUILD_INFO_ACK 0x3831 <len>.W <guild_id>.L {<guild_data}.*B
 * Sends complete guild information.
 *
 * @param server Map-server to send information (when NULL sends to all maps)
 * @param success Was the guild information found?
 * @remarks Guild data is only sent when success is true
 **/
static void mapif_guild_info(struct mmo_map_server *server, struct guild *g, bool success)
{
	unsigned char buf[12];
	WBUFW(buf, 0) = 0x3831;
	if(!success) {
		WBUFW(buf, 2) = 8;
		WBUFL(buf, 4) = g->guild_id;
		ShowWarning("int_guild: info not found %d\n", g->guild_id);
	} else {
		// TODO/FIXME: Copy of a padded struct
		WBUFW(buf, 2) = 4 + sizeof(struct guild);
		memcpy(buf + 4, g, sizeof(struct guild));
	}
	if (!server)
		mapif->sendall(buf, 8);
	else
		mapif->send(server, buf, 8);
}

/**
 * WZ_GUILD_MEMBER_ADD_ACK 0x3832
 * Member addition ack
 **/
static int mapif_guild_memberadded(struct socket_data *session, int guild_id, int account_id, int char_id, int flag)
{
	WFIFOHEAD(session, 15, true);
	WFIFOW(session, 0) = 0x3832;
	WFIFOL(session, 2) = guild_id;
	WFIFOL(session, 6) = account_id;
	WFIFOL(session, 10) = char_id;
	WFIFOB(session, 14) = flag;
	WFIFOSET(session, 15);
	// TODO/FIXME: Shouldn't this packet be sent to all map-servers as map_guild_withdraw is?
}

/**
 * WZ_GUILD_WITHDRAW_ACK 0x3834
 * Member leave ack
 **/
static int mapif_guild_withdraw(int guild_id, int account_id, int char_id, int flag, const char *name, const char *mes)
{
	unsigned char buf[55 + NAME_LENGTH];

	nullpo_ret(name);
	nullpo_ret(mes);

	WBUFW(buf, 0) = 0x3834;
	WBUFL(buf, 2) = guild_id;
	WBUFL(buf, 6) = account_id;
	WBUFL(buf, 10) = char_id;
	WBUFB(buf, 14) = flag;
	safestrncpy(WBUFP(buf, 15), mes, 40);
	memcpy(WBUFP(buf, 55), name, NAME_LENGTH);
	mapif->sendall(buf, 55 + NAME_LENGTH);
	ShowInfo("int_guild: guild withdraw (%d - %d: %s - %s)\n", guild_id, account_id, name, mes);
	return 0;
}

// Send short member's info
static int mapif_guild_memberinfoshort(struct guild *g, int idx)
{
	unsigned char buf[25];
	nullpo_ret(g);
	Assert_ret(idx >= 0 && idx < MAX_GUILD);
	WBUFW(buf, 0) = 0x3835;
	WBUFL(buf, 2) = g->guild_id;
	WBUFL(buf, 6) = g->member[idx].account_id;
	WBUFL(buf, 10) = g->member[idx].char_id;
	WBUFB(buf, 14) = (unsigned char)g->member[idx].online;
	WBUFW(buf, 15) = g->member[idx].lv;
	WBUFL(buf, 17) = g->member[idx].class;
	WBUFL(buf, 21) = g->member[idx].last_login;
	mapif->sendall(buf, 25);
	return 0;
}

// Send guild broken
static int mapif_guild_broken(int guild_id, int flag)
{
	unsigned char buf[7];
	WBUFW(buf, 0) = 0x3836;
	WBUFL(buf, 2) = guild_id;
	WBUFB(buf, 6) = flag;
	mapif->sendall(buf, 7);
	ShowInfo("int_guild: Guild broken (%d)\n", guild_id);
	return 0;
}

// Send basic info
static int mapif_guild_basicinfochanged(int guild_id, int type, const void *data, int len)
{
	unsigned char buf[2048];
	nullpo_ret(data);
	if (len > 2038)
		len = 2038;
	WBUFW(buf, 0) = 0x3839;
	WBUFW(buf, 2) = len + 10;
	WBUFL(buf, 4) = guild_id;
	WBUFW(buf, 8) = type;
	memcpy(WBUFP(buf, 10), data, len);
	mapif->sendall(buf, len + 10);
	return 0;
}

// Send member info
static int mapif_guild_memberinfochanged(int guild_id, int account_id, int char_id, int type, const void *data, int len)
{
	unsigned char buf[2048];
	nullpo_ret(data);
	if (len > 2030)
		len = 2030;
	WBUFW(buf, 0) = 0x383a;
	WBUFW(buf, 2) = len + 18;
	WBUFL(buf, 4) = guild_id;
	WBUFL(buf, 8) = account_id;
	WBUFL(buf, 12) = char_id;
	WBUFW(buf, 16) = type;
	memcpy(WBUFP(buf, 18), data, len);
	mapif->sendall(buf, len + 18);
	return 0;
}

// ACK guild skill up
static int mapif_guild_skillupack(int guild_id, uint16 skill_id, int account_id)
{
	unsigned char buf[14];
	WBUFW(buf, 0) = 0x383c;
	WBUFL(buf, 2) = guild_id;
	WBUFL(buf, 6) = skill_id;
	WBUFL(buf,10) = account_id;
	mapif->sendall(buf, 14);
	return 0;
}

// ACK guild alliance
static int mapif_guild_alliance(int guild_id1, int guild_id2, int account_id1, int account_id2, int flag, const char *name1, const char *name2)
{
	unsigned char buf[19 + 2 * NAME_LENGTH];
	nullpo_ret(name1);
	nullpo_ret(name2);
	WBUFW(buf, 0) = 0x383d;
	WBUFL(buf, 2) = guild_id1;
	WBUFL(buf, 6) = guild_id2;
	WBUFL(buf, 10) = account_id1;
	WBUFL(buf, 14) = account_id2;
	WBUFB(buf, 18) = flag;
	memcpy(WBUFP(buf, 19), name1, NAME_LENGTH);
	memcpy(WBUFP(buf, 19 + NAME_LENGTH), name2, NAME_LENGTH);
	mapif->sendall(buf,19 + 2 * NAME_LENGTH);
	return 0;
}

// Send a guild position desc
static int mapif_guild_position(struct guild *g, int idx)
{
	unsigned char buf[12 + sizeof(struct guild_position)];
	nullpo_ret(g);
	Assert_ret(idx >= 0 && idx < MAX_GUILDPOSITION);
	WBUFW(buf, 0) = 0x383b;
	WBUFW(buf, 2) = sizeof(struct guild_position)+12;
	WBUFL(buf, 4) = g->guild_id;
	WBUFL(buf, 8) = idx;
	memcpy(WBUFP(buf, 12), &g->position[idx], sizeof(struct guild_position)); // TODO/FIXME: Copy of a padded struct
	mapif->sendall(buf, WBUFW(buf, 2));
	return 0;
}

// Send the guild notice
static int mapif_guild_notice(struct guild *g)
{
	unsigned char buf[256];
	nullpo_ret(g);
	WBUFW(buf, 0) = 0x383e;
	WBUFL(buf, 2) = g->guild_id;
	memcpy(WBUFP(buf, 6), g->mes1, MAX_GUILDMES1);
	memcpy(WBUFP(buf, 66), g->mes2, MAX_GUILDMES2);
	mapif->sendall(buf, 186);
	return 0;
}

// Send emblem data
static int mapif_guild_emblem(struct guild *g)
{
	unsigned char buf[12 + sizeof(g->emblem_data)];
	nullpo_ret(g);
	WBUFW(buf, 0) = 0x383f;
	WBUFW(buf, 2) = g->emblem_len+12;
	WBUFL(buf, 4) = g->guild_id;
	WBUFL(buf, 8) = g->emblem_id;
	memcpy(WBUFP(buf, 12), g->emblem_data, g->emblem_len);
	mapif->sendall(buf, WBUFW(buf, 2));
	return 0;
}

static int mapif_guild_master_changed(struct guild *g, int aid, int cid)
{
	unsigned char buf[14];
	nullpo_ret(g);
	WBUFW(buf, 0) = 0x3843;
	WBUFL(buf, 2) = g->guild_id;
	WBUFL(buf, 6) = aid;
	WBUFL(buf, 10) = cid;
	mapif->sendall(buf, 14);
	return 0;
}

/**
 * WZ_GUILD_CASTLE_LOAD_ACK
 * @param castle_ids Array of castle ids to be sent
 * @param len        Length of castle_ids
 **/
static int mapif_guild_castle_dataload(struct socket_data *session, const int *castle_ids, int num)
{
	struct guild_castle *gc = NULL;
	int len = 4 + num * sizeof(*gc);
	int i;

	nullpo_ret(castle_ids);
	WFIFOHEAD(session, len, true);
	WFIFOW(session, 0) = 0x3840;
	WFIFOW(session, 2) = len;
	for (i = 0; i < num; i++) {
		gc = inter_guild->castle_fromsql(*(castle_ids++));
		// TODO/FIXME: Copy of a padded struct
		memcpy(WFIFOP(session, 4 + i * sizeof(*gc)), gc, sizeof(*gc));
	}
	WFIFOSET(session, len);
	return 0;
}

/**
 * ZW_GUILD_CREATE
 * Guild creation request
 **/
static void mapif_parse_CreateGuild(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	struct guild *g;
	int master_account_id = RFIFOL(act, 26);
	struct guild_member m = {
			.account_id = RFIFOL(act, 26),
			.char_id    = RFIFOL(act, 30),
			.hair       = RFIFOW(act, 34),
			.hair_color = RFIFOW(act, 36),
			.gender     = RFIFOW(act, 38),
			.class      = RFIFOL(act, 40),
			.lv         = RFIFOW(act, 44),
			.exp        = RFIFOQ(act, 46),
			.exp_payper = RFIFOL(act, 54),
			.online     = RFIFOW(act, 58),
			.position   = RFIFOW(act, 60),
			//.name       = RFIFOP(act, 62),
			.modified   = RFIFOB(act, 86),
		};
	memcpy(m.name, RFIFOP(act, 62), sizeof(m.name));
	g = inter_guild->create(RFIFOP(act, 2), &m);

	// Report to client
	mapif->guild_created(act->session, master_account_id,g);
	if (g != NULL) {
		mapif->guild_info(server, g, true);
	}
}

/**
 * ZW_GUILD_INFO
 * Guild information request
 **/
static void mapif_parse_GuildInfo(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	//We use this because on start-up the info of castle-owned guilds is required. [Skotlex]
	struct guild * g = inter_guild->fromsql(RFIFOL(act, 2));
	if(g != NULL) {
		if(!inter_guild->calcinfo(g))
			mapif->guild_info(server, g, true);
	} else {
		// Failed to load info
		mapif->guild_info(server, &(struct guild){.guild_id = RFIFOL(act, 2)}, false);
	}
}

/**
 * ZW_GUILD_MEMBER
 * Add a new guild member
 **/
static void mapif_parse_GuildAddMember(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	struct guild_member m = {
		.account_id = RFIFOL(act, 6),
		.char_id    = RFIFOL(act, 10),
		.hair       = RFIFOW(act, 14),
		.hair_color = RFIFOW(act, 16),
		.gender     = RFIFOW(act, 18),
		.class      = RFIFOL(act, 20),
		.lv         = RFIFOW(act, 24),
		.exp        = RFIFOQ(act, 26),
		.exp_payper = RFIFOL(act, 34),
		.online     = RFIFOW(act, 38),
		.position   = RFIFOW(act, 40),
		//.name       = RFIFOP(act, 42),
		.modified   = RFIFOB(act, 66),
	};
	memcpy(m.name, RFIFOP(act, 42), sizeof(m.name));
	inter_guild->add_member(RFIFOL(act, 2), &m, server);
}

/**
 * ZW_GUILD_WITHDRAW
 * Delete member from guild
 **/
static void mapif_parse_GuildLeave(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	inter_guild->leave(RFIFOL(act, 2), RFIFOL(act, 6),
		RFIFOL(act, 10), RFIFOB(act, 14), RFIFOP(act, 15), server);
}

/**
 * ZW_GUILD_MEMBER_UPDATE_SHORT
 * Change member info
 **/
static void mapif_parse_GuildChangeMemberInfoShort(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	inter_guild->update_member_info_short(RFIFOL(act, 2), RFIFOL(act, 6),
		RFIFOL(act, 10), RFIFOB(act, 14), RFIFOL(act, 15), RFIFOL(act, 19));
}

/**
 * ZW_GUILD_MEMBER_UPDATE_FIELD
 * Update member information request
 **/
static void mapif_parse_GuildMemberInfoChange(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	int field_length = RFIFOW(act,2) - sizeof(struct PACKET_ZW_GUILD_MEMBER_UPDATE_FIELD) - sizeof(intptr);
	Assert(field_length > 0 && "Malformed ZW_GUILD_MEMBER_UPDATE_FIELD");
	inter_guild->update_member_info(RFIFOL(act, 4), RFIFOL(act, 8),
		RFIFOL(act, 12), RFIFOW(act, 16), RFIFOP(act, 18), field_length);
}

/**
 * ZW_GUILD_BREAK
 * BreakGuild
 **/
static void mapif_parse_BreakGuild(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	inter_guild->disband(RFIFOL(act, 2));
}

/**
 * ZW_GUILD_INFO_UPDATE
 * Changes basic guild information
 * The types are available in mmo.h::guild_basic_info
 **/
static void mapif_parse_GuildBasicInfoChange(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	int field_length = RFIFOW(act,2) - sizeof(struct PACKET_ZW_GUILD_INFO_UPDATE) - sizeof(intptr);
	Assert(field_length > 0 && "Malformed PACKET_ZW_GUILD_INFO_UPDATE");
	inter_guild->update_basic_info(RFIFOL(act, 4), RFIFOW(act, 8),
		RFIFOP(act, 10), field_length);
	// Information is already sent in mapif->guild_info
	//mapif->guild_basicinfochanged(guild_id,type,data,len);
}

/**
 * ZW_GUILD_TITLE_UPDATE
 * Update a guild title
 **/
static void mapif_parse_GuildPosition(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	struct guild_position p = {
		//.name     = RFIFOP(act, 6),
		.mode     = RFIFOL(act, 30),
		.exp_mode = RFIFOL(act, 34),
		.modified = 0x1,
	};
	memcpy(p.name, RFIFOP(act, 6), sizeof(p.name));
	inter_guild->update_position(RFIFOL(act, 2), RFIFOW(act, 4), &p);
}

/**
 * ZW_GUILD_SKILL_UP
 * Guild Skill UP
 **/
static void mapif_parse_GuildSkillUp(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	inter_guild->use_skill_point(RFIFOL(act, 2), RFIFOL(act, 6),
		RFIFOL(act, 10), RFIFOL(act, 14));
}

/**
 * ZW_GUILD_ALLY_UPDATE
 * Alliance modification
 **/
static void mapif_parse_GuildAlliance(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	inter_guild->change_alliance(RFIFOL(act, 2), RFIFOL(act, 6),
		RFIFOL(act,10), RFIFOL(act,14), RFIFOB(act,18));
}

/**
 * ZW_GUILD_NOTICE
 * Change guild message
 **/
static void mapif_parse_GuildNotice(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	inter_guild->update_notice(RFIFOL(act, 2),
		RFIFOP(act, 6), RFIFOP(act, 6+MAX_GUILDMES1));
}

/**
 * ZW_GUILD_EMBLEM
 * Update emblem request
 **/
static void mapif_parse_GuildEmblem(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	int emblem_len = RFIFOW(act, 2) - sizeof(struct PACKET_ZW_GUILD_EMBLEM)-sizeof(intptr);
	Assert(emblem_len > 0 && "Malformed ZW_GUILD_EMBLEM");
	inter_guild->update_emblem(RFIFOL(act, 4), RFIFOP(act, 8), emblem_len);
}

/**
 * ZW_GUILD_CASTLE_LOAD
 * Request castle data
 **/
static void mapif_parse_GuildCastleDataLoad(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	int castle_count = RFIFOW(act,2) - sizeof(struct PACKET_ZW_GUILD_CASTLE_LOAD) - sizeof(intptr);
	castle_count = castle_count/sizeof(int32);
	mapif->guild_castle_dataload(act->session, RFIFOP(act, 4), castle_count);
}

/**
 * ZW_GUILD_CASTLE_SAVE
 * Save castle data
 **/
static void mapif_parse_GuildCastleDataSave(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	inter_guild->update_castle_data(RFIFOW(act, 2), RFIFOB(act, 4), RFIFOL(act, 5));
}

/**
 * ZW_GUILD_MASTER
 * Change guild master
 **/
static void mapif_parse_GuildMasterChange(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	inter_guild->change_leader(RFIFOL(act, 2), RFIFOP(act, 6), strnlen(RFIFOP(act, 6), NAME_LENGTH));
}

/*======================================
 * MAPIF : HOMUNCULUS
 *--------------------------------------*/

/**
 * WZ_HOMUNCULUS_CREATE_ACK
 * Notifies map-server of a homunculus creation request status
 *
 * @param flag boolean success
 **/
static void mapif_homunculus_created(struct socket_data *session, int account_id, const struct s_homunculus *sh, unsigned char flag)
{
	nullpo_retv(sh);
	WFIFOHEAD(session, sizeof(struct s_homunculus) + 9, true);
	WFIFOW(session, 0) = 0x3890;
	WFIFOW(session, 2) = sizeof(struct s_homunculus) + 9;
	WFIFOL(session, 4) = account_id;
	WFIFOB(session, 8) = flag;
	memcpy(WFIFOP(session, 9), sh, sizeof(struct s_homunculus));// TODO/FIXME: Copy of a padded struct
	WFIFOSET(session, WFIFOW(session, 2));
}

/**
 * WZ_HOMUNCULUS_DELETE_ACK
 * Notifies map-server of a homunculus delete request status
 *
 * @param flag boolean success
 **/
static void mapif_homunculus_deleted(struct socket_data *session, int flag)
{
	WFIFOHEAD(session, 3, true);
	WFIFOW(session, 0) = 0x3893;
	WFIFOB(session,2) = flag; //Flag 1 = success
	WFIFOSET(session, 3);
}

/**
 * WZ_HOMUNCULUS_LOAD_ACK
 * Sends requested homunculus data
 **/
static void mapif_homunculus_loaded(struct socket_data *session, int account_id, struct s_homunculus *hd)
{
	WFIFOHEAD(session, sizeof(struct s_homunculus) + 9, true);
	WFIFOW(session, 0) = 0x3891;
	WFIFOW(session, 2) = sizeof(struct s_homunculus) + 9;
	WFIFOL(session, 4) = account_id;
	if (hd != NULL) {
		WFIFOB(session, 8) = 1; // success
		memcpy(WFIFOP(session, 9), hd, sizeof(struct s_homunculus)); // TODO/FIXME: Copy of a padded struct
	} else {
		WFIFOB(session, 8) = 0; // not found.
		memset(WFIFOP(session, 9), 0, sizeof(struct s_homunculus));
	}
	WFIFOSET(session, sizeof(struct s_homunculus) + 9);
}

/**
 * WZ_HOMUNCULUS_SAVE_ACK
 * Result of a save request
 **/
static void mapif_homunculus_saved(struct socket_data *session, int account_id, bool flag)
{
	WFIFOHEAD(session, 7, true);
	WFIFOW(session, 0) = 0x3892;
	WFIFOL(session, 2) = account_id;
	WFIFOB(session, 6) = flag; // 1:success, 0:failure
	WFIFOSET(session, 7);
}

/**
 * WZ_HOMUNCULUS_RENAME_ACK
 * Result of a rename request
 **/
static void mapif_homunculus_renamed(struct socket_data *session, int account_id, int homun_id, unsigned char flag, const char *name)
{
	nullpo_retv(name);
	WFIFOHEAD(session, NAME_LENGTH + 12, true);
	WFIFOW(session, 0) = 0x3894;
	WFIFOL(session, 2) = account_id;
	WFIFOL(session, 6) = homun_id;
	WFIFOB(session, 10) = flag;
	safestrncpy(WFIFOP(session, 11), name, NAME_LENGTH);
	WFIFOSET(session, NAME_LENGTH + 12);
}

/**
 * ZW_HOMUNCULUS_CREATE
 * Create homunculus request
 **/
static void mapif_parse_homunculus_create(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	bool result;
	int32 account_id = RFIFOL(act, 2);
	struct s_homunculus hd = {
		.char_id = RFIFOL(act, 6),
		//.name = RFIFOP(act, 10),
		.class_     = RFIFOL(act, 34),
		.hp         = RFIFOL(act, 38),
		.max_hp     = RFIFOL(act, 42),
		.sp         = RFIFOL(act, 46),
		.max_sp     = RFIFOL(act, 50),
		.level      = RFIFOW(act, 54),
		.hunger     = RFIFOW(act, 56),
		.intimacy   = RFIFOL(act, 58),
		.str        = RFIFOL(act, 62),
		.agi        = RFIFOL(act, 66),
		.vit        = RFIFOL(act, 70),
		.int_       = RFIFOL(act, 74),
		.dex        = RFIFOL(act, 78),
		.luk        = RFIFOL(act, 82),
	};
	memcpy(hd.name, RFIFOP(act, 10), NAME_LENGTH);

	result = inter_homunculus->create(&hd);
	mapif->homunculus_created(act->session, account_id, &hd, result);
}

/**
 * ZW_HOMUNCULUS_DELETE
 * Delete homunculus request
 **/
static void mapif_parse_homunculus_delete(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	bool result = inter_homunculus->delete(RFIFOL(act, 2));
	mapif->homunculus_deleted(act->session, result);
}

/**
 * ZW_HOMUNCULUS_LOAD
 * Load homunculus request
 **/
static void mapif_parse_homunculus_load(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	struct s_homunculus hd;
	bool result = inter_homunculus->load(RFIFOL(act, 6), &hd);
	mapif->homunculus_loaded(act->session, RFIFOL(act, 2), (result ? &hd : NULL));
}

/**
 * ZW_HOMUNCULUS_SAVE
 * Save homunculus request
 *
 * TODO: Too much information is sent every time a save request is made, maybe
 * we could use a similar to guild system instead, only sending what was really
 * updated.
 **/
static void mapif_parse_homunculus_save(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	int account_id = RFIFOL(act, 2);
	size_t hskill_len = SIZEOF_MEMBER(struct s_homunculus_packet_data, hskill);
	struct s_homunculus hd = {
		//.name = RFIFOP(act, 6),
		.hom_id      = RFIFOL(act, 30),
		.char_id     = RFIFOL(act, 34),
		.class_      = RFIFOL(act, 38),
		.prev_class  = RFIFOL(act, 42),
		.hp          = RFIFOL(act, 46),
		.max_hp      = RFIFOL(act, 50),
		.sp          = RFIFOL(act, 54),
		.max_sp      = RFIFOL(act, 58),
		.intimacy    = RFIFOL(act, 62),
		.hunger      = RFIFOW(act, 66),
		//.hskill = RFIFOP(act, 68),
		.skillpts     = RFIFOW(act, hskill_len+68+0),
		.level        = RFIFOW(act, hskill_len+68+2),
		.exp          = RFIFOQ(act, hskill_len+68+4),
		.rename_flag  = RFIFOW(act, hskill_len+68+12),
		.vaporize     = RFIFOW(act, hskill_len+68+14),
		.str          = RFIFOL(act, hskill_len+68+16),
		.agi          = RFIFOL(act, hskill_len+68+20),
		.vit          = RFIFOL(act, hskill_len+68+24),
		.int_         = RFIFOL(act, hskill_len+68+28),
		.dex          = RFIFOL(act, hskill_len+68+32),
		.luk          = RFIFOL(act, hskill_len+68+36),
		.str_value    = RFIFOL(act, hskill_len+68+40),
		.agi_value    = RFIFOL(act, hskill_len+68+44),
		.vit_value    = RFIFOL(act, hskill_len+68+48),
		.int_value    = RFIFOL(act, hskill_len+68+52),
		.dex_value    = RFIFOL(act, hskill_len+68+56),
		.luk_value    = RFIFOL(act, hskill_len+68+60),
		.spiritball   = RFIFOB(act, hskill_len+68+64),
		.autofeed     = RFIFOL(act, hskill_len+68+65),
	};
	memcpy(hd.name,   RFIFOP(act, 6), NAME_LENGTH);
	memcpy(hd.hskill, RFIFOP(act, 68), hskill_len);
	bool result = inter_homunculus->save(&hd);
	mapif->homunculus_saved(act->session, account_id, result);
}

/**
 * ZW_HOMUNCULUS_RENAME
 * Homunculus rename request
 *
 * TODO: This doesn't seem to be implemented in map-server
 * Currently all rename requests are handled by 0x3006 (parse_NameChangeRequest),
 * but all char-server is doing now is verifying if the names are valid or not
 * without actually updating the database...
 **/
static void mapif_parse_homunculus_rename(struct s_receive_action_data *act, struct mmo_map_server *server)
{
	int account_id = RFIFOL(act, 2);
	int homun_id   = RFIFOL(act, 6);
	bool result = inter_homunculus->rename(homun_id, RFIFOP(act, 10));
	mapif->homunculus_renamed(act->session, account_id, homun_id, result, RFIFOP(act, 10));
}

/*======================================
 * MAPIF : MAIL
 *--------------------------------------*/

/**
 * WZ_MAIL_SENDINBOX 0x3848 <len>.W <char_id>.L <flag>.B <mail_data>.*
 * Notify map-server of a received e-mail
 **/
static void mapif_mail_sendinbox(struct socket_data *session, int char_id,
	unsigned char flag, const struct mail_data *md
) {
	//FIXME: dumping the whole structure like this is unsafe [ultramage]
	// TODO/FIXME: Copy of a padded struct
	WFIFOHEAD(session, sizeof(struct mail_data) + 9, true);
	WFIFOW(session, 0) = 0x3848;
	WFIFOW(session, 2) = sizeof(struct mail_data) + 9;
	WFIFOL(session, 4) = char_id;
	WFIFOB(session, 8) = flag;
	memcpy(WFIFOP(session, 9),md,sizeof(struct mail_data));
	WFIFOSET(session,WFIFOW(session, 2));
}

/**
 * ZW_MAIL_INBOX_REQUEST
 * Client Inbox Request
 **/
static void mapif_parse_mail_requestinbox(struct s_receive_action_data *act)
{
	int char_id = RFIFOL(act, 2);
	unsigned char flag = RFIFOB(act, 6);

	struct mail_data md = {0};
	inter_mail->fromsql(char_id, &md);
	mapif->mail_sendinbox(act->session, char_id, flag, &md);
}

/**
 * ZW_MAIL_READ
 * Mark mail as 'Read'
 **/
static void mapif_parse_mail_read(struct s_receive_action_data *act)
{
	int mail_id = RFIFOL(act, 2);
	inter_mail->mark_read(mail_id);
}

/**
 * WZ_MAIL_ATTACHMENT_ACK 0x384a <len>.W <char_id>.L <zeny>.L <item>.*
 * Returns attachment of an email (answer)
 **/
static void mapif_mail_sendattach(struct socket_data *session, int char_id,
	const struct mail_message *msg
) {
	nullpo_retv(msg);
	WFIFOHEAD(session, sizeof(struct item) + 12, true);
	WFIFOW(session, 0) = 0x384a;
	WFIFOW(session, 2) = sizeof(struct item) + 12;
	WFIFOL(session, 4) = char_id;
	WFIFOL(session, 8) = (msg->zeny > 0) ? msg->zeny : 0;
	// TODO/FIXME: Copy of a padded struct
	memcpy(WFIFOP(session, 12), &msg->item, sizeof(struct item));
	WFIFOSET(session,WFIFOW(session, 2));
}

/**
 * ZW_MAIL_ATTACHMENT
 * Attachment request
 **/
static void mapif_parse_mail_getattach(struct s_receive_action_data *act)
{
	struct mail_message msg = { 0 };
	int char_id = RFIFOL(act, 2);
	int mail_id = RFIFOL(act, 6);

	if (!inter_mail->get_attachment(char_id, mail_id, &msg))
		return;

	mapif->mail_sendattach(act->session, char_id, &msg);
}

/**
 * WZ_MAIL_DELETE_ACK 0x384b <char_id>.L <mail_id>.L <failed>.B
 **/
static void mapif_mail_delete(struct socket_data *session, int char_id, int mail_id, bool failed)
{
	WFIFOHEAD(session, 11, true);
	WFIFOW(session, 0) = 0x384b;
	WFIFOL(session, 2) = char_id;
	WFIFOL(session, 6) = mail_id;
	WFIFOB(session, 10) = failed;
	WFIFOSET(session, 11);
}

/**
 * ZW_MAIL_DELETE
 * Mail deletion request
 **/
static void mapif_parse_mail_delete(struct s_receive_action_data *act)
{
	int char_id = RFIFOL(act, 2);
	int mail_id = RFIFOL(act, 6);
	bool failed = !inter_mail->delete(char_id, mail_id);
	mapif->mail_delete(act->session, char_id, mail_id, failed);
}

/**
 * WZ_MAIL_NEW <dest_id>.L <mail_id>.L <send_name>.24B <title>.40B
 * Reports New Mail to Map Server
 **/
static void mapif_mail_new(struct mail_message *msg)
{
	unsigned char buf[74];

	if (msg == NULL || msg->id == 0)
		return;

	WBUFW(buf, 0) = 0x3849;
	WBUFL(buf, 2) = msg->dest_id;
	WBUFL(buf, 6) = msg->id;
	memcpy(WBUFP(buf, 10), msg->send_name, NAME_LENGTH);
	memcpy(WBUFP(buf, 34), msg->title, MAIL_TITLE_LENGTH);
	mapif->sendall(buf, 74);
}

/**
 * WZ_MAIL_RETURN_ACK <char_id>.L <mail_id>.L <flag>.B
 * Answer to return message request
 *
 * @param new_mail New mail id (0 if no mail)
 **/
static void mapif_mail_return(struct socket_data *session, int char_id, int mail_id, int new_mail)
{
	WFIFOHEAD(session, 11, true);
	WFIFOW(session, 0) = 0x384c;
	WFIFOL(session, 2) = char_id;
	WFIFOL(session, 6) = mail_id;
	WFIFOB(session, 10) = (new_mail == 0);
	WFIFOSET(session, 11);
}

/**
 * ZW_MAIL_RETURN
 * Return message request
 **/
static void mapif_parse_mail_return(struct s_receive_action_data *act)
{
	int char_id = RFIFOL(act, 2);
	int mail_id = RFIFOL(act, 6);
	int new_mail = 0;

	if (!inter_mail->return_message(char_id, mail_id, &new_mail))
		return;

	mapif->mail_return(act->session, char_id, mail_id, new_mail);
}

/**
 * WZ_MAIL_SEND_ACK 0x384d <len>.W <mail_message>.*
 * Answer to send request
 **/
static void mapif_mail_send(struct socket_data *session, struct mail_message* msg)
{
	int len = sizeof(struct mail_message) + 4;

	nullpo_retv(msg);
	WFIFOHEAD(session, len, true);
	WFIFOW(session, 0) = 0x384d;
	WFIFOW(session, 2) = len;
	// TODO/FIXME: Copy of a padded struct
	memcpy(WFIFOP(session, 4), msg, sizeof(struct mail_message));
	WFIFOSET(session,len);
}

/**
 * ZW_MAIL_SEND
 * Send a mail
 **/
static void mapif_parse_mail_send(struct s_receive_action_data *act)
{
	struct mail_message msg;
	int account_id = 0;
	int pos = 2;

	pos += sizeof((account_id  = RFIFOL(act, pos)));
	pos += sizeof((msg.id      = RFIFOL(act, pos)));
	pos += sizeof((msg.send_id = RFIFOL(act, pos)));
	memcpy(msg.send_name, RFIFOP(act, pos),
		SIZEOF_MEMBER(struct mail_message_packet_data, send_name));
	pos += SIZEOF_MEMBER(struct mail_message_packet_data, send_name);
	pos += sizeof((msg.dest_id = RFIFOL(act, pos)));
	memcpy(msg.dest_name, RFIFOP(act, pos),
		SIZEOF_MEMBER(struct mail_message_packet_data, dest_name));
	pos += SIZEOF_MEMBER(struct mail_message_packet_data, dest_name);
	memcpy(msg.title, RFIFOP(act, pos),
		SIZEOF_MEMBER(struct mail_message_packet_data, title));
	pos += SIZEOF_MEMBER(struct mail_message_packet_data, title);
	memcpy(msg.body, RFIFOP(act, pos),
		SIZEOF_MEMBER(struct mail_message_packet_data, body));
	pos += SIZEOF_MEMBER(struct mail_message_packet_data, body);
	pos += sizeof((msg.status    = RFIFOB(act, pos)));
	pos += sizeof((msg.timestamp = RFIFOQ(act, pos)));
	pos += sizeof((msg.zeny      = RFIFOL(act, pos)));
	pos += mapif->parse_item_data(act, pos, &msg.item);

	inter_mail->send(account_id, &msg);

	mapif->mail_send(act->session, &msg); // notify sender
	mapif->mail_new(&msg); // notify recipient
}

/*==========================================
 * MAPIF : MERCENARY
 *------------------------------------------*/

/**
 * WZ_MERCENARY_SEND 0x3870 <flag>.B <s_mercenary_packet_data>.*
 * Sends mercenary data
 *
 * @param result true mercenary data is complete (success state)
 **/
static void mapif_mercenary_send(struct socket_data *session, const struct s_mercenary *merc, bool result)
{
	WFIFOHEAD(session, sizeof(struct s_mercenary_packet_data)+3, true);
	WFIFOW(session, 0) = 0x3870;
	WFIFOB(session, 2) = result;
	WFIFOL(session, 3) = merc->mercenary_id;
	WFIFOL(session, 7) = merc->char_id;
	WFIFOL(session, 11) = merc->class_;
	WFIFOL(session, 15) = merc->hp;
	WFIFOL(session, 19) = merc->sp;
	WFIFOL(session, 23) = merc->kill_count;
	WFIFOL(session, 27) = merc->life_time;
	WFIFOSET(session, sizeof(struct s_mercenary_packet_data)+3);
}

/**
 * Parses a s_mercenary_packet_data object of provided packet
 *
 * @param pos  Offset of data in packet
 * @param out  Object to be filled
 * @return pos Position in buffer after filling
 **/
static int mapif_parse_mercenary_data(struct s_receive_action_data *act,
	int pos, struct s_mercenary *out
) {
	pos += sizeof((out->mercenary_id = RFIFOL(act,pos)));
	pos += sizeof((out->char_id      = RFIFOL(act,pos)));
	pos += sizeof((out->class_       = RFIFOL(act,pos)));
	pos += sizeof((out->hp           = RFIFOL(act,pos)));
	pos += sizeof((out->sp           = RFIFOL(act,pos)));
	pos += sizeof((out->kill_count   = RFIFOL(act,pos)));
	pos += sizeof((out->life_time    = RFIFOL(act,pos)));
	return pos;
}

/**
 * ZW_MERCENARY_CREATE
 * Request to create a mercenary
 **/
static void mapif_parse_mercenary_create(struct s_receive_action_data *act)
{
	struct s_mercenary merc = {0};
	bool result;

	mapif->parse_mercenary_data(act, 2, &merc);

	result = inter_mercenary->create(&merc);
	mapif->mercenary_send(act->session, &merc, result);
}

/**
 * ZW_MERCENARY_LOAD
 * Mercenary load request
 **/
static void mapif_parse_mercenary_load(struct s_receive_action_data *act)
{
	struct s_mercenary merc = {0};
	bool result = inter_mercenary->load(RFIFOL(act, 2), RFIFOL(act, 6), &merc);
	mapif->mercenary_send(act->session, &merc, result);
}

/**
 * WZ_MERCENARY_DELETE_ACK <merc_id>.L <char_id>.L <success>.B
 * Delete response
 **/
static void mapif_mercenary_deleted(struct socket_data *session, int char_id, int merc_id, bool success)
{
	WFIFOHEAD(session, 11, true);
	WFIFOW(session, 0) = 0x3871;
	WFIFOL(session, 2) = merc_id;
	WFIFOL(session, 6) = char_id;
	WFIFOB(session, 10) = success;
	WFIFOSET(session, 11);
}

/**
 * ZW_MERCENARY_DELETE
 * Deletion request
 **/
static void mapif_parse_mercenary_delete(struct s_receive_action_data *act)
{
	int merc_id = RFIFOL(act, 2);
	int char_id = RFIFOL(act, 6);
	bool result = inter_mercenary->delete(merc_id);
	mapif->mercenary_deleted(act->session, char_id, merc_id, result);
}

/**
 * WZ_MERCENARY_SAVE_ACK
 * Answer of save request
 **/
static void mapif_mercenary_saved(struct socket_data *session, int char_id, int merc_id, bool success)
{
	WFIFOHEAD(session, 11, true);
	WFIFOW(session, 0) = 0x3872;
	WFIFOL(session, 2) = merc_id;
	WFIFOL(session, 6) = char_id;
	WFIFOB(session, 10) = success;
	WFIFOSET(session, 11);
}

/**
 * ZW_MERCENARY_SAVE
 * Save request
 **/
static void mapif_parse_mercenary_save(struct s_receive_action_data *act)
{
	struct s_mercenary merc = {0};
	mapif->parse_mercenary_data(act, 2, &merc);

	bool result = inter_mercenary->save(&merc);
	mapif->mercenary_saved(act->session, merc.char_id, merc.mercenary_id, result);
}

/*==========================================
 * MAPIF : PARTY
 *------------------------------------------*/

// Create a party whether or not
static int mapif_party_created(int fd, int account_id, int char_id, struct party *p)
{
	WFIFOHEAD(fd, 39);
	WFIFOW(fd, 0) = 0x3820;
	WFIFOL(fd, 2) = account_id;
	WFIFOL(fd, 6) = char_id;
	if (p != NULL) {
		WFIFOB(fd, 10) = 0;
		WFIFOL(fd, 11) = p->party_id;
		memcpy(WFIFOP(fd, 15), p->name, NAME_LENGTH);
		ShowInfo("int_party: Party created (%d - %s)\n", p->party_id, p->name);
	} else {
		WFIFOB(fd, 10) = 1;
		WFIFOL(fd, 11) = 0;
		memset(WFIFOP(fd, 15), 0, NAME_LENGTH);
	}
	WFIFOSET(fd, 39);

	return 0;
}

//Party information not found
static void mapif_party_noinfo(int fd, int party_id, int char_id)
{
	WFIFOHEAD(fd, 12);
	WFIFOW(fd, 0) = 0x3821;
	WFIFOW(fd, 2) = 12;
	WFIFOL(fd, 4) = char_id;
	WFIFOL(fd, 8) = party_id;
	WFIFOSET(fd, 12);
	ShowWarning("int_party: info not found (party_id=%d char_id=%d)\n", party_id, char_id);
}

//Digest party information
static void mapif_party_info(int fd, struct party* p, int char_id)
{
	unsigned char buf[8 + sizeof(struct party)];
	nullpo_retv(p);
	WBUFW(buf, 0) = 0x3821;
	WBUFW(buf, 2) = 8 + sizeof(struct party);
	WBUFL(buf, 4) = char_id;
	memcpy(WBUFP(buf, 8), p, sizeof(struct party));

	if (fd < 0)
		mapif->sendall(buf, WBUFW(buf, 2));
	else
		mapif->send(fd, buf, WBUFW(buf, 2));
}

//Whether or not additional party members
static int mapif_party_memberadded(int fd, int party_id, int account_id, int char_id, int flag)
{
	WFIFOHEAD(fd, 15);
	WFIFOW(fd, 0) = 0x3822;
	WFIFOL(fd, 2) = party_id;
	WFIFOL(fd, 6) = account_id;
	WFIFOL(fd, 10) = char_id;
	WFIFOB(fd, 14) = flag;
	WFIFOSET(fd, 15);

	return 0;
}

// Party setting change notification
static int mapif_party_optionchanged(int fd, struct party *p, int account_id, int flag)
{
	unsigned char buf[16];
	nullpo_ret(p);
	WBUFW(buf, 0) = 0x3823;
	WBUFL(buf, 2) = p->party_id;
	WBUFL(buf, 6) = account_id;
	WBUFW(buf, 10) = p->exp;
	WBUFW(buf, 12) = p->item;
	WBUFB(buf, 14) = flag;
	if (flag == 0)
		mapif->sendall(buf, 15);
	else
		mapif->send(fd, buf, 15);
	return 0;
}

//Withdrawal notification party
static int mapif_party_withdraw(int party_id, int account_id, int char_id)
{
	unsigned char buf[16];

	WBUFW(buf, 0) = 0x3824;
	WBUFL(buf, 2) = party_id;
	WBUFL(buf, 6) = account_id;
	WBUFL(buf, 10) = char_id;
	mapif->sendall(buf, 14);
	return 0;
}

//Party map update notification
static int mapif_party_membermoved(struct party *p, int idx)
{
	unsigned char buf[20];

	nullpo_ret(p);
	Assert_ret(idx >= 0 && idx < MAX_PARTY);
	WBUFW(buf, 0) = 0x3825;
	WBUFL(buf, 2) = p->party_id;
	WBUFL(buf, 6) = p->member[idx].account_id;
	WBUFL(buf, 10) = p->member[idx].char_id;
	WBUFW(buf, 14) = p->member[idx].map;
	WBUFB(buf, 16) = p->member[idx].online;
	WBUFW(buf, 17) = p->member[idx].lv;
	mapif->sendall(buf, 19);
	return 0;
}

//Dissolution party notification
static int mapif_party_broken(int party_id, int flag)
{
	unsigned char buf[16];
	WBUFW(buf, 0) = 0x3826;
	WBUFL(buf, 2) = party_id;
	WBUFB(buf, 6) = flag;
	mapif->sendall(buf, 7);
	//printf("int_party: broken %d\n",party_id);
	return 0;
}

// Create Party
static int mapif_parse_CreateParty(int fd, const char *name, int item, int item2, const struct party_member *leader)
{
	struct party_data *p;

	nullpo_ret(name);
	nullpo_ret(leader);

	p = inter_party->create(name, item, item2, leader);

	if (p == NULL) {
		mapif->party_created(fd, leader->account_id, leader->char_id, NULL);
		return 0;
	}

	mapif->party_info(fd, &p->party, 0);
	mapif->party_created(fd, leader->account_id, leader->char_id, &p->party);

	return 0;
}

// Party information request
static void mapif_parse_PartyInfo(int fd, int party_id, int char_id)
{
	struct party_data *p;
	p = inter_party->fromsql(party_id);

	if (p != NULL)
		mapif->party_info(fd, &p->party, char_id);
	else
		mapif->party_noinfo(fd, party_id, char_id);
}

// Add a player to party request
static int mapif_parse_PartyAddMember(int fd, int party_id, const struct party_member *member)
{
	nullpo_ret(member);

	if (!inter_party->add_member(party_id, member)) {
		mapif->party_memberadded(fd, party_id, member->account_id, member->char_id, 1);
		return 0;
	}
	mapif->party_memberadded(fd, party_id, member->account_id, member->char_id, 0);

	return 0;
}

//Party setting change request
static int mapif_parse_PartyChangeOption(int fd, int party_id, int account_id, int exp, int item)
{
	inter_party->change_option(party_id, account_id, exp, item, fd);
	return 0;
}

//Request leave party
static int mapif_parse_PartyLeave(int fd, int party_id, int account_id, int char_id)
{
	inter_party->leave(party_id, account_id, char_id);
	return 0;
}

// When member goes to other map or levels up.
static int mapif_parse_PartyChangeMap(int fd, int party_id, int account_id, int char_id, unsigned short map, int online, unsigned int lv)
{
	inter_party->change_map(party_id, account_id, char_id, map, online, lv);
	return 0;
}

//Request party dissolution
static int mapif_parse_BreakParty(int fd, int party_id)
{
	inter_party->disband(party_id);
	return 0;
}

static int mapif_parse_PartyLeaderChange(int fd, int party_id, int account_id, int char_id)
{
	if (!inter_party->change_leader(party_id, account_id, char_id))
		return 0;
	return 1;
}

/*==========================================
 * MAPIF : PET
 *------------------------------------------*/

static int mapif_pet_created(int fd, int account_id, struct s_pet *p)
{
	WFIFOHEAD(fd, 14);
	WFIFOW(fd, 0) = 0x3880;
	WFIFOL(fd, 2) = account_id;
	if (p != NULL){
		WFIFOL(fd, 6) = p->class_;
		WFIFOL(fd, 10) = p->pet_id;
		ShowInfo("int_pet: created pet %d - %s\n", p->pet_id, p->name);
	} else {
		WFIFOL(fd, 6) = 0;
		WFIFOL(fd, 10) = 0;
	}
	WFIFOSET(fd, 14);

	return 0;
}

static int mapif_pet_info(int fd, int account_id, struct s_pet *p)
{
	nullpo_ret(p);
	WFIFOHEAD(fd, sizeof(struct s_pet) + 9);
	WFIFOW(fd, 0) = 0x3881;
	WFIFOW(fd, 2) = sizeof(struct s_pet) + 9;
	WFIFOL(fd, 4) = account_id;
	WFIFOB(fd, 8) = 0;
	memcpy(WFIFOP(fd, 9), p, sizeof(struct s_pet));
	WFIFOSET(fd, WFIFOW(fd, 2));

	return 0;
}

static int mapif_pet_noinfo(int fd, int account_id)
{
	WFIFOHEAD(fd, sizeof(struct s_pet) + 9);
	WFIFOW(fd, 0) = 0x3881;
	WFIFOW(fd, 2) = sizeof(struct s_pet) + 9;
	WFIFOL(fd, 4) = account_id;
	WFIFOB(fd, 8) = 1;
	memset(WFIFOP(fd, 9), 0, sizeof(struct s_pet));
	WFIFOSET(fd, WFIFOW(fd, 2));

	return 0;
}

static int mapif_save_pet_ack(int fd, int account_id, int flag)
{
	WFIFOHEAD(fd, 7);
	WFIFOW(fd, 0) = 0x3882;
	WFIFOL(fd, 2) = account_id;
	WFIFOB(fd, 6) = flag;
	WFIFOSET(fd, 7);

	return 0;
}

static int mapif_delete_pet_ack(int fd, int flag)
{
	WFIFOHEAD(fd, 3);
	WFIFOW(fd, 0) = 0x3883;
	WFIFOB(fd, 2) = flag;
	WFIFOSET(fd, 3);

	return 0;
}

static int mapif_save_pet(int fd, int account_id, const struct s_pet *data)
{
	//here process pet save request.
	int len;
	nullpo_ret(data);
	RFIFOHEAD(fd);
	len = RFIFOW(fd, 2);
	if (sizeof(struct s_pet) != len-8) {
		ShowError("inter pet: data size mismatch: %d != %"PRIuS"\n", len-8, sizeof(struct s_pet));
		return 0;
	}

	inter_pet->tosql(data);
	mapif->save_pet_ack(fd, account_id, 0);

	return 0;
}

static int mapif_delete_pet(int fd, int pet_id)
{
	mapif->delete_pet_ack(fd, inter_pet->delete_(pet_id));

	return 0;
}

static int mapif_parse_CreatePet(int fd)
{
	int account_id;
	struct s_pet *pet;

	RFIFOHEAD(fd);
	account_id = RFIFOL(fd, 2);
	pet = inter_pet->create(account_id,
		RFIFOL(fd, 6),
		RFIFOL(fd, 10),
		RFIFOL(fd, 14),
		RFIFOL(fd, 18),
		RFIFOL(fd, 22),
		RFIFOW(fd, 26),
		RFIFOW(fd, 28),
		RFIFOB(fd, 30),
		RFIFOB(fd, 31),
		RFIFOP(fd, 32));

	if (pet != NULL)
		mapif->pet_created(fd, account_id, pet);
	else
		mapif->pet_created(fd, account_id, NULL);

	return 0;
}

static int mapif_parse_LoadPet(int fd)
{
	int account_id;
	struct s_pet *pet;

	RFIFOHEAD(fd);
	account_id = RFIFOL(fd, 2);
	pet = inter_pet->load(account_id, RFIFOL(fd, 6), RFIFOL(fd, 10));

	if (pet != NULL)
		mapif->pet_info(fd, account_id, pet);
	else
		mapif->pet_noinfo(fd, account_id);
	return 0;
}

static int mapif_parse_SavePet(int fd)
{
	RFIFOHEAD(fd);
	mapif->save_pet(fd, RFIFOL(fd, 4), RFIFOP(fd, 8));
	return 0;
}

static int mapif_parse_DeletePet(int fd)
{
	RFIFOHEAD(fd);
	mapif->delete_pet(fd, RFIFOL(fd, 2));
	return 0;
}

/*==========================================
 * MAPIF : QUEST
 *------------------------------------------*/

static void mapif_quest_save_ack(int fd, int char_id, bool success)
{
	WFIFOHEAD(fd, 7);
	WFIFOW(fd, 0) = 0x3861;
	WFIFOL(fd, 2) = char_id;
	WFIFOB(fd, 6) = success ? 1 : 0;
	WFIFOSET(fd, 7);
}

/**
 * Handles the save request from mapserver for a character's questlog.
 *
 * Received quests are saved, and an ack is sent back to the map server.
 *
 * @see inter_parse_frommap
 */
static int mapif_parse_quest_save(int fd)
{
	int num = (RFIFOW(fd, 2) - 8) / sizeof(struct quest);
	int char_id = RFIFOL(fd, 4);
	const struct quest *qd = NULL;
	bool success;

	if (num > 0)
		qd = RFIFOP(fd,8);

	success = inter_quest->save(char_id, qd, num);

	// Send ack
	mapif->quest_save_ack(fd, char_id, success);

	return 0;
}

static void mapif_send_quests(int fd, int char_id, struct quest *tmp_questlog, int num_quests)
{
	WFIFOHEAD(fd,num_quests*sizeof(struct quest) + 8);
	WFIFOW(fd, 0) = 0x3860;
	WFIFOW(fd, 2) = num_quests*sizeof(struct quest) + 8;
	WFIFOL(fd, 4) = char_id;

	if (num_quests > 0) {
		nullpo_retv(tmp_questlog);
		memcpy(WFIFOP(fd, 8), tmp_questlog, sizeof(struct quest) * num_quests);
	}

	WFIFOSET(fd, num_quests * sizeof(struct quest) + 8);
}

/**
 * Sends questlog to the map server
 *
 * Note: Completed quests (state == Q_COMPLETE) are guaranteed to be sent last
 * and the map server relies on this behavior (once the first Q_COMPLETE quest,
 * all of them are considered to be Q_COMPLETE)
 *
 * @see inter_parse_frommap
 */
static int mapif_parse_quest_load(int fd)
{
	int char_id = RFIFOL(fd,2);
	struct quest *tmp_questlog = NULL;
	int num_quests;

	tmp_questlog = inter_quest->fromsql(char_id, &num_quests);
	mapif->send_quests(fd, char_id, tmp_questlog, num_quests);

	if (tmp_questlog != NULL)
		aFree(tmp_questlog);

	return 0;
}

/*==========================================
 * MAPIF : RoDEX
 *------------------------------------------*/

/*==========================================
 * Inbox Request
 *------------------------------------------*/
static void mapif_parse_rodex_requestinbox(int fd)
{
	int count;
	int char_id = RFIFOL(fd,2);
	int account_id = RFIFOL(fd, 6);
	int8 flag = RFIFOB(fd, 10);
	int8 opentype = RFIFOB(fd, 11);
	int64 mail_id = RFIFOQ(fd, 12);
	struct rodex_maillist mails = { 0 };

	VECTOR_INIT(mails);
	if (flag == 0)
		count = inter_rodex->fromsql(char_id, account_id, opentype, 0, &mails);
	else
		count = inter_rodex->fromsql(char_id, account_id, opentype, mail_id, &mails);
	mapif->rodex_sendinbox(fd, char_id, opentype, flag, count, mail_id, &mails);
	VECTOR_CLEAR(mails);
}

static void mapif_rodex_sendinbox(int fd, int char_id, int8 opentype, int8 flag, int count, int64 mail_id, struct rodex_maillist *mails)
{
	int per_packet = (UINT16_MAX - 24) / sizeof(struct rodex_message);
	int sent = 0;
	bool is_first = true;
	nullpo_retv(mails);
	Assert_retv(char_id > 0);
	Assert_retv(count >= 0);
	Assert_retv(mail_id >= 0);

	do {
		int i = 24, j, size, limit;
		int to_send = count - sent;
		bool is_last = true;

		if (to_send <= per_packet) {
			size = to_send * sizeof(struct rodex_message) + 24;
			limit = to_send;
			is_last = true;
		} else {
			limit = min(to_send, per_packet);
			if (limit != to_send) {
				is_last = false;
			}
			size = limit * sizeof(struct rodex_message) + 24;
		}

		WFIFOHEAD(fd, size);
		WFIFOW(fd, 0) = 0x3895;
		WFIFOW(fd, 2) = size;
		WFIFOL(fd, 4) = char_id;
		WFIFOB(fd, 8) = opentype;
		WFIFOB(fd, 9) = flag;
		WFIFOB(fd, 10) = is_last;
		WFIFOB(fd, 11) = is_first;
		WFIFOL(fd, 12) = limit;
		WFIFOQ(fd, 16) = mail_id;
		for (j = 0; j < limit; ++j, ++sent, i += sizeof(struct rodex_message)) {
			memcpy(WFIFOP(fd, i), &VECTOR_INDEX(*mails, sent), sizeof(struct rodex_message));
		}
		WFIFOSET(fd, size);

		is_first = false;
	} while (sent < count);
}

/*==========================================
 * Checks if there are new mails
 *------------------------------------------*/
static void mapif_parse_rodex_checkhasnew(int fd)
{
	int char_id = RFIFOL(fd, 2);
	int account_id = RFIFOL(fd, 6);
	bool has_new;

	Assert_retv(account_id >= START_ACCOUNT_NUM && account_id <= END_ACCOUNT_NUM);
	Assert_retv(char_id >= START_CHAR_NUM);

	has_new = inter_rodex->hasnew(char_id, account_id);
	mapif->rodex_sendhasnew(fd, char_id, has_new);
}

static void mapif_rodex_sendhasnew(int fd, int char_id, bool has_new)
{
	Assert_retv(char_id > 0);

	WFIFOHEAD(fd, 7);
	WFIFOW(fd, 0) = 0x3896;
	WFIFOL(fd, 2) = char_id;
	WFIFOB(fd, 6) = has_new;
	WFIFOSET(fd, 7);
}

/*==========================================
 * Update/Delete mail
 *------------------------------------------*/
static void mapif_parse_rodex_updatemail(int fd)
{
	int account_id = RFIFOL(fd, 2);
	int char_id = RFIFOL(fd, 6);
	int64 mail_id = RFIFOQ(fd, 10);
	uint8 opentype = RFIFOB(fd, 18);
	int8 flag = RFIFOB(fd, 19);

	inter_rodex->updatemail(fd, account_id, char_id, mail_id, opentype, flag);
}

/*==========================================
 * Send Mail
 *------------------------------------------*/
static void mapif_parse_rodex_send(int fd)
{
	struct rodex_message msg = { 0 };

	if (RFIFOW(fd,2) != 4 + sizeof(struct rodex_message))
		return;

	memcpy(&msg, RFIFOP(fd,4), sizeof(struct rodex_message));
	if (msg.receiver_id > 0 || msg.receiver_accountid > 0)
		msg.id = inter_rodex->savemessage(&msg);

	mapif->rodex_send(fd, msg.sender_id, msg.receiver_id, msg.receiver_accountid, msg.id > 0 ? true : false);
}

static void mapif_rodex_send(int fd, int sender_id, int receiver_id, int receiver_accountid, bool result)
{
	Assert_retv(sender_id >= 0);
	Assert_retv(receiver_id + receiver_accountid > 0);

	WFIFOHEAD(fd,15);
	WFIFOW(fd,0) = 0x3897;
	WFIFOL(fd,2) = sender_id;
	WFIFOL(fd,6) = receiver_id;
	WFIFOL(fd,10) = receiver_accountid;
	WFIFOB(fd,14) = result;
	WFIFOSET(fd,15);
}

/*------------------------------------------
 * Check Player
 *------------------------------------------*/
static void mapif_parse_rodex_checkname(int fd)
{
	int reqchar_id = RFIFOL(fd, 2);
	char name[NAME_LENGTH];
	int target_char_id, target_level;
	int target_class;

	safestrncpy(name, RFIFOP(fd, 6), NAME_LENGTH);

	if (inter_rodex->checkname(name, &target_char_id, &target_class, &target_level) == true)
		mapif->rodex_checkname(fd, reqchar_id, target_char_id, target_class, target_level, name);
	else
		mapif->rodex_checkname(fd, reqchar_id, 0, 0, 0, name);
}

static void mapif_rodex_checkname(int fd, int reqchar_id, int target_char_id, int target_class, int target_level, char *name)
{
	nullpo_retv(name);
	Assert_retv(reqchar_id > 0);
	Assert_retv(target_char_id >= 0);

	WFIFOHEAD(fd, 18 + NAME_LENGTH);
	WFIFOW(fd, 0) = 0x3898;
	WFIFOL(fd, 2) = reqchar_id;
	WFIFOL(fd, 6) = target_char_id;
	WFIFOL(fd, 10) = target_class;
	WFIFOL(fd, 14) = target_level;
	safestrncpy(WFIFOP(fd, 18), name, NAME_LENGTH);
	WFIFOSET(fd, 18 + NAME_LENGTH);
}

static void mapif_rodex_getzenyack(int fd, int char_id, int64 mail_id, uint8 opentype, int64 zeny)
{
	WFIFOHEAD(fd, 23);
	WFIFOW(fd, 0) = 0x3899;
	WFIFOL(fd, 2) = char_id;
	WFIFOQ(fd, 6) = zeny;
	WFIFOQ(fd, 14) = mail_id;
	WFIFOB(fd, 22) = opentype;
	WFIFOSET(fd, 23);
}

static void mapif_rodex_getitemsack(int fd, int char_id, int64 mail_id, uint8 opentype, int count, const struct rodex_item *items)
{
	WFIFOHEAD(fd, 15 + sizeof(struct rodex_item) * RODEX_MAX_ITEM);
	WFIFOW(fd, 0) = 0x389a;
	WFIFOL(fd, 2) = char_id;
	WFIFOQ(fd, 6) = mail_id;
	WFIFOB(fd, 14) = opentype;
	WFIFOB(fd, 15) = count;
	memcpy(WFIFOP(fd, 16), items, sizeof(struct rodex_item) * RODEX_MAX_ITEM);
	WFIFOSET(fd, 16 + sizeof(struct rodex_item) * RODEX_MAX_ITEM);
}

/*==========================================
 * MAPIF : STORAGE
 *------------------------------------------*/

/**
 * Sends loaded guild storage to a map-server.
 *
 * Packets sent:
 * 0x3818 <len>.W <account id>.L <guild id != 0>.L <flag>.B <capacity>.L <amount>.L {<item>.P}*<capacity>
 * 0x3818 <len>.W <account id>.L <guild id == 0>.L
 *
 * @param fd         The map-server's fd.
 * @param account_id The requesting character's account id.
 * @param guild_id   The requesting guild's ID.
 * @param flag       Additional options, passed through to the map server (1 = open storage)
 * @return Error code
 * @retval 0 in case of success.
 */
static int mapif_load_guild_storage(int fd, int account_id, int guild_id, char flag)
{
	if (SQL_ERROR == SQL->Query(inter->sql_handle, "SELECT `guild_id` FROM `%s` WHERE `guild_id`='%d'", guild_db, guild_id)) {
		Sql_ShowDebug(inter->sql_handle);
	} else if (SQL->NumRows(inter->sql_handle) > 0) {
		// guild exists
		struct guild_storage *gs = aCalloc(1, sizeof(*gs));

		if (inter_storage->guild_storage_fromsql(guild_id, gs) == 0) {
			int size = 21 + sizeof gs->items.data[0] * gs->items.capacity;
			WFIFOHEAD(fd, size);
			WFIFOW(fd, 0) = 0x3818;
			WFIFOW(fd, 2) = size;
			WFIFOL(fd, 4) = account_id;
			WFIFOL(fd, 8) = guild_id;
			WFIFOB(fd, 12) = flag;
			WFIFOL(fd, 13) = gs->items.capacity;
			WFIFOL(fd, 17) = gs->items.amount;
			if (gs->items.data != NULL) {
				memcpy(WFIFOP(fd, 21), gs->items.data, sizeof gs->items.data[0] * gs->items.capacity);
				aFree(gs->items.data);
			}
			WFIFOSET(fd, size);
			aFree(gs);
			return 0;
		}
		aFree(gs);
	}
	// guild does not exist or there was an error
	SQL->FreeResult(inter->sql_handle);
	WFIFOHEAD(fd, 12);
	WFIFOW(fd, 0) = 0x3818;
	WFIFOW(fd, 2) = 12;
	WFIFOL(fd, 4) = account_id;
	WFIFOL(fd, 8) = 0;
	WFIFOSET(fd, 12);
	return 0;
}

static int mapif_save_guild_storage_ack(int fd, int account_id, int guild_id, int fail)
{
	WFIFOHEAD(fd, 11);
	WFIFOW(fd, 0) = 0x3819;
	WFIFOL(fd, 2) = account_id;
	WFIFOL(fd, 6) = guild_id;
	WFIFOB(fd, 10) = fail;
	WFIFOSET(fd, 11);
	return 0;
}

/**
 * Loads the account storage and send to the map server.
 * @packet 0x3805     [out] <account_id>.L <struct item[]>.P
 * @param  fd         [in]  file/socket descriptor.
 * @param  account_id [in]  account id of the session.
 * @return 1 on success, 0 on failure.
 */
static int mapif_account_storage_load(int fd, int account_id)
{
	struct storage_data stor = { 0 };
	int count = 0, i = 0, len = 0;

	Assert_ret(account_id > 0);

	VECTOR_INIT(stor.item);
	count = inter_storage->fromsql(account_id, &stor);

	len = 8 + count * sizeof(struct item);

	WFIFOHEAD(fd, len);
	WFIFOW(fd, 0) = 0x3805;
	WFIFOW(fd, 2) = (uint16) len;
	WFIFOL(fd, 4) = account_id;
	for (i = 0; i < count; i++)
		memcpy(WFIFOP(fd, 8 + i * sizeof(struct item)), &VECTOR_INDEX(stor.item, i), sizeof(struct item));
	WFIFOSET(fd, len);

	VECTOR_CLEAR(stor.item);

	return 1;
}

/**
 * Parses account storage load request from map server.
 * @packet 0x3010 [in] <account_id>.L
 * @param  fd     [in] file/socket descriptor
 * @return 1 on success, 0 on failure.
 */
static int mapif_parse_AccountStorageLoad(int fd)
{
	int account_id = RFIFOL(fd, 2);

	Assert_ret(fd > 0);
	Assert_ret(account_id > 0);

	mapif->account_storage_load(fd, account_id);

	return 1;
}

/**
 * Parses an account storage save request from the map server.
 *
 * @code{.unparsed}
 *	@packet 0x3011 [in] <packet_len>.W <account_id>.L <struct item[]>.P
 * @endcode
 *
 * @attention If the size of packet 0x3011 changes,
 *            @ref MAX_STORAGE_ASSERT "the related static assertion check"
 *            in mmo.h needs to be adjusted, too.
 *
 * @see intif_send_account_storage()
 *
 * @param[in] fd The file/socket descriptor.
 * @retval 1 Success.
 * @retval 0 Failure.
 *
 **/
static int mapif_parse_AccountStorageSave(int fd)
{
	int payload_size = RFIFOW(fd, 2) - 8, account_id = RFIFOL(fd, 4);
	int i = 0, count = 0;
	struct storage_data p_stor = { 0 };

	Assert_ret(fd > 0);
	Assert_ret(account_id > 0);

	count = payload_size/sizeof(struct item);

	VECTOR_INIT(p_stor.item);

	if (count > 0) {
		VECTOR_ENSURE(p_stor.item, count, 1);

		for (i = 0; i < count; i++) {
			const struct item *it = RFIFOP(fd, 8 + i * sizeof(struct item));

			VECTOR_PUSH(p_stor.item, *it);
		}

		p_stor.aggregate = count;
	}

	inter_storage->tosql(account_id, &p_stor);

	VECTOR_CLEAR(p_stor.item);

	mapif->sAccountStorageSaveAck(fd, account_id, true);

	return 1;
}

/**
 * Sends an acknowledgement for the save
 * status of the account storage.
 * @packet 0x3808     [out] <account_id>.L <save_flag>.B
 * @param  fd         [in]  File/Socket Descriptor.
 * @param  account_id [in]  Account ID of the storage in question.
 * @param  flag       [in]  Save flag, true for success and false for failure.
 */
static void mapif_send_AccountStorageSaveAck(int fd, int account_id, bool flag)
{
	WFIFOHEAD(fd, 7);
	WFIFOW(fd, 0) = 0x3808;
	WFIFOL(fd, 2) = account_id;
	WFIFOB(fd, 6) = flag ? 1 : 0;
	WFIFOSET(fd, 7);
}

static int mapif_parse_LoadGuildStorage(int fd)
{
	RFIFOHEAD(fd);

	mapif->load_guild_storage(fd, RFIFOL(fd, 2), RFIFOL(fd, 6), 1);

	return 0;
}

/**
 * Parses a guild storage save request from the map server.
 *
 * @code{.unparsed}
 *	@packet 0x3019 [in] <packet_len>.W <account_id>.L <guild_id>.L {<struct item>.P}*<capacity>
 * @endcode
 *
 * @attention If the size of packet 0x3019 changes,
 *            @ref MAX_GUILD_STORAGE_ASSERT "the related static assertion check"
 *            in mmo.h needs to be adjusted, too.
 *
 * @see intif_send_guild_storage()
 *
 * @param[in] fd The file/socket descriptor.
 * @return Always 0.
 *
 **/
static int mapif_parse_SaveGuildStorage(int fd)
{
	RFIFOHEAD(fd);
	int len = RFIFOW(fd, 2);
	int account_id = RFIFOL(fd, 4);
	int guild_id = RFIFOL(fd, 8);
	int storage_capacity = RFIFOL(fd, 12);
	int storage_amount = RFIFOL(fd, 16);

	int expected = 20 + sizeof(struct item) * storage_capacity;
	if (expected != len) {
		ShowError("mapif_parse_SaveGuildStorage: data size mismatch: %d != %d\n", len, expected);

		mapif->save_guild_storage_ack(fd, account_id, guild_id, 1);
		return 1;
	}

	struct guild_storage gstor = { 0 };

	if (storage_capacity > 0) {
		gstor.items.data = aCalloc(storage_capacity, sizeof gstor.items.data[0]);
		memcpy(&gstor.items.data, RFIFOP(fd, 20), sizeof gstor.items.data[0] * storage_capacity);
	}
	gstor.items.amount = storage_amount;
	gstor.items.capacity = storage_capacity;
	gstor.guild_id = guild_id;

	if (!inter_storage->guild_storage_tosql(guild_id, &gstor)) {
		if (gstor.items.data != NULL)
			aFree(gstor.items.data);
		mapif->save_guild_storage_ack(fd, account_id, guild_id, 1);
		return 1;
	}

	if (gstor.items.data != NULL)
		aFree(gstor.items.data);
	mapif->save_guild_storage_ack(fd, RFIFOL(fd, 4), guild_id, 0);
	return 0;
}

/*==========================================
 * MAPIF : BOUND ITEMS
 *------------------------------------------*/

static int mapif_itembound_ack(int fd, int aid, int guild_id)
{
#ifdef GP_BOUND_ITEMS
	WFIFOHEAD(fd, 8);
	WFIFOW(fd, 0) = 0x3856;
	WFIFOL(fd, 2) = aid;/* the value is not being used, drop? */
	WFIFOW(fd, 6) = guild_id;
	WFIFOSET(fd, 8);
#endif
	return 0;
}

static void mapif_parse_ItemBoundRetrieve(int fd)
{
#ifdef GP_BOUND_ITEMS
	int char_id = RFIFOL(fd, 2);
	int account_id = RFIFOL(fd, 6);
	int guild_id = RFIFOW(fd, 10);

	inter_storage->retrieve_bound_items(char_id, account_id, guild_id);

	//Finally reload storage and tell map we're done
	mapif->load_guild_storage(fd, account_id, guild_id, 0);

	// If character is logged in char, disconnect
	chr->disconnect_player(account_id);
#endif // GP_BOUND_ITEMS

	/* tell map server the operation is over and it can unlock the storage */
	mapif->itembound_ack(fd, RFIFOL(fd, 6), RFIFOW(fd, 10));
}

/*==========================================
 * MAPIF : General player requests
 *------------------------------------------*/

/**
 * 0x3007 ZW_ACCINFO_REQUEST <requester fd>.L <target aid>.L <requester group lvl>.W <target name>.NAME_LENGTH
 * Parses account information request
 **/
static void mapif_parse_accinfo(struct s_receive_action_data *act)
{
	char query[NAME_LENGTH];
	int u_fd = RFIFOL(act, 2);
	int aid = RFIFOL(act, 6);
	int castergroup = RFIFOL(act, 10);

	safestrncpy(query, RFIFOP(act, 14), NAME_LENGTH);

	inter->accinfo(u_fd, aid, castergroup, query, act->session_id);
}

#if 0
// Account registry transfer to map-server
static void mapif_account_reg(int fd, unsigned char *src)
{
	nullpo_retv(src);
	WBUFW(src, 0) = 0x3804; //NOTE: writing to RFIFO
	mapif->sendallwos(fd, src, WBUFW(src, 2));
}
#endif // 0

// Send the requested account_reg
static int mapif_account_reg_reply(int fd,int account_id,int char_id, int type)
{
	inter->accreg_fromsql(account_id, char_id, fd, type);
	return 0;
}

//Request to kick char from a certain map server. [Skotlex]
static int mapif_disconnectplayer(int fd, int account_id, int char_id, int reason)
{
	if (fd < 0)
		return -1;

	WFIFOHEAD(fd, 7);
	WFIFOW(fd, 0) = 0x2b1f;
	WFIFOL(fd, 2) = account_id;
	WFIFOB(fd, 6) = reason;
	WFIFOSET(fd, 7);
	return 0;
}

// Save account_reg into sql (type=2)
static int mapif_parse_Registry(int fd)
{
	int account_id = RFIFOL(fd, 4), char_id = RFIFOL(fd, 8), count = RFIFOW(fd, 12);

	if (count != 0) {
		int cursor = 14, i;
		char key[SCRIPT_VARNAME_LENGTH + 1];
		char sval[SCRIPT_STRING_VAR_LENGTH + 1];
		bool isLoginActive = sockt->session_is_active(chr->login_fd);

		/**
		 * Prepare packet to request login-server to save, this packet is filled
		 * in every call of inter->savereg, and then set to send in the end of
		 * this function.
		 **/
		if (isLoginActive)
			loginif->save_accreg2_head(account_id, char_id);

		for (i = 0; i < count; i++) {
			unsigned int index;
			int len = RFIFOB(fd, cursor);
			safestrncpy(key, RFIFOP(fd, cursor + 1), min((int)sizeof(key), len));
			cursor += len + 1;

			index = RFIFOL(fd, cursor);
			cursor += 4;

			switch (RFIFOB(fd, cursor++)) {
			/* int */
			case 0:
				inter->savereg(account_id, char_id, key, index, RFIFOL(fd, cursor), false);
				cursor += 4;
				break;
			case 1:
				inter->savereg(account_id, char_id, key, index, 0, false);
				break;
			/* str */
			case 2:
				len = RFIFOB(fd, cursor);
				safestrncpy(sval, RFIFOP(fd, cursor + 1), min((int)sizeof(sval), len + 1));
				cursor += len + 2;
				inter->savereg(account_id, char_id, key, index, (intptr_t)sval, true);
				break;
			case 3:
				inter->savereg(account_id, char_id, key, index, 0, true);
				break;
			default:
				ShowError("mapif->parse_Registry: unknown type %d\n", RFIFOB(fd, cursor - 1));
				return 1;
			}
		}

		if (isLoginActive)
			loginif->save_accreg2_send();
	}
	return 0;
}

// Request the value of all registries.
static int mapif_parse_RegistryRequest(int fd)
{
	//Load Char Registry
	if (RFIFOB(fd, 12))
		mapif->account_reg_reply(fd, RFIFOL(fd, 2), RFIFOL(fd, 6), 3); // 3: char reg
	//Load Account Registry
	if (RFIFOB(fd, 11) != 0)
		mapif->account_reg_reply(fd, RFIFOL(fd, 2), RFIFOL(fd, 6), 2); // 2: account reg
	//Ask Login Server for Account2 values.
	if (RFIFOB(fd, 10) != 0)
		loginif->request_accreg2(RFIFOL(fd, 2), RFIFOL(fd, 6));
	return 1;
}

static void mapif_namechange_ack(int fd, int account_id, int char_id, int type, int flag, const char *const name)
{
	nullpo_retv(name);
	WFIFOHEAD(fd, NAME_LENGTH+13);
	WFIFOW(fd, 0) = 0x3806;
	WFIFOL(fd, 2) = account_id;
	WFIFOL(fd, 6) = char_id;
	WFIFOB(fd, 10) = type;
	WFIFOB(fd, 11) = flag;
	memcpy(WFIFOP(fd, 12), name, NAME_LENGTH);
	WFIFOSET(fd, NAME_LENGTH + 13);
}

static int mapif_parse_NameChangeRequest(int fd)
{
	int account_id, char_id, type;
	const char *name;
	int i;

	account_id = RFIFOL(fd, 2);
	char_id = RFIFOL(fd, 6);
	type = RFIFOB(fd, 10);
	name = RFIFOP(fd, 11);

	// Check Authorized letters/symbols in the name
	if (char_name_option == 1) { // only letters/symbols in char_name_letters are authorized
		for (i = 0; i < NAME_LENGTH && name[i]; i++)
		if (strchr(char_name_letters, name[i]) == NULL) {
			mapif->namechange_ack(fd, account_id, char_id, type, 0, name);
			return 0;
		}
	} else if (char_name_option == 2) { // letters/symbols in char_name_letters are forbidden
		for (i = 0; i < NAME_LENGTH && name[i]; i++)
		if (strchr(char_name_letters, name[i]) != NULL) {
			mapif->namechange_ack(fd, account_id, char_id, type, 0, name);
			return 0;
		}
	}
	//TODO: type holds the type of object to rename.
	//If it were a player, it needs to have the guild information and db information
	//updated here, because changing it on the map won't make it be saved [Skotlex]

	//name allowed.
	mapif->namechange_ack(fd, account_id, char_id, type, 1, name);
	return 0;
}

/*==========================================
 * MAPIF : CLAN
 *------------------------------------------*/

// Clan System
static int mapif_parse_ClanMemberKick(int fd, int clan_id, int kick_interval)
{
	int count = 0;

	if (inter_clan->kick_inactive_members(clan_id, kick_interval) == 1)
		count = inter_clan->count_members(clan_id, kick_interval);

	WFIFOHEAD(fd, 10);
	WFIFOW(fd, 0) = 0x3858;
	WFIFOL(fd, 2) = clan_id;
	WFIFOL(fd, 6) = count;
	WFIFOSET(fd, 10);
	return 0;
}

static int mapif_parse_ClanMemberCount(int fd, int clan_id, int kick_interval)
{
	WFIFOHEAD(fd, 10);
	WFIFOW(fd, 0) = 0x3858;
	WFIFOL(fd, 2) = clan_id;
	WFIFOL(fd, 6) = inter_clan->count_members(clan_id, kick_interval);
	WFIFOSET(fd, 10);
	return 0;
}

/*==========================================
 * MAPIF : ACHIEVEMENT
 *------------------------------------------*/
// Achievement System
/**
 * Parse achievement load request from the map server
 * @param[in] fd  socket descriptor.
 */
static void mapif_parse_load_achievements(int fd)
{
	int char_id = 0;

	/* Read received information from map-server. */
	RFIFOHEAD(fd);
	char_id = RFIFOL(fd, 2);

	/* Load and send achievements to map */
	mapif->achievement_load(fd, char_id);
}

/**
 * Loads achievements and sends to the map server.
 * @param[in] fd       socket descriptor
 * @param[in] char_id  character Id.
 */
static void mapif_achievement_load(int fd, int char_id)
{
	struct char_achievements *cp = NULL;

	/* Ensure data exists */
	cp = idb_ensure(inter_achievement->char_achievements, char_id, inter_achievement->ensure_char_achievements);

	/* Load storage for char-server. */
	inter_achievement->fromsql(char_id, cp);

	/* Send Achievements to map server. */
	mapif->sAchievementsToMap(fd, char_id, cp);
}

/**
 * Sends achievement data of a character to the map server.
 * @packet[out] 0x3810  <packet_id>.W <payload_size>.W <char_id>.L <char_achievements[]>.P
 * @param[in]  fd      socket descriptor.
 * @param[in]  char_id Character ID.
 * @param[in]  cp      Pointer to character's achievement data vector.
 */
static void mapif_send_achievements_to_map(int fd, int char_id, const struct char_achievements *cp)
{
	int i = 0;
	int data_size = 0;

	nullpo_retv(cp);

	data_size = sizeof(struct achievement) * VECTOR_LENGTH(*cp);

STATIC_ASSERT((sizeof(struct achievement) * MAX_ACHIEVEMENT_DB + 8 <= UINT16_MAX),
	"The achievements data can potentially be larger than the maximum packet size. This may cause errors at run-time.");

	/* Send to the map server. */
	WFIFOHEAD(fd, (8 + data_size));
	WFIFOW(fd, 0) = 0x3810;
	WFIFOW(fd, 2) = (8 + data_size);
	WFIFOL(fd, 4) = char_id;
	for (i = 0; i < VECTOR_LENGTH(*cp); i++)
		memcpy(WFIFOP(fd, 8 + i * sizeof(struct achievement)), &VECTOR_INDEX(*cp, i), sizeof(struct achievement));
	WFIFOSET(fd, 8 + data_size);
}

/**
 * Handles achievement request and saves data from map server.
 * @packet[in] 0x3013 <packet_size>.W <char_id>.L <char_achievement>.P
 * @param[in]  fd     session socket descriptor.
 */
static void mapif_parse_save_achievements(int fd)
{
	int size = 0, char_id = 0, payload_count = 0, i = 0;
	struct char_achievements p = { 0 };

	RFIFOHEAD(fd);
	size = RFIFOW(fd, 2);
	char_id = RFIFOL(fd, 4);

	payload_count = (size - 8) / sizeof(struct achievement);

	VECTOR_INIT(p);
	VECTOR_ENSURE(p, payload_count, 1);

	for (i = 0; i < payload_count; i++) {
		struct achievement ach = { 0 };
		memcpy(&ach, RFIFOP(fd, 8 + i * sizeof(struct achievement)), sizeof(struct achievement));
		VECTOR_PUSH(p, ach);
	}

	mapif->achievement_save(char_id, &p);

	VECTOR_CLEAR(p);
}

/**
 * Handles inter-server achievement db ensuring
 * and saves current achievements to sql.
 * @param[in]  char_id      character identifier.
 * @param[out] p            pointer to character achievements vector.
 */
static void mapif_achievement_save(int char_id, struct char_achievements *p)
{
	struct char_achievements *cp = NULL;

	nullpo_retv(p);
	
	/* Get loaded achievements. */
	cp = idb_ensure(inter_achievement->char_achievements, char_id, inter_achievement->ensure_char_achievements);

	if (VECTOR_LENGTH(*p)) /* Save current achievements. */
		inter_achievement->tosql(char_id, cp, p);
}

/**
 * Frees mapif data
 **/
void mapif_final(void)
{
	int i;
	for( i = 0; i < ARRAYLENGTH(chr->server); ++i ) //FIXME
		mapif->server_destroy(i);

	db_clear(mapif->packet_db);
	aFree(mapif->packet_list);
}

/**
 * Initializes mapif data
 **/
void mapif_init(void)
{
	struct {
		int16 packet_id;
		int16 packet_len;
		MapifParseFunc *pFunc;
	} inter_packet[] = {
#define packet_def(name, fname) { HEADER_ ## name, sizeof(struct PACKET_ ## name), chr->parse_frommap_ ## fname }
#define packet_def2(name, fname, len) { HEADER_ ## name, (len), chr->parse_frommap_ ## fname }
	packet_def2(ZW_DATASYNC,             datasync, -1),
	packet_def2(ZW_SKILLID2IDX,          skillid2idx, -1),
	packet_def2(ZW_OWNED_MAP_LIST,       map_names, -1),
	packet_def(ZW_REQUEST_SCDATA,        request_scdata),
	packet_def(ZW_SEND_USERS_COUNT,      set_users_count),
	packet_def2(ZW_USER_LIST,            set_users, -1),
	packet_def2(ZW_SAVE_CHARACTER,       save_character, -1),
	packet_def(ZW_CHAR_SELECT_REQ,       char_select_req),
	packet_def(ZW_CHANGE_SERVER_REQUEST, change_map_server),
	packet_def(ZW_REMOVE_FRIEND,         remove_friend),
	packet_def(ZW_CHARNAME_REQUEST,      char_name_request),
	packet_def(ZW_REQUEST_CHANGE_EMAIL,  change_email),
	packet_def(ZW_UPDATE_ACCOUNT,        change_account),
	packet_def(ZW_FAME_LIST_UPDATE,      fame_list),
	packet_def(ZW_DIVORCE,               divorce_char),
	packet_def(ZW_RATES,                 ragsrvinfo),
	packet_def(ZW_SET_CHARACTER_OFFLINE, set_char_offline),
	packet_def(ZW_SET_ALL_OFFLINE,       set_all_offline),
	packet_def(ZW_SET_CHARACTER_ONLINE,  set_char_online),
	packet_def(ZW_FAME_LIST_BUILD,       build_fame_list),
	packet_def2(ZW_STATUS_CHANGE_SAVE,   save_status_change_data, -1),
	packet_def(ZW_PING,                  ping),
	packet_def(ZW_AUTH,                  auth_request),
	packet_def(ZW_WAN_UPDATE,            update_ip),
	packet_def(ZW_STATUS_CHANGE_UPDATE,  scdata_update),
	packet_def(ZW_STATUS_CHANGE_DELETE,  scdata_delete),
#undef packet_def
#undef packet_def2
	};
	size_t length = ARRAYLENGTH(inter_packet);

	mapif->packet_list = aMalloc(sizeof(*mapif->packet_list)*length);
	mapif->packet_db = idb_alloc(DB_OPT_BASE);

	// Fill packet db
	for(size_t i = 0; i < length; i++) {
		int exists;
		mapif->packet_list[i].len = inter_packet[i].packet_len;
		mapif->packet_list[i].pFunc = inter_packet[i].pFunc;
		exists = idb_put(mapif->packet_db,
			inter_packet[i].packet_id, &mapif->packet_list[i]);
		if(exists) {
			ShowWarning("mapif_init: Packet 0x%x already in database, replacing...\n",
				inter_packet[i].packet_id);
		}
	}
}

void mapif_defaults(void)
{
	mapif = &mapif_s;

	mapif->packet_db = NULL;
	mapif->packet_list = NULL;

	mapif->init = mapif_init;
	mapif->final = mapif_final;

	mapif->server_find = mapif_server_find;
	mapif->server_destroy = mapif_server_destroy;
	mapif->server_reset = mapif_server_reset;
	mapif->on_disconnect = mapif_on_disconnect;
	mapif->on_connect = mapif_on_connect;

	mapif->char_ban = mapif_char_ban;
	mapif->update_state = mapif_update_state;

	mapif->sendall = mapif_sendall;
	mapif->sendallwos = mapif_sendallwos;
	mapif->send = mapif_send;

	mapif->parse_item_data = mapif_parse_item_data;
	mapif->send_users_count = mapif_users_count;
	mapif->pLoadAchievements = mapif_parse_load_achievements;
	mapif->sAchievementsToMap = mapif_send_achievements_to_map;
	mapif->pSaveAchievements = mapif_parse_save_achievements;
	mapif->achievement_load = mapif_achievement_load;
	mapif->achievement_save = mapif_achievement_save;
	mapif->auction_message = mapif_auction_message;
	mapif->auction_sendlist = mapif_auction_sendlist;
	mapif->parse_auction_requestlist = mapif_parse_auction_requestlist;
	mapif->auction_register = mapif_auction_register;
	mapif->parse_auction_register = mapif_parse_auction_register;
	mapif->auction_cancel = mapif_auction_cancel;
	mapif->parse_auction_cancel = mapif_parse_auction_cancel;
	mapif->auction_close = mapif_auction_close;
	mapif->parse_auction_close = mapif_parse_auction_close;
	mapif->auction_bid = mapif_auction_bid;
	mapif->parse_auction_bid = mapif_parse_auction_bid;
	mapif->elemental_send = mapif_elemental_send;
	mapif->parse_elemental_create = mapif_parse_elemental_create;
	mapif->parse_elemental_load = mapif_parse_elemental_load;
	mapif->elemental_deleted = mapif_elemental_deleted;
	mapif->parse_elemental_delete = mapif_parse_elemental_delete;
	mapif->elemental_saved = mapif_elemental_saved;
	mapif->parse_elemental_save = mapif_parse_elemental_save;
	mapif->guild_created = mapif_guild_created;
	mapif->guild_info = mapif_guild_info;
	mapif->guild_memberadded = mapif_guild_memberadded;
	mapif->guild_withdraw = mapif_guild_withdraw;
	mapif->guild_memberinfoshort = mapif_guild_memberinfoshort;
	mapif->guild_broken = mapif_guild_broken;
	mapif->guild_basicinfochanged = mapif_guild_basicinfochanged;
	mapif->guild_memberinfochanged = mapif_guild_memberinfochanged;
	mapif->guild_skillupack = mapif_guild_skillupack;
	mapif->guild_alliance = mapif_guild_alliance;
	mapif->guild_position = mapif_guild_position;
	mapif->guild_notice = mapif_guild_notice;
	mapif->guild_emblem = mapif_guild_emblem;
	mapif->guild_master_changed = mapif_guild_master_changed;
	mapif->guild_castle_dataload = mapif_guild_castle_dataload;
	mapif->parse_CreateGuild = mapif_parse_CreateGuild;
	mapif->parse_GuildInfo = mapif_parse_GuildInfo;
	mapif->parse_GuildAddMember = mapif_parse_GuildAddMember;
	mapif->parse_GuildLeave = mapif_parse_GuildLeave;
	mapif->parse_GuildChangeMemberInfoShort = mapif_parse_GuildChangeMemberInfoShort;
	mapif->parse_BreakGuild = mapif_parse_BreakGuild;
	mapif->parse_GuildBasicInfoChange = mapif_parse_GuildBasicInfoChange;
	mapif->parse_GuildMemberInfoChange = mapif_parse_GuildMemberInfoChange;
	mapif->parse_GuildPosition = mapif_parse_GuildPosition;
	mapif->parse_GuildSkillUp = mapif_parse_GuildSkillUp;
	mapif->parse_GuildAlliance = mapif_parse_GuildAlliance;
	mapif->parse_GuildNotice = mapif_parse_GuildNotice;
	mapif->parse_GuildEmblem = mapif_parse_GuildEmblem;
	mapif->parse_GuildCastleDataLoad = mapif_parse_GuildCastleDataLoad;
	mapif->parse_GuildCastleDataSave = mapif_parse_GuildCastleDataSave;
	mapif->parse_GuildMasterChange = mapif_parse_GuildMasterChange;
	mapif->homunculus_created = mapif_homunculus_created;
	mapif->homunculus_deleted = mapif_homunculus_deleted;
	mapif->homunculus_loaded = mapif_homunculus_loaded;
	mapif->homunculus_saved = mapif_homunculus_saved;
	mapif->homunculus_renamed = mapif_homunculus_renamed;
	mapif->parse_homunculus_create = mapif_parse_homunculus_create;
	mapif->parse_homunculus_delete = mapif_parse_homunculus_delete;
	mapif->parse_homunculus_load = mapif_parse_homunculus_load;
	mapif->parse_homunculus_save = mapif_parse_homunculus_save;
	mapif->parse_homunculus_rename = mapif_parse_homunculus_rename;
	mapif->mail_sendinbox = mapif_mail_sendinbox;
	mapif->parse_mail_requestinbox = mapif_parse_mail_requestinbox;
	mapif->parse_mail_read = mapif_parse_mail_read;
	mapif->mail_sendattach = mapif_mail_sendattach;
	mapif->parse_mail_getattach = mapif_parse_mail_getattach;
	mapif->mail_delete = mapif_mail_delete;
	mapif->parse_mail_delete = mapif_parse_mail_delete;
	mapif->mail_new = mapif_mail_new;
	mapif->mail_return = mapif_mail_return;
	mapif->parse_mail_return = mapif_parse_mail_return;
	mapif->mail_send = mapif_mail_send;
	mapif->parse_mail_send = mapif_parse_mail_send;
	mapif->mercenary_send = mapif_mercenary_send;
	mapif->parse_mercenary_create = mapif_parse_mercenary_create;
	mapif->parse_mercenary_load = mapif_parse_mercenary_load;
	mapif->mercenary_deleted = mapif_mercenary_deleted;
	mapif->parse_mercenary_delete = mapif_parse_mercenary_delete;
	mapif->mercenary_saved = mapif_mercenary_saved;
	mapif->parse_mercenary_save = mapif_parse_mercenary_save;
	mapif->parse_mercenary_data = mapif_parse_mercenary_data;
	mapif->party_created = mapif_party_created;
	mapif->party_noinfo = mapif_party_noinfo;
	mapif->party_info = mapif_party_info;
	mapif->party_memberadded = mapif_party_memberadded;
	mapif->party_optionchanged = mapif_party_optionchanged;
	mapif->party_withdraw = mapif_party_withdraw;
	mapif->party_membermoved = mapif_party_membermoved;
	mapif->party_broken = mapif_party_broken;
	mapif->parse_CreateParty = mapif_parse_CreateParty;
	mapif->parse_PartyInfo = mapif_parse_PartyInfo;
	mapif->parse_PartyAddMember = mapif_parse_PartyAddMember;
	mapif->parse_PartyChangeOption = mapif_parse_PartyChangeOption;
	mapif->parse_PartyLeave = mapif_parse_PartyLeave;
	mapif->parse_PartyChangeMap = mapif_parse_PartyChangeMap;
	mapif->parse_BreakParty = mapif_parse_BreakParty;
	mapif->parse_PartyLeaderChange = mapif_parse_PartyLeaderChange;
	mapif->pet_created = mapif_pet_created;
	mapif->pet_info = mapif_pet_info;
	mapif->pet_noinfo = mapif_pet_noinfo;
	mapif->save_pet_ack = mapif_save_pet_ack;
	mapif->delete_pet_ack = mapif_delete_pet_ack;
	mapif->save_pet = mapif_save_pet;
	mapif->delete_pet = mapif_delete_pet;
	mapif->parse_CreatePet = mapif_parse_CreatePet;
	mapif->parse_LoadPet = mapif_parse_LoadPet;
	mapif->parse_SavePet = mapif_parse_SavePet;
	mapif->parse_DeletePet = mapif_parse_DeletePet;
	mapif->quest_save_ack = mapif_quest_save_ack;
	mapif->parse_quest_save = mapif_parse_quest_save;
	mapif->send_quests = mapif_send_quests;
	mapif->parse_quest_load = mapif_parse_quest_load;
	/* RoDEX */
	mapif->parse_rodex_requestinbox = mapif_parse_rodex_requestinbox;
	mapif->rodex_sendinbox = mapif_rodex_sendinbox;
	mapif->parse_rodex_checkhasnew = mapif_parse_rodex_checkhasnew;
	mapif->rodex_sendhasnew = mapif_rodex_sendhasnew;
	mapif->parse_rodex_updatemail = mapif_parse_rodex_updatemail;
	mapif->parse_rodex_send = mapif_parse_rodex_send;
	mapif->rodex_send = mapif_rodex_send;
	mapif->parse_rodex_checkname = mapif_parse_rodex_checkname;
	mapif->rodex_checkname = mapif_rodex_checkname;
	mapif->rodex_getzenyack = mapif_rodex_getzenyack;
	mapif->rodex_getitemsack = mapif_rodex_getitemsack;
	mapif->load_guild_storage = mapif_load_guild_storage;
	mapif->save_guild_storage_ack = mapif_save_guild_storage_ack;
	mapif->parse_LoadGuildStorage = mapif_parse_LoadGuildStorage;
	mapif->parse_SaveGuildStorage = mapif_parse_SaveGuildStorage;
	mapif->pAccountStorageLoad = mapif_parse_AccountStorageLoad;
	mapif->pAccountStorageSave = mapif_parse_AccountStorageSave;
	mapif->sAccountStorageSaveAck = mapif_send_AccountStorageSaveAck;
	mapif->account_storage_load = mapif_account_storage_load;
	mapif->itembound_ack = mapif_itembound_ack;
	mapif->parse_ItemBoundRetrieve = mapif_parse_ItemBoundRetrieve;
	mapif->parse_accinfo = mapif_parse_accinfo;
	mapif->account_reg_reply = mapif_account_reg_reply;
	mapif->disconnectplayer = mapif_disconnectplayer;
	mapif->parse_Registry = mapif_parse_Registry;
	mapif->parse_RegistryRequest = mapif_parse_RegistryRequest;
	mapif->namechange_ack = mapif_namechange_ack;
	mapif->parse_NameChangeRequest = mapif_parse_NameChangeRequest;
	/* Clan System */
	mapif->parse_ClanMemberKick = mapif_parse_ClanMemberKick;
	mapif->parse_ClanMemberCount = mapif_parse_ClanMemberCount;
}
