/**
 * This file is part of Hercules.
 * http://herc.ws - http://github.com/HerculesWS/Hercules
 *
 * Copyright (C) 2021 Hercules Dev Team
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

#ifndef COMMON_PACKETS_WA_STRUCT_H
#define COMMON_PACKETS_WA_STRUCT_H

#include "common/hercules.h"
#include "common/mmo.h"
#include "common/packetsstatic_len.h"

/**
 * World-Account packets (char - login server) IDs
 **/
enum inter_packet_wa_id {
	HEADER_CA_CHARSERVERCONNECT            = 0x2710,
	HEADER_WA_AUTH                         = 0x2712, // login->fromchar_parse_auth
	HEADER_WA_SEND_USERS_COUNT             = 0x2714, // login->fromchar_parse_update_users
	HEADER_WA_REQUEST_CHANGE_DEFAULT_EMAIL = 0x2715, // login->fromchar_parse_request_change_email
	HEADER_WA_REQUEST_ACCOUNT              = 0x2716, // login->fromchar_parse_account_data
	HEADER_WA_PING                         = 0x2719, // login->fromchar_parse_ping
	HEADER_WA_REQUEST_CHANGE_EMAIL         = 0x2722, // login->fromchar_parse_change_email
	HEADER_WA_UPDATE_STATE                 = 0x2724, // login->fromchar_parse_account_update
	HEADER_WA_BAN                          = 0x2725, // login->fromchar_parse_ban
	HEADER_WA_SEX_CHANGE                   = 0x2727, // login->fromchar_parse_change_sex
	HEADER_WA_ACCOUNT_REG2                 = 0x2728, // login->fromchar_parse_account_reg2
	HEADER_WA_UNBAN                        = 0x272a, // login->fromchar_parse_unban
	HEADER_WA_ACCOUNT_ONLINE               = 0x272b, // login->fromchar_parse_account_online
	HEADER_WA_ACCOUNT_OFFLINE              = 0x272c, // login->fromchar_parse_account_offline
	HEADER_WA_ACCOUNT_LIST                 = 0x272d, // login->fromchar_parse_online_accounts
	HEADER_WA_ACCOUNT_REG2_REQ             = 0x272e, // login->fromchar_parse_request_account_reg2
	HEADER_WA_WAN_UPDATE                   = 0x2736, // login->fromchar_parse_update_wan_ip
	HEADER_WA_SET_ALL_OFFLINE              = 0x2737, // login->fromchar_parse_all_offline
	HEADER_WA_PINCODE_UPDATE               = 0x2738, // login->fromchar_parse_change_pincode
	HEADER_WA_PINCODE_FAILED               = 0x2739, // login->fromchar_parse_wrong_pincode
	HEADER_WA_ACCOUNT_INFO_REQUEST         = 0x2740, // login->fromchar_parse_accinfo
};

#if !defined(sun) && (!defined(__NETBSD__) || __NetBSD_Version__ >= 600000000) // NetBSD 5 and Solaris don't like pragma pack but accept the packed attribute
#pragma pack(push, 1)
#endif // not NetBSD < 6 / Solaris

/**
 * Packet structure for CA_CHARSERVERCONNECT.
 *
 * This packet is used internally, to signal a char-server connection.
 * @remarks
 * This packet is identified with CA because it's included in the same packet db
 * as client-server packets.
 */
struct PACKET_CA_CHARSERVERCONNECT {
	int16 packet_id;   ///< Packet ID (#HEADER_CA_CHARSERVERCONNECT)
	char userid[24];   ///< Username
	char password[24]; ///< Password
	int32 unknown;
	int32 ip;          ///< Charserver IP
	int16 port;        ///< Charserver port
	char name[20];     ///< Charserver name
	int16 unknown2;
	int16 type;        ///< Charserver type
	int16 new;         ///< Whether charserver is to be marked as new
} __attribute__((packed));

/**
 * Char-server account authentication request
 *
 * @param account_id      Account id
 * @param login_id1       id1 provided by the client @see login_session_data::login_id1
 * @param login_id2       id2 provided by the client @see login_session_data::login_id2
 * @param sex             Account sex (@see login_session_data::sex)
 * @param ipl             Client ip
 * @param request_id      Identifier of this authentication request
 * @see login_fromchar_parse_auth
 * @see struct login_auth_node
 **/
struct PACKET_WA_AUTH {
	int16 packet_id;
	int32 account_id;
	uint32 login_id1;
	uint32 login_id2;
	uint8 sex;
	uint32 ipl;
	int32 request_id;
} __attribute__((packed));

/**
 * @copydoc login_fromchar_parse_update_users
 **/
struct PACKET_WA_SEND_USERS_COUNT {
	int16 packet_id;
	int32 users;
} __attribute__((packed));

/**
 * @copydoc login_fromchar_parse_request_change_email
 **/
struct PACKET_WA_REQUEST_CHANGE_DEFAULT_EMAIL {
	int16 packet_id;
	int32 account_id;
	uint8 email[40];
} __attribute__((packed));

/**
 * @copydoc login_fromchar_parse_account_data
 * @param request_id Identifier in char-server
 **/
struct PACKET_WA_REQUEST_ACCOUNT {
	int16 packet_id;
	int32 account_id;
	int32 request_id;
} __attribute__((packed));

/**
 * @copydoc login_fromchar_parse_ping
 **/
struct PACKET_WA_PING {
	int16 packet_id;
} __attribute__((packed));

/**
 * @copydoc login_fromchar_parse_change_email
 **/
struct PACKET_WA_REQUEST_CHANGE_EMAIL {
	int16 packet_id;
	int32 account_id;
	char actual_email[40];
	char new_email[40];
} __attribute__((packed));

/**
 * Update state request.
 *
 * @param state New account state @see mmo_account::state
 * @see login_fromchar_parse_account_update
 * @see struct mmo_account
 **/
struct PACKET_WA_UPDATE_STATE {
	int16 packet_id;
	int32 account_id;
	int32 state;
} __attribute__((packed));

/**
 * @copydoc login_fromchar_parse_ban
 **/
struct PACKET_WA_BAN {
	int16 packet_id;
	int32 account_id;
	int16 year;
	int16 month;
	int16 day;
	int16 hour;
	int16 minute;
	int16 second;
} __attribute__((packed));

/**
 * @copydoc login_fromchar_parse_change_sex
 **/
struct PACKET_WA_SEX_CHANGE {
	int16 packet_id;
	int32 account_id;
} __attribute__((packed));

/**
 * Account re2 new information.
 *
 * @param account_id Account id
 * @param char_id    Character id
 * @param count      Number of entries to be altered
 * @param entry      Entry data
 * @see login_fromchar_parse_account_reg2
 * @see account->mmo_save_accreg2
 * @see intif_saveregistry
 * @see mapif_parse_Registry
 **/
struct PACKET_WA_ACCOUNT_REG2 {
	int16 packet_id;
	int16 len;
	int32 account_id;
	int32 char_id;
	int16 count;
	/**
	 * Entry data
	 *
	 * @param key_len Length of key (maximum value SCRIPT_VARNAME_LENGTH + 1)
	 * @param key     Key to be altered
	 * @param index   Index in db
	 * @param flag    Operation flag (0: Replace int, 1: Delete int, 2: Replace string, 3: Delete string)
	 * @param val     Entry value, in deletion operations this is not sent
	 **/
	struct {
		int16 key_len;
		uint8 *key; // key[key_len]
		int32 index;
		/**
		 * Operation flag
		 * 0 Replace int
		 * 1 Delete int
		 * 2 Replace string
		 * 3 Delete string
		 **/
		uint8 flag;
		union {
			int32 integer;
			uint8 *string;
			void *empty;
		} val;
	} *entry;
} __attribute__((packed));

/**
 * @copydoc login_fromchar_parse_unban
 **/
struct PACKET_WA_UNBAN {
	int16 packet_id;
	int32 account_id;
} __attribute__((packed));

/**
 * @copydoc login_fromchar_parse_account_online
 **/
struct PACKET_WA_ACCOUNT_ONLINE {
	int16 packet_id;
	int32 account_id;
} __attribute__((packed));

/**
 * @copydoc login_fromchar_parse_account_offline
 **/
struct PACKET_WA_ACCOUNT_OFFLINE {
	int16 packet_id;
	int32 account_id;
} __attribute__((packed));

/**
 * @copydoc login_fromchar_parse_online_accounts
 **/
struct PACKET_WA_ACCOUNT_LIST {
	int16 packet_id;
	int16 len;
	int16 user_count;
	int32 user_aid[];
} __attribute__((packed));

/**
 * @copydoc login_fromchar_parse_request_account_reg2
 **/
struct PACKET_WA_ACCOUNT_REG2_REQ {
	int16 packet_id;
	int32 account_id;
	int32 char_id;
} __attribute__((packed));

/**
 * @copydoc login_fromchar_parse_update_wan_ip
 **/
struct PACKET_WA_WAN_UPDATE {
	int16 packet_id;
	uint32 ip;
} __attribute__((packed));

/**
 * @copydoc login_fromchar_parse_all_offline
 **/
struct PACKET_WA_SET_ALL_OFFLINE {
	int16 packet_id;
} __attribute__((packed));

/**
 * @copydoc login_fromchar_parse_change_pincode
 **/
struct PACKET_WA_PINCODE_UPDATE {
	int16 packet_id;
	int32 account_id;
	uint8 pincode[5];
} __attribute__((packed));

/**
 * @copydoc login_fromchar_parse_wrong_pincode
 **/
struct PACKET_WA_PINCODE_FAILED {
	int16 packet_id;
	int32 account_id;
} __attribute__((packed));

/**
 * @copydoc login_fromchar_parse_accinfo
 **/
struct PACKET_WA_ACCOUNT_INFO_REQUEST {
	int16 packet_id;
	int32 account_id; //< Target for the request
	// Caster data
	int32 u_id; //< Caster session id in map-server
	int32 u_aid;
	int32 u_group;
	int32 map_id; //< Map-server session id in char-server
} __attribute__((packed));

#if !defined(sun) && (!defined(__NETBSD__) || __NetBSD_Version__ >= 600000000) // NetBSD 5 and Solaris don't like pragma pack but accept the packed attribute
#pragma pack(pop)
#endif // not NetBSD < 6 / Solaris

#endif // COMMON_PACKETS_WA_STRUCT_H
