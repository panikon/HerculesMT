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

#ifndef COMMON_PACKETS_AW_STRUCT_H
#define COMMON_PACKETS_AW_STRUCT_H

#include "common/hercules.h"
#include "common/mmo.h"
#include "common/packetsstatic_len.h"

/**
 * Account-World packets (login - char server) IDs
 **/
enum inter_packet_aw_id {
	HEADER_AW_CHARSERVERCONNECT_ACK= 0x2711,
	HEADER_AW_AUTH_ACK             = 0x2713,
	HEADER_AW_REQUEST_ACCOUNT_ACK  = 0x2717,
	HEADER_AW_PONG                 = 0x2718,
	HEADER_AW_SEX_BROADCAST        = 0x2723,
	HEADER_AW_UPDATE_STATE         = 0x2731,
	HEADER_AW_KICK                 = 0x2734,
	HEADER_AW_IP_UPDATE            = 0x2735,
	HEADER_AW_ACCOUNT_INFO_SUCCESS = 0x2743,
	HEADER_AW_ACCOUNT_INFO_FAILURE = 0x2744,
	HEADER_AW_ACCOUNT_REG2         = 0x3804,
};

#if !defined(sun) && (!defined(__NETBSD__) || __NetBSD_Version__ >= 600000000) // NetBSD 5 and Solaris don't like pragma pack but accept the packed attribute
#pragma pack(push, 1)
#endif // not NetBSD < 6 / Solaris

/**
 * Result of a connection request (answer of PACKET_CA_CHARSERVERCONNECT)
 *
 * @param status Result
 * @see enum ac_charserverconnect_ack_status
 * @see login_parse_request_connection
 * @see login_char_server_connection_status
 **/
struct PACKET_AW_CHARSERVERCONNECT_ACK {
	int16 packet_id;
	uint8 status;
} __attribute__((packed));

/**
 * Result of a char-server player authentication request (answer of PACKET_WA_AUTH)
 *
 * @param account_id      Account id
 * @param login_id1       id1 provided by the client @see login_session_data::login_id1
 * @param login_id2       id2 provided by the client @see login_session_data::login_id2
 * @param sex             Account sex (@see login_session_data::sex)
 * @param result          Boolean, when false the authentication was successful
 * @param request_id      Identifier of this authentication request
 * @param version         Client version @see login_session_data::version
 * @param clienttype      Client type @see login_session_data::clienttype
 * @param group_id        Group id @see mmo_account::group_id
 * @param expiration_time Account expiration time @see @see mmo_account::expiration_time
 * @see login_fromchar_auth_ack
 * @see login_fromchar_parse_auth
 * @see struct login_session_data
 * @see struct mmo_account
 **/
struct PACKET_AW_AUTH_ACK  {
	int16 packet_id;
	int32 account_id;
	int32 login_id1;
	int32 login_id2;
	uint8 sex;
	uint8 result;
	int32 request_id;
	int32 version;
	uint8 clienttype;
	int32 group_id;
	int32 expiration_time;
} __attribute__((packed));

/**
 * Result of a char-server player account data request (answer of PACKET_WA_REQUEST_ACCOUNT)
 * This is data is loaded from the accountDB
 *
 * @param account_id      Account id
 * @param request_id      Id of this request in char-server
 * @param found           True when this account was found by login-server
 * @param email           E-mail
 * @param expiration_time Account expiration time @see mmo_account::expiration_time
 * @param group_id        Group id @see mmo_account::group_id
 * @param char_slots      Slots allowed for this account @see mmo_account::char_slots
 * @param birthdate       Birthdate @see mmo_account::birthdate
 * @param pincode[5]      Pincode @see mmo_account::expiration_time
 * @param pincode_change  Last time of pincode change @see mmo_account::pincode_change
 * @see struct mmo_account
 * @see login_fromchar_account
 **/
struct PACKET_AW_REQUEST_ACCOUNT_ACK {
	int16 packet_id;
	int32 account_id;
	int32 request_id;
	uint8 found;
	uint8 email[40];
	int32 expiration_time;
	int32 group_id;
	uint8 char_slots;
	uint8 birthdate[10+1];
	uint8 pincode[5];
	int32 pincode_change;
} __attribute__((packed));

/**
 * @copydoc login_fromchar_pong
 **/
struct PACKET_AW_PONG {
	int16 packet_id;
} __attribute__((packed));

/**
 * @copydoc login_fromchar_change_sex_other
 **/
struct PACKET_AW_SEX_BROADCAST {
	int16 packet_id;
	int32 account_id;
	uint8 sex;
} __attribute__((packed));

/**
 * @copydoc login_fromchar_account_update_state
 **/
struct PACKET_AW_UPDATE_STATE {
	int16 packet_id;
	int32 account_id;
	uint8 flag;
	int32 state;
} __attribute__((packed));

/**
 * @copydoc login_kick
 **/
struct PACKET_AW_KICK {
	int16 packet_id;
	int32 account_id;
} __attribute__((packed));

/**
 * @copydoc login_sync_ip_addresses
 **/
struct PACKET_AW_IP_UPDATE {
	int16 packet_id;
} __attribute__((packed));

/**
 * @copydoc login_fromchar_accinfo
 **/
struct PACKET_AW_ACCOUNT_INFO_SUCCESS {
	int16 packet_id;
	int32 map_id;
	int32 u_fd;
	int32 u_aid;
	int32 account_id;
	struct {
		char userid[NAME_LENGTH];
		char email[40];
		char last_ip[16];
		int32 group_id;
		char last_login[24];
		uint32 login_count;
		uint32 state;
		char birthdate[11];
	} data;
} __attribute__((packed));

/**
 * @copydoc login_fromchar_accinfo
 **/
struct PACKET_AW_ACCOUNT_INFO_FAILURE {
	int16 packet_id;
	int32 map_id;
	int32 u_fd;
	int32 u_aid;
	int32 account_id;
} __attribute__((packed));

/**
 * Reg2 account data
 *
 * @param char_id      Character id
 * @param is_complete  Boolean, have all variables been sent
 * @param var_type     Vessel value type 1 string / 2 int
 * @param count        Number of vessels in this packet
 * @param vessel       Key-value pair
 * @see account_mmo_send_accreg2
 **/
struct PACKET_AW_ACCOUNT_REG2 {
	int16 packet_id;
	int16 packet_len;
	int32 account_id;
	int32 char_id;
	uint8 is_complete;
	uint8 var_type;
	int16 count;
	/**
	 * Vessel with key-value pair information
	 *
	 * @param key_length Length of key
	 * @param key        Key
	 * @param index      Index in database
	 * @param value      Value
	 **/
	struct {
		uint8 key_length;
		uint8 *key; //key[key_length]
		int32 index;
		union {
			struct {
				uint8 val_length;
				uint8 *val; //val[val_length];
			} string;
			struct {
				int32 val;
			} integer;
		} *value;
	} *vessel;
} __attribute__((packed));


#if !defined(sun) && (!defined(__NETBSD__) || __NetBSD_Version__ >= 600000000) // NetBSD 5 and Solaris don't like pragma pack but accept the packed attribute
#pragma pack(pop)
#endif // not NetBSD < 6 / Solaris

#endif // COMMON_PACKETS_AW_STRUCT_H

