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

#ifndef CHAR_PACKETS_CH_STRUCT_H
#define CHAR_PACKETS_CH_STRUCT_H

#include "common/hercules.h"
#include "common/mmo.h"
#include "common/packetsstatic_len.h"

/**
 * Client-Char-server packet IDs
 **/
enum ch_packet_id {
	HEADER_CH_ENTER = 0x065, // chclif_parse_enter
	HEADER_CH_SELECT_CHAR = 0x066, // chclif_parse_select_char
#if PACKETVER >= 20151001
	HEADER_CH_MAKE_CHAR = 0xa39, // chclif_parse_make_char
#elif PACKETVER >= 20120307
	HEADER_CH_MAKE_CHAR = 0x970, // chclif_parse_make_char
#else
	HEADER_CH_MAKE_CHAR = 0x67,	// chclif_parse_make_char
#endif
	HEADER_CH_DELETE_CHAR2 = 0x1fb, // chclif_parse_delete_char
	HEADER_CH_DELETE_CHAR  = 0x68,  // chclif_parse_delete_char
	HEADER_CH_PING = 0x187, // chclif_parse_ping

	HEADER_CH_REQ_IS_VALID_CHARNAME  = 0x8fc, // chclif_parse_rename
	HEADER_CH_REQ_IS_VALID_CHARNAME2 = 0x28d, // chclif_parse_rename
	HEADER_CH_REQ_CHANGE_CHARNAME    = 0x28f, // chclif_parse_rename_confirm

	// 2009-09-22aRagexeRE Captcha (TODO) chclif_parse_captcha_default
	HEADER_CH_ENTER_CHECKBOT = 0x7e5, // R 07e5 <?>.w <aid>.l
	HEADER_CH_CHECKBOT  = 0x7e7,      // R 07e7 <len>.w <aid>.l <code>.b10 <?>.b14

	// New deletion system
	HEADER_CH_DELETE_CHAR3_RESERVED = 0x827, // chclif_parse_delete2_req
	HEADER_CH_DELETE_CHAR3          = 0x829, // chclif_parse_delete2_accept
	HEADER_CH_DELETE_CHAR3_CANCEL   = 0x82b, // chclif_parse_delete2_cancel

	// Pincode
	HEADER_CH_SECOND_PASSWD_ACK        = 0x8b8, //pincode_check
	HEADER_CH_AVAILABLE_SECOND_PASSWD  = 0x8c5, //pincode_window
	HEADER_CH_EDIT_SECOND_PASSWD       = 0x8be, //pincode_change
	HEADER_CH_MAKE_SECOND_PASSWD       = 0x8ba, //pincode_setnew

	HEADER_CH_CHARLIST_REQ              = 0x9a1, // chclif_parse_request_chars
	HEADER_CH_REQ_CHANGE_CHARACTER_SLOT = 0x8d4, // chclif_parse_move_character
};

#if !defined(sun) && (!defined(__NETBSD__) || __NetBSD_Version__ >= 600000000) // NetBSD 5 and Solaris don't like pragma pack but accept the packed attribute
#pragma pack(push, 1)
#endif // not NetBSD < 6 / Solaris

/**
 * Client authentication request
 * @param account_id   Account id
 * @param login_id1    Authentication code
 * @param login_id2    User level
 * @param client_type  Client type
 * @param sex          Sex
 **/
struct PACKET_CH_ENTER {
	int16 packet_id;
	int32 account_id;
	int32 login_id1;
	int32 login_id2;
	int16 client_type;
	uint8_t sex;
} __attribute__((packed));

/**
 * Client character selection (to enter map-server)
 **/
struct PACKET_CH_SELECT_CHAR {
	int16 packet_id;
	uint8 char_slot;
} __attribute__((packed));

/**
 * Character creation request
 **/
struct PACKET_CH_MAKE_CHAR {
	int16 packet_id;
	uint8 name[24];
#if PACKETVER < 20120307 //CH_MAKE_CHAR_NO_STATS
	uint8 str;
	uint8 agi;
	uint8 vit;
	uint8 int_;
	uint8 dex;
	uint8 luk;
#endif
	uint8 slot;
	int16 hair_color;
	int16 hair_style;
#if PACKETVER >= 20151001 // CH_MAKE_CHAR_
	int16 job_id;
	int16 unknown; // <Unknown>.(W or 2 B's)???
	uint8 sex;
#endif
} __attribute__((packed));

/**
 * Character deletion request
 **/
struct PACKET_CH_DELETE_CHAR {
	int16 packet_id;
	int32 char_id;
	char key[40];
} __attribute__((packed));

/**
 * Character deletion request
 * 2004-04-19aSakexe+ langtype 12 char deletion packet
 **/
struct PACKET_CH_DELETE_CHAR2 {
	int16 packet_id;
	int32 char_id;
	char key[50];
} __attribute__((packed));

/**
 * Keep-alive packet (every 12 seconds)
 **/
struct PACKET_CH_PING {
	int16 packet_id;
	int32 account_id;
} __attribute__((packed));

/**
 * Rename request
 **/
struct PACKET_CH_REQ_IS_VALID_CHARNAME {
	int16 packet_id;
	int32 char_id;
	uint8 name[24];
} __attribute__((packed));

/**
 * Rename request
 **/
struct PACKET_CH_REQ_IS_VALID_CHARNAME2 {
	int16 packet_id;
	int32 account_id;
	int32 char_id;
	uint8 name[24];
} __attribute__((packed));

/**
 * Player confirms that desires the new name
 **/
struct PACKET_CH_REQ_CHANGE_CHARNAME {
	int16 packet_id;
	int32 char_id;
} __attribute__((packed));

/**
 * Request for a captcha
 **/
struct PACKET_CH_ENTER_CHECKBOT {
	int16 packet_id;
	int16 unknown;
	int32 account_id;
} __attribute__((packed));

/**
 * Captcha answer
 **/
struct PACKET_CH_CHECKBOT {
	int16 packet_id;
	int16 packet_len;
	int32 account_id;
	uint8 code[10];
	uint8 unknown[14];
} __attribute__((packed));

/**
 * Request to delete character (reserve to delete)
 **/
struct PACKET_CH_DELETE_CHAR3_RESERVED {
	int16 packet_id;
	int32 char_id;
} __attribute__((packed));

/**
 * Player confirms deletion
 **/
struct PACKET_CH_DELETE_CHAR3 {
	int16 packet_id;
	int32 char_id;
	uint8 birthdate[6];
} __attribute__((packed));

/**
 * Cancel character deletion
 **/
struct PACKET_CH_DELETE_CHAR3_CANCEL {
	int16 packet_id;
	int32 char_id;
} __attribute__((packed));


/**
 * Answered PIN
 **/
struct PACKET_CH_SECOND_PASSWD_ACK {
	int16 packet_id;
	int32 account_id;
	uint8 pincode[4];
} __attribute__((packed));

/**
 * Request for PIN window
 **/
struct PACKET_CH_AVAILABLE_SECOND_PASSWD {
	int16 packet_id;
	int32 account_id;
} __attribute__((packed));

/**
 * Pincode change request
 **/
struct PACKET_CH_EDIT_SECOND_PASSWD {
	int16 packet_id;
	int32 account_id;
	int32 seed;
	uint8 pincode[4];
} __attribute__((packed));

/**
 * Activate PIN system and set first PIN
 **/
struct PACKET_CH_MAKE_SECOND_PASSWD {
	int16 packet_id;
	int32 account_id;
	uint8 pincode[4];
} __attribute__((packed));

/**
 * Request for character list
 * packet 
 **/
struct PACKET_CH_CHARLIST_REQ {
	int16 packet_id;
} __attribute__((packed));

/**
 * Slot change request
 **/
struct PACKET_CH_REQ_CHANGE_CHARACTER_SLOT {
	int16 packet_id;
	int16 from;
	int16 to;
	int16 not_used;
} __attribute__((packed));


#if !defined(sun) && (!defined(__NETBSD__) || __NetBSD_Version__ >= 600000000) // NetBSD 5 and Solaris don't like pragma pack but accept the packed attribute
#pragma pack(pop)
#endif // not NetBSD < 6 / Solaris

#endif /* CHAR_PACKETS_CH_STRUCT_H */

