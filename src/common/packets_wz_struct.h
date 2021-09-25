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

#ifndef COMMON_PACKETS_WZ_STRUCT_H
#define COMMON_PACKETS_WZ_STRUCT_H

#include "common/hercules.h"
#include "common/mmo.h"
#include "common/packetsstatic_len.h"


#if !defined(sun) && (!defined(__NETBSD__) || __NetBSD_Version__ >= 600000000) // NetBSD 5 and Solaris don't like pragma pack but accept the packed attribute
#pragma pack(push, 1)
#endif // not NetBSD < 6 / Solaris

/**
 * User count
 * @see mapif_users_count
 **/
struct PACKET_WZ_USER_COUNT {
	int16 packet_len;
	int32 user_count;
} __attribute__((packed));
DEFINE_PACKET_ID(WZ_USER_COUNT, 0x2b00);

/**
 * Sex-change notification
 * @see mapif_change_sex
 **/
struct PACKET_WZ_CHANGE_SEX {
	int16 packet_len;
	int32 account_id;
	uint8 sex;
} __attribute__((packed));
DEFINE_PACKET_ID(WZ_CHANGE_SEX, 0x2b0d);

/**
 * Fame list
 * @see mapif_fame_list
 **/
struct fame_list_packet_data {
	int32 id;
	int32 fame;
	uint8 name[24];
} __attribute__((packed));
struct PACKET_WZ_FAME_LIST {
	int16 packet_id;
	int16 packet_len;
	int16 smith_block_size;    // 8 + size
	int16 chemist_block_size;  // smith_block_size + size
	struct fame_list_packet_data *smith;
	struct fame_list_packet_data *chemist;
	struct fame_list_packet_data *taekwon;
} __attribute__((packed));
DEFINE_PACKET_ID(WZ_FAME_LIST, 0x2b1b);

/**
 * Updates the index of a fame list
 * @param type  enum fame_list_type
 * @param index Player position
 * @param fame  Fame count
 **/
struct PACKET_WZ_FAME_LIST_UPDATE {
	int16 packet_id;
	uint8 type;
	uint8 index;
	int32 fame;
} __attribute__((packed));
DEFINE_PACKET_ID(WZ_FAME_LIST_UPDATE, 0x2b22);

/**
 * Notifies map-server if the maps were received
 * @param flag 0 Not successful
 * @param flag 1 Successful
 **/
struct PACKET_WZ_SEND_MAP_ACK {
	int16 packet_id;
	uint8 flag;
	uint8 wisp_server_name[24];
} __attribute__((packed));
DEFINE_PACKET_ID(WZ_SEND_MAP_ACK, 0x2afb);

/**
 * Map list of a given map-server (relayed)
 **/
struct PACKET_WZ_SEND_MAP {
	int16 packet_id;
	int16 packet_len;
	int32 ip;
	int16 port;
	int16 map_id[];
} __attribute__((packed));
DEFINE_PACKET_ID(WZ_SEND_MAP, 0x2b04);

/**
 * Status change data
 **/
struct status_change_packet_data { // @see struct status_change_data
	uint16 type;
	int32 val1, val2, val3, val4;
	int32 tick;
	int32 total_tick;
} __attribute__((packed));
struct PACKET_WZ_STATUS_CHANGE {
	int16 packet_id;
	int16 packet_len;
	int32 account_id;
	int32 character_id;
	int16 count;
	struct status_change_packet_data *data;
} __attribute__((packed));
DEFINE_PACKET_ID(WZ_STATUS_CHANGE, 0x2b1d);

/**
 * Notifies map-server that a character was saved
 * Only needed on final save.
 **/
struct PACKET_WZ_SAVE_CHARACTER_ACK {
	int16 packet_id;
	int32 account_id;
	int32 character_id;
} __attribute__((packed));
DEFINE_PACKET_ID(WZ_SAVE_CHARACTER_ACK, 0x2b21);

/**
 * Notifies map-server of a request to receive a character to selection screen
 * @param flag 0 Not ok
 * @param flag 1 ok
 **/
struct PACKET_WZ_CHAR_SELECT_ACK {
	int16 packet_id;
	int32 account_id;
	uint8 flag;
} __attribute__((packed));
DEFINE_PACKET_ID(WZ_CHAR_SELECT_ACK, 0x2b03);

/**
 * Reply to change map server request, whether it was successful or not
 * @copydoc struct PACKET_ZW_CHANGE_SERVER_REQUEST
 * @param login_id1 Is set to 0 on failure.
 **/
struct PACKET_WZ_CHANGE_SERVER_REQUEST_ACK {
	int16 packet_id;
	int32 account_id;
	int32 login_id1;
	int32 login_id2;
	int32 char_id;
	struct {
		int16 mapindex;
		int16 x;
		int16 y;
	} spawn_point;
	struct {
		int32 ipl;
		int16 port;
	} map;
} __attribute__((packed));
DEFINE_PACKET_ID(WZ_CHANGE_SERVER_REQUEST_ACK, 0x2b06);

/**
 * Answer to a char name request
 * When the name is not found name is \0
 **/
struct PACKET_WZ_CHARNAME_REQUEST_ACK {
	int16 packet_id;
	int32 character_id;
	uint8 name[24];
} __attribute__((packed));
DEFINE_PACKET_ID(WZ_CHARNAME_REQUEST_ACK, 0x2b09);

/**
 * Answer of an update account request
 * This is only sent when the original request was made by a player
 * and not only by map-server.
 * @param type enum zh_char_ask_name_type
 * @param result 0-login-server request done, 1-player not found, 2-gm level too low, 3-login-server offline
 **/
struct PACKET_ZW_UPDATE_ACCOUNT_ACK {
	int16 packet_id;
	int32 account_id;
	uint8 name[24];
	int16 type;
	int32 result;
} __attribute__((packed));
DEFINE_PACKET_ID(ZW_UPDATE_ACCOUNT_ACK, 0x2b0f);

/**
 * WZ_PONG
 **/
struct PACKET_ZW_PONG {
	int16 packet_id;
} __attribute__((packed));
DEFINE_PACKET_ID(ZW_PONG, 0x2b24);


/**
 * Answer to WZ_AUTH
 * @see struct mmo_charstatus
 **/
struct mmo_charstatus_packet {
	int char_id;
	int account_id;
	int partner_id;
	int father;
	int mother;
	int child;

	uint64 base_exp, job_exp;
	int zeny;
	int bank_vault;

	int class;
	int status_point, skill_point;
	int hp,max_hp,sp,max_sp;
	unsigned int option;
	short manner;
	unsigned char karma;
	short hair, hair_color, clothes_color;
	int body;
	int party_id,guild_id,clan_id,pet_id,hom_id,mer_id,ele_id;
	int fame;

	int arch_faith, arch_calls;
	int spear_faith, spear_calls;
	int sword_faith, sword_calls;

	struct {
		int weapon;      ///< Weapon view sprite id.
		int shield;      ///< Shield view sprite id.
		int head_top;    ///< Top headgear view sprite id.
		int head_mid;    ///< Middle headgear view sprite id.
		int head_bottom; ///< Bottom headgear view sprite id.
		int robe;        ///< Robe view sprite id.
	} look;

	char name[NAME_LENGTH];
	int base_level, job_level;
	short str,agi,vit,int_,dex,luk;
	unsigned char slot,sex;

	uint32 mapip;
	uint16 mapport;

	int64 last_login;
	struct point last_point,save_point,memo_point[MAX_MEMOPOINTS];
	int inventorySize;
	struct item inventory[MAX_INVENTORY],cart[MAX_CART];
	struct s_skill skill[MAX_SKILL_DB];

	struct s_friend friends[MAX_FRIENDS];
#ifdef HOTKEY_SAVING
	struct hotkey hotkeys[MAX_HOTKEYS_DB];
#endif
	bool show_equip;
	bool allow_party;
	bool allow_call;

	unsigned short rename;
	unsigned short slotchange;

	time_t delete_date;

	unsigned short mod_exp,mod_drop,mod_death;

	unsigned char font;

	uint32 uniqueitem_counter;

	int64 attendance_timer;
	short attendance_count;

	unsigned char hotkey_rowshift;
	unsigned char hotkey_rowshift2;

	int32 title_id;
} __attribute__((packed));
struct PACKET_ZW_AUTH_OK {
	int16 packet_id;
	int16 packet_len;
	int32 account_id;
	int32 login_id1;
	int32 login_id2;
	uint32 expiration_time;
	int32 group_id;
	uint8 changing_mapservers;
	struct mmo_charstatus_packet data;
} __attribute__((packed));
DEFINE_PACKET_ID(ZW_AUTH_OK, 0x2afd);

/**
 * Answer of WZ_AUTH
 **/
struct PACKET_ZW_AUTH_FAILED {
	int16 packet_id;
	int32 account_id;
	int32 character_id;
	int32 login_id1;
	uint8 sex;
	int32 ipl;
} __attribute__((packed));
DEFINE_PACKET_ID(ZW_AUTH_FAILED,0x2b27);

/**
 * Answer of WZ_MAP_AUTH
 **/
struct PACKET_WZ_MAP_AUTH_ACK {
	int16 packet_id;
	uint8 flag;
} __attribute__((packed));
DEFINE_PACKET_ID(WZ_MAP_AUTH_ACK,0x2af9);

#if !defined(sun) && (!defined(__NETBSD__) || __NetBSD_Version__ >= 600000000) // NetBSD 5 and Solaris don't like pragma pack but accept the packed attribute
#pragma pack(pop)
#endif // not NetBSD < 6 / Solaris

#endif /* COMMON_PACKETS_WZ_STRUCT_H */
