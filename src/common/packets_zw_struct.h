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

#ifndef COMMON_PACKETS_ZW_STRUCT_H
#define COMMON_PACKETS_ZW_STRUCT_H

#include "common/hercules.h"
#include "common/mmo.h"
#include "common/packetsstatic_len.h"

/**
 * Zone-world packets (map - char server) IDs
 **/
enum inter_packet_zw_id {
	// char_parse_frommap
	HEADER_ZW_DATASYNC                      = 0x2b0a, // chr->parse_frommap_datasync(act);
	HEADER_ZW_SKILLID2IDX                   = 0x2b0b, // chr->parse_frommap_skillid2idx(act);
	HEADER_ZW_OWNED_MAP_LIST                = 0x2afa, // chr->parse_frommap_map_names(act, server);
	HEADER_ZW_REQUEST_SCDATA                = 0x2afc, // chr->parse_frommap_request_scdata(act);
	HEADER_ZW_SEND_USERS_COUNT              = 0x2afe, // chr->parse_frommap_set_users_count(act, server);
	HEADER_ZW_USER_LIST                     = 0x2aff, // chr->parse_frommap_set_users(act, server);
	HEADER_ZW_SAVE_CHARACTER                = 0x2b01, // chr->parse_frommap_save_character(act, server);
	HEADER_ZW_CHAR_SELECT_REQ               = 0x2b02, // chr->parse_frommap_char_select_req(act);
	HEADER_ZW_CHANGE_SERVER_REQUEST         = 0x2b05, // chr->parse_frommap_change_map_server(fd);
	HEADER_ZW_REMOVE_FRIEND                 = 0x2b07, // chr->parse_frommap_remove_friend(fd);
	HEADER_ZW_CHARNAME_REQUEST              = 0x2b08, // chr->parse_frommap_char_name_request(act);
	HEADER_ZW_REQUEST_CHANGE_EMAIL          = 0x2b0c, // chr->parse_frommap_change_email(act);
	HEADER_ZW_UPDATE_ACCOUNT                = 0x2b0e, // chr->parse_frommap_change_account(fd);
	HEADER_ZW_FAME_LIST_UPDATE              = 0x2b10, // chr->parse_frommap_fame_list(act);
	HEADER_ZW_DIVORCE                       = 0x2b11, // chr->parse_frommap_divorce_char(act);
	HEADER_ZW_RATES                         = 0x2b16, // chr->parse_frommap_ragsrvinfo(act);
	HEADER_ZW_SET_CHARACTER_OFFLINE         = 0x2b17, // chr->parse_frommap_set_char_offline(act);
	HEADER_ZW_SET_ALL_OFFLINE               = 0x2b18, // chr->parse_frommap_set_all_offline(act, server);
	HEADER_ZW_SET_CHARACTER_ONLINE          = 0x2b19, // chr->parse_frommap_set_char_online(act, server);
	HEADER_ZW_FAME_LIST_BUILD               = 0x2b1a, // chr->parse_frommap_build_fame_list(act);
	HEADER_ZW_STATUS_CHANGE_SAVE            = 0x2b1c, // chr->parse_frommap_save_status_change_data(act);
	HEADER_ZW_PING                          = 0x2b23, // chr->parse_frommap_ping(act);
	HEADER_ZW_AUTH                          = 0x2b26, // chr->parse_frommap_auth_request(act, server);
	HEADER_ZW_WAN_UPDATE                    = 0x2736, // chr->parse_frommap_update_ip(act, server);
	HEADER_ZW_STATUS_CHANGE_UPDATE          = 0x2740, // chr->parse_frommap_scdata_update(fd);
	HEADER_ZW_STATUS_CHANGE_DELETE          = 0x2741, // chr->parse_frommap_scdata_delete(act);
#if 0
	// inter_parse_frommap
	0x3004, // mapif->parse_Registry(act); break;
    0x3005, // mapif->parse_RegistryRequest(act); break;
    0x3006, // mapif->parse_NameChangeRequest(act); break;
    0x3007, // mapif->parse_accinfo(act); break;
	// inter_party_parse_frommap
	0x3020, // mapif->parse_CreateParty(fd, R
	0x3021, // mapif->parse_PartyInfo(fd, RFI
	0x3022, // mapif->parse_PartyAddMember(fd
	0x3023, // mapif->parse_PartyChangeOption
	0x3024, // mapif->parse_PartyLeave(fd, RF
	0x3025, // mapif->parse_PartyChangeMap(fd
	0x3026, // mapif->parse_BreakParty(fd, RF
	0x3029, // mapif->parse_PartyLeaderChange
#endif
	// inter_guild_parse_frommap
	HEADER_ZW_GUILD_CREATE              = 0x3030, // mapif->parse_CreateGuild(fd, RFIFO
	HEADER_ZW_GUILD_INFO                = 0x3031, // mapif->parse_GuildInfo(fd,RFIFOL(f
	HEADER_ZW_GUILD_MEMBER              = 0x3032, // mapif->parse_GuildAddMember(fd, RF
	HEADER_ZW_GUILD_MASTER              = 0x3033, // mapif->parse_GuildMasterChange(fd,
	HEADER_ZW_GUILD_WITHDRAW            = 0x3034, // mapif->parse_GuildLeave(fd, RFIFOL
	HEADER_ZW_GUILD_MEMBER_UPDATE_SHORT = 0x3035, // mapif->parse_GuildChangeMemberInfo
	HEADER_ZW_GUILD_BREAK               = 0x3036, // mapif->parse_BreakGuild(fd,RFIFOL(
	HEADER_ZW_GUILD_INFO_UPDATE         = 0x3039, // mapif->parse_GuildBasicInfoChange(
	HEADER_ZW_GUILD_MEMBER_UPDATE_FIELD = 0x303A, // mapif->parse_GuildMemberInfoChange
	HEADER_ZW_GUILD_TITLE_UPDATE        = 0x303B, // mapif->parse_GuildPosition(fd, RFI
	HEADER_ZW_GUILD_SKILL_UP            = 0x303C, // mapif->parse_GuildSkillUp(fd,RFIFO
	HEADER_ZW_GUILD_ALLY_UPDATE         = 0x303D, // mapif->parse_GuildAlliance(fd,RFIF
	HEADER_ZW_GUILD_NOTICE              = 0x303E, // mapif->parse_GuildNotice(fd, RFIFO
	HEADER_ZW_GUILD_EMBLEM              = 0x303F, // mapif->parse_GuildEmblem(fd, RFIFO
	HEADER_ZW_GUILD_CASTLE_LOAD         = 0x3040, // mapif->parse_GuildCastleDataLoad(f
	HEADER_ZW_GUILD_CASTLE_SAVE         = 0x3041, // mapif->parse_GuildCastleDataSave(f
#if 0
	// inter_storage_parse_frommap
	0x3010, // mapif->pAccountStorageLoad(fd); bre
	0x3011, // mapif->pAccountStorageSave(fd); bre
	0x3018, // mapif->parse_LoadGuildStorage(fd); 
	0x3019, // mapif->parse_SaveGuildStorage(fd); 
	0x3056, // mapif->parse_ItemBoundRetrieve(fd);
	// inter_pet_parse_frommap
	0x3080, // mapif->parse_CreatePet
    0x3081, // mapif->parse_LoadPet(f
    0x3082, // mapif->parse_SavePet(f
    0x3083, // mapif->parse_DeletePet
	// inter_homunculus_parse_frommap
	0x3090, // mapif->parse_homunculus_create
    0x3091, // mapif->parse_homunculus_load  
    0x3092, // mapif->parse_homunculus_save  
    0x3093, // mapif->parse_homunculus_delete
    0x3094, // mapif->parse_homunculus_rename
	// inter_mercenary_parse_frommap
	0x3070, // mapif->parse_mercenary_create
    0x3071, // mapif->parse_mercenary_load(f
    0x3072, // mapif->parse_mercenary_delete
    0x3073, // mapif->parse_mercenary_save(f
#endif
	// inter_elemental_parse_frommap
	HEADER_ZW_ELEMENTAL_CREATE = 0x307c, // mapif->parse_elemental_create
	HEADER_ZW_ELEMENTAL_LOAD   = 0x307d, // mapif->parse_elemental_load(f
	HEADER_ZW_ELEMENTAL_DELETE =0x307e, // mapif->parse_elemental_delete
	HEADER_ZW_ELEMENTAL_SAVE   =0x307f, // mapif->parse_elemental_save(f
#if 0
	// inter_mail_parse_frommap
	0x3048, // mapif->parse_mail_requestinbox
	0x3049, // mapif->parse_mail_read(fd); br
	0x304a, // mapif->parse_mail_getattach(fd
	0x304b, // mapif->parse_mail_delete(fd); 
	0x304c, // mapif->parse_mail_return(fd); 
	0x304d, // mapif->parse_mail_send(fd); br
	// inter_auction_parse_frommap
	0x3050, // mapif->parse_auction_requestlist
    0x3051, // mapif->parse_auction_register(ac
    0x3052, // mapif->parse_auction_cancel(act)
    0x3053, // mapif->parse_auction_close(act);
    0x3055, // mapif->parse_auction_bid(act); b
	// inter_quest_parse_frommap
	0x3060, // mapif->parse_quest_load
	0x3061, // mapif->parse_quest_save
	// inter_rodex_parse_frommap
	0x3095, // mapif->parse_rodex_requestinbox
    0x3096, // mapif->parse_rodex_checkhasnew(
    0x3097, // mapif->parse_rodex_updatemail(f
    0x3098, // mapif->parse_rodex_send(fd); br
    0x3099, // mapif->parse_rodex_checkname(fd
	// inter_clan_parse_frommap
	0x3044, // mapif->parse_ClanMemberCount
    0x3045, // mapif->parse_ClanMemberKick(
	// inter_achievement_parse_frommap
	0x3012, // mapif->pLoadAchievements
	0x3013, // mapif->pSaveAchievements
#endif // 0
};

#if !defined(sun) && (!defined(__NETBSD__) || __NetBSD_Version__ >= 600000000) // NetBSD 5 and Solaris don't like pragma pack but accept the packed attribute
#pragma pack(push, 1)
#endif // not NetBSD < 6 / Solaris

/**
 * Inter-server data synchronization
 * @see socket_io->datasync
 **/
struct PACKET_ZW_DATASYNC {
	int16 packet_id;
	int16 packet_len;
	uint32 *data_length;
} __attribute__((packed));

/**
 * Skill id (nameid) index in map-server skill_db
 * @see chr->parse_frommap_skillid2idx
 **/
struct PACKET_ZW_SKILLID2IDX {
	int16 packet_id;
	int16 packet_len;
	struct {
		int16 skill_id;
		int16 skill_index;
	} *skill;
} __attribute__((packed));

/**
 * Owned map list of the map-server
 * @see char_parse_frommap_map_names
 **/
struct PACKET_ZW_OWNED_MAP_LIST {
	int16 packet_id;
	int16 packet_len;
	uint16 *map_index;
} __attribute__((packed));

/**
 * Request of status change data of a character
 * @see char_parse_frommap_request_scdata
 **/
struct PACKET_ZW_REQUEST_SCDATA {
	int16 packet_id;
	int32 account_id;
	int32 character_id;
} __attribute__((packed));

/**
 * User count of a map-server
 * @see char_parse_frommap_set_users_count
 **/
struct PACKET_ZW_SEND_USERS_COUNT {
	int16 packet_id;
	int16 user_count;
} __attribute__((packed));

/**
 * List of online characters
 * @see char_parse_frommap_set_users
 **/
struct PACKET_ZW_USER_LIST {
	int16 packet_id;
	int16 len;
	int16 user_count;
	struct {
		int32 account_id;
		int32 character_id;
	} *character;
} __attribute__((packed));

/**
 * Save character request
 * @see char_parse_frommap_save_character
 **/
struct PACKET_ZW_SAVE_CHARACTER {
	int16 packet_id;
	int16 packet_len;
	int32 account_id;
	int32 char_id;
	uint8 is_final_save;
	struct mmo_char_status *state;
} __attribute__((packed));

/**
 * Notification of client request to select another character
 * @see char_parse_frommap_char_select_req
 **/
struct PACKET_ZW_CHAR_SELECT_REQ {
	int16 packet_id;
	int32 account_id;
	int32 login_id1;
	int32 login_id2;
	int32 ipl;
	int32 group_id;
} __attribute__((packed));

/**
 * Request to move a character between map-servers
 *
 * @param account_id  Account id
 * @param login_id1   id1 provided by the client @see login_session_data::login_id1
 * @param login_id2   id2 provided by the client @see login_session_data::login_id2
 * @param char_id     Character id
 * @param spawn_point Spawn point in new map-server
 * @param map         New map-server connection information
 * @param sex         Account sex
 * @param client_addr Client ip
 * @param group_id    Account group id
 * @see char_parse_frommap_change_map_server
 **/
struct PACKET_ZW_CHANGE_SERVER_REQUEST {
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
	uint8 sex;
	int32 client_addr;
	int32 group_id;
} __attribute__((packed));

/**
 * Friend removal request
 * @see char_parse_frommap_remove_friend
 **/
struct PACKET_ZW_REMOVE_FRIEND {
	int16 packet_id;
	int32 char_id;
	int32 friend_id;
} __attribute__((packed));

/**
 * Character name request
 * @see char_parse_frommap_char_name_request
 **/
struct PACKET_ZW_CHARNAME_REQUEST {
	int16 packet_id;
	int32 char_id;
} __attribute__((packed));

/**
 * Change email request
 * @see char_parse_frommap_change_email
 **/
struct PACKET_ZW_REQUEST_CHANGE_EMAIL {
	int16 packet_id;
	int32 account_id;
	char actual_email[40];
	char new_email[40];
} __attribute__((packed));

/**
 * Update account/character data
 *
 * @param u_aid             Caster account id, -1 when server asked
 * @param name              Target name
 * @param type              Operation type (@see enum zh_char_ask_name_type)
 * @param additional_fields Dynamic data depends on type
 * @see char_parse_frommap_change_account
 **/
struct PACKET_ZW_UPDATE_ACCOUNT {
	int16 packet_id;
	int32 u_aid;
	uint8 name[NAME_LENGTH];
	int16 type;
	/**
	 * Additional fields
	 * For any other type these fields are empty.
	 *
	 * @param sex  CHAR_ASK_NAME_CHANGECHARSEX
	 * @param time CHAR_ASK_NAME_BAN / CHAR_ASK_NAME_CHARBAN
	 **/
	union {
		uint8 sex;
		struct {
			int16 year;
			int16 month;
			int16 day;
			int16 hour;
			int16 minute;
			int16 second;
		} time;
	} additional_fields;
} __attribute__((packed));

/**
 * Fame list update request
 * @see char_parse_frommap_fame_list
 **/
struct PACKET_ZW_FAME_LIST_UPDATE {
	int16 packet_id;
	int32 char_id;
	int32 fame;
	uint8 type;
} __attribute__((packed));

/**
 * Divorce characters
 * @see char_parse_frommap_divorce_char
 **/
struct PACKET_ZW_DIVORCE {
	int16 packet_id;
	int32 cid1;
	int32 cid2;
} __attribute__((packed));

/**
 * Updates map-server rates
 * @see char_parse_frommap_ragsrvinfo
 **/
struct PACKET_ZW_RATES {
	int16 packet_id;
	int16 base_rate;
	int16 job_rate;
	int16 drop_rate;	
} __attribute__((packed));

/**
 * Sets character offline.
 * @see char_parse_frommap_set_char_offline
 **/
struct PACKET_ZW_SET_CHARACTER_OFFLINE {
	int16 packet_id;
	int32 character_id;
	int32 account_id;
} __attribute__((packed));

/**
 * Request to set all characters offline
 * @see char_parse_frommap_set_all_offline
 **/
struct PACKET_ZW_SET_ALL_OFFLINE {
	int16 packet_id;
} __attribute__((packed));

/**
 * Sets character online.
 * @see char_parse_frommap_set_char_online
 **/
struct PACKET_ZW_SET_CHARACTER_ONLINE {
	int16 packet_id;
	int32 character_id;
	int32 account_id;
} __attribute__((packed));

/**
 * Request to build and send fame lists.
 * @see char_parse_frommap_build_fame_list
 **/
struct PACKET_ZW_FAME_LIST_BUILD {
	int16 packet_id;
} __attribute__ ((packed));

/**
 * Request to save status change data
 * @see char_parse_frommap_save_status_change_data
 **/
struct PACKET_ZW_STATUS_CHANGE_SAVE {
	int16 packet_id;
	int16 packet_len;
	int32 account_id;
	int32 character_id;
	int16 count;
	struct status_change_data *status[];
} __attribute__ ((packed));

/**
 * Ping packet
 * @see char_parse_frommap_ping
 **/
struct PACKET_ZW_PING {
	int16 packet_id;
} __attribute__ ((packed));

/**
 * Map-server account authentication request
 *
 * @param account_id      Account id
 * @param char_id         Character id
 * @param login_id1       id1 provided by the client @see login_session_data::login_id1
 * @param sex             Account sex (@see login_session_data::sex)
 * @param ipl             Client ip
 * @param standalone      When true doesn't send node data in ackt, this is used when
 *                        am auth request was triggered by the map-server without
 *                        a client (e.g. autotrade)
 * @see login_fromchar_parse_auth
 * @see struct login_auth_node
 **/
struct PACKET_ZW_AUTH {
	int16 packet_id;
	int32 account_id;
	int32 char_id;
	uint32 login_id1;
	uint8 sex;
	uint32 ipl;
	uint8 standalone;
} __attribute__((packed));

/**
 * Update wan IP of map-server
 * @see char_parse_frommap_update_ip
 **/
struct PACKET_ZW_WAN_UPDATE {
	int16 packet_id;
	uint32 ip;
} __attribute__((packed));

/**
 * Individual SC data insertion/update
 * @see struct status_change_data
 * @see char_parse_frommap_scdata_update
 **/
struct PACKET_ZW_STATUS_CHANGE_UPDATE {
	int16 packet_id;
	int32 account_id;
	int32 char_id;
	int16 type;
	int32 val1;
	int32 val2;
	int32 val3;
	int32 val4;
} __attribute__((packed));

/**
 * Individual SC data delete
 * @see struct status_change_data
 * @see char_parse_frommap_scdata_delete
 **/
struct PACKET_ZW_STATUS_CHANGE_DELETE {
	int16 packet_id;
	int32 account_id;
	int32 char_id;
	int16 type;
} __attribute__((packed));

/**
 * Elemental data used in inter-server
 * Should be the same as struct s_elemental
 * @see struct s_elemental
 **/
struct s_elemental_packet_data {
	int32 elemental_id;
	int32 char_id;
	int32 class_;
	uint32 mode;
	int32 hp, sp, max_hp, max_sp, matk, atk, atk2;
	int16 hit, flee, amotion, def, mdef;
	int32 life_time;
} __attribute__((packed));

/**
 * Elemental creation
 **/
struct PACKET_ZW_ELEMENTAL_CREATE {
	int16 packet_id;
	struct s_elemental_packet_data data;
} __attribute__((packed));

/**
 * Elemental load request
 **/
struct PACKET_ZW_ELEMENTAL_LOAD {
	int16 packet_id;
	int32 ele_id;
	int32 char_id;
} __attribute__((packed));

/**
 * Elemental delete request
 **/
struct PACKET_ZW_ELEMENTAL_DELETE {
	int16 packet_id;
	int32 ele_id;
} __attribute__((packed));

/**
 * Elemental save request
 **/
struct PACKET_ZW_ELEMENTAL_SAVE {
	int16 packet_id;
	struct s_elemental_packet_data data;
} __attribute__((packed));

/**
 * Guild member data used in inter-server
 * @see guild_member
 * @param hair       GMI_HAIR
 * @param hair_color GMI_HAIR_COLOR
 * @param gender     GMI_GENDER
 * @param class      GMI_CLASS
 * @param lv         GMI_LEVEL
 **/
struct s_guild_member_packet_data {
	int32 account_id;
	int32 char_id;
	int16 hair;
	int16 hair_color;
	int16 gender;
	int32 class;
	int16 lv;
	uint64 exp;
	int32 exp_payper;
	int16 online,position;
	uint8 name[NAME_LENGTH];
	uint8 modified;
} __attribute__((packed));
/**
 * Request to create a guild
 **/
struct PACKET_ZW_GUILD_CREATE {
	int16 packet_id;
	uint8 guild_name[NAME_LENGTH];
	struct s_guild_member_packet_data master_data;
} __attribute__((packed));

/**
 * Request guild information
 **/
struct PACKET_ZW_GUILD_INFO {
	int16 packet_id;
	int32 guild_id;
} __attribute__((packed));

/**
 * Add a new guild member
 **/
struct PACKET_ZW_GUILD_MEMBER_ADD {
	int16 packet_id;
	int32 guild_id;
	struct s_guild_member_packet_data data;
} __attribute__((packed));

/**
 * Remove a guild member
 * @param flag 0 Leave
 * @param flag 1 Expulsion
 **/
struct PACKET_ZW_GUILD_WITHDRAW {
	int16 packet_id;
	int32 guild_id;
	int32 char_id;
	uint8 flag;
	uint8 reason[40];
} __attribute__((packed));

/**
 * Member information update request
 **/
struct PACKET_ZW_GUILD_MEMBER_UPDATE {
	int16 packet_id;
	int32 guild_id;
	int32 account_id;
	int32 char_id;
	uint8 online;
	int32 lv;
	int32 class;
} __attribute__((packed));

/**
 * Member information field update request
 *
 * @param type enum guild_member_info
 * @param data Equivalent type of `type` @see s_guild_member_packet_data
 * @see inter_guild_update_member_info
 **/
struct PACKET_ZW_GUILD_MEMBER_UPDATE_FIELD {
	int16 packet_id;
	int16 packet_len;
	int32 guild_id;
	int32 account_id;
	int32 char_id;
	int16 type;
	uint8 *data;
} __attribute__((packed));

/**
 * Break guild request
 **/
struct PACKET_ZW_GUILD_BREAK {
	int16 packet_id;
	int32 guild_id;
} __attribute__((packed));

/**
 * Update guild information
 *
 * @param type enum guild_basic_info
 * @see inter_guild_update_basic_info
 **/
struct PACKET_ZW_GUILD_INFO_UPDATE {
	int16 packet_id;
	int16 packet_len;
	int32 guild_id;
	int16 type;
	uint8 *data;
} __attribute__((packed));

/**
 * Guild position packet data
 * @see guild_position
 **/
struct guild_position_packet_data {
	uint8 name[NAME_LENGTH];
	int32 mode;
	int32 exp_mode;
} __attribute__((packed));
/**
 * Update guild title request
 *
 * @param idx Position index
 **/
struct PACKET_ZW_GUILD_TITLE_UPDATE {
	int16 packet_id;
	int32 guild_id;
	int16 idx;
	struct guild_position_packet_data data;
} __attribute__((packed));

/**
 * Guild skill up
 *
 * @param account_id Account id of the player that changed the skill
 **/
struct PACKET_ZW_GUILD_SKILL_UP {
	int16 packet_id;
	int32 guild_id;
	int32 skill_id;
	int32 account_id;
	int32 max;
} __attribute__((packed));

/**
 * Update guild ally
 *
 * @param flag @see GUILD_ALLIANCE_TYPE_MASK and GUILD_ALLIANCE_REMOVE
 **/
struct PACKET_ZW_GUILD_ALLY_UPDATE {
	int16 packet_id;
	int32 guild_id1;
	int32 guild_id2;
	int32 aid1;
	int32 aid2;
	uint8 flag;
} __attribute__((packed));

/**
 * Update guild notice
 **/
struct PACKET_ZW_GUILD_NOTICE {
	int16 packet_id;
	int32 guild_id;
	uint8 mes1[MAX_GUILDMES1];
	uint8 mes2[MAX_GUILDMES2];
} __attribute__((packed));

/**
 * Update guild emblem
 * @param emblem Emblem bitmap (maximum length 2048 @see guild::emblem_data)
 **/
struct PACKET_ZW_GUILD_EMBLEM {
	int16 packet_id;
	int16 packet_len;
	int32 guild_id;
	uint8 *emblem;
} __attribute__((packed));

/**
 * Castle load request
 **/
struct PACKET_ZW_GUILD_CASTLE_LOAD {
	int16 packet_id;
	int16 packet_len;
	int32 *castle_id;
} __attribute__((packed));

/**
 * Change castle ownership
 **/
struct PACKET_ZW_GUILD_CASTLE_SAVE {
	int16 packet_id;
	int16 castle_id;
	uint8 index;
	int32 value;
} __attribute__((packed));

/**
 * Update guild master
 **/
struct PACKET_ZW_GUILD_MASTER {
	int16 packet_id;
	int32 guild_id;
	uint8 name[NAME_LENGTH];
} __attribute__((packed));

#if !defined(sun) && (!defined(__NETBSD__) || __NetBSD_Version__ >= 600000000) // NetBSD 5 and Solaris don't like pragma pack but accept the packed attribute
#pragma pack(pop)
#endif // not NetBSD < 6 / Solaris

#endif // COMMON_PACKETS_WA_STRUCT_H
