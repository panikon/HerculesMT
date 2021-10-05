/**
 * This file is part of Hercules.
 * http://herc.ws - http://github.com/HerculesWS/Hercules
 *
 * Copyright (C) 2012-2021 Hercules Dev Team
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
#ifndef CHAR_MAPIF_H
#define CHAR_MAPIF_H

#include "common/hercules.h"
#include "common/mmo.h"

struct rodex_item;

/**
 * Map inter-server parse function
 * @see inter_parse_frommap
 * @readlock chr->map_server_list_lock
 **/
typedef void (MapifParseFunc)(struct s_receive_action_data *act, struct mmo_map_server *server);

/**
 * Map inter-server packet information
 * @see mapif_init
 **/
struct mapif_packet_entry {
	int16 len;
	MapifParseFunc *pFunc;
};

/**
 * mapif interface
 **/
struct mapif_interface {
	/**
	 * Inter-server packet database (mapif)
	 * This database doesn't have any locks because it's not meant to be edited
	 * after it's creation.
	 * @see mapif->init
	 **/
	struct DBMap *packet_db; // int16 packet_id -> struct mapif_packet_entry*
	struct mapif_packet_entry *packet_list;

	void (*init) (void);
	void (*final) (void);

	struct mmo_map_server *(*server_find) (struct socket_data *session);
	void (*server_destroy)(struct mmo_map_server *server);
	void (*server_reset)  (struct mmo_map_server *server);
	void (*on_disconnect) (struct mmo_map_server *server);
	struct mmo_map_server *(*on_connect) (struct socket_data *session, uint32 ip_, uint16 port_);

	int (*sendall) (const unsigned char *buf, unsigned int len);
	int (*sendallwos) (struct mmo_map_server *server, const unsigned char *buf, unsigned int len);
	int (*send) (struct mmo_map_server *server, unsigned char *buf, unsigned int len);

	void (*accinfo_request) (int account_id, int u_fd, int u_aid, int u_group, int map_id);
	void (*update_state) (int id, unsigned char flag, unsigned int state);
	void (*char_ban) (int char_id, time_t timestamp);
	void (*change_sex) (int account_id, int sex);
	void (*fame_list)(struct mmo_map_server *server, struct fame_list *smith, int smith_len, struct fame_list *chemist, int chemist_len, struct fame_list *taekwon, int taekwon_len);
	void (*fame_list_update) (enum fame_list_type type, int index, int fame);
	void (*map_received) (struct socket_data *session, char *wisp_server_name, uint8 flag);
	void (*send_maps) (struct mmo_map_server *server, const uint16 *map_list);

	void (*scdata_head) (struct socket_data *session, int aid, int cid, int count);
	void (*scdata_data) (struct socket_data *session, struct status_change_data *data);
	void (*scdata_send) (struct socket_data *session);

	void (*save_character_ack) (struct socket_data *session, int aid, int cid);
	void (*char_select_ack) (struct socket_data *session, int account_id, uint8 flag);
	void (*change_map_server_ack) (struct socket_data *session, const uint8 *data, bool ok);
	void (*char_name_ack) (struct socket_data *session, int char_id);
	void (*change_account_ack) (struct socket_data *session, int acc, const char *name, enum zh_char_ask_name_type type, int result);
	void (*pong)(struct socket_data *session);
	void (*auth_ok) (struct socket_data *session, int account_id, struct char_auth_node *node, struct mmo_charstatus *cd);
	void (*auth_failed) (struct socket_data *session, int account_id, int char_id, int login_id1, char sex, uint32 ip);
	void (*login_map_server_ack) (struct socket_data *session, uint8 flag);
	int (*parse_item_data) (struct s_receive_action_data *act, int pos, struct item *out);
	int (*send_item_data) (struct socket_data *session, int pos, const struct item *in);

	void (*send_users_count) (int users);

	void (*pLoadAchievements) (struct s_receive_action_data *act);
	void (*sAchievementsToMap) (struct socket_data *session, int char_id, const struct char_achievements *cp);
	void (*pSaveAchievements) (struct s_receive_action_data *act);
	void (*achievement_save) (int char_id, const struct char_achievements *p);

	void (*auction_message) (int char_id, enum e_auction_result_message result);
	void (*auction_sendlist) (struct socket_data *session, int char_id, short count, short pages, unsigned char *buf);
	void (*parse_auction_requestlist) (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*auction_register) (struct socket_data *session, unsigned int auction_id, unsigned int auction_hours, const uint8 *item_data);
	void (*parse_auction_register) (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*auction_cancel) (struct socket_data *session, int char_id, enum e_auction_cancel result);
	void (*parse_auction_cancel) (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*auction_close) (struct socket_data *session, int char_id, enum e_auction_cancel result);
	void (*parse_auction_close) (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*auction_bid) (struct socket_data *session, int char_id, int bid, enum e_auction_result_message result);
	void (*parse_auction_bid) (struct s_receive_action_data *act, struct mmo_map_server *server);

	void (*elemental_send) (struct socket_data *session, unsigned char flag, const uint8_t *elemental_data);
	void (*parse_elemental_create) (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_elemental_load) (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*elemental_deleted) (struct socket_data *session, unsigned char flag);
	void (*parse_elemental_delete) (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*elemental_saved) (struct socket_data *session, unsigned char flag);
	void (*parse_elemental_save) (struct s_receive_action_data *act, struct mmo_map_server *server);

	int (*guild_created)     (struct socket_data *session, int account_id, struct guild *g);
	void (*guild_info)       (struct mmo_map_server *server, struct guild *g, bool success);
	int (*guild_memberadded) (struct socket_data *session, int guild_id, int account_id, int char_id, int flag);
	int (*guild_withdraw) (int guild_id, int account_id, int char_id, int flag, const char *name, const char *mes);
	int (*guild_memberinfoshort) (struct guild *g, int idx);
	int (*guild_broken) (int guild_id, int flag);
	int (*guild_basicinfochanged) (int guild_id, int type, const void *data, int len);
	int (*guild_memberinfochanged) (int guild_id, int account_id, int char_id, int type, const void *data, int len);
	int (*guild_skillupack) (int guild_id, uint16 skill_id, int account_id);
	int (*guild_alliance) (int guild_id1, int guild_id2, int account_id1, int account_id2, int flag, const char *name1, const char *name2);
	int (*guild_position) (struct guild *g, int idx);
	int (*guild_notice) (struct guild *g);
	int (*guild_emblem) (struct guild *g);
	int (*guild_master_changed) (struct guild *g, int aid, int cid);
	int (*guild_castle_dataload) (struct socket_data *session, const int *castle_ids, int num);
	void (*parse_CreateGuild)                (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_GuildInfo)                  (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_GuildAddMember)             (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_GuildLeave)                 (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_GuildChangeMemberInfoShort) (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_BreakGuild)                 (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_GuildBasicInfoChange)       (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_GuildMemberInfoChange)      (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_GuildPosition)              (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_GuildSkillUp)               (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_GuildAlliance)              (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_GuildNotice)                (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_GuildEmblem)                (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_GuildCastleDataLoad)        (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_GuildCastleDataSave)        (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_GuildMasterChange)          (struct s_receive_action_data *act, struct mmo_map_server *server);

	void (*homunculus_created) (struct socket_data *session, int account_id, const struct s_homunculus *sh, unsigned char flag);
	void (*homunculus_deleted) (struct socket_data *session, int flag);
	void (*homunculus_loaded)  (struct socket_data *session, int account_id, struct s_homunculus *hd);
	void (*homunculus_saved)   (struct socket_data *session, int account_id, bool flag);
	void (*parse_homunculus_create) (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_homunculus_delete) (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_homunculus_load)   (struct s_receive_action_data *act, struct mmo_map_server *server);
	void (*parse_homunculus_save)   (struct s_receive_action_data *act, struct mmo_map_server *server);

	void (*mail_sendinbox) (struct socket_data *session, int char_id, unsigned char flag, const struct mail_data *md);
	void (*parse_mail_requestinbox) (struct s_receive_action_data *act);
	void (*parse_mail_read) (struct s_receive_action_data *act);
	void (*mail_sendattach) (struct socket_data *session, int char_id, const struct mail_message *msg);
	void (*parse_mail_getattach) (struct s_receive_action_data *act);
	void (*mail_delete) (struct socket_data *session, int char_id, int mail_id, bool failed);
	void (*parse_mail_delete) (struct s_receive_action_data *act);
	void (*mail_new) (struct mail_message *msg);
	void (*mail_return) (struct socket_data *session, int char_id, int mail_id, int new_mail);
	void (*parse_mail_return) (struct s_receive_action_data *act);
	void (*mail_send) (struct socket_data *session, const struct mail_message* msg);
	void (*parse_mail_send) (struct s_receive_action_data *act);

	int (*parse_mercenary_data) (struct s_receive_action_data *act, int pos, struct s_mercenary *out);
	void (*mercenary_send) (struct socket_data *session, const struct s_mercenary *merc, bool result);
	void (*parse_mercenary_create) (struct s_receive_action_data *act);
	void (*parse_mercenary_load) (struct s_receive_action_data *act);
	void (*mercenary_deleted) (struct socket_data *session, int char_id, int merc_id, bool success);
	void (*parse_mercenary_delete) (struct s_receive_action_data *act);
	void (*mercenary_saved) (struct socket_data *session, int char_id, int merc_id, bool success);
	void (*parse_mercenary_save) (struct s_receive_action_data *act);

	void (*party_created) (struct socket_data *session, int account_id, int char_id, const struct party *p);
	void (*party_info) (struct socket_data *session, int party_id, int char_id, const struct party *p);
	void (*party_memberadded) (struct socket_data *session, int party_id, int account_id, int char_id, int flag);
	void (*party_optionchanged) (struct socket_data *session, const struct party *p, int account_id, int flag);
	void (*party_withdraw) (int party_id,int account_id, int char_id);
	void (*party_membermoved) (const struct party *p, int idx);
	void (*party_broken) (int party_id, int flag);
	void (*parse_party_member) (struct s_receive_action_data *act, int pos, struct party_member *out);
	void (*parse_CreateParty)       (struct s_receive_action_data *act);
	void (*parse_PartyInfo)         (struct s_receive_action_data *act);
	void (*parse_PartyAddMember)    (struct s_receive_action_data *act);
	void (*parse_PartyChangeOption) (struct s_receive_action_data *act);
	void (*parse_PartyLeave)        (struct s_receive_action_data *act);
	void (*parse_PartyChangeMap)    (struct s_receive_action_data *act);
	void (*parse_BreakParty)        (struct s_receive_action_data *act);
	void (*parse_PartyLeaderChange) (struct s_receive_action_data *act);

	void (*pet_created) (struct socket_data *session, int account_id, const struct s_pet *p);
	void (*pet_info) (struct socket_data *session, int account_id, const struct s_pet *p);
	void (*save_pet_ack) (struct socket_data *session, int account_id, int flag);
	void (*delete_pet_ack) (struct socket_data *session, int account_id, int flag);
	void (*parse_pet_data) (struct s_receive_action_data *act, int pos, struct s_pet *out);
	void (*parse_CreatePet) (struct s_receive_action_data *act);
	void (*parse_LoadPet)   (struct s_receive_action_data *act);
	void (*parse_SavePet)   (struct s_receive_action_data *act);
	void (*parse_DeletePet) (struct s_receive_action_data *act);

	void (*quest_save_ack) (struct socket_data *session, int char_id, bool success);
	void (*parse_quest_save) (struct s_receive_action_data *act);
	void (*send_quests) (struct socket_data *session, int char_id, struct quest *quest, int num_quests);
	void (*parse_quest_load) (struct s_receive_action_data *act);

	void (*parse_rodex_requestinbox) (struct s_receive_action_data *act);
	void (*rodex_sendinbox) (struct socket_data *session, int char_id, int8 opentype, int8 flag, int count, int64 mail_id, const struct rodex_maillist *mails);
	void (*parse_rodex_checkhasnew) (struct s_receive_action_data *act);
	void (*rodex_sendhasnew) (struct socket_data *session, int char_id, bool has_new);
	void (*parse_rodex_updatemail) (struct s_receive_action_data *act);
	void (*parse_rodex_send) (struct s_receive_action_data *act);
	void (*rodex_send) (struct socket_data *session, int sender_id, int receiver_id, int receiver_accountid, bool result);
	void (*parse_rodex_checkname) (struct s_receive_action_data *act);
	void (*rodex_checkname)   (struct socket_data *session, int reqchar_id, int target_char_id, int target_class, int target_level, const char *name);
	void (*rodex_getzenyack)  (struct socket_data *session, int char_id, int64 mail_id, uint8 opentype, int64 zeny);
	void (*rodex_getitemsack) (struct socket_data *session, int char_id, int64 mail_id, uint8 opentype, int count, const struct rodex_item *items);

	void (*load_guild_storage) (struct socket_data *session, int account_id, int guild_id, char flag);
	void (*save_guild_storage_ack) (struct socket_data *session, int account_id, int guild_id, int fail);
	void (*parse_LoadGuildStorage) (struct s_receive_action_data *act);
	void (*parse_SaveGuildStorage) (struct s_receive_action_data *act);
	void (*account_storage_load) (struct socket_data *session, int account_id);
	void (*pAccountStorageLoad) (struct s_receive_action_data *act);
	void (*pAccountStorageSave) (struct s_receive_action_data *act);
	void (*sAccountStorageSaveAck) (struct socket_data *session, int account_id, bool save);

	void (*itembound_ack) (struct socket_data *session, int guild_id);
	void (*parse_ItemBoundRetrieve) (struct s_receive_action_data *act);

	void (*parse_accinfo) (struct s_receive_action_data *act);
	void (*disconnectplayer)  (struct socket_data *session, int account_id, int char_id, enum notify_ban_errorcode reason);
	void (*parse_Registry) (struct s_receive_action_data *act);
	void (*parse_RegistryRequest) (struct s_receive_action_data *act);
	void (*namechange_ack) (struct socket_data *session, int account_id, int char_id, int type, uint8 flag, const char *esc_name);
	void (*parse_NameChangeRequest) (struct s_receive_action_data *act);
	// Clan System
	void (*ClanMemberKick_ack) (struct socket_data *session, int clan_id, int count);
	void (*parse_ClanMemberKick) (struct s_receive_action_data *act);
	void (*parse_ClanMemberCount) (struct s_receive_action_data *act, int clan_id, int kick_interval);
};

#ifdef HERCULES_CORE
void mapif_defaults(void);
#endif // HERCULES_CORE

HPShared struct mapif_interface *mapif;

#endif /* CHAR_MAPIF_H */
