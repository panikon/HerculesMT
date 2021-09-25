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
#ifndef CHAR_CHCLIF_H
#define CHAR_CHCLIF_H

#include "common/hercules.h"
#include "common/db.h"

/**
 * Char client parse function
 * @param act Action to be parsed
 * @param sd  Valid session data
 * @param ipl Client address
 * @see chclif_parse
 **/
typedef void (ChclifParseFunc)(struct s_receive_action_data *act, struct char_session_data *sd, int ipl);

/**
 * Char client packet information
 * @see chclif_init
 **/
struct chclif_packet_entry {
	int16 len;
	ChclifParseFunc *pFunc;
};

/**
 * Chclif interface
 **/
struct chclif_interface {
	/**
	 * Client packet database (chclif)
	 * This database doesn't have any locks because it's not meant to be edited
	 * after it's creation.
	 * @see chclif->init
	 **/
	struct DBMap *packet_db; // int16 packet_id -> struct chclif_packet_entry*
	struct chclif_packet_entry *packet_list;

	void (*parse_captcha)       (struct s_receive_action_data *act, struct char_session_data *sd, int ipl);
	void (*parse_request_chars) (struct s_receive_action_data *act, struct char_session_data *sd, int ipl);
	void (*parse_move_character)(struct s_receive_action_data *act, struct char_session_data *sd, int ipl);

	void (*parse_delete2_req)   (struct s_receive_action_data *act, struct char_session_data *sd, int ipl);
	void (*parse_delete2_accept)(struct s_receive_action_data *act, struct char_session_data *sd, int ipl);
	void (*parse_delete2_cancel)(struct s_receive_action_data *act, struct char_session_data *sd, int ipl);
	void (*parse_delete_char)   (struct s_receive_action_data *act, struct char_session_data *sd, int ipl);

	void (*parse_rename)        (struct s_receive_action_data *act, struct char_session_data *sd, int ipl);

	void (*parse_rename_confirm)(struct s_receive_action_data *act, struct char_session_data *sd, int ipl);
	void (*parse_ping)          (struct s_receive_action_data *act, struct char_session_data *sd, int ipl);
	void (*parse_make_char)     (struct s_receive_action_data *act, struct char_session_data *sd, int ipl);
	void (*parse_select_char)   (struct s_receive_action_data *act, struct char_session_data *sd, int ipl);
	void (*parse_enter)         (struct s_receive_action_data *act, int ipl);
	enum parsefunc_rcode (*parse) (struct s_receive_action_data *act);

	void (*final)(void);
	void (*init)(void);
};

#ifdef HERCULES_CORE
void chclif_defaults(void);
#endif

HPShared struct chclif_interface *chclif;

#endif /* CHAR_CHCLIF_H */
