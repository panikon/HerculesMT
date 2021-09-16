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
#ifndef CHAR_LOGINIF_H
#define CHAR_LOGINIF_H

#include "common/hercules.h"

struct char_session_data;

/**
 * Login inter-server parse function
 * @see char_parse_fromlogin
 **/
typedef void (LoginifParseFunc)(struct s_receive_action_data *act);

/**
 * Login inter-server packet information
 * @see lchrif_init
 **/
struct loginif_packet_entry {
	int16 len;
	LoginifParseFunc *pFunc;
};

/**
 * loginif interface
 **/
struct loginif_interface {
	/**
	 * Inter-server packet database (loginif)
	 * This database doesn't have any locks because it's not meant to be edited
	 * after it's creation.
	 * @see loginif->init
	 **/
	struct DBMap *packet_db; // int16 packet_id -> struct loginif_packet_entry*
	struct loginif_packet_entry *packet_list;

	void (*init) (void);
	void (*final) (void);
	void (*check_shutdown) (void);
	void (*on_disconnect) (void);
	void (*on_ready) (void);

	void (*ping) (void);
	void (*pincode_update) (int account_id, const char *pin);
	void (*pincode_failed) (int account_id);
	void (*update_ip) (void);
	void (*accinfo_request) (int account_id, int u_fd, int u_aid, int u_group, int map_fd);
	int (*account_list_sub) (const struct DBKey_s *key, struct DBData *data, va_list ap);
	int (*account_list) (struct timer_interface *tm, int tid, int64 tick, int id, intptr_t data);
	void (*request_account_data) (int account_id);
	void (*set_all_offline) (void);
	void (*set_account_online) (int account_id);
	void (*set_account_offline) (int account_id);
	void (*request_change_email) (int account_id, char current_email[40], char new_email[40]);
	void (*save_accreg2_head) (int account_id, int char_id);
	void (*save_accreg2_entry)(const char *key, unsigned int index, intptr_t val, bool is_string);
	void (*save_accreg2_send) (void);

	void (*request_accreg2) (int account_id, int char_id);
	void (*update_state) (int account_id, enum accept_login_errorcode state);
	void (*ban_account) (int account_id, short year, short month, short day, short hour, short minute, short second);
	void (*unban_account) (int account_id);
	void (*changesex) (int account_id);
	void (*auth) (int session_id, struct char_session_data* sd, uint32 ipl);
	void (*send_users_count) (int users);
	void (*connect_to_server) (void);
};

#ifdef HERCULES_CORE
void loginif_defaults(void);
#endif // HERCULES_CORE

HPShared struct loginif_interface *loginif;

#endif /* CHAR_LOGINIF_H */
