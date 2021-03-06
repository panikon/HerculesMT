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
#ifndef CHAR_INTER_H
#define CHAR_INTER_H

#include "common/hercules.h"
#include "common/db.h"

#include <stdarg.h>

/* Forward Declarations */
struct Sql; // common/sql.h
struct config_t; // common/conf.h

/**
 * inter interface
 **/
struct inter_interface {
	bool enable_logs; ///< Whether to log inter-server operations.

	struct Sql *(*sql_handle_get) (void);
	void (*sql_handle_close) (void);
	void (*sql_handle_open) (void);

	const char* (*msg_txt) (int msg_number);
	bool (*msg_config_read) (const char *cfg_name, bool allow_override);
	void (*do_final_msg) (void);
	const char* (*job_name) (int class);
	void (*vmsg_to_fd) (int map_id, int u_fd, int aid, char* msg, va_list ap);
	void (*msg_to_fd) (int map_id, int u_fd, int aid, char *msg, ...) __attribute__((format(printf, 4, 5)));
	uint8 (*char_rename) (int char_id, int guild_id, const char *esc_name);
	void (*savereg) (int account_id, int char_id, const char *key, unsigned int index, intptr_t val, bool is_string);
	int (*accreg_fromsql) (int account_id,int char_id, struct socket_data *session, int type);
	int (*vlog) (char* fmt, va_list ap);
	int (*log) (char* fmt, ...);
	void (*load_config) (const char *file);
	void (*init_sql) (void);
	int (*mapif_init) (struct socket_data *session);
	void (*final) (void);
	bool (*config_read) (const char *filename, bool imported);
	bool (*config_read_log) (const char *filename, const struct config_t *config, bool imported);
	bool (*config_read_connection) (const char *filename, const struct config_t *config, bool imported);
	void (*accinfo) (int u_fd, int aid, int castergroup, const char *query, int map_id);
	void (*accinfo_ack) (bool success, int map_fd, int u_fd, int u_aid, int account_id, const char *userid,
			const char *email, const char *last_ip, const char *lastlogin, const char *birthdate,
			int group_id, int logincount, int state);
};

#ifdef HERCULES_CORE
extern int party_share_level; ///< Share range for parties.

void inter_defaults(void);
#endif // HERCULES_CORE

HPShared struct inter_interface *inter;

#endif /* CHAR_INTER_H */
