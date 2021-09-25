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
#ifndef CHAR_PINCODE_H
#define CHAR_PINCODE_H

#include "common/hercules.h"
#include "common/db.h"

/* Forward Declarations */
struct char_session_data;
struct config_t; // common/conf.h

/**
 * 0x8bb Answer to a pincode creation request
 * @see pincode_makestate
 **/
enum pincode_make_response {
	PINCODE_MAKE_SUCCESS        = 0,
	PINCODE_MAKE_DUPLICATED     = 1,
	PINCODE_MAKE_RESTRICT_PW    = 2,
	PINCODE_MAKE_PERSONALNUM_PW = 3,
	PINCODE_MAKE_FAILED         = 4,
};

/**
 * 0x8bf Answer to a pincode edit request
 * @see pincode_editstate
 **/
enum pincode_edit_response {
	PINCODE_EDIT_SUCCESS        = 0x0,
	PINCODE_EDIT_FAILED         = 0x1,
	PINCODE_EDIT_RESTRICT_PW    = 0x2,
	PINCODE_EDIT_PERSONALNUM_PW = 0x3,
};

/**
 * 0x8b9 / 0xae9 response states
 * @see pincode_loginstate
 * @see pincode_loginstate2
 **/
enum pincode_login_response {
	PINCODE_LOGIN_OK          = 0, // Pin is correct
	PINCODE_LOGIN_ASK         = 1, // Ask for pin - client sends 0x8b8
	PINCODE_LOGIN_NOTSET      = 2, // Create new pin - client sends 0x8ba
	PINCODE_LOGIN_EXPIRED     = 3, // Pin must be changed - client 0x8be
	PINCODE_LOGIN_CREATE      = 4, // Create new pin ?? - client sends 0x8ba
	PINCODE_LOGIN_RESTRICT_PW = 5, // Client shows msgstr(1896)
	PINCODE_LOGIN_INVALID_KSSN= 6, // Client shows msgstr(1897) Unable to use your KSSN number
	PINCODE_LOGIN_UNUSED      = 7, // Char select window shows a button - client sends 0x8c5
	PINCODE_LOGIN_WRONG       = 8, // Pincode was incorrect
};

enum pincode_login_response2 {
	PINCODE_LOGIN_FLAG_LOCKED = 0,
	PINCODE_LOGIN_FLAG_WRONG  = 2,
};

/**
 * Result of pincode comparison
 * @see pincode_compare
 **/
enum pincode_compare_result {
	PINCODE_DISCONNECTED = -1,
	PINCODE_FAILED       = 0,
	PINCODE_SUCCESS      = 1,
};

/**
 * pincode interface
 **/
struct pincode_interface {
	/* vars */
	int enabled;
	int changetime;
	int maxtry;
	/**
	 * Should the pincode be queried in every selection or only on login?
	 * This is a boolean and is defined in pincode:request at char-server.conf
	 **/
	int charselect;

	// Should the pincode blacklist be checked against
	bool check_blacklist;
	// Prohibited pincodes
	VECTOR_DECL(char *) blacklist;

	unsigned int multiplier;
	unsigned int baseSeed;
	/* handler */
	void (*handle) (struct socket_data *session, struct char_session_data* sd);
	void (*disconnect) (struct socket_data *session);
	void (*decrypt) (unsigned int userSeed, char* pin);
	void (*error) (int account_id);
	void (*update) (int account_id, const char* pin);
	void (*makestate)  (struct socket_data *session, struct char_session_data *sd, enum pincode_make_response state);
	void (*editstate)  (struct socket_data *session, struct char_session_data *sd, enum pincode_edit_response state);
	void (*loginstate) (struct socket_data *session, struct char_session_data *sd, enum pincode_login_response state);
	void (*loginstate2)(struct socket_data *session, struct char_session_data *sd, enum pincode_login_response state, enum pincode_login_response2 flag);
	void (*setnew) (struct s_receive_action_data *act, struct char_session_data *sd, int ipl);
	void (*change) (struct s_receive_action_data *act, struct char_session_data *sd, int ipl);
	void (*window) (struct s_receive_action_data *act, struct char_session_data *sd, int ipl);
	bool (*isBlacklisted) (const char *pin);
	enum pincode_compare_result  (*compare) (struct socket_data *session, struct char_session_data* sd, const char* pin);
	void (*check)   (struct s_receive_action_data *act, struct char_session_data* sd, int ipl);
	bool (*config_read) (const char *filename, const struct config_t *config, bool imported);
	void (*init) (void);
	void (*final) (void);
};

#ifdef HERCULES_CORE
void pincode_defaults(void);
#endif // HERCULES_CORE

HPShared struct pincode_interface *pincode;

#endif /* CHAR_PINCODE_H */
