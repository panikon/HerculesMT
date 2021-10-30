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
#define HERCULES_CORE

#include "pincode.h"

#include "char/char.h"
#include "char/loginif.h"
#include "common/cbasetypes.h"
#include "common/conf.h"
#include "common/db.h"
#include "common/memmgr.h"
#include "common/mmo.h"
#include "common/nullpo.h"
#include "common/random.h"
#include "common/showmsg.h"
#include "common/socket.h"
#include "common/strlib.h"
#include "common/mutex.h"

#include <stdio.h>
#include <stdlib.h>

static struct pincode_interface pincode_s;
struct pincode_interface *pincode;

/**
 * Pincode system activation triggered after login-server authentication
 * @see pincode->loginstate
 *
 * Acquires db_lock(chr->online_char_db)
 **/
static void pincode_handle(struct socket_data *session, struct char_session_data *sd)
{
	struct online_char_data* character;

	nullpo_retv(sd);

	db_lock(chr->online_char_db, WRITE_LOCK);
	character = idb_get(chr->online_char_db, sd->account_id);

	if(character && character->pincode_enable > pincode->charselect) {
		character->pincode_enable = pincode->charselect * 2;
	} else {
		db_unlock(chr->online_char_db);
		// Player already answered the PIN correctly enough times.
		pincode->loginstate(session, sd, PINCODE_LOGIN_OK);
		return;
	}

	if (strlen(sd->pincode) == 4) {
		if (pincode->check_blacklist && pincode->isBlacklisted(sd->pincode)) {
			// Ask player to change pincode to be able to connect
			pincode->loginstate(session, sd, PINCODE_LOGIN_EXPIRED);
		} else if (pincode->changetime && time(NULL) > (sd->pincode_change + pincode->changetime)) {
			// User hasn't changed his PIN code for a long time
			pincode->loginstate(session, sd, PINCODE_LOGIN_EXPIRED);
		} else { // Ask user for his PIN code
			pincode->loginstate(session, sd, PINCODE_LOGIN_ASK);
		}
	} else // No PIN code has been set yet
		pincode->loginstate(session, sd, PINCODE_LOGIN_NOTSET);

	if (character)
		character->pincode_enable = -1;
	db_unlock(chr->online_char_db);
}

/**
 * Notifies login-server of a failure to answer the correct PIN and then
 * disconnects the player.
 **/
static void pincode_disconnect(struct socket_data *session)
{
	struct char_session_data *sd = session->session_data;

	loginif->pincode_failed(sd->account_id);
	chr->authfail_fd(session, 0);
	chr->disconnect_player(sd->account_id);
	return;
}

/**
 * Checks if provided pincode is valid
 * [server] pincode->loginstate(PINCODE_LOGIN_ASK)
 * [client] 0x8b8 CH_SECOND_PASSWD_ACK
 * [server] pincode->loginstate
 **/
static void pincode_check(struct s_receive_action_data *act, struct char_session_data *sd, int ipl)
{
	char pin[5] = "\0\0\0\0";

	// Disconnect player, the client shouldn't have sent this packet
	if(RFIFOL(act,2) != sd->account_id || strlen(sd->pincode) != 4) {
		pincode->disconnect(act->session);
		return;
	}

	safestrncpy(pin, RFIFOP(act, 6), sizeof(pin));
	pincode->decrypt(sd->pincode_seed, pin);

	if (pincode->check_blacklist && pincode->isBlacklisted(pin)) {
		pincode->loginstate(act->session, sd, PINCODE_LOGIN_RESTRICT_PW);
		return;
	}

	switch(pincode->compare(act->session, sd, pin)) {
		case PINCODE_SUCCESS:
		{
			struct online_char_data* character;
			if((character = idb_get(chr->online_char_db, sd->account_id)))
				character->pincode_enable = pincode->charselect * 2;
			pincode->loginstate(act->session, sd, PINCODE_LOGIN_OK);
			break;
		}
		case PINCODE_FAILED:
			// @see loginstate2, kRO is currently using loginstate2 only for failure
#if PACKETVER_MAIN_NUM >= 20180124 || PACKETVER_RE_NUM >= 20180124 || PACKETVER_ZERO_NUM >= 20180131
			pincode->loginstate2(act->session, sd, PINCODE_LOGIN_WRONG, PINCODE_LOGIN_FLAG_WRONG);
#else
			pincode->loginstate(act->session, sd, PINCODE_LOGIN_WRONG);
#endif
			break;
		default:
		case PINCODE_DISCONNECTED:
			return;
	}
}

/**
 * Checks if this pincode is blacklisted or not
 *
 * @param (const char *) pin The pin to be verified
 * @return bool
 */
static bool pincode_isBlacklisted(const char *pin)
{
	int i;

	nullpo_retr(false, pin);

	ARR_FIND(0, VECTOR_LENGTH(pincode->blacklist), i, strcmp(VECTOR_INDEX(pincode->blacklist, i), pin) == 0);

	if (i < VECTOR_LENGTH(pincode->blacklist)) {
		return true;
	}

	return false;
}

/**
 * Compares given pincode against sd->pincode, each time that the comparison fails
 * pincode_try is increased, if it reaches pincode->maxtry the player is
 * disconnected.
 * @see enum pincode_compare_result
 **/
static enum pincode_compare_result pincode_compare(struct socket_data *session,
	struct char_session_data *sd, const char *pin
) {
	nullpo_ret(sd);
	nullpo_ret(pin);

	if(strcmp(sd->pincode, pin) == 0) {
		sd->pincode_try = 0;
		return PINCODE_SUCCESS;
	}
	if(pincode->maxtry && ++sd->pincode_try >= pincode->maxtry) {
		pincode->disconnect(session);
		return PINCODE_DISCONNECTED;
	}
	return PINCODE_FAILED;
}

/**
 * Performs pincode update after a client request
 * [server] pincode->loginstate(PINCODE_LOGIN_ASK)
 * [client] 0x8be CH_EDIT_SECOND_PASSWD
 * [server] pincode->loginstate
 **/
static void pincode_change(struct s_receive_action_data *act, struct char_session_data *sd, int ipl)
{
	char oldpin[5] = "\0\0\0\0", newpin[5] = "\0\0\0\0";

	nullpo_retv(sd);

	// Disconnect player, the client shouldn't have sent this packet
	if(RFIFOL(act,2) != sd->account_id || strlen(sd->pincode) != 4) {
		pincode->disconnect(act->session);
		return;
	}

	safestrncpy(oldpin, RFIFOP(act, 6), sizeof(oldpin));
	pincode->decrypt(sd->pincode_seed, oldpin);

	switch(pincode->compare(act->session, sd, oldpin)) {
		case PINCODE_FAILED:
			pincode->editstate(act->session, sd, PINCODE_EDIT_FAILED);
			pincode->loginstate(act->session, sd, PINCODE_LOGIN_ASK);
			return;
		case PINCODE_SUCCESS:
			break;
		default:
		case PINCODE_DISCONNECTED:
			return;
	}

	safestrncpy(newpin, RFIFOP(act, 10), sizeof(newpin));
	pincode->decrypt(sd->pincode_seed, newpin);

	if(pincode->check_blacklist && pincode->isBlacklisted(newpin)) {
		pincode->editstate(act->session, sd, PINCODE_EDIT_RESTRICT_PW);
		return;
	}

	loginif->pincode_update(sd->account_id, newpin);
	safestrncpy(sd->pincode, newpin, sizeof(sd->pincode));
	pincode->editstate(act->session, sd, PINCODE_EDIT_SUCCESS);
	pincode->loginstate(act->session, sd, PINCODE_LOGIN_ASK);
}

/**
 * Activates PIN system and sets a pincode (triggered by 0x8ba).
 * [server] pincode->loginstate(PINCODE_LOGIN_NOTSET)
 * [client] 0x8ba CH_MAKE_SECOND_PASSWD
 * [server] pincode->makestate (if success sends loginstate as well)
 **/
static void pincode_setnew(struct s_receive_action_data *act, struct char_session_data *sd, int ipl)
{
	char newpin[5] = "\0\0\0\0";

	nullpo_retv(sd);

	// Disconnect player, the client shouldn't have sent this packet
	if(RFIFOL(act,2) != sd->account_id || strlen(sd->pincode) == 4) {
		pincode->disconnect(act->session);
		return;
	}

	safestrncpy(newpin, RFIFOP(act, 6), sizeof(newpin));
	pincode->decrypt(sd->pincode_seed, newpin);

	if (pincode->check_blacklist && pincode->isBlacklisted(newpin)) {
		pincode->makestate(act->session, sd, PINCODE_MAKE_RESTRICT_PW);
		return;
	}

	loginif->pincode_update(sd->account_id, newpin);
	safestrncpy(sd->pincode, newpin, sizeof(sd->pincode));
	pincode->makestate(act->session, sd, PINCODE_MAKE_SUCCESS);
	pincode->loginstate(act->session, sd, PINCODE_LOGIN_ASK);
}

/**
 * 0x8bb Answer to a pincode creation request
 *
 * @param[in] fd
 * @param[in, out] sd Session Data
 * @param[in] state Pincode Edit State
 */
static void pincode_makestate(struct socket_data *session,
	struct char_session_data *sd, enum pincode_make_response state
) {
	nullpo_retv(sd);

	WFIFOHEAD(session, 8, true);
	WFIFOW(session, 0) = 0x8bb;
	WFIFOW(session, 2) = state;
	WFIFOL(session, 4) = sd->pincode_seed;
	WFIFOSET(session, 8);
}

/**
 * 0x8bf Answer to a pincode edit request
 * Changes current pincode_seed
 *
 * @param[in] fd
 * @param[in, out] sd Session Data
 * @param[in] state Pincode Edit State
 * @see enum pincode_edit_response
 */
static void pincode_editstate(struct socket_data *session,
	struct char_session_data *sd, enum pincode_edit_response state
) {
	nullpo_retv(sd);

	WFIFOHEAD(session, 8, true);
	WFIFOW(session, 0) = 0x8bf;
	WFIFOW(session, 2) = state;
	WFIFOL(session, 4) = sd->pincode_seed = rnd() % 0xFFFF;
	WFIFOSET(session, 8);
}

/**
 * CH_AVAILABLE_SECOND_PASSWD
 * Client request for a pincode window
 **/
static void pincode_window(struct s_receive_action_data *act,
	struct char_session_data *sd, int ipl)
{
	if(RFIFOL(act,2) != sd->account_id)
		return;
	pincode->loginstate(act->session, sd, PINCODE_LOGIN_NOTSET);
}

/**
 * 0x8b9 Pincode request/response
 * @see enum pincode_login_response
 **/
static void pincode_loginstate(struct socket_data *session,
	struct char_session_data *sd, enum pincode_login_response state
) {
	nullpo_retv(sd);

	WFIFOHEAD(session, 12, true);
	WFIFOW(session, 0) = 0x8b9;
	WFIFOL(session, 2) = sd->pincode_seed = rnd() % 0xFFFF;
	WFIFOL(session, 6) = sd->account_id;
	WFIFOW(session, 10) = state;
	WFIFOSET(session, 12);
}

/**
 * 0xae9 Pincode request/response
 * @see enum pincode_login_response
 * @remarks
 * [4144] pincode_loginstate2 can replace pincode_loginstate,
 * but kro using pincode_loginstate2 only for send wrong pin error or locked after 3 pins wrong
 **/
static void pincode_loginstate2(struct socket_data *session, struct char_session_data *sd,
	enum pincode_login_response state, enum pincode_login_response2 flag
) {
#if PACKETVER_MAIN_NUM >= 20180124 || PACKETVER_RE_NUM >= 20180124 || PACKETVER_ZERO_NUM >= 20180131
	nullpo_retv(sd);

	WFIFOHEAD(session, 13, true);
	WFIFOW(session, 0) = 0xae9;
	WFIFOL(session, 2) = sd->pincode_seed = rnd() % 0xFFFF;
	WFIFOL(session, 6) = sd->account_id;
	WFIFOW(session, 10) = state;
	WFIFOW(session, 12) = flag;
	WFIFOSET(session, 13);
#endif
}

/**
 * Decrypts received pincode
 *
 * @param userSeed User seed used to decrypt
 * @param pin Pincode to be decrypted (IN/OUT)
 **/
static void pincode_decrypt(unsigned int userSeed, char *pin)
{
	int i;
	char tab[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

	nullpo_retv(pin);

	for (i = 1; i < 10; i++) {
		int pos;
		userSeed = pincode->baseSeed + userSeed * pincode->multiplier;
		pos = userSeed % (i + 1);
		if (i != pos) {
			tab[i] ^= tab[pos];
			tab[pos] ^= tab[i];
			tab[i] ^= tab[pos];
		}
	}

	for (i = 0; i < 4; i++) {
		if (pin[i] < '0' || pin[i] > '9')
			pin[i] = '0';
		else
			pin[i] = tab[pin[i] - '0'];
	}

	sprintf(pin, "%d%d%d%d", pin[0], pin[1], pin[2], pin[3]);
}

/**
 * Reads the 'char_configuration/pincode' config entry and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool pincode_config_read(const char *filename, const struct config_t *config, bool imported)
{
	const struct config_setting_t *setting = NULL;
	const struct config_setting_t *temp = NULL;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "char_configuration/pincode")) == NULL) {
		if (imported)
			return true;
		ShowError("char_config_read: char_configuration/pincode was not found in %s!\n", filename);
		return false;
	}

	if (libconfig->setting_lookup_bool(setting, "enabled", &pincode->enabled) == CONFIG_TRUE) {
#if PACKETVER < 20110309
		if (pincode->enabled) {
			ShowWarning("pincode_enabled requires PACKETVER 20110309 or higher. disabling...\n");
			pincode->enabled = 0;
		}
#endif
	}

	if (libconfig->setting_lookup_int(setting, "change_time", &pincode->changetime) == CONFIG_TRUE)
		pincode->changetime *= 60;

	if (libconfig->setting_lookup_int(setting, "max_tries", &pincode->maxtry) == CONFIG_TRUE) {
		if (pincode->maxtry > 3) {
			ShowWarning("pincode_maxtry is too high (%d); Maximum allowed: 3! Capping to 3...\n",pincode->maxtry);
			pincode->maxtry = 3;
		}
	}

	if (libconfig->setting_lookup_int(setting, "request", &pincode->charselect) == CONFIG_TRUE) {
		if (pincode->charselect != 1 && pincode->charselect != 0) {
			ShowWarning("Invalid pincode/request! Defaulting to 0\n");
			pincode->charselect = 0;
		}
	}

	if (libconfig->setting_lookup_bool_real(setting, "check_blacklisted", &pincode->check_blacklist) == CONFIG_FALSE) {
		if (!imported) {
			ShowWarning("pincode 'check_blacklisted' not found, defaulting to false...\n");
			pincode->check_blacklist = false;
		}
	}

	if (pincode->check_blacklist) {
		if ((temp = libconfig->setting_get_member(setting, "blacklist")) != NULL) {
			VECTOR_DECL(char *) duplicate;
			int i, j, size = libconfig->setting_length(temp);
			VECTOR_INIT(duplicate);
			VECTOR_ENSURE(duplicate, size, 1);
			for (i = 0; i < size; i++) {
				const char *pin = libconfig->setting_get_string_elem(temp, i);

				if (pin == NULL)
					continue;

				if (strlen(pin) != 4) {
					ShowError("Wrong size on element %d of blacklist. Desired size = 4, received = %d\n", i, (int)strlen(pin));
					continue;
				}

				ARR_FIND(0, VECTOR_LENGTH(duplicate), j, strcmp(VECTOR_INDEX(duplicate, j), pin) == 0);

				if (j < VECTOR_LENGTH(duplicate)) {
					ShowWarning("Duplicate pin on pincode blacklist. Item #%d\n", i);
					continue;
				}

				VECTOR_ENSURE(pincode->blacklist, 1, 1);
				VECTOR_PUSH(pincode->blacklist, aStrdup(pin));
				VECTOR_PUSH(duplicate, aStrdup(pin));
			}
			while (VECTOR_LENGTH(duplicate) > 0) {
				aFree(VECTOR_POP(duplicate));
			}
			VECTOR_CLEAR(duplicate);
		} else if (!imported) {
			ShowError("Pincode Blacklist Check is enabled but there's no blacklist setting! Disabling check.\n");
			pincode->check_blacklist = false;
		}
	}

	return true;
}

static void do_pincode_init(void)
{
	VECTOR_INIT(pincode->blacklist);
}

static void do_pincode_final(void)
{
	while (VECTOR_LENGTH(pincode->blacklist) > 0) {
		aFree(VECTOR_POP(pincode->blacklist));
	}
	VECTOR_CLEAR(pincode->blacklist);
}

void pincode_defaults(void)
{
	pincode = &pincode_s;

	pincode->enabled = 0;
	pincode->changetime = 0;
	pincode->maxtry = 3;
	pincode->charselect = 0;
	pincode->check_blacklist = false;
	pincode->multiplier = 0x3498;
	pincode->baseSeed = 0x881234;

	pincode->init = do_pincode_init;
	pincode->final = do_pincode_final;

	pincode->handle = pincode_handle;
	pincode->disconnect = pincode_disconnect;
	pincode->decrypt = pincode_decrypt;
	pincode->makestate = pincode_makestate;
	pincode->editstate = pincode_editstate;
	pincode->loginstate = pincode_loginstate;
	pincode->loginstate2 = pincode_loginstate2;
	pincode->setnew = pincode_setnew;
	pincode->change = pincode_change;
	pincode->isBlacklisted = pincode_isBlacklisted;
	pincode->compare = pincode_compare;
	pincode->check = pincode_check;
	pincode->config_read = pincode_config_read;
}
