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

#include "inter.h"

#include "char/char.h"
#include "char/geoip.h"
#include "char/int_auction.h"
#include "char/int_clan.h"
#include "char/int_elemental.h"
#include "char/int_guild.h"
#include "char/int_homun.h"
#include "char/int_mail.h"
#include "char/int_mercenary.h"
#include "char/int_party.h"
#include "char/int_pet.h"
#include "char/int_quest.h"
#include "char/int_rodex.h"
#include "char/int_storage.h"
#include "char/int_achievement.h"
#include "char/mapif.h"
#include "char/loginif.h"
#include "common/cbasetypes.h"
#include "common/conf.h"
#include "common/db.h"
#include "common/memmgr.h"
#include "common/mmo.h"
#include "common/nullpo.h"
#include "common/showmsg.h"
#include "common/socket.h"
#include "common/sql.h"
#include "common/strlib.h"
#include "common/timer.h"

#include <stdio.h>
#include <stdlib.h>

static struct inter_interface inter_s;
struct inter_interface *inter;

static int char_server_port = 3306;
static char char_server_ip[32] = "127.0.0.1";
static char char_server_id[32] = "ragnarok";
static char char_server_pw[100] = "ragnarok";
static char char_server_db[32] = "ragnarok";
static char default_codepage[32] = ""; //Feature by irmin.

int party_share_level = 10;

#define MAX_JOB_NAMES 150
static char *msg_table[MAX_JOB_NAMES]; //  messages 550 ~ 699 are job names

static const char *inter_msg_txt(int msg_number)
{
	msg_number -= 550;
	if (msg_number >= 0 && msg_number < MAX_JOB_NAMES &&
	    msg_table[msg_number] != NULL && msg_table[msg_number][0] != '\0')
		return msg_table[msg_number];

	return "Unknown";
}

/**
 * Reads Message Data.
 *
 * This is a modified version of the mapserver's inter->msg_config_read to
 * only read messages with IDs between 550 and 550+MAX_JOB_NAMES.
 *
 * @param[in] cfg_name       configuration filename to read.
 * @param[in] allow_override whether to allow duplicate message IDs to override the original value.
 * @return success state.
 */
static bool inter_msg_config_read(const char *cfg_name, bool allow_override)
{
	int msg_number;
	char line[1024], w1[1024], w2[1024];
	FILE *fp;
	static int called = 1;

	nullpo_ret(cfg_name);
	if ((fp = fopen(cfg_name, "r")) == NULL) {
		ShowError("Messages file not found: %s\n", cfg_name);
		return 1;
	}

	if ((--called) == 0)
		memset(msg_table, 0, sizeof(msg_table[0]) * MAX_JOB_NAMES);

	while(fgets(line, sizeof(line), fp) ) {
		if (line[0] == '/' && line[1] == '/')
			continue;
		if (sscanf(line, "%1023[^:]: %1023[^\r\n]", w1, w2) != 2)
			continue;

		if (strcmpi(w1, "import") == 0)
			inter->msg_config_read(w2, true);
		else {
			msg_number = atoi(w1);
			if( msg_number < 550 || msg_number > (550+MAX_JOB_NAMES) )
				continue;
			msg_number -= 550;
			if (msg_number >= 0 && msg_number < MAX_JOB_NAMES) {
				if (msg_table[msg_number] != NULL) {
					if (!allow_override) {
						ShowError("Duplicate message: ID '%d' was already used for '%s'. Message '%s' will be ignored.\n",
						          msg_number, w2, msg_table[msg_number]);
						continue;
					}
					aFree(msg_table[msg_number]);
				}
				msg_table[msg_number] = (char *)aMalloc((strlen(w2) + 1)*sizeof (char));
				strcpy(msg_table[msg_number],w2);
			}
		}
	}

	fclose(fp);

	return 0;
}

/*==========================================
 * Cleanup Message Data
 *------------------------------------------*/
static void inter_do_final_msg(void)
{
	int i;
	for (i = 0; i < MAX_JOB_NAMES; i++)
		aFree(msg_table[i]);
}
/* from pc.c due to @accinfo. any ideas to replace this crap are more than welcome. */
static const char *inter_job_name(int class)
{
	switch (class) {
		case JOB_NOVICE:   // 550
		case JOB_SWORDMAN: // 551
		case JOB_MAGE:     // 552
		case JOB_ARCHER:   // 553
		case JOB_ACOLYTE:  // 554
		case JOB_MERCHANT: // 555
		case JOB_THIEF:    // 556
			return inter->msg_txt(550 - JOB_NOVICE + class);

		case JOB_KNIGHT:     // 557
		case JOB_PRIEST:     // 558
		case JOB_WIZARD:     // 559
		case JOB_BLACKSMITH: // 560
		case JOB_HUNTER:     // 561
		case JOB_ASSASSIN:   // 562
			return inter->msg_txt(557 - JOB_KNIGHT + class);

		case JOB_KNIGHT2:
			return inter->msg_txt(557);

		case JOB_CRUSADER:  // 563
		case JOB_MONK:      // 564
		case JOB_SAGE:      // 565
		case JOB_ROGUE:     // 566
		case JOB_ALCHEMIST: // 567
		case JOB_BARD:      // 568
		case JOB_DANCER:    // 569
			return inter->msg_txt(563 - JOB_CRUSADER + class);

		case JOB_CRUSADER2:
			return inter->msg_txt(563);

		case JOB_WEDDING:      // 570
		case JOB_SUPER_NOVICE: // 571
		case JOB_GUNSLINGER:   // 572
		case JOB_NINJA:        // 573
		case JOB_XMAS:         // 574
			return inter->msg_txt(570 - JOB_WEDDING + class);

		case JOB_SUMMER:
			return inter->msg_txt(621);

		case JOB_NOVICE_HIGH:   // 575
		case JOB_SWORDMAN_HIGH: // 576
		case JOB_MAGE_HIGH:     // 577
		case JOB_ARCHER_HIGH:   // 578
		case JOB_ACOLYTE_HIGH:  // 579
		case JOB_MERCHANT_HIGH: // 580
		case JOB_THIEF_HIGH:    // 581
			return inter->msg_txt(575 - JOB_NOVICE_HIGH + class);

		case JOB_LORD_KNIGHT:    // 582
		case JOB_HIGH_PRIEST:    // 583
		case JOB_HIGH_WIZARD:    // 584
		case JOB_WHITESMITH:     // 585
		case JOB_SNIPER:         // 586
		case JOB_ASSASSIN_CROSS: // 587
			return inter->msg_txt(582 - JOB_LORD_KNIGHT + class);

		case JOB_LORD_KNIGHT2:
			return inter->msg_txt(582);

		case JOB_PALADIN:   // 588
		case JOB_CHAMPION:  // 589
		case JOB_PROFESSOR: // 590
		case JOB_STALKER:   // 591
		case JOB_CREATOR:   // 592
		case JOB_CLOWN:     // 593
		case JOB_GYPSY:     // 594
			return inter->msg_txt(588 - JOB_PALADIN + class);

		case JOB_PALADIN2:
			return inter->msg_txt(588);

		case JOB_BABY:          // 595
		case JOB_BABY_SWORDMAN: // 596
		case JOB_BABY_MAGE:     // 597
		case JOB_BABY_ARCHER:   // 598
		case JOB_BABY_ACOLYTE:  // 599
		case JOB_BABY_MERCHANT: // 600
		case JOB_BABY_THIEF:    // 601
			return inter->msg_txt(595 - JOB_BABY + class);

		case JOB_BABY_KNIGHT:     // 602
		case JOB_BABY_PRIEST:     // 603
		case JOB_BABY_WIZARD:     // 604
		case JOB_BABY_BLACKSMITH: // 605
		case JOB_BABY_HUNTER:     // 606
		case JOB_BABY_ASSASSIN:   // 607
			return inter->msg_txt(602 - JOB_BABY_KNIGHT + class);

		case JOB_BABY_KNIGHT2:
			return inter->msg_txt(602);

		case JOB_BABY_CRUSADER:  // 608
		case JOB_BABY_MONK:      // 609
		case JOB_BABY_SAGE:      // 610
		case JOB_BABY_ROGUE:     // 611
		case JOB_BABY_ALCHEMIST: // 612
		case JOB_BABY_BARD:      // 613
		case JOB_BABY_DANCER:    // 614
			return inter->msg_txt(608 - JOB_BABY_CRUSADER + class);

		case JOB_BABY_CRUSADER2:
			return inter->msg_txt(608);

		case JOB_SUPER_BABY:
			return inter->msg_txt(615);

		case JOB_TAEKWON:
			return inter->msg_txt(616);
		case JOB_STAR_GLADIATOR:
		case JOB_STAR_GLADIATOR2:
			return inter->msg_txt(617);
		case JOB_SOUL_LINKER:
			return inter->msg_txt(618);

		case JOB_GANGSI:         // 622
		case JOB_DEATH_KNIGHT:   // 623
		case JOB_DARK_COLLECTOR: // 624
			return inter->msg_txt(622 - JOB_GANGSI + class);

		case JOB_RUNE_KNIGHT:      // 625
		case JOB_WARLOCK:          // 626
		case JOB_RANGER:           // 627
		case JOB_ARCH_BISHOP:      // 628
		case JOB_MECHANIC:         // 629
		case JOB_GUILLOTINE_CROSS: // 630
			return inter->msg_txt(625 - JOB_RUNE_KNIGHT + class);

		case JOB_RUNE_KNIGHT_T:      // 656
		case JOB_WARLOCK_T:          // 657
		case JOB_RANGER_T:           // 658
		case JOB_ARCH_BISHOP_T:      // 659
		case JOB_MECHANIC_T:         // 660
		case JOB_GUILLOTINE_CROSS_T: // 661
			return inter->msg_txt(656 - JOB_RUNE_KNIGHT_T + class);

		case JOB_ROYAL_GUARD:   // 631
		case JOB_SORCERER:      // 632
		case JOB_MINSTREL:      // 633
		case JOB_WANDERER:      // 634
		case JOB_SURA:          // 635
		case JOB_GENETIC:       // 636
		case JOB_SHADOW_CHASER: // 637
			return inter->msg_txt(631 - JOB_ROYAL_GUARD + class);

		case JOB_ROYAL_GUARD_T:   // 662
		case JOB_SORCERER_T:      // 663
		case JOB_MINSTREL_T:      // 664
		case JOB_WANDERER_T:      // 665
		case JOB_SURA_T:          // 666
		case JOB_GENETIC_T:       // 667
		case JOB_SHADOW_CHASER_T: // 668
			return inter->msg_txt(662 - JOB_ROYAL_GUARD_T + class);

		case JOB_RUNE_KNIGHT2:
			return inter->msg_txt(625);

		case JOB_RUNE_KNIGHT_T2:
			return inter->msg_txt(656);

		case JOB_ROYAL_GUARD2:
			return inter->msg_txt(631);

		case JOB_ROYAL_GUARD_T2:
			return inter->msg_txt(662);

		case JOB_RANGER2:
			return inter->msg_txt(627);

		case JOB_RANGER_T2:
			return inter->msg_txt(658);

		case JOB_MECHANIC2:
			return inter->msg_txt(629);

		case JOB_MECHANIC_T2:
			return inter->msg_txt(660);

		case JOB_BABY_RUNE:     // 638
		case JOB_BABY_WARLOCK:  // 639
		case JOB_BABY_RANGER:   // 640
		case JOB_BABY_BISHOP:   // 641
		case JOB_BABY_MECHANIC: // 642
		case JOB_BABY_CROSS:    // 643
		case JOB_BABY_GUARD:    // 644
		case JOB_BABY_SORCERER: // 645
		case JOB_BABY_MINSTREL: // 646
		case JOB_BABY_WANDERER: // 647
		case JOB_BABY_SURA:     // 648
		case JOB_BABY_GENETIC:  // 649
		case JOB_BABY_CHASER:   // 650
			return inter->msg_txt(638 - JOB_BABY_RUNE + class);

		case JOB_BABY_RUNE2:
			return inter->msg_txt(638);

		case JOB_BABY_GUARD2:
			return inter->msg_txt(644);

		case JOB_BABY_RANGER2:
			return inter->msg_txt(640);

		case JOB_BABY_MECHANIC2:
			return inter->msg_txt(642);

		case JOB_SUPER_NOVICE_E: // 651
		case JOB_SUPER_BABY_E:   // 652
			return inter->msg_txt(651 - JOB_SUPER_NOVICE_E + class);

		case JOB_KAGEROU: // 653
		case JOB_OBORO:   // 654
			return inter->msg_txt(653 - JOB_KAGEROU + class);

		case JOB_REBELLION:
			return inter->msg_txt(655);

		case JOB_SUMMONER:
			return inter->msg_txt(669);

		default:
			return inter->msg_txt(620); // "Unknown Job"
	}
}

/**
 * 0x3807 WZ_MSG_TO_FD
 * Argument-list version of inter_msg_to_fd
 * @see inter_msg_to_fd
 */
static void inter_vmsg_to_fd(int map_id, int u_fd, int aid, char *msg, va_list ap)
{
	char msg_out[512];
	va_list apcopy;
	int len = 1;/* yes we start at 1 */

	struct socket_data *session = socket_io->session_from_id(map_id);
	if(!session)
		return;

	nullpo_retv(msg);
	va_copy(apcopy, ap);
	len += vsnprintf(msg_out, 512, msg, apcopy);
	va_end(apcopy);

	WFIFOHEAD(session, 12 + len, true);

	WFIFOW(session,0) = 0x3807;
	WFIFOW(session,2) = 12 + (unsigned short)len;
	WFIFOL(session,4) = u_fd;
	WFIFOL(session,8) = aid;
	safestrncpy(WFIFOP(session,12), msg_out, len);

	WFIFOSET(session,12 + len);

	return;
}

/**
 * Sends a message to map server (id) to a user (u_fd) although we use fd we
 * keep aid for safe-check.
 * @param map_id   Mapserver's id
 * @param u_fd     Recipient's fd
 * @param aid      Recipient's expected for sanity checks on the mapserver
 * @param msg      Message format string
 * @param ...      Additional parameters for (v)sprinf
 */
static void inter_msg_to_fd(int map_id, int u_fd, int aid, char *msg, ...) __attribute__((format(printf, 4, 5)));
static void inter_msg_to_fd(int map_id, int u_fd, int aid, char *msg, ...)
{
	va_list ap;
	va_start(ap,msg);
	inter->vmsg_to_fd(map_id, u_fd, aid, msg, ap);
	va_end(ap);
}

/** 
 * Performs rename operation in provided char-id (used in map-server requests)
 *
 * @param esc_name Escaped and normalized name.
 * @retval 0 Successfuly updated name
 * @retval 2 Duplicate
 * @retval 3 Already renamed
 * @see mapif_parse_NameChangeRequest
 *
 * @remarks
 * Regular name change operations are performed only when the player is logged
 * in the char-server via @see char_rename_char_sql
 **/
static uint8 inter_char_rename(int char_id, int guild_id, const char *esc_name)
{
	/**
	 * There's no need to check if the name is in use when performing the update, the 
	 * `name` field is defined as UNIQUE, so the query will simply fail if there's
	 * a duplicate. This way we avoid possible data-races of multiple simultaneous writes.
	 **/
	int sql_result = 
	SQL->Query(inter->sql_handle,
		"UPDATE `%s` SET `name` = '%s', `rename` = rename-1 WHERE `char_id` = '%d' AND `rename` > 0",
		char_db, esc_name, char_id);
	if(SQL_ERROR == sql_result) {
		Sql_ShowDebug(inter->sql_handle);
		return 2; // Duplicate
	}
	if(SQL->NumAffectedRows(inter->sql_handle) <= 0)
		return 3; // Already renamed

	// Change character's name into guild_db.
	if(guild_id)
		inter_guild->charname_changed(guild_id, char_id, esc_name);

	// log change
	if(chr->enable_logs) {
		if(SQL_ERROR == SQL->Query(inter->sql_handle,
					"INSERT INTO `%s` ("
					" `time`, `char_msg`, `char_id`, `name`"
					") VALUES ("
					" NOW(), 'change char name (inter request)', '%d', '%d'"
					")",
					charlog_db,
					char_id, esc_name
					))
			Sql_ShowDebug(inter->sql_handle);
	}

	return 0;
}

/**
 * Processes account information request and relays to login-server
 * When the account isn't found relays message to map-server via inter->msg_to_fd,
 * otherwise calls loginif->accinfo_request and sends 0x2740 to login.
 *
 * @param u_fd        Requester fd
 * @param aid         AID to be searched for (-1 search for query instead)
 * @param castergroup Requester group level
 * @param query       Character name to be searched for
 * @param map_id      Session id of the requester map server
 * @author [Dekamaster/Nightroad]
 * @remarks Triggered by 0x3007 @see mapif->parse_accinfo
 *
 * [Map]   0x3007 ZW_ACCINFO_REQUEST
 * [Char]  0x2740 WA_ACCOUNT_INFO_REQUEST
 * [Login] 0x2743 (success) / 0x2744 (failed)
 * [Char]  0x3807 WZ_MSG_TO_FD
 **/
static void inter_accinfo(int u_fd, int aid, int castergroup, const char *query, int map_id)
{
	char query_esq[NAME_LENGTH*2+1];
	int account_id;
	char *data;

	SQL->EscapeString(inter->sql_handle, query_esq, query);

	account_id = atoi(query);

	if (account_id < START_ACCOUNT_NUM) {
		// Search for name
		if ( SQL_ERROR == SQL->Query(inter->sql_handle, "SELECT `account_id`,`name`,"
			"`class`,`base_level`,`job_level`,`online` FROM `%s` WHERE `name` "
			"LIKE '%s' LIMIT 10", char_db, query_esq)
				|| SQL->NumRows(inter->sql_handle) == 0
		) {
			if( SQL->NumRows(inter->sql_handle) == 0 ) {
				inter->msg_to_fd(map_id, u_fd, aid, "No matches were found for "
					"your criteria, '%s'", query);
			} else {
				Sql_ShowDebug(inter->sql_handle);
				inter->msg_to_fd(map_id, u_fd, aid, "An error occurred, bother "
					"your admin about it.");
			}
			SQL->FreeResult(inter->sql_handle);
			return;
		}
		// We found a perfect match
		if( SQL->NumRows(inter->sql_handle) == 1 ) {
			SQL->NextRow(inter->sql_handle);
			SQL->GetData(inter->sql_handle, 0, &data, NULL); account_id = atoi(data);
			SQL->FreeResult(inter->sql_handle);
		} else {// more than one, listing... [Dekamaster/Nightroad]
			inter->msg_to_fd(map_id, u_fd, aid, "Your query returned the "
				"following %d results, please be more specific...",
				(int)SQL->NumRows(inter->sql_handle));
			while ( SQL_SUCCESS == SQL->NextRow(inter->sql_handle) ) {
				int class;
				int base_level, job_level, online;
				char name[NAME_LENGTH];

				SQL->GetData(inter->sql_handle, 0, &data, NULL); account_id = atoi(data);
				SQL->GetData(inter->sql_handle, 1, &data, NULL); safestrncpy(name, data, sizeof(name));
				SQL->GetData(inter->sql_handle, 2, &data, NULL); class = atoi(data);
				SQL->GetData(inter->sql_handle, 3, &data, NULL); base_level = atoi(data);
				SQL->GetData(inter->sql_handle, 4, &data, NULL); job_level = atoi(data);
				SQL->GetData(inter->sql_handle, 5, &data, NULL); online = atoi(data);

				inter->msg_to_fd(map_id, u_fd, aid, "[AID: %d] %s | %s | "
					"Level: %d/%d | %s", account_id, name, inter->job_name(class),
					base_level, job_level, online?"Online":"Offline");
			}
			SQL->FreeResult(inter->sql_handle);
			return;
		}
	}

	/* it will only get here if we have a single match */
	/* and we will send packet with account id to login server asking for account info */
	if( account_id ) {
		loginif->accinfo_request(account_id, u_fd, aid, castergroup, map_id);
	}

	return;
}

/**
 * Answers an account information request from map-server using msg_to_fd
 *
 * @param success    Was the account found
 * @param map_id     Session id of map-server that requested information
 * @param u_fd       Requester fd
 * @param u_aid      Requester account id
 * @param userid     Targets login
 * @param email      Targets e-mail
 * @param last-ip    Targets last ip
 * @param lastlogin  Targets last login date
 * @param birthdate  Targets birthdate
 * @param group_id   Targets group id
 * @param logincount Targets login count
 * @param state      Targets state
 * @see inter_accinfo
 **/
static void inter_accinfo_ack(bool success, int map_id, int u_fd, int u_aid, int account_id, const char *userid,
		const char *email, const char *last_ip, const char *lastlogin, const char *birthdate,
		int group_id, int logincount, int state)
{
	struct socket_data *map_session = socket_io->session_from_id(map_id);
	if(!map_session)
		return; // check if we have a valid fd

	if (!success) {
		inter->msg_to_fd(map_id, u_fd, u_aid, "No account with ID '%d' was found.", account_id);
		return;
	}

	inter->msg_to_fd(map_id, u_fd, u_aid, "-- Account %d --", account_id);
	inter->msg_to_fd(map_id, u_fd, u_aid, "User: %s | GM Group: %d | State: %d",
		userid, group_id, state);

	inter->msg_to_fd(map_id, u_fd, u_aid, "Account e-mail: %s | Birthdate: %s",
		email, birthdate);
	inter->msg_to_fd(map_id, u_fd, u_aid, "Last IP: %s (%s)", last_ip,
		geoip->getcountry(socket_io->str2ip(last_ip)));
	inter->msg_to_fd(map_id, u_fd, u_aid, "This user has logged %d times, the "
		"last time were at %s", logincount, lastlogin);
	inter->msg_to_fd(map_id, u_fd, u_aid, "-- Character Details --");

	if ( SQL_ERROR == SQL->Query(inter->sql_handle, "SELECT `char_id`, `name`, "
		"`char_num`, `class`, `base_level`, `job_level`, `online` "
	    "FROM `%s` WHERE `account_id` = '%d' ORDER BY `char_num` LIMIT %d",
		char_db, account_id, MAX_CHARS)
	  || SQL->NumRows(inter->sql_handle) == 0
	) {
		if (SQL->NumRows(inter->sql_handle) == 0) {
			inter->msg_to_fd(map_id, u_fd, u_aid, "This account doesn't have characters.");
		} else {
			inter->msg_to_fd(map_id, u_fd, u_aid, "An error occurred, bother your admin about it.");
			Sql_ShowDebug(inter->sql_handle);
		}
	} else {
		while ( SQL_SUCCESS == SQL->NextRow(inter->sql_handle) ) {
			char *data;
			int char_id, class;
			int char_num, base_level, job_level, online;
			char name[NAME_LENGTH];

			SQL->GetData(inter->sql_handle, 0, &data, NULL); char_id = atoi(data);
			SQL->GetData(inter->sql_handle, 1, &data, NULL); safestrncpy(name, data, sizeof(name));
			SQL->GetData(inter->sql_handle, 2, &data, NULL); char_num = atoi(data);
			SQL->GetData(inter->sql_handle, 3, &data, NULL); class = atoi(data);
			SQL->GetData(inter->sql_handle, 4, &data, NULL); base_level = atoi(data);
			SQL->GetData(inter->sql_handle, 5, &data, NULL); job_level = atoi(data);
			SQL->GetData(inter->sql_handle, 6, &data, NULL); online = atoi(data);

			inter->msg_to_fd(map_id, u_fd, u_aid, "[Slot/CID: %d/%d] %s | %s | "
				"Level: %d/%d | %s", char_num, char_id, name,
				inter->job_name(class), base_level, job_level, online?"On":"Off");
		}
	}
	SQL->FreeResult(inter->sql_handle);

	return;
}
/**
 * Handles save reg data from map server and distributes accordingly.
 *
 * @param val either str or int, depending on type
 * @param type false when int, true otherwise
 **/
static void inter_savereg(int account_id, int char_id, const char *key, unsigned int index, intptr_t val, bool is_string)
{
	char val_esq[1000];
	nullpo_retv(key);
	/* to login server we go! */
	if( key[0] == '#' && key[1] == '#' ) {/* global account reg */
		if(chr->login_session)
			loginif->save_accreg2_entry(key, index, val, is_string);
		else {
			ShowError("Login server unavailable, cant perform update on '%s' variable "
				"for AID:%d CID:%d\n",key,account_id,char_id);
		}
		return;
	}
	if ( key[0] == '#' ) {/* local account reg */
		if( is_string ) {
			if( val ) {
				SQL->EscapeString(inter->sql_handle, val_esq, (char*)val);
				if( SQL_ERROR == SQL->Query(inter->sql_handle, "REPLACE INTO `%s` (`account_id`,`key`,`index`,`value`) VALUES ('%d','%s','%u','%s')", acc_reg_str_db, account_id, key, index, val_esq) )
					Sql_ShowDebug(inter->sql_handle);
			} else {
				if( SQL_ERROR == SQL->Query(inter->sql_handle, "DELETE FROM `%s` WHERE `account_id` = '%d' AND `key` = '%s' AND `index` = '%u' LIMIT 1", acc_reg_str_db, account_id, key, index) )
					Sql_ShowDebug(inter->sql_handle);
			}
		} else {
			if( val ) {
				if( SQL_ERROR == SQL->Query(inter->sql_handle, "REPLACE INTO `%s` (`account_id`,`key`,`index`,`value`) VALUES ('%d','%s','%u','%d')", acc_reg_num_db, account_id, key, index, (int)val) )
					Sql_ShowDebug(inter->sql_handle);
			} else {
				if( SQL_ERROR == SQL->Query(inter->sql_handle, "DELETE FROM `%s` WHERE `account_id` = '%d' AND `key` = '%s' AND `index` = '%u' LIMIT 1", acc_reg_num_db, account_id, key, index) )
					Sql_ShowDebug(inter->sql_handle);
			}
		}
		return;
	}

	/* char reg */
	if( is_string ) {
		if( val ) {
			SQL->EscapeString(inter->sql_handle, val_esq, (char*)val);
			if( SQL_ERROR == SQL->Query(inter->sql_handle, "REPLACE INTO `%s` (`char_id`,`key`,`index`,`value`) VALUES ('%d','%s','%u','%s')", char_reg_str_db, char_id, key, index, val_esq) )
				Sql_ShowDebug(inter->sql_handle);
		} else {
			if( SQL_ERROR == SQL->Query(inter->sql_handle, "DELETE FROM `%s` WHERE `char_id` = '%d' AND `key` = '%s' AND `index` = '%u' LIMIT 1", char_reg_str_db, char_id, key, index) )
				Sql_ShowDebug(inter->sql_handle);
		}
	} else {
		if( val ) {
			if( SQL_ERROR == SQL->Query(inter->sql_handle, "REPLACE INTO `%s` (`char_id`,`key`,`index`,`value`) VALUES ('%d','%s','%u','%d')", char_reg_num_db, char_id, key, index, (int)val) )
				Sql_ShowDebug(inter->sql_handle);
		} else {
			if( SQL_ERROR == SQL->Query(inter->sql_handle, "DELETE FROM `%s` WHERE `char_id` = '%d' AND `key` = '%s' AND `index` = '%u' LIMIT 1", char_reg_num_db, char_id, key, index) )
				Sql_ShowDebug(inter->sql_handle);
		}
	}
}

/**
 * Sends all account-specific registry information (0x3804)
 *  At least one packet per type is sent, and if either has more than 6000bytes it's broken into
 *  more packets.
 *  The last packet has <is complete> marked.
 * 0x3804 <account_id>.L <char_id>.L <is complete>.B <var type>.B <count>.W {vessel type}
 * @param type 1 account2 (login-server)
 *             2 account
 *             3 character
 * This is the same packet as account_mmo_send_accreg2
 **/
static int inter_accreg_fromsql(int account_id, int char_id, struct socket_data *session, int type)
{
	char* data;
	size_t len;
	unsigned int plen = 0;

	switch( type ) {
		case 3: //char reg
			if( SQL_ERROR == SQL->Query(inter->sql_handle, "SELECT `key`, `index`, `value` FROM `%s` WHERE `char_id`='%d'", char_reg_str_db, char_id) )
				Sql_ShowDebug(inter->sql_handle);
			break;
		case 2: //account reg
			if( SQL_ERROR == SQL->Query(inter->sql_handle, "SELECT `key`, `index`, `value` FROM `%s` WHERE `account_id`='%d'", acc_reg_str_db, account_id) )
				Sql_ShowDebug(inter->sql_handle);
			break;
		case 1: //account2 reg
			ShowError("inter->accreg_fromsql: Char server shouldn't handle type 1 registry values (##). That is the login server's work!\n");
			return 0;
		default:
			ShowError("inter->accreg_fromsql: Invalid type %d\n", type);
			return 0;
	}

	WFIFOHEAD(session, 60000 + 300, true);
	WFIFOW(session, 0) = 0x3804;
	/* 0x2 = length, set prior to being sent */
	WFIFOL(session, 4) = account_id;
	WFIFOL(session, 8) = char_id;
	WFIFOB(session, 12) = 0;/* var type (only set when all vars have been sent, regardless of type) */
	WFIFOB(session, 13) = 1;/* is string type */
	WFIFOW(session, 14) = 0;/* count */
	plen = 16;

	/**
	 * Vessel!
	 *
	 * str type
	 * { keyLength(B), key(<keyLength>), index(L), valLength(B), val(<valLength>) }
	 **/
	while ( SQL_SUCCESS == SQL->NextRow(inter->sql_handle) ) {
		SQL->GetData(inter->sql_handle, 0, &data, NULL);
		len = strlen(data)+1;

		WFIFOB(session, plen) = (unsigned char)len;/* won't be higher; the column size is 32 */
		plen += 1;

		safestrncpy(WFIFOP(session,plen), data, len);
		plen += len;

		SQL->GetData(inter->sql_handle, 1, &data, NULL);

		WFIFOL(session, plen) = (unsigned int)atol(data);
		plen += 4;

		SQL->GetData(inter->sql_handle, 2, &data, NULL);
		len = strlen(data);

		WFIFOB(session, plen) = (unsigned char)len; // Won't be higher; the column size is 255.
		plen += 1;

		safestrncpy(WFIFOP(session, plen), data, len + 1);
		plen += len + 1;

		WFIFOW(session, 14) += 1;

		if( plen > 60000 ) {
			WFIFOW(session, 2) = plen;
			WFIFOSET(session, plen);

			/* prepare follow up */
			WFIFOHEAD(session, 60000 + 300, true);
			WFIFOW(session, 0) = 0x3804;
			/* 0x2 = length, set prior to being sent */
			WFIFOL(session, 4) = account_id;
			WFIFOL(session, 8) = char_id;
			WFIFOB(session, 12) = 0;/* var type (only set when all vars have been sent, regardless of type) */
			WFIFOB(session, 13) = 1;/* is string type */
			WFIFOW(session, 14) = 0;/* count */
			plen = 16;
		}
	}

	/* mark & go. */
	WFIFOW(session, 2) = plen;
	WFIFOSET(session, plen);

	SQL->FreeResult(inter->sql_handle);

	switch( type ) {
		case 3: //char reg
			if( SQL_ERROR == SQL->Query(inter->sql_handle, "SELECT `key`, `index`, `value` FROM `%s` WHERE `char_id`='%d'", char_reg_num_db, char_id) )
				Sql_ShowDebug(inter->sql_handle);
			break;
		case 2: //account reg
			if( SQL_ERROR == SQL->Query(inter->sql_handle, "SELECT `key`, `index`, `value` FROM `%s` WHERE `account_id`='%d'", acc_reg_num_db, account_id) )
				Sql_ShowDebug(inter->sql_handle);
			break;
#if 0 // This is already checked above.
		case 1: //account2 reg
			ShowError("inter->accreg_fromsql: Char server shouldn't handle type 1 registry values (##). That is the login server's work!\n");
			return 0;
#endif // 0
	}

	WFIFOHEAD(session, 60000 + 300, true);
	WFIFOW(session, 0) = 0x3804;
	/* 0x2 = length, set prior to being sent */
	WFIFOL(session, 4) = account_id;
	WFIFOL(session, 8) = char_id;
	WFIFOB(session, 12) = 0;/* var type (only set when all vars have been sent, regardless of type) */
	WFIFOB(session, 13) = 0;/* is int type */
	WFIFOW(session, 14) = 0;/* count */
	plen = 16;

	/**
	 * Vessel!
	 *
	 * int type
	 * { keyLength(B), key(<keyLength>), index(L), value(L) }
	 **/
	while ( SQL_SUCCESS == SQL->NextRow(inter->sql_handle) ) {
		SQL->GetData(inter->sql_handle, 0, &data, NULL);
		len = strlen(data)+1;

		WFIFOB(session, plen) = (unsigned char)len;/* won't be higher; the column size is 32 */
		plen += 1;

		safestrncpy(WFIFOP(session,plen), data, len);
		plen += len;

		SQL->GetData(inter->sql_handle, 1, &data, NULL);

		WFIFOL(session, plen) = (unsigned int)atol(data);
		plen += 4;

		SQL->GetData(inter->sql_handle, 2, &data, NULL);

		WFIFOL(session, plen) = atoi(data);
		plen += 4;

		WFIFOW(session, 14) += 1;

		if( plen > 60000 ) {
			WFIFOW(session, 2) = plen;
			WFIFOSET(session, plen);

			/* prepare follow up */
			WFIFOHEAD(session, 60000 + 300, true);
			WFIFOW(session, 0) = 0x3804;
			/* 0x2 = length, set prior to being sent */
			WFIFOL(session, 4) = account_id;
			WFIFOL(session, 8) = char_id;
			WFIFOB(session, 12) = 0;/* var type (only set when all vars have been sent, regardless of type) */
			WFIFOB(session, 13) = 0;/* is int type */
			WFIFOW(session, 14) = 0;/* count */
			plen = 16;
		}
	}

	/* mark as complete & go. */
	WFIFOB(session, 12) = type;
	WFIFOW(session, 2) = plen;
	WFIFOSET(session, plen);

	SQL->FreeResult(inter->sql_handle);
	return 1;
}

/**
 * Reads the 'inter_configuration/log' config entry and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool inter_config_read_log(const char *filename, const struct config_t *config, bool imported)
{
	const struct config_setting_t *setting = NULL;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "inter_configuration/log")) == NULL) {
		if (imported)
			return true;
		ShowError("sql_config_read: inter_configuration/log was not found in %s!\n", filename);
		return false;
	}

	libconfig->setting_lookup_bool_real(setting, "log_inter", &inter->enable_logs);

	return true;
}

/**
 * Reads the 'char_configuration/sql_connection' config entry and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool inter_config_read_connection(const char *filename, const struct config_t *config, bool imported)
{
	const struct config_setting_t *setting = NULL;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "char_configuration/sql_connection")) == NULL) {
		if (imported)
			return true;
		ShowError("char_config_read: char_configuration/sql_connection was not found in %s!\n", filename);
		ShowWarning("inter_config_read_connection: Defaulting sql_connection...\n");
		return false;
	}

	libconfig->setting_lookup_int(setting, "db_port", &char_server_port);
	libconfig->setting_lookup_mutable_string(setting, "db_hostname", char_server_ip, sizeof(char_server_ip));
	libconfig->setting_lookup_mutable_string(setting, "db_username", char_server_id, sizeof(char_server_id));
	libconfig->setting_lookup_mutable_string(setting, "db_password", char_server_pw, sizeof(char_server_pw));
	libconfig->setting_lookup_mutable_string(setting, "db_database", char_server_db, sizeof(char_server_db));
	libconfig->setting_lookup_mutable_string(setting, "default_codepage", default_codepage, sizeof(default_codepage));

	return true;
}

/**
 * Reads the 'inter_configuration' config file and initializes required variables.
 *
 * @param filename Path to configuration file
 * @param imported Whether the current config is from an imported file.
 *
 * @retval false in case of error.
 */
static bool inter_config_read(const char *filename, bool imported)
{
	struct config_t config;
	const struct config_setting_t *setting = NULL;
	const char *import = NULL;
	bool retval = true;

	nullpo_retr(false, filename);

	if (!libconfig->load_file(&config, filename))
		return false;

	if ((setting = libconfig->lookup(&config, "inter_configuration")) == NULL) {
		libconfig->destroy(&config);
		if (imported)
			return true;
		ShowError("inter_config_read: inter_configuration was not found in %s!\n", filename);
		return false;
	}
	libconfig->setting_lookup_int(setting, "party_share_level", &party_share_level);

	if (!inter->config_read_log(filename, &config, imported))
		retval = false;

	ShowInfo("Done reading %s.\n", filename);

	// import should overwrite any previous configuration, so it should be called last
	if (libconfig->lookup_string(&config, "import", &import) == CONFIG_TRUE) {
		if (strcmp(import, filename) == 0 || strcmp(import, chr->INTER_CONF_NAME) == 0) {
			ShowWarning("inter_config_read: Loop detected in %s! Skipping 'import'...\n", filename);
		} else {
			if (!inter->config_read(import, true))
				retval = false;
		}
	}

	libconfig->destroy(&config);
	return retval;
}

/**
 * Save interlog into sql (arglist version)
 * @see inter_log
 */
static int inter_vlog(char *fmt, va_list ap)
{
	char str[255];
	char esc_str[sizeof(str)*2+1];// escaped str
	va_list apcopy;

	va_copy(apcopy, ap);
	vsnprintf(str, sizeof(str), fmt, apcopy);
	va_end(apcopy);

	SQL->EscapeStringLen(inter->sql_handle, esc_str, str, strnlen(str, sizeof(str)));
	if( SQL_ERROR == SQL->Query(inter->sql_handle, "INSERT INTO `%s` (`time`, `log`) VALUES (NOW(),  '%s')", interlog_db, esc_str) )
		Sql_ShowDebug(inter->sql_handle);

	return 0;
}

/**
 * Save interlog into sql
 * @param fmt Message's format string
 * @param ... Additional (printf-like) arguments
 * @return Always 0 // FIXME
 */
static int inter_log(char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap,fmt);
	ret = inter->vlog(fmt, ap);
	va_end(ap);

	return ret;
}

/**
 * Initializes inter SQL connection
 **/
static int inter_init_sql(const char *file)
{
	inter->config_read(file, false);

	//DB connection initialized
	inter->sql_handle = SQL->Malloc();
	ShowInfo("Connect Character DB server.... (Character Server)\n");
	if( SQL_ERROR == SQL->Connect(inter->sql_handle, char_server_id,
		char_server_pw, char_server_ip, (uint16)char_server_port, char_server_db)
	) {
		Sql_ShowDebug(inter->sql_handle);
		SQL->Free(inter->sql_handle);
		exit(EXIT_FAILURE);
	}

	if( *default_codepage ) {
		if( SQL_ERROR == SQL->SetEncoding(inter->sql_handle, default_codepage) )
			Sql_ShowDebug(inter->sql_handle);
	}

	inter_guild->sql_init();
	inter_storage->sql_init();
	inter_party->sql_init();
	inter_pet->sql_init();
	inter_homunculus->sql_init();
	inter_mercenary->sql_init();
	inter_elemental->sql_init();
	inter_mail->sql_init();
	inter_auction->sql_init();
	inter_rodex->sql_init();
	inter_achievement->sql_init();

	geoip->init();
	inter->msg_config_read("conf/messages.conf", false);
	return 0;
}

// finalize
static void inter_final(void)
{
	inter_guild->sql_final();
	inter_storage->sql_final();
	inter_party->sql_final();
	inter_pet->sql_final();
	inter_homunculus->sql_final();
	inter_mercenary->sql_final();
	inter_elemental->sql_final();
	inter_mail->sql_final();
	inter_auction->sql_final();
	inter_rodex->sql_final();
	inter_achievement->sql_final();

	geoip->final(true);
	inter->do_final_msg();
	return;
}

/**
 * Called upon successful authentication of a map-server
 * (currently only initialization inter_mapif)
 **/
static int inter_mapif_init(struct socket_data *session)
{
	return 0;
}

//--------------------------------------------------------

void inter_defaults(void)
{
	inter = &inter_s;

	inter->enable_logs = true;
	inter->sql_handle = NULL;

	inter->msg_txt = inter_msg_txt;
	inter->msg_config_read = inter_msg_config_read;
	inter->do_final_msg = inter_do_final_msg;
	inter->job_name = inter_job_name;
	inter->vmsg_to_fd = inter_vmsg_to_fd;
	inter->msg_to_fd = inter_msg_to_fd;
	inter->char_rename = inter_char_rename;
	inter->savereg = inter_savereg;
	inter->accreg_fromsql = inter_accreg_fromsql;
	inter->config_read = inter_config_read;
	inter->vlog = inter_vlog;
	inter->log = inter_log;
	inter->init_sql = inter_init_sql;
	inter->mapif_init = inter_mapif_init;
	inter->final = inter_final;
	inter->config_read_log = inter_config_read_log;
	inter->config_read_connection = inter_config_read_connection;
	inter->accinfo = inter_accinfo;
	inter->accinfo_ack = inter_accinfo_ack;
}
