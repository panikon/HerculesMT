/**
 * This file is part of Hercules.
 * http://herc.ws - http://github.com/HerculesWS/Hercules
 *
 * Copyright (C) 2016-2021 Hercules Dev Team
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
#ifndef CHAR_PACKETS_HC_STRUCT_H
#define CHAR_PACKETS_HC_STRUCT_H

#include "common/hercules.h"
#include "common/mmo.h"
#include "common/packetsstatic_len.h"

/* Packets Structs */
#if !defined(sun) && (!defined(__NETBSD__) || __NetBSD_Version__ >= 600000000) // NetBSD 5 and Solaris don't like pragma pack but accept the packed attribute
#pragma pack(push, 1)
#endif // not NetBSD < 6 / Solaris

/**
 * Notifies a failure in server connection
 * @param error_code @see enum notify_ban_errorcode
 * @see char_authfail_fd
 **/
struct PACKET_SC_NOTIFY_BAN {
	int16 packet_id;
	unsigned char error_code;
} __attribute__((packed));
DEFINE_PACKET_HEADER(SC_NOTIFY_BAN, 0x81);

/**
 * Notifies a denial of authentication (one of the possible answers to CH_ENTER)
 * @param error_code 0 - "Rejected from server"
 * @param error_code 1 - "You cannot use this ID on this server"
 **/
struct PACKET_HC_REFUSE_ENTER {
	int16 packet_id;
	unsigned char error_code;
} __attribute__((packed));
DEFINE_PACKET_HEADER(HC_REFUSE_ENTER, 0x6c);

#if PACKETVER_MAIN_NUM >= 20130522 || PACKETVER_RE_NUM >= 20130327 || defined(PACKETVER_ZERO)
struct PACKET_HC_ACK_CHARINFO_PER_PAGE {
	int16 packetId;
	int16 packetLen;
	// chars list[]
} __attribute__((packed));
DEFINE_PACKET_HEADER(HC_ACK_CHARINFO_PER_PAGE, 0x099d);
#endif

#if !defined(sun) && (!defined(__NETBSD__) || __NetBSD_Version__ >= 600000000) // NetBSD 5 and Solaris don't like pragma pack but accept the packed attribute
#pragma pack(pop)
#endif // not NetBSD < 6 / Solaris

#endif // CHAR_PACKETS_HC_STRUCT_H
