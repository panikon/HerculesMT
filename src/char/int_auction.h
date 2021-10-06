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
#ifndef CHAR_INT_AUCTION_H
#define CHAR_INT_AUCTION_H

#include "common/hercules.h"
#include "common/mmo.h"

/* Forward Declarations */
struct DBMap; // common/db.h

/**
 * inter_auction_interface interface
 **/
struct inter_auction_interface {
	/**
	 * Auction cache
	 *
	 * int auction_id -> struct auction_data*
	 **/
	struct DBMap *db;
	struct mutex_data *db_mutex;

	void (*cancel) (struct socket_data *session, int char_id, unsigned int auction_id);
	void (*close) (struct socket_data *session, int char_id, unsigned int auction_id);
	void (*bid)(struct socket_data *session, int char_id, unsigned int auction_id, int bid, const char *buyer_name);

	int (*count) (int char_id, bool buy);
	void (*save) (struct auction_data *auction);
	unsigned int (*create) (const struct auction_data *auction);
	int (*end_timer) (struct timer_interface *tm, int tid, int64 tick, int id, intptr_t data);
	void (*delete_) (struct auction_data *auction);
	void (*fromsql) (void);

	int (*sql_init) (void);
	void (*sql_final) (void);
};

#ifdef HERCULES_CORE
void inter_auction_defaults(void);
#endif // HERCULES_CORE

HPShared struct inter_auction_interface *inter_auction;

#endif /* CHAR_INT_AUCTION_H */
