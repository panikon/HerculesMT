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

#include "int_auction.h"

#include "char/char.h"
#include "char/int_mail.h"
#include "char/inter.h"
#include "char/mapif.h"
#include "common/cbasetypes.h"
#include "common/db.h"
#include "common/memmgr.h"
#include "common/mmo.h"
#include "common/nullpo.h"
#include "common/showmsg.h"
#include "common/socket.h"
#include "common/sql.h"
#include "common/strlib.h"
#include "common/timer.h"
#include "common/mutex.h"

#include <stdio.h>
#include <stdlib.h>

static struct inter_auction_interface inter_auction_s;
struct inter_auction_interface *inter_auction;

/**
 * Returns number of active auctions of a char_id
 *
 * @mutex inter_auction->db_mutex
 **/
static int inter_auction_count(int char_id, bool buy)
{
	int i = 0;
	struct auction_data *auction;
	struct DBIterator *iter = db_iterator(inter_auction->db);

	for( auction = dbi_first(iter); dbi_exists(iter); auction = dbi_next(iter) )
	{
		if ((buy && auction->buyer_id == char_id) || (!buy && auction->seller_id == char_id))
			i++;
	}
	dbi_destroy(iter);

	return i;
}

static void inter_auction_save(struct auction_data *auction)
{
	int j;
	StringBuf buf;
	struct SqlStmt *stmt;

	if( !auction )
		return;

	StrBuf->Init(&buf);
	StrBuf->Printf(&buf, "UPDATE `%s` SET `seller_id` = '%d', `seller_name` = ?, `buyer_id` = '%d', `buyer_name` = ?, `price` = '%d', `buynow` = '%d', `hours` = '%d', `timestamp` = '%lu', `nameid` = '%d', `item_name` = ?, `type` = '%d', `refine` = '%d', `attribute` = '%d'",
		auction_db, auction->seller_id, auction->buyer_id, auction->price, auction->buynow, auction->hours, (unsigned long)auction->timestamp, auction->item.nameid, auction->type, auction->item.refine, auction->item.attribute);
	for (j = 0; j < MAX_SLOTS; j++)
		StrBuf->Printf(&buf, ", `card%d` = '%d'", j, auction->item.card[j]);
	for (j = 0; j < MAX_ITEM_OPTIONS; j++)
		StrBuf->Printf(&buf, ", `opt_idx%d` = '%d', `opt_val%d` = '%d'", j, auction->item.option[j].index, j, auction->item.option[j].value);
	StrBuf->Printf(&buf, " WHERE `auction_id` = '%u'", auction->auction_id);

	stmt = SQL->StmtMalloc(inter->sql_handle);
	if( SQL_SUCCESS != SQL->StmtPrepareStr(stmt, StrBuf->Value(&buf))
	||  SQL_SUCCESS != SQL->StmtBindParam(stmt, 0, SQLDT_STRING, auction->seller_name, strnlen(auction->seller_name, NAME_LENGTH))
	||  SQL_SUCCESS != SQL->StmtBindParam(stmt, 1, SQLDT_STRING, auction->buyer_name, strnlen(auction->buyer_name, NAME_LENGTH))
	||  SQL_SUCCESS != SQL->StmtBindParam(stmt, 2, SQLDT_STRING, auction->item_name, strnlen(auction->item_name, ITEM_NAME_LENGTH))
	||  SQL_SUCCESS != SQL->StmtExecute(stmt) )
	{
		SqlStmt_ShowDebug(stmt);
	}

	SQL->StmtFree(stmt);
	StrBuf->Destroy(&buf);
}

/**
 * Inserts an auction into online database and internal database.
 *
 * @remarks timestamp is ignored and is generated using auction->hours
 * @return auction id
 * @retval 0 Failed
 * @mutex inter_auction->db_mutex
 **/
static unsigned int inter_auction_create(const struct auction_data *auction)
{
	int j;
	StringBuf buf;
	struct SqlStmt *stmt;
	unsigned int id = 0;

	nullpo_ret(auction);

	uint64 timestamp = time(NULL) + (auction->hours * 3600);

	StrBuf->Init(&buf);
	StrBuf->Printf(&buf, "INSERT INTO `%s` (`seller_id`,`seller_name`,"
		"`buyer_id`,`buyer_name`,`price`,`buynow`,`hours`,`timestamp`,`nameid`,"
		"`item_name`,`type`,`refine`,`attribute`,`unique_id`",
		auction_db);
	for (j = 0; j < MAX_SLOTS; j++)
		StrBuf->Printf(&buf, ",`card%d`", j);
	for (j = 0; j < MAX_ITEM_OPTIONS; j++)
		StrBuf->Printf(&buf, ", `opt_idx%d`, `opt_val%d`", j, j);
	StrBuf->Printf(&buf,
		") VALUES ('%d',?,'%d',?,'%d','%d','%d','%lu','%d',?,'%d','%d','%d','%"PRIu64"'",
		auction->seller_id, auction->buyer_id, auction->price, auction->buynow,
		auction->hours, (unsigned long)timestamp, auction->item.nameid,
		auction->type, auction->item.refine, auction->item.attribute,
		auction->item.unique_id);
	for (j = 0; j < MAX_SLOTS; j++)
		StrBuf->Printf(&buf, ",'%d'", auction->item.card[j]);
	for (j = 0; j < MAX_ITEM_OPTIONS; j++)
		StrBuf->Printf(&buf, ",'%d','%d'", auction->item.option[j].index, auction->item.option[j].value);

	StrBuf->AppendStr(&buf, ")");

	stmt = SQL->StmtMalloc(inter->sql_handle);
	if (SQL_SUCCESS != SQL->StmtPrepareStr(stmt, StrBuf->Value(&buf))
	||  SQL_SUCCESS != SQL->StmtBindParam(stmt, 0, SQLDT_STRING, auction->seller_name, strnlen(auction->seller_name, NAME_LENGTH))
	||  SQL_SUCCESS != SQL->StmtBindParam(stmt, 1, SQLDT_STRING, auction->buyer_name, strnlen(auction->buyer_name, NAME_LENGTH))
	||  SQL_SUCCESS != SQL->StmtBindParam(stmt, 2, SQLDT_STRING, auction->item_name, strnlen(auction->item_name, ITEM_NAME_LENGTH))
	||  SQL_SUCCESS != SQL->StmtExecute(stmt))
	{
		SqlStmt_ShowDebug(stmt);
		id = 0;
	} else {
		struct auction_data *auction_;
		int64 tick = (int64)auction->hours * 3600000;

		id = (unsigned int)SQL->StmtLastInsertId(stmt);
		int end_timer = timer->add( timer->gettick() + tick , inter_auction->end_timer, id, 0);

		ShowInfo("New Auction %u | time left %"PRId64" ms | By %s.\n", id, tick, auction->seller_name);

		CREATE(auction_, struct auction_data, 1);
		memcpy(auction_, auction, sizeof(struct auction_data));
		auction_->item.amount = 1;
		auction_->item.identify = 1;
		auction_->item.expire_time = 0;
		auction_->timestamp = timestamp;
		auction_->auction_id = id;
		auction_->auction_end_timer = end_timer;
		idb_put(inter_auction->db, auction_->auction_id, auction_);
	}

	SQL->StmtFree(stmt);
	StrBuf->Destroy(&buf);

	return id;
}

/**
 * Auction end timer
 *
 * @see TimerFunc
 * Acquires inter_auction->db_mutex
 **/
static int inter_auction_end_timer(struct timer_interface *tm, int tid, int64 tick, int id, intptr_t data)
{
	struct auction_data *auction;
	mutex->lock(inter_auction->db_mutex);

	if( (auction = idb_get(inter_auction->db, id)) != NULL )
	{
		if( auction->buyer_id )
		{
			inter_mail->sendmail(0, "Auction Manager", auction->buyer_id,
				auction->buyer_name, "Auction", "Thanks, you won the auction!.",
				0, &auction->item);
			mapif->auction_message(auction->buyer_id, 6); // You have won the auction
			inter_mail->sendmail(0, "Auction Manager", auction->seller_id,
				auction->seller_name, "Auction", "Payment for your auction!.",
				auction->price, NULL);
		}
		else
			inter_mail->sendmail(0, "Auction Manager", auction->seller_id,
				auction->seller_name, "Auction", "No buyers have been found for your auction.",
				0, &auction->item);

		ShowInfo("Auction End: id %u.\n", auction->auction_id);

		auction->auction_end_timer = INVALID_TIMER;
		inter_auction->delete_(auction);
	}

	mutex->unlock(inter_auction->db_mutex);
	return 0;
}

/**
 * Removes auction from database and cache
 *
 * @mutex inter_auction->db_mutex
 **/
static void inter_auction_delete(struct auction_data *auction)
{
	unsigned int auction_id;
	nullpo_retv(auction);

	auction_id = auction->auction_id;

	if( SQL_ERROR == SQL->Query(inter->sql_handle, "DELETE FROM `%s` WHERE `auction_id` = '%u'", auction_db, auction_id) )
		Sql_ShowDebug(inter->sql_handle);

	if( auction->auction_end_timer != INVALID_TIMER )
		timer->delete(auction->auction_end_timer, inter_auction->end_timer);

	idb_remove(inter_auction->db, auction_id);
}

/**
 * Cancels an auction
 *
 * @mutex inter_auction->db_mutex
 **/
static void inter_auction_cancel(struct socket_data *session, int char_id,
	unsigned int auction_id
) {
	struct auction_data *auction = idb_get(inter_auction->db, auction_id);

	if(!auction) {
		mapif->auction_cancel(session, char_id, AUCTIONCANCEL_INCORRECT_ID);
		return;
	}

	if (auction->seller_id != char_id) {
		mapif->auction_cancel(session, char_id, AUCTIONCANCEL_FAILED);
		return;
	}

	if(auction->buyer_id > 0) {
		// An auction with at least one bidder cannot be canceled
		mapif->auction_message(char_id, AUCTIONRESULT_CANNOT_CANCEL);
		return;
	}

	inter_mail->sendmail(0, "Auction Manager", auction->seller_id,
		auction->seller_name, "Auction", "Auction canceled.", 0, &auction->item);
	inter_auction->delete_(auction);

	mapif->auction_cancel(session, char_id, AUCTIONCANCEL_SUCCESS);
}

/**
 * Closes an auction
 *
 * @mutex inter_auction->db_mutex
 **/
static void inter_auction_close(struct socket_data *session, int char_id,
	unsigned int auction_id
) {
	struct auction_data *auction = idb_get(inter_auction->db, auction_id);

	if(!auction) {
		mapif->auction_close(session, char_id, AUCTIONCANCEL_INCORRECT_ID);
		return;
	}

	if(auction->seller_id != char_id || auction->buyer_id == 0) {
		mapif->auction_close(session, char_id, AUCTIONCANCEL_FAILED); // You cannot end the auction
		return;
	}

	// Send Money to Seller
	inter_mail->sendmail(0, "Auction Manager", auction->seller_id,
		auction->seller_name, "Auction", "Auction closed.", auction->price, NULL);
	// Send Item to Buyer
	inter_mail->sendmail(0, "Auction Manager", auction->buyer_id,
		auction->buyer_name, "Auction", "Auction winner.", 0, &auction->item);
	mapif->auction_message(auction->buyer_id, AUCTIONRESULT_WON); // You have won the auction
	inter_auction->delete_(auction);

	mapif->auction_close(session, char_id, AUCTIONCANCEL_SUCCESS); // You have ended the auction
}

/**
 * Places a new bid in provided auction
 *
 * @mutex inter_auction->db_mutex
 **/
static void inter_auction_bid(struct socket_data *session, int char_id,
	unsigned int auction_id, int bid, const char *buyer_name
) {
	struct auction_data *auction = idb_get(inter_auction->db, auction_id);

	if(auction == NULL || auction->price >= bid || auction->seller_id == char_id) {
		mapif->auction_bid(session, char_id, bid, AUCTIONRESULT_BID_FAILED);
		return;
	}

	if(inter_auction->count(char_id, true) > 4
	&& bid < auction->buynow
	&& auction->buyer_id != char_id
	) {
		// You cannot place more than 5 bids at a time
		mapif->auction_bid(session, char_id, bid, AUCTIONRESULT_BID_EXCEEDED);
		return;
	}

	if(auction->buyer_id > 0) {
		// Send Money back to the previous Buyer
		if(auction->buyer_id != char_id) {
			inter_mail->sendmail(0, "Auction Manager", auction->buyer_id,
				auction->buyer_name,
				"Auction", "Someone has placed a higher bid.",
				auction->price, NULL);
			mapif->auction_message(auction->buyer_id, AUCTIONRESULT_LOSE); // You have failed to win the auction
		} else {
			inter_mail->sendmail(0, "Auction Manager", auction->buyer_id,
				auction->buyer_name,
				"Auction", "You have placed a higher bid.",
				auction->price, NULL);
		}
	}

	auction->buyer_id = char_id;
	safestrncpy(auction->buyer_name, buyer_name, NAME_LENGTH);
	auction->price = bid;

	if(bid >= auction->buynow) {
		// Automatic win the auction
		mapif->auction_bid(session, char_id, bid - auction->buynow, AUCTIONRESULT_BID_SUCCESS);

		inter_mail->sendmail(0, "Auction Manager", auction->buyer_id,
			auction->buyer_name,
			"Auction", "You have won the auction.", 0, &auction->item);
		mapif->auction_message(char_id, AUCTIONRESULT_WON); // You have won the auction
		inter_mail->sendmail(0, "Auction Manager", auction->seller_id,
			auction->seller_name,
			"Auction", "Payment for your auction!.", auction->buynow, NULL);

		inter_auction->delete_(auction);
		return;
	}

	inter_auction->save(auction);

	mapif->auction_bid(session, char_id, 0, AUCTIONRESULT_BID_SUCCESS);
}

/**
 * Loads auctions from database to cache
 *
 * @mutex inter_auction->db_mutex
 **/
static void inter_auctions_fromsql(void)
{
	int i;
	struct auction_data *auction;
	char *data;
	StringBuf buf;
	int64 tick = timer->gettick(), endtick;
	time_t now = time(NULL);

	StrBuf->Init(&buf);
	StrBuf->AppendStr(&buf, "SELECT `auction_id`,`seller_id`,`seller_name`,`buyer_id`,`buyer_name`,"
		"`price`,`buynow`,`hours`,`timestamp`,`nameid`,`item_name`,`type`,`refine`,`attribute`,`unique_id`");
	for (i = 0; i < MAX_SLOTS; i++)
		StrBuf->Printf(&buf, ",`card%d`", i);
	for (i = 0; i < MAX_ITEM_OPTIONS; i++)
		StrBuf->Printf(&buf, ", `opt_idx%d`, `opt_val%d`", i, i);
	StrBuf->Printf(&buf, " FROM `%s` ORDER BY `auction_id` DESC", auction_db);

	if (SQL_ERROR == SQL->QueryStr(inter->sql_handle, StrBuf->Value(&buf)))
		Sql_ShowDebug(inter->sql_handle);

	StrBuf->Destroy(&buf);

	while (SQL_SUCCESS == SQL->NextRow(inter->sql_handle)) {
		struct item *item;
		CREATE(auction, struct auction_data, 1);
		SQL->GetData(inter->sql_handle, 0, &data, NULL); auction->auction_id = atoi(data);
		SQL->GetData(inter->sql_handle, 1, &data, NULL); auction->seller_id = atoi(data);
		SQL->GetData(inter->sql_handle, 2, &data, NULL); safestrncpy(auction->seller_name, data, NAME_LENGTH);
		SQL->GetData(inter->sql_handle, 3, &data, NULL); auction->buyer_id = atoi(data);
		SQL->GetData(inter->sql_handle, 4, &data, NULL); safestrncpy(auction->buyer_name, data, NAME_LENGTH);
		SQL->GetData(inter->sql_handle, 5, &data, NULL); auction->price = atoi(data);
		SQL->GetData(inter->sql_handle, 6, &data, NULL); auction->buynow = atoi(data);
		SQL->GetData(inter->sql_handle, 7, &data, NULL); auction->hours = atoi(data);
		SQL->GetData(inter->sql_handle, 8, &data, NULL); auction->timestamp = atoi(data);

		item = &auction->item;
		SQL->GetData(inter->sql_handle, 9, &data, NULL); item->nameid = atoi(data);
		SQL->GetData(inter->sql_handle,10, &data, NULL); safestrncpy(auction->item_name, data, ITEM_NAME_LENGTH);
		SQL->GetData(inter->sql_handle,11, &data, NULL); auction->type = atoi(data);

		SQL->GetData(inter->sql_handle,12, &data, NULL); item->refine = atoi(data);
		SQL->GetData(inter->sql_handle,13, &data, NULL); item->attribute = atoi(data);
		SQL->GetData(inter->sql_handle,14, &data, NULL); item->unique_id = strtoull(data, NULL, 10);

		item->identify = 1;
		item->amount = 1;
		item->expire_time = 0;
		/* Card Slots */
		for (i = 0; i < MAX_SLOTS; i++) {
			SQL->GetData(inter->sql_handle, 15 + i, &data, NULL);
			item->card[i] = atoi(data);
		}
		/* Item Options */
		for (i = 0; i < MAX_ITEM_OPTIONS; i++) {
			SQL->GetData(inter->sql_handle, 15 + MAX_SLOTS + i * 2, &data, NULL);
			item->option[i].index = atoi(data);
			SQL->GetData(inter->sql_handle, 16 + MAX_SLOTS + i * 2, &data, NULL);
			item->option[i].value = atoi(data);
		}

		if (auction->timestamp > now)
			endtick = ((int64)(auction->timestamp - now) * 1000) + tick;
		else
			endtick = tick + 10000; // 10 seconds to process ended auctions

		auction->auction_end_timer = timer->add(endtick, inter_auction->end_timer, auction->auction_id, 0);
		idb_put(inter_auction->db, auction->auction_id, auction);
	}

	SQL->FreeResult(inter->sql_handle);
}

static int inter_auction_sql_init(void)
{
	inter_auction->db = idb_alloc(DB_OPT_RELEASE_DATA);
	inter_auction->db_mutex = mutex->create();
	inter_auction->fromsql();

	return 0;
}

static void inter_auction_sql_final(void)
{
	inter_auction->db->destroy(inter_auction->db,NULL);
	mutex->destroy(inter_auction->db_mutex);

	return;
}

void inter_auction_defaults(void)
{
	inter_auction = &inter_auction_s;

	inter_auction->db = NULL; // int auction_id -> struct auction_data*
	inter_auction->db_mutex = NULL;

	inter_auction->cancel = inter_auction_cancel;
	inter_auction->close = inter_auction_close;
	inter_auction->bid = inter_auction_bid;

	inter_auction->count = inter_auction_count;
	inter_auction->save = inter_auction_save;
	inter_auction->create = inter_auction_create;
	inter_auction->end_timer = inter_auction_end_timer;
	inter_auction->delete_ = inter_auction_delete;
	inter_auction->fromsql = inter_auctions_fromsql;
	inter_auction->sql_init = inter_auction_sql_init;
	inter_auction->sql_final = inter_auction_sql_final;
}
