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

#include "int_mail.h"

#include "char/char.h"
#include "char/inter.h"
#include "char/mapif.h"
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

static struct inter_mail_interface inter_mail_s;
struct inter_mail_interface *inter_mail;

/**
 * Get mail data of a given character from database
 *
 * @param char_id Target character
 * @param md      Mail data to be filled (initiated to 0), out
 **/
static void inter_mail_fromsql(int char_id, struct mail_data *md)
{
	int i, j;
	struct mail_message *msg;
	char *data;
	StringBuf buf;
	struct Sql *sql_handle = inter->sql_handle_get();

	nullpo_retv(md);
	md->amount = 0;
	md->full = false;

	StrBuf->Init(&buf);
	StrBuf->AppendStr(&buf, "SELECT `id`,`send_name`,`send_id`,`dest_name`,`dest_id`,`title`,`message`,`time`,`status`,"
		"`zeny`,`amount`,`nameid`,`refine`,`attribute`,`identify`,`unique_id`");
	for (i = 0; i < MAX_SLOTS; i++)
		StrBuf->Printf(&buf, ",`card%d`", i);
	for (i = 0; i < MAX_ITEM_OPTIONS; i++)
		StrBuf->Printf(&buf, ", `opt_idx%d`, `opt_val%d`", i, i);

	// I keep the `status` < 3 just in case someone forget to apply the sqlfix
	// TODO: Review this section, probably this verification is not needed anymore [Panikon]
	StrBuf->Printf(&buf, " FROM `%s` WHERE `dest_id`='%d' AND `status` < 3 ORDER BY `id` LIMIT %d",
		mail_db, char_id, MAIL_MAX_INBOX + 1);

	if (SQL_ERROR == SQL->QueryStr(sql_handle, StrBuf->Value(&buf)))
		Sql_ShowDebug(sql_handle);

	StrBuf->Destroy(&buf);

	for (i = 0; i < MAIL_MAX_INBOX && SQL_SUCCESS == SQL->NextRow(sql_handle); ++i )
	{
		struct item *item;
		msg = &md->msg[i];
		SQL->GetData(sql_handle, 0, &data, NULL); msg->id = atoi(data);
		SQL->GetData(sql_handle, 1, &data, NULL); safestrncpy(msg->send_name, data, NAME_LENGTH);
		SQL->GetData(sql_handle, 2, &data, NULL); msg->send_id = atoi(data);
		SQL->GetData(sql_handle, 3, &data, NULL); safestrncpy(msg->dest_name, data, NAME_LENGTH);
		SQL->GetData(sql_handle, 4, &data, NULL); msg->dest_id = atoi(data);
		SQL->GetData(sql_handle, 5, &data, NULL); safestrncpy(msg->title, data, MAIL_TITLE_LENGTH);
		SQL->GetData(sql_handle, 6, &data, NULL); safestrncpy(msg->body, data, MAIL_BODY_LENGTH);
		SQL->GetData(sql_handle, 7, &data, NULL); msg->timestamp = atoi(data);
		SQL->GetData(sql_handle, 8, &data, NULL); msg->status = (mail_status)atoi(data);
		SQL->GetData(sql_handle, 9, &data, NULL); msg->zeny = atoi(data);
		item = &msg->item;
		SQL->GetData(sql_handle,10, &data, NULL); item->amount = (short)atoi(data);
		SQL->GetData(sql_handle,11, &data, NULL); item->nameid = atoi(data);
		SQL->GetData(sql_handle,12, &data, NULL); item->refine = atoi(data);
		SQL->GetData(sql_handle,13, &data, NULL); item->attribute = atoi(data);
		SQL->GetData(sql_handle,14, &data, NULL); item->identify = atoi(data);
		SQL->GetData(sql_handle,15, &data, NULL); item->unique_id = strtoull(data, NULL, 10);
		item->expire_time = 0;
		item->bound = 0;
		/* Card Slots */
		for (j = 0; j < MAX_SLOTS; j++) {
			SQL->GetData(sql_handle, 16 + j, &data, NULL);
			item->card[j] = atoi(data);
		}
		/* Item Options */
		for (j = 0; j < MAX_ITEM_OPTIONS; j++) {
			SQL->GetData(sql_handle, 16 + MAX_SLOTS + j * 2, &data, NULL);
			item->option[j].index = atoi(data);
			SQL->GetData(sql_handle, 17 + MAX_SLOTS + j * 2, &data, NULL);
			item->option[j].value = atoi(data);
		}
	}

	md->full = ( SQL->NumRows(sql_handle) > MAIL_MAX_INBOX );

	md->amount = i;
	SQL->FreeResult(sql_handle);

	md->unchecked = 0;
	md->unread = 0;
	for (i = 0; i < md->amount; i++)
	{
		msg = &md->msg[i];
		if( msg->status == MAIL_NEW )
		{
			if ( SQL_ERROR == SQL->Query(sql_handle, "UPDATE `%s` SET `status` = '%d' WHERE `id` = '%d'", mail_db, MAIL_UNREAD, msg->id) )
				Sql_ShowDebug(sql_handle);

			msg->status = MAIL_UNREAD;
			md->unchecked++;
		}
		else if ( msg->status == MAIL_UNREAD )
			md->unread++;
	}

	ShowInfo("mail load complete from DB - id: %d (total: %d)\n", char_id, md->amount);
}

/// Stores a single message in the database.
/// Returns the message's ID if successful (or 0 if it fails).
static int inter_mail_savemessage(struct mail_message *msg)
{
	StringBuf buf;
	struct SqlStmt *stmt;
	int j;
	struct Sql *sql_handle = inter->sql_handle_get();

	nullpo_ret(msg);
	// build message save query
	StrBuf->Init(&buf);
	StrBuf->Printf(&buf, "INSERT INTO `%s` (`send_name`, `send_id`, `dest_name`, `dest_id`, `title`, `message`, `time`, `status`, `zeny`, `amount`, `nameid`, `refine`, `attribute`, `identify`, `unique_id`", mail_db);
	for (j = 0; j < MAX_SLOTS; j++)
		StrBuf->Printf(&buf, ", `card%d`", j);
	for (j = 0; j < MAX_ITEM_OPTIONS; j++)
		StrBuf->Printf(&buf, ", `opt_idx%d`, `opt_val%d`", j, j);
	StrBuf->Printf(&buf, ") VALUES (?, '%d', ?, '%d', ?, ?, '%lu', '%u', '%d', '%d', '%d', '%d', '%d', '%d', '%"PRIu64"'",
		msg->send_id, msg->dest_id, (unsigned long)msg->timestamp, msg->status, msg->zeny, msg->item.amount, msg->item.nameid, msg->item.refine, msg->item.attribute, msg->item.identify, msg->item.unique_id);
	for (j = 0; j < MAX_SLOTS; j++)
		StrBuf->Printf(&buf, ", '%d'", msg->item.card[j]);
	for (j = 0; j < MAX_ITEM_OPTIONS; j++)
		StrBuf->Printf(&buf, ", '%d', '%d'", msg->item.option[j].index, msg->item.option[j].value);
	StrBuf->AppendStr(&buf, ")");

	// prepare and execute query
	stmt = SQL->StmtMalloc(sql_handle);
	if (SQL_SUCCESS != SQL->StmtPrepareStr(stmt, StrBuf->Value(&buf))
	||  SQL_SUCCESS != SQL->StmtBindParam(stmt, 0, SQLDT_STRING, msg->send_name, strnlen(msg->send_name, NAME_LENGTH))
	||  SQL_SUCCESS != SQL->StmtBindParam(stmt, 1, SQLDT_STRING, msg->dest_name, strnlen(msg->dest_name, NAME_LENGTH))
	||  SQL_SUCCESS != SQL->StmtBindParam(stmt, 2, SQLDT_STRING, msg->title, strnlen(msg->title, MAIL_TITLE_LENGTH))
	||  SQL_SUCCESS != SQL->StmtBindParam(stmt, 3, SQLDT_STRING, msg->body, strnlen(msg->body, MAIL_BODY_LENGTH))
	||  SQL_SUCCESS != SQL->StmtExecute(stmt))
	{
		SqlStmt_ShowDebug(stmt);
		msg->id = 0;
	} else {
		msg->id = (int)SQL->StmtLastInsertId(stmt);
	}

	SQL->StmtFree(stmt);
	StrBuf->Destroy(&buf);

	return msg->id;
}

/**
 * Retrieves a single message from the database.
 * Returns true if the operation succeeds (or false if it fails).
 **/
static bool inter_mail_loadmessage(int mail_id, struct mail_message *msg)
{
	int j;
	StringBuf buf;
	struct Sql *sql_handle = inter->sql_handle_get();
	nullpo_ret(msg);
	memset(msg, 0, sizeof(struct mail_message)); // Initialize data

	StrBuf->Init(&buf);
	StrBuf->AppendStr(&buf, "SELECT `id`,`send_name`,`send_id`,`dest_name`,`dest_id`,`title`,`message`,`time`,`status`,"
		"`zeny`,`amount`,`nameid`,`refine`,`attribute`,`identify`,`unique_id`");
	for (j = 0; j < MAX_SLOTS; j++)
		StrBuf->Printf(&buf, ",`card%d`", j);
	for (j = 0; j < MAX_ITEM_OPTIONS; j++)
		StrBuf->Printf(&buf, ",`opt_idx%d`,`opt_val%d`", j, j);
	StrBuf->Printf(&buf, " FROM `%s` WHERE `id` = '%d'", mail_db, mail_id);

	if (SQL_ERROR == SQL->QueryStr(sql_handle, StrBuf->Value(&buf))
	 || SQL_SUCCESS != SQL->NextRow(sql_handle)) {
		Sql_ShowDebug(sql_handle);
		SQL->FreeResult(sql_handle);
		StrBuf->Destroy(&buf);
		return false;
	} else {
		char* data;

		SQL->GetData(sql_handle, 0, &data, NULL); msg->id = atoi(data);
		SQL->GetData(sql_handle, 1, &data, NULL); safestrncpy(msg->send_name, data, NAME_LENGTH);
		SQL->GetData(sql_handle, 2, &data, NULL); msg->send_id = atoi(data);
		SQL->GetData(sql_handle, 3, &data, NULL); safestrncpy(msg->dest_name, data, NAME_LENGTH);
		SQL->GetData(sql_handle, 4, &data, NULL); msg->dest_id = atoi(data);
		SQL->GetData(sql_handle, 5, &data, NULL); safestrncpy(msg->title, data, MAIL_TITLE_LENGTH);
		SQL->GetData(sql_handle, 6, &data, NULL); safestrncpy(msg->body, data, MAIL_BODY_LENGTH);
		SQL->GetData(sql_handle, 7, &data, NULL); msg->timestamp = atoi(data);
		SQL->GetData(sql_handle, 8, &data, NULL); msg->status = (mail_status)atoi(data);
		SQL->GetData(sql_handle, 9, &data, NULL); msg->zeny = atoi(data);
		SQL->GetData(sql_handle,10, &data, NULL); msg->item.amount = (short)atoi(data);
		SQL->GetData(sql_handle,11, &data, NULL); msg->item.nameid = atoi(data);
		SQL->GetData(sql_handle,12, &data, NULL); msg->item.refine = atoi(data);
		SQL->GetData(sql_handle,13, &data, NULL); msg->item.attribute = atoi(data);
		SQL->GetData(sql_handle,14, &data, NULL); msg->item.identify = atoi(data);
		SQL->GetData(sql_handle,15, &data, NULL); msg->item.unique_id = strtoull(data, NULL, 10);
		msg->item.expire_time = 0;
		msg->item.bound = 0;
		/* Card Slots */
		for (j = 0; j < MAX_SLOTS; j++) {
			SQL->GetData(sql_handle,16 + j, &data, NULL);
			msg->item.card[j] = atoi(data);
		}
		/* Item Options */
		for (j = 0 ; j < MAX_ITEM_OPTIONS; j++) {
			SQL->GetData(sql_handle, 16 + MAX_SLOTS + j * 2, &data, NULL);
			msg->item.option[j].index = atoi(data);
			SQL->GetData(sql_handle, 17 + MAX_SLOTS + j * 2, &data, NULL);
			msg->item.option[j].value = atoi(data);
		}
	}

	StrBuf->Destroy(&buf);
	SQL->FreeResult(sql_handle);

	return true;
}

/**
 * Mark mail as 'Read'
 **/
static bool inter_mail_mark_read(int mail_id)
{
	struct Sql *sql_handle = inter->sql_handle_get();
	if (SQL_ERROR == SQL->Query(sql_handle, "UPDATE `%s` SET `status` = '%d' WHERE `id` = '%d'", mail_db, MAIL_READ, mail_id)) {
		Sql_ShowDebug(sql_handle);
		return false;
	}
	return true;
}

/*==========================================
 * Client Attachment Request
 *------------------------------------------*/
static bool inter_mail_DeleteAttach(int mail_id)
{
	StringBuf buf;
	int i;
	struct Sql *sql_handle = inter->sql_handle_get();

	StrBuf->Init(&buf);
	StrBuf->Printf(&buf, "UPDATE `%s` SET `zeny` = '0', `nameid` = '0', `amount` = '0', `refine` = '0', `attribute` = '0', `identify` = '0'", mail_db);
	for (i = 0; i < MAX_SLOTS; i++)
		StrBuf->Printf(&buf, ", `card%d` = '0'", i);
	for (i = 0; i < MAX_ITEM_OPTIONS; i++)
		StrBuf->Printf(&buf, ", `opt_idx%d` = '0', `opt_val%d` = '0'", i, i);
	StrBuf->Printf(&buf, " WHERE `id` = '%d'", mail_id);

	if (SQL_ERROR == SQL->QueryStr(sql_handle, StrBuf->Value(&buf))) {
		Sql_ShowDebug(sql_handle);
		StrBuf->Destroy(&buf);

		return false;
	}

	StrBuf->Destroy(&buf);
	return true;
}

/**
 * Gets attachment of provided mail and deletes it.
 *
 * @param char_id      Character that requested the mail
 * @param mail_id      Target mail
 * @param mail_message Mail message (to be filled, should be zeroed prior to call) OUT
 *
 * @return true Attachment found and loaded
 * @return false Failed to find attachment / message already read
 **/
static bool inter_mail_get_attachment(int char_id, int mail_id, struct mail_message *msg)
{
	nullpo_retr(false, msg);

	if (!inter_mail->loadmessage(mail_id, msg))
		return false;

	if (msg->dest_id != char_id)
		return false;

	if (msg->status != MAIL_READ)
		return false;

	if ((msg->item.nameid < 1 || msg->item.amount < 1) && msg->zeny < 1)
		return false; // No Attachment

	if (!inter_mail->DeleteAttach(mail_id))
		return false;

	return true;
}

/**
 * Deletes mail
 * @return BOOL Success
 **/
static bool inter_mail_delete(int char_id, int mail_id)
{
	struct Sql *sql_handle = inter->sql_handle_get();
	if(SQL_ERROR == SQL->Query(sql_handle,
		"DELETE FROM `%s` WHERE `id` = '%d' AND `dest_id` = '%d'",
		mail_db, mail_id, char_id)
	) {
		Sql_ShowDebug(sql_handle);
		return false;
	}
	return true;
}

/**
 * Removes message from current owner and then sends to 'char_id'
 *
 * @param new_mail (out)Message's ID if successful (or 0 in failure)
 **/
static bool inter_mail_return_message(int char_id, int mail_id, int *new_mail)
{
	struct mail_message msg;
	struct Sql *sql_handle = inter->sql_handle_get();
	nullpo_retr(false, new_mail);

	if (!inter_mail->loadmessage(mail_id, &msg))
		return false;

	if (msg.dest_id != char_id)
		return false;

	if (SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `id` = '%d'", mail_db, mail_id)) {
		Sql_ShowDebug(sql_handle);
	} else {
		char temp_[MAIL_TITLE_LENGTH];

		// swap sender and receiver
		swap(msg.send_id, msg.dest_id);
		safestrncpy(temp_, msg.send_name, NAME_LENGTH);
		safestrncpy(msg.send_name, msg.dest_name, NAME_LENGTH);
		safestrncpy(msg.dest_name, temp_, NAME_LENGTH);

		// set reply message title
		safesnprintf(temp_, MAIL_TITLE_LENGTH, "RE:%s", msg.title);
		safestrncpy(msg.title, temp_, MAIL_TITLE_LENGTH);

		msg.status = MAIL_NEW;
		msg.timestamp = time(NULL);

		*new_mail = inter_mail->savemessage(&msg);
		mapif->mail_new(&msg);
	}

	return true;

}

static bool inter_mail_send(int account_id, struct mail_message *msg)
{
	char esc_name[ESC_NAME_LENGTH];
	struct Sql *sql_handle = inter->sql_handle_get();

	nullpo_retr(false, msg);

	// Try to find the Dest Char by Name
	SQL->EscapeStringLen(sql_handle, esc_name, msg->dest_name, strnlen(msg->dest_name, NAME_LENGTH));
	if (SQL_ERROR == SQL->Query(sql_handle, "SELECT `account_id`, `char_id` FROM `%s` WHERE `name` = '%s'", char_db, esc_name)) {
		Sql_ShowDebug(sql_handle);
	} else if (SQL_SUCCESS == SQL->NextRow(sql_handle)) {
		char *data;
		SQL->GetData(sql_handle, 0, &data, NULL);
		if (atoi(data) != account_id) {
			// Cannot send mail to char in the same account
			SQL->GetData(sql_handle, 1, &data, NULL);
			msg->dest_id = atoi(data);
		}
	}
	SQL->FreeResult(sql_handle);
	msg->status = MAIL_NEW;

	if (msg->dest_id > 0)
		msg->id = inter_mail->savemessage(msg);

	return true;
}

static void inter_mail_sendmail(int send_id, const char* send_name, int dest_id, const char *dest_name, const char *title, const char *body, int zeny, struct item *item)
{
	struct mail_message msg;
	nullpo_retv(send_name);
	nullpo_retv(dest_name);
	nullpo_retv(title);
	nullpo_retv(body);
	memset(&msg, 0, sizeof(struct mail_message));

	msg.send_id = send_id;
	safestrncpy(msg.send_name, send_name, NAME_LENGTH);
	msg.dest_id = dest_id;
	safestrncpy(msg.dest_name, dest_name, NAME_LENGTH);
	safestrncpy(msg.title, title, MAIL_TITLE_LENGTH);
	safestrncpy(msg.body, body, MAIL_BODY_LENGTH);
	msg.zeny = zeny;
	if( item != NULL )
		memcpy(&msg.item, item, sizeof(struct item));

	msg.timestamp = time(NULL);

	inter_mail->savemessage(&msg);
	mapif->mail_new(&msg);
}

static int inter_mail_sql_init(void)
{
	return 1;
}

static void inter_mail_sql_final(void)
{
	return;
}

void inter_mail_defaults(void)
{
	inter_mail = &inter_mail_s;

	inter_mail->savemessage = inter_mail_savemessage;
	inter_mail->DeleteAttach = inter_mail_DeleteAttach;
	inter_mail->sendmail = inter_mail_sendmail;
	inter_mail->sql_init = inter_mail_sql_init;
	inter_mail->sql_final = inter_mail_sql_final;
	inter_mail->fromsql = inter_mail_fromsql;
	inter_mail->loadmessage = inter_mail_loadmessage;
	inter_mail->mark_read = inter_mail_mark_read;
	inter_mail->get_attachment = inter_mail_get_attachment;
	inter_mail->delete = inter_mail_delete;
	inter_mail->return_message = inter_mail_return_message;
	inter_mail->send = inter_mail_send;
}
