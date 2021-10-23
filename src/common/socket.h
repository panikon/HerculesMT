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
#ifndef COMMON_SOCKET_H
#define COMMON_SOCKET_H

#include "common/hercules.h"
#include "common/db.h"

#ifdef WIN32
#	include "common/winapi.h"
	typedef long in_addr_t;
#else
#	include <netinet/in.h>
#	include <sys/socket.h>
#	include <sys/types.h>
#endif

/* Forward Declarations */
struct hplugin_data_store;
struct config_setting_t;

// Quickhack (FIXME: REMOVE LATER)
//#define SOCKET_EPOLL
#define SOCKET_IOCP

#define FIFOSIZE_SERVERLINK 256*1024

/**
 * Parse function return code
 **/
enum parsefunc_rcode {
	PACKET_VALID         =  1,
	PACKET_INCOMPLETE    =  0,
	PACKET_UNKNOWN       = -1,
	PACKET_INVALIDLENGTH = -2,
	PACKET_STOPPARSE     = -3,
	PACKET_SKIP          = -4, //< internal parser will skip this packet and go
};                             //  parse another, meant for plugins. [hemagx]

/**
 * Data passed to the default_action_parse after IO_RECV dequeual
 * @see set_default_parse_action
 * @see socket_operation_process
 **/
struct s_receive_action_data {
	struct socket_data *session;
	uint8_t *rdata;
	size_t max_rdata, rdata_size, rdata_pos;
	bool validate; // flag.validate
	/**
	 * Last received buffer
	 * Initially rdata points to the first buffer of this data, but when there
	 * are incomplete packets rdata can be pointed to another memory location.
	 * @see action_receive
	 **/
	struct s_iocp_buffer_data *read_buffer;

	enum {
		ACTTYPE_NOT_QUEUED = 0, //< Non initialized action
		ACTTYPE_EMPTY = 30,     //< Purposefully empty action
		ACTTYPE_RECV = 32,      //< Properly filled action
	} act_type;
	int session_id;
};

/**
 * Send action
 * All send operations queued in an action thread are of this object.
 **/
struct s_send_action_data {
	struct socket_data *session;
	uint32_t session_id;
	bool is_server, validate;

	uint8 *wdata;
	size_t max_wdata, wdata_size, last_head_size;
	/**
	 * Position of the buffer in write_buffer that's currently in use
	 **/
	int write_buffer_pos;
	struct s_iocp_buffer_data *write_buffer;
};

// socket I/O macros
#define RFIFOHEAD(fd)
#define WFIFOHEAD(s, size, get_mutex) socket_io->wfifohead(s, size, get_mutex)

#define RFIFOP(a, pos) ((const void *)((a)->rdata + (a)->rdata_pos + (pos)))
#define WFIFOP(s, pos) (socket_io->wfifop((s),(pos)))

#define RFIFOB(a, pos) (*(const uint8*)RFIFOP((a),(pos)))
#define WFIFOB(s, pos) (*(uint8*)WFIFOP((s),(pos)))
#define RFIFOW(a, pos) (*(const uint16*)RFIFOP((a),(pos)))
#define WFIFOW(s, pos) (*(uint16*)WFIFOP((s),(pos)))
#define RFIFOL(a, pos) (*(const uint32*)RFIFOP((a),(pos)))
#define WFIFOL(s, pos) (*(uint32*)WFIFOP((s),(pos)))
#define RFIFOQ(a, pos) (*(const uint64*)RFIFOP((a),(pos)))
#define WFIFOQ(s, pos) (*(uint64*)WFIFOP((s),(pos)))

#define RFIFOREST(a)  (socket_io->rfiforest(a))
#define RFIFOFLUSH(a) (socket_io->rfifoflush(a))

#define WFIFOSET(s, len)  (socket_io->wfifoset(s, len, true))
#define WFIFOSET2(s, len)  (socket_io->wfifoset(s, len, false))
#define RFIFOSKIP(a, len) (socket_io->rfifoskip(a, len))

/* [Ind/Hercules] */
#define RFIFO2PTR(a) RFIFOP((a),0)
#define RP2PTR(a) RFIFO2PTR(a)

/* [Hemagx/Hercules] */
#define WFIFO2PTR(s) WFIFOP((s),0)
#define WP2PTR(s) WFIFO2PTR(s)

// buffer I/O macros
static inline const void *RBUFP_(const void *p, int pos) __attribute__((const, unused));
static inline const void *RBUFP_(const void *p, int pos)
{
	return ((const uint8 *)p) + pos;
}
#define RBUFP(p,pos) RBUFP_(p, (int)(pos))
#define RBUFB(p,pos) (*(const uint8 *)RBUFP((p),(pos)))
#define RBUFW(p,pos) (*(const uint16 *)RBUFP((p),(pos)))
#define RBUFL(p,pos) (*(const uint32 *)RBUFP((p),(pos)))
#define RBUFQ(p,pos) (*(const uint64 *)RBUFP((p),(pos)))

static inline void *WBUFP_(void *p, int pos) __attribute__((const, unused));
static inline void *WBUFP_(void *p, int pos)
{
	return ((uint8 *)p) + pos;
}
#define WBUFP(p,pos) WBUFP_(p, (int)(pos))
#define WBUFB(p,pos) (*(uint8*)WBUFP((p),(pos)))
#define WBUFW(p,pos) (*(uint16*)WBUFP((p),(pos)))
#define WBUFL(p,pos) (*(uint32*)WBUFP((p),(pos)))
#define WBUFQ(p,pos) (*(uint64*)WBUFP((p),(pos)))

#define TOB(n) ((uint8)((n)&UINT8_MAX))
#define TOW(n) ((uint16)((n)&UINT16_MAX))
#define TOL(n) ((uint32)((n)&UINT32_MAX))


#ifdef SOCKET_IOCP

/**
 * Possible buffer status in queue
 **/
enum e_queue_type {
	QT_OUTSIDE = 0,     //< Not in queue
	QT_WAITING_DEQUEUE, //< After being posted
	QT_WAITING_QUEUE    //< Waiting to be posted
};

/**
 * Buffer operations
 **/
enum e_buffer_operation {
	IO_NONE = 0,
	IO_RECV,
	IO_SEND,
};

/**
 * Buffer data
 *
 * Used to maintain a buffer valid until the corresponding packet is dequeued
 * From WSASend documentation:
 * "The lpOverlapped parameter must be valid for the duration of the overlapped operation.
 *  If multiple I/O operations are simultaneously outstanding, each must reference a separate
 *  WSAOVERLAPPED structure."
 * "For a Winsock application, once the WSASend function is called, the system owns these
 *  buffers and the application may not access them. This array must remain valid for the
 *  duration of the send operation."
 **/
struct s_iocp_buffer_data {
	/**
	 * Overlapped structure of the operation
	 *
	 * Must always be the first member of this struct when IOCP is active
	 * @see https://blogs.msdn.microsoft.com/oldnewthing/20101217-00/?p=11983/
	 **/
	OVERLAPPED overlapped;
	/**
	 * WSA buffer array
	 *
	 * For receive operations wsa_buffer.len is the total allocated length of
	 * wsa_buffer.buf, while in send operations is the number of bytes to be sent.
	 * On receive operations only one of the buffers is used, because we know the
	 * maximum possible receive packet len, for send we use the number of buffers
	 * required to send all the data in one system call.
	 * wsa_buffer.buf is allocated via ers_alloc in multiples of FIFO_SIZE
	 **/
	WSABUF *wsa_buffer;
	int buffer_count; // Count of WSABUF (0 indexed)

	enum e_queue_type status;
	enum e_buffer_operation operation;
};

#endif

// Struct declaration
typedef int (*RecvFunc)(int fd);
typedef int (*SendFunc)(int fd);
typedef int (*ParseFunc)(int fd);
typedef enum parsefunc_rcode (*ActionParseFunc)(struct s_receive_action_data *act); 

struct socket_data {
	struct {
		unsigned char eof : 1;
		unsigned char server : 1;
		unsigned char ping : 2;
		unsigned char validate : 1;
#ifdef SOCKET_IOCP
		// Socket marked for deletion later, there are still remaining operations.
		unsigned char wait_removal : 1;
		// Set if EOF was queued by session_disconnect
		unsigned char post_eof : 1;
#endif
	} flag;

	uint32 client_addr; // remote client address

#ifdef SOCKET_IOCP
	/**
	 * Queue that this session is attached to
	 * -1 No queue attached
	 **/
	int32_t action_queue_id;
	/**
	 * Identifier in session_db
	 **/
	uint32_t id;
	SOCKET socket;
	/**
	 * MUTEX lock of I/O operations performed by this session
	 * session_data is not protected by this mutex.
	 **/
	struct mutex_data *mutex;

	/**
	 * Buffers available for filling
	 *
	 * More than one s_iocp_buffer_data is required because every time
	 * an operation is queued we lose the management rights of the data
	 * to the kernel until "dequeual".
	 **/
	VECTOR_DECL(struct s_iocp_buffer_data*) iocp_available_buffer;

	/**
	 * Number of remaining completion packets to be dequeued
	 *  When a packet is expected to be dequeued this counter should be increased
	 *  and when it's dequeued it should be decreased
	 * It is only safe to free the the session while there are
	 * no operations remaining.
	 * @see socket_iocp_post_send
	 * @see socket_iocp_post_recv
	 **/
	int operations_remaining;

	/**
	 * Write reference counter
	 * The number of send operations that are to be performed in any of the
	 * action threads. After sending this is decreased.
	 * It is only safe to free the the session while there are
	 * no operations remaining.
	 * @see wfifoflush_act
	 * @see wfifohead
	 **/
	int writes_remaining;

	/**
	 * session_data usage counter
	 * Increased when an action thread receives a receive action.
	 * It is only safe to free the the session while there are
	 * no operations remaining.
	 * @see action_receive
	 **/
	int session_counter;

	ActionParseFunc parse;
	/**
	 * Timer id of timeout function
	 * @see session_timeout
	 **/
	int timeout_id;

	/**
	 * Incomplete packet data.
	 * This is only set after a the parse function returns PACKET_INCOMPLETE,
	 * all the received packets of a given session are processed by the same
	 * worker so there won't be any data-races with this data.
	 * So we can keep this property it's paramount that all incomplete data
	 * is processed by the current worker thread before attaching this session
	 * to another.
	 * @see action_receive
	 **/
	struct {
		uint8_t *data;
		size_t length;
	} incomplete_packet;
#else

	uint8 *rdata, *wdata;
	size_t max_rdata, max_wdata;
	size_t rdata_size, wdata_size;
	size_t rdata_pos;
	uint32 last_head_size;
#endif // Not SOCKET_IOCP
	time_t rdata_tick; // time of last recv (for detecting timeouts); zero when timeout is disabled
	time_t wdata_tick; // time of last send (for detecting timeouts);

#ifndef SOCKET_IOCP
	RecvFunc func_recv;
	SendFunc func_send;
	ParseFunc func_parse;
#endif

	/**
	 * Stores application-specific data related to the session
	 *
	 * Upon usage the session_counter is incremented, the session->mutex doesn't
	 * protect this data structure.
	 * This is done this way so we can minimize the number of blocks that I/O
	 * workers have because of sessions, when an Action Worker is handling this
	 * session_data it can use another lock if desired.
	 **/
	void* session_data;
	struct hplugin_data_store *hdata; ///< HPM Plugin Data Store.
};

struct hSockOpt {
	unsigned int silent : 1;
	unsigned int setTimeo : 1;
};

/// Subnet/IP range in the IP/Mask format.
struct s_subnet {
	uint32 ip;
	uint32 mask;
};

/// A vector of subnets/IP ranges.
VECTOR_STRUCT_DECL(s_subnet_vector, struct s_subnet);

/// Use a shortlist of sockets instead of iterating all sessions for sockets
/// that have data to send or need eof handling.
/// Adapted to use a static array instead of a linked list.
///
/// @author Buuyo-tama
#define SEND_SHORTLIST

// Note: purposely returns four comma-separated arguments
#define CONVIP(ip) ((ip)>>24)&0xFF,((ip)>>16)&0xFF,((ip)>>8)&0xFF,((ip)>>0)&0xFF
#define MAKEIP(a,b,c,d) ((uint32)( ( ( (a)&0xFF ) << 24 ) | ( ( (b)&0xFF ) << 16 ) | ( ( (c)&0xFF ) << 8 ) | ( ( (d)&0xFF ) << 0 ) ))

/// Applies a subnet mask to an IP
#define APPLY_MASK(ip, mask) ((ip)&(mask))
/// Verifies the match between two IPs, with a subnet mask applied
#define SUBNET_MATCH(ip1, ip2, mask) (APPLY_MASK((ip1), (mask)) == APPLY_MASK((ip2), (mask)))

/**
 * Common socket functions interface (socket.c)
 **/
struct socket_io_interface {
	int fd_max;
	/* */
	time_t stall_time;
	time_t last_tick;

	const char *SOCKET_CONF_FILENAME;
	/* */
	uint32 addr_[16];   // ip addresses of local host (host byte order)
	int naddr_;   // # of ip addresses
	bool validate;

	struct s_subnet_vector lan_subnets; ///< LAN subnets.
	struct s_subnet_vector trusted_ips; ///< Trusted IP ranges
	struct s_subnet_vector allowed_ips; ///< Allowed server IP ranges

	void (*rfifoflush)(struct s_receive_action_data *act);
	void (*rfifoskip)(struct s_receive_action_data *act, size_t len);
	size_t (*rfiforest)(const struct s_receive_action_data *act);
	bool (*wfifoset)(struct socket_data *session, size_t len, bool validate);
	void *(*wfifop)(struct socket_data *session, int pos);
	void (*wfifohead)(struct socket_data *session, size_t len, bool get_mutex);
	void (*wfifoflush)(struct socket_data *session);
	void (*wfifoflush_all)(void);

	/* */
	void (*init) (void);
	void (*final) (void);

	/* */
	bool (*make_listen_bind) (uint32 ip, uint16 port);
	struct socket_data *(*make_connection) (uint32 ip, uint16 port, struct hSockOpt *opt);
	void (*close) (int fd);

	/* */
	void (*flush) (struct socket_data *session);

	void (*set_defaultparse) (ActionParseFunc defaultparse);


	/* */
	uint32 (*lan_subnet_check) (uint32 ip, struct s_subnet *info);
	bool (*allowed_ip_check) (uint32 ip);
	bool (*trusted_ip_check) (uint32 ip);
	void (*net_config_read) (const char *filename);

	/* hostname/ip conversion functions */
	uint32 (*host2ip) (const char* hostname);
	const char * (*ip2str) (uint32 ip, char *ip_str);
	uint32 (*str2ip) (const char* ip_str);
	/* */
	uint16 (*ntows) (uint16 netshort);

	/* [Ind/Hercules] - socket_datasync */
	void (*datasync) (struct s_receive_action_data *act, bool send);

	bool (*session_marked_removal) (struct socket_data *session);
	bool (*session_mark_removal) (struct socket_data *session);
	void (*session_disconnect) (struct socket_data *session);
	void (*session_disconnect_guard) (struct socket_data *session);
	struct socket_data *(*session_from_id) (int32_t id);
	void (*session_update_parse) (struct socket_data *session, ActionParseFunc parse);
	int (*session_timeout) (struct timer_interface *tm, int tid, int64 tick, int id, intptr_t data);
};

#ifdef HERCULES_CORE
void socket_io_defaults(void);
#endif // HERCULES_CORE

HPShared struct socket_io_interface *socket_io;

#endif /* COMMON_SOCKET_H */
