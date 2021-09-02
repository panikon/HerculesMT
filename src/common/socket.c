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

#include "config/core.h" // SHOW_SERVER_STATS
#include "socket.h"

#include "common/HPM.h"
#include "common/cbasetypes.h"
#include "common/conf.h"
#include "common/ers.h"
#include "common/db.h"
#include "common/memmgr.h"
#include "common/mmo.h"
#include "common/nullpo.h"
#include "common/packets.h"
#include "common/showmsg.h"
#include "common/strlib.h"
#include "common/timer.h"

#include "common/rwlock.h"
#include "common/thread.h" //iocp
#include "common/mutex.h" // iocp
#include "common/sysinfo.h" // cpucores
#include "common/random.h"
#include "common/action.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#ifdef WIN32
#	include "common/winapi.h"
#endif  // WIN32

/////////////////////////////////////////////////////////////////////
#if defined(WIN32)
/////////////////////////////////////////////////////////////////////
// windows portability layer

typedef int socklen_t;

#define sErrno WSAGetLastError()
#define S_ENOTSOCK WSAENOTSOCK
#define S_EWOULDBLOCK WSAEWOULDBLOCK
#define S_EINTR WSAEINTR
#define S_ECONNABORTED WSAECONNABORTED

#define SHUT_RD   SD_RECEIVE
#define SHUT_WR   SD_SEND
#define SHUT_RDWR SD_BOTH

static char *sErr(int code)
{
	static char sbuf[512];
	// strerror does not handle socket codes
	if( FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
			code, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), (LPTSTR)&sbuf, sizeof(sbuf), NULL) == 0 )
		snprintf(sbuf, sizeof(sbuf), "unknown error");
	return sbuf;
}

/////////////////////////////////////////////////////////////////////
#else  // defined(WIN32)
/////////////////////////////////////////////////////////////////////
// nix portability layer

#define SOCKET_ERROR (-1)

#define sErrno errno
#define S_ENOTSOCK EBADF
#define S_EWOULDBLOCK EAGAIN
#define S_EINTR EINTR
#define S_ECONNABORTED ECONNABORTED

#define sAccept accept
#define sClose close
#define sSocket socket
#define sErr strerror

#define sBind bind
#define sConnect connect
#define sIoctl ioctl
#define sListen listen
#define sRecv recv
#define sSelect select
#define sSend send
#define sSetsockopt setsockopt
#define sShutdown shutdown
#define sFD_SET FD_SET
#define sFD_CLR FD_CLR
#define sFD_ISSET FD_ISSET
#define sFD_ZERO FD_ZERO

/////////////////////////////////////////////////////////////////////
#endif  // defined(WIN32)
/////////////////////////////////////////////////////////////////////

// Maximum packet size in bytes, which the client is able to handle.
// Larger packets cause a buffer overflow and stack corruption.
#if PACKETVER >= 20131223
static size_t socket_max_client_packet = 0xFFFF;
#else  // PACKETVER >= 20131223
static size_t socket_max_client_packet = 0x6000;
#endif  // PACKETVER >= 20131223

#ifdef SHOW_SERVER_STATS
// Data I/O statistics
static size_t socket_data_i = 0, socket_data_ci = 0, socket_data_qi = 0;
static size_t socket_data_o = 0, socket_data_co = 0, socket_data_qo = 0;
static time_t socket_data_last_tick = 0;
#endif  // SHOW_SERVER_STATS

// initial recv buffer size (this will also be the max. size)
// biggest known packet: S 0153 <len>.w <emblem data>.?B -> 24x24 256 color .bmp (0153 + len.w + 1618/1654/1756 bytes)
#define RFIFO_SIZE (2*1024)
// initial send buffer size (will be resized as needed)
#define WFIFO_SIZE (16*1024)

// Maximum size of pending data in the write fifo. (for non-server connections)
// The connection is closed if it goes over the limit.
#define WFIFO_MAX (1*1024*1024)

/**
 * The maximum number of concurrent threads active associated with
 * io_completion_port.
 * When 0 is specified the Concurrency Value is set
 * to the number of cores in the system
 * @see io_completion_port_init
 **/
#define IOCP_CONCURRENCY_VALUE 0

/**
 * Number of worker threads in the pool per processor
 *  Note that the concurrency value of our I/O completion port is set to the
 *  number of processors, but the number of workers is double this value. This
 *  is because when a function causes a thread to block then the I/O Completion
 *  port detects it and activates another thread. When the first thread unblocks
 *  it will be activated and the concurrency value will be greater than the
 *  limit for a brief period of time.
 *  See Jeffery Richter's Windows via C/C++ for more information
 **/
#define IOCP_WORKERS_PER_PROCESSOR 2

/**
 * Initial number of buffers allocated for a session
 * @see socket_data::iocp_available_buffer
 **/
#define IOCP_INITIAL_BUFFER_COUNT 5

/**
 * FIFO minimum size
 * This should be set to the same value as RFIFO_SIZE because this is the default
 * allocation value for all buffers.
 *
 * @see socket_wsa_init
 * @see ers_buffer_instance
 **/
#define FIFO_SIZE RFIFO_SIZE

#ifdef WIN32
#ifdef SOCKET_IOCP
// Most of the functions used for completion ports require
// at least winsock 2.2
#define HERC_WSA_MAJOR 2
#define HERC_WSA_MINOR 2
#else
#define HERC_WSA_MAJOR 2
#define HERC_WSA_MINOR 0
#endif // not SOCKET_IOCP
#endif // WIN32

static int ip_rules = 1;
static int connect_check(uint32 ip);

static const char *error_msg(void)
{
	static char buf[512];
	int code = sErrno;
	snprintf(buf, sizeof(buf), "error %d: %s", code, sErr(code));
	return buf;
}

/**
 * Socket Interface
 **/
static struct socket_io_interface socket_io_s;
struct socket_io_interface *socket_io;

/**
 * Session table
 *
 * Contains all valid sessions, with a number (int32) as key.
 * Sessions are created via create_session
 * Members are of struct socket_data* type
 **/
static struct DBMap *session_db = NULL;
static struct mutex_data *session_db_mutex = NULL;

static struct ers_collection_t *ers_socket_collection = NULL;
static ERS *ers_session_instance = NULL;
static ERS *ers_buffer_instance = NULL;

#ifdef SOCKET_IOCP
/**
 * Completion port handle
 * @see socket_init_wsa
 * @see socket_worker
 **/
static HANDLE io_completion_port = NULL;
/**
 * Accept event used by the listen thread
 * @see make_listen_bind
 * @see socket_listen
 **/
static HANDLE io_accept_event = NULL;
#endif

/**
 * List of pointers to the handles of the IO workers
 * @see socket_init_thread_pool
 **/
struct thread_handle **socket_thread = NULL;
int socket_thread_count = 0;
struct thread_handle *socket_listen_thread = NULL;

struct mutex_data *socket_shutdown_mutex = NULL;
struct cond_data *socket_shutdown_event = NULL;
bool socket_run = true;

/**
 * List of send operations remaining for an action thread.
 * [session ptr][s_send_action_data]
 * @see socket_wfifoset
 **/
static thread_local struct linkdb_node *l_write_list = NULL;
static thread_local struct s_send_action_data *l_write_cache = NULL;

static ERS *ers_send_action_instance = NULL;
static ERS *ers_receive_action_instance = NULL;

// Prototypes
bool session_mark_removal(struct socket_data *session);
void action_receive(void *data);
void socket_iocp_buffer_grow(struct s_iocp_buffer_data *buffer_data);
void socket_iocp_buffer_clear(struct s_iocp_buffer_data *buffer_data);
void socket_iocp_buffer_free(struct s_iocp_buffer_data *buffer_data);
static int socket_getips(uint32 *ips, int max);

/*======================================
 * CORE : Default processing functions
 *--------------------------------------*/

static void null_parse(struct s_receive_action_data *act)
{
	return;
}

static ActionParseFunc default_func_parse = null_parse;

static void set_defaultparse(ActionParseFunc defaultparse)
{
	default_func_parse = defaultparse;
}

/**
 * Tries to force a disconnection
 * @warning This should only be called otuside I/O workers
 * @mutex session->mutex
 **/
static void session_disconnect(struct socket_data *session)
{
	if(!session_mark_removal(session))
		return;

	/**
	 * Don't post from I/O worker, only session_mark_removal should be called
	 * from those threads.
	 **/
	if(thread->flag_get()&THREADFLAG_IO) {
		ShowDebug("session_disconnect: Tried to disconnect a session from an I/O worker, "
			"only session_mark_removal should be called from those threads.\n");
		return;
	}

	if(session->flag.post_eof)
		return; // Already posted

	/**
	 * This is the last operation of this session, post an empty completion
	 * status so the I/O worker knows to close this connection and delete it.
	 * Otherwise this session will be lost into the void and will never be
	 * properly freed.
	 **/
	PostQueuedCompletionStatus(io_completion_port, 0, (ULONG_PTR)session, NULL);
	session->flag.post_eof = 1;
}
static void session_disconnect_guard(struct socket_data *session)
{
	mutex->lock(session->mutex);
	session_disconnect(session);
	mutex->unlock(session->mutex);
}

/**
 * Verifies if provided session has timed out.
 * Should be executed from the responsible action worker.
 *
 * @param tm   Timer interface.
 * @param tid  Timer id.
 * @param tick Current tick.
 * @param id   0
 * @param data session data.
 * @see TimerFunc
 **/
static int session_timeout(struct timer_interface *tm, int tid, int64 tick, int id, intptr_t data)
{
	struct socket_data *session = (struct socket_data*)data;
	mutex->lock(session->mutex);
	if(DIFF_TICK(timer->get_server_tick(), session->rdata_tick) > socket_io->stall_time) {
		// Server doesn't timeout
		if(session->flag.server) {
			if(session->flag.ping != 2) // Only update if necessary, otherwise
				session->flag.ping = 1; // it'd resend the ping unnecessarily
		} else {
			ShowInfo("Session #%d timed out\n", session->id);
			socket_io->session_disconnect(session);
			tm->delete(tid, session_timeout);
		}
	}
	mutex->unlock(session->mutex);
	return 0;
}

/*======================================
 * CORE : Session handling
 *--------------------------------------*/

/**
 * Grows available buffers
 * @mutex session->mutex
 **/
static void session_buffer_available_grow(struct socket_data *session)
{
	struct s_iocp_buffer_data *buffer;

	rwlock->read_lock(ers_collection_lock(ers_socket_collection));
	mutex->lock(ers_buffer_instance->cache_mutex);
	for(int i = 0; i < IOCP_INITIAL_BUFFER_COUNT; i++) {
		buffer = aCalloc(1, sizeof(*buffer));
		CREATE(buffer->wsa_buffer, WSABUF, 1);
		buffer->wsa_buffer->buf = ers_alloc(ers_buffer_instance);
		VECTOR_PUSH(session->iocp_available_buffer, buffer);
	}
	mutex->unlock(ers_buffer_instance->cache_mutex);
	rwlock->read_unlock(ers_collection_lock(ers_socket_collection));
}

/**
 * Gets next available buffer, grows iocp_available_buffer if necessary
 * @mutex session->mutex
 **/
static struct s_iocp_buffer_data *session_buffer_available(struct socket_data *session)
{
	if(!VECTOR_LENGTH(session->iocp_available_buffer))
		session_buffer_available_grow(session);

	return VECTOR_POP(session->iocp_available_buffer);
}

/**
 * Frees data and removes session from session_db
 *
 * Session should already have been closed before calling
 *
 * @param session Session
 * @param remove_db Should the session be removed from session_db
 * @mutex session->mutex
 *
 * @remarks The mutex is unlocked even in failure
 **/
static void delete_session(struct socket_data *session, bool remove_db)
{
	nullpo_retv(session);
#ifdef SHOW_SERVER_STATS
	//TODO
	socket_data_qi -= socket_io->session[fd]->rdata_size - socket_io->session[fd]->rdata_pos;
	socket_data_qo -= socket_io->session[fd]->wdata_size;
#endif  // SHOW_SERVER_STATS
	if(!session_mark_removal(session)) {
		// Not ready for removal
		// Upon the dequeue of the last operation delete will be called again.
		ShowError("delete_session: Tried to delete session(%d) with %d operations remaining, %d writes\n",
			session->id, session->operations_remaining, session->writes_remaining);
		mutex->unlock(session->mutex);
		return;
	}
	if(session->timeout_id != -1)
		timer->delete(session->timeout_id, socket_io->session_timeout);

	rwlock->read_lock(ers_collection_lock(ers_socket_collection));
	mutex->lock(ers_buffer_instance->cache_mutex);
	while(VECTOR_LENGTH(session->iocp_available_buffer))
		socket_iocp_buffer_free(VECTOR_POP(session->iocp_available_buffer));
	mutex->unlock(ers_buffer_instance->cache_mutex);
	rwlock->read_unlock(ers_collection_lock(ers_socket_collection));

	VECTOR_CLEAR_SHARED(session->iocp_available_buffer);

	mutex->unlock(session->mutex);
	mutex->destroy(session->mutex);

	if(remove_db) {
		mutex->lock(session_db_mutex);
		idb_remove(session_db, session->id);
		mutex->unlock(session_db_mutex);
	}

	rwlock->read_lock(ers_collection_lock(ers_socket_collection));
	mutex->lock(ers_session_instance->cache_mutex);
	ers_free(ers_session_instance, session);
	mutex->unlock(ers_session_instance->cache_mutex);
	rwlock->read_unlock(ers_collection_lock(ers_socket_collection));
}

/**
 * Creates a new session
 *
 * @param socket     Session socket
 * @param func_send  Send function
 * @param func_parse Parse function
 * @return Session
 * @retval NULL Failure
 * @warning The mutex of the created session is LOCKED and should be freed by the caller!
 *
 * @remarks Why *Func are not being set? In the traditional socket approach all types
 * of sockets were created with a session associated, so for the listen socket there was
 * the need for another receive function to be called. See also sock->session[0] that was
 * reserved for disconnected sessions of the map-server.
 * In this approach listening is handled by another thread and because only client/server
 * sessions are in the session_db there's no need to change receive processing from an
 * I/O worker.
 * @see socket_operation_process
 **/
static struct socket_data *create_session(SOCKET socket)
{
	struct socket_data *session;

	rwlock->read_lock(ers_collection_lock(ers_socket_collection));

	mutex->lock(ers_session_instance->cache_mutex);
	session = ers_alloc(ers_session_instance);
	mutex->unlock(ers_session_instance->cache_mutex);
	session->mutex = mutex->create();

	if(!session->mutex) {
		ShowError("create_session: Failed to create new mutex\n");
		mutex->lock(ers_session_instance->cache_mutex);
		ers_free(ers_session_instance, session);
		mutex->unlock(ers_session_instance->cache_mutex);
		rwlock->read_unlock(ers_collection_lock(ers_socket_collection));
		return NULL;
	}
	rwlock->read_unlock(ers_collection_lock(ers_socket_collection));

	VECTOR_INIT_CAPACITY_SHARED(session->iocp_available_buffer, IOCP_INITIAL_BUFFER_COUNT);
	session_buffer_available_grow(session);

	session->socket     = socket;
	session->rdata_tick = timer->gettick_nocache();
	session->parse      = default_func_parse;
	session->timeout_id = -1;

	/**
	 * Lock before adding to session_db so we don't risk a data race in case
	 * someone accesses the db after our addition and tries to handle this
	 * session
	 **/
	mutex->lock(session->mutex);

	mutex->lock(session_db_mutex);
	do {
		session->id = rnd->value(1, INT32_MAX);
	} while(idb_exists(session_db, session->id));
	idb_put(session_db, session->id, session);
	mutex->unlock(session_db_mutex);

	session->timeout_id = timer->add_sub(timer->gettick_nocache(),
		socket_io->session_timeout,
		0, (intptr_t)session,
		(int)socket_io->stall_time, TIMER_INTERVAL,
		TIMER_SESSION, session->id);
	if(session->timeout_id == -1) {
		ShowError("create_session: Failed to setup timeout timer\n");
		delete_session(session, true); // Needs session->mutex previously locked
		return NULL;
	}

	return session;
}

/**
 * Aborts connection
 * @mutex session->mutex
 **/
static void close_session(struct socket_data *session)
{
	nullpo_retv(session);
	if(session->socket == INVALID_SOCKET)
		return;
	if(WSAGetLastError() == WSA_OPERATION_ABORTED) // Already aborted
		return;

	// Raises WSA_OPERATION_ABORTED
	if(!CancelIo((HANDLE)session->socket))
		ShowError("close_session: Connection %ld (%u.%u.%u.%u), CancelIo '%s'\n",
			CONVIP(session->client_addr), error_msg());

	if(closesocket(session->socket) == SOCKET_ERROR) {
		ShowError("close_session: Connection %ld (%u.%u.%u.%u), closesocket '%s'\n",
			CONVIP(session->client_addr), error_msg());
	}
	session->socket = INVALID_SOCKET;
	// Closed connection from x
}

/**
 * Called upon perceived disconnection.
 * If session is ready for removal posts an empty receive action so the server
 * can do proper session cleanup before we do socket_data cleanup.
 *
 * Acquires session->mutex
 **/
static void socket_connection_lost(struct socket_data *session)
{
	nullpo_retv(session);

	mutex->lock(session->mutex);

	session->operations_remaining--;
	if(session_mark_removal(session)) {
		// Advance next parsing call so the session EOF can be handled by
		// server-specific functions.
		struct s_receive_action_data *recv_action;
		rwlock->read_lock(ers_collection_lock(ers_socket_collection));
		mutex->lock(ers_receive_action_instance->cache_mutex);
		recv_action = ers_alloc(ers_receive_action_instance);
		mutex->unlock(ers_receive_action_instance->cache_mutex);
		rwlock->read_unlock(ers_collection_lock(ers_socket_collection));
		recv_action->session = session;
		// ERS_OPT_CLEAN, post empty action

		action->enqueue(action->queue_get(session),
			action_receive, recv_action);
	}

	mutex->unlock(session->mutex);
}

/**
 * Sets the options for a socket.
 *
 * @param s   Socket
 * @param opt Optional, additional options to set (Can be NULL).
 */
static void setsocketopts(SOCKET s, struct hSockOpt *opt)
{ // TODO: Remerge with original setsocketopts
	BOOL yes = TRUE;
	struct linger lopt = { 0 };

	// Set the socket into no-delay mode; otherwise packets get delayed for up to 200ms, likely creating server-side lag.
	// The RO protocol is mainly single-packet request/response, plus the FIFO model already does packet grouping anyway.
	if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&yes, sizeof(yes)))
		ShowWarning("setsocketopts: Unable to set TCP_NODELAY mode for connection!\n");

	if (opt && opt->setTimeo) {
		DWORD timeout = 5000; // https://msdn.microsoft.com/en-us/library/windows/desktop/ms740476(v=vs.85).aspx

		if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)))
			ShowWarning("setsocketopts: Unable to set SO_RCVTIMEO for connection #%d!\n");
		if (setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)))
			ShowWarning("setsocketopts: Unable to set SO_SNDTIMEO for connection #%d!\n");
	}

	// force the socket into no-wait, graceful-close mode (should be the default, but better make sure)
	//(http://msdn.microsoft.com/library/default.asp?url=/library/en-us/winsock/winsock/closesocket_2.asp)
	lopt.l_onoff = 0; // SO_DONTLINGER
	lopt.l_linger = 0; // Do not care
	if (setsockopt(s, SOL_SOCKET, SO_LINGER, (char *)&lopt, sizeof(lopt)))
		ShowWarning("setsocketopts: Unable to set SO_LINGER mode for connection!\n");

#ifdef TCP_THIN_LINEAR_TIMEOUTS
	if (setsockopt(s, IPPROTO_TCP, TCP_THIN_LINEAR_TIMEOUTS, (char *)&yes, sizeof(yes)))
		ShowWarning("setsocketopts: Unable to set TCP_THIN_LINEAR_TIMEOUTS mode for connection #%d!\n", fd);
#endif  // TCP_THIN_LINEAR_TIMEOUTS
#ifdef TCP_THIN_DUPACK
	if (setsockopt(s, IPPROTO_TCP, TCP_THIN_DUPACK, (char *)&yes, sizeof(yes)))
		ShowWarning("setsocketopts: Unable to set TCP_THIN_DUPACK mode for connection #%d!\n", fd);
#endif  // TCP_THIN_DUPACK
}


/*======================================
 * CORE : IOCP Post
 *--------------------------------------*/

/**
 * Posts next send receive for the provided session
 * @param buffer_data Buffers to be sent
 * @param buffer_count Number of WSABUF to be sent
 * @mutex session->mutex
 **/
static bool socket_iocp_post_send(struct socket_data *session,
	struct s_iocp_buffer_data *buffer_data, size_t buffer_count)
{
	int retval;
	DWORD flags = 0;
	assert(!(thread->flag_get()&THREADFLAG_IO)
		&& "Send should only be posted from action threads");

	buffer_data->status = QT_WAITING_DEQUEUE;
	buffer_data->operation = IO_SEND;

	session->operations_remaining++;
	retval = WSASend(session->socket,
					 buffer_data->wsa_buffer,
					 buffer_count,
					 /**
					  * lpNumberOfBytesSent should be NULL when lpOverlapped is not
					  * so as to avoid potentially erroneous results
					  **/
					 NULL,
					 flags,
					 (LPOVERLAPPED)buffer_data,
					 /**
					  * There is no need to set lpCompletionRoutine or to define
					  * context->overlapped.hEvent because the completion notifications
					  * are received via GetQueuedCompletionStatus
					  **/
					 NULL);
	if(retval == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
		session->operations_remaining--;
		/**
		 * We're calling from an action thread, make sure the server knows
		 * to disconnect this session even if there are no more buffers to dequeue.
		 **/
		session_disconnect(session);
		ShowError("socket_iocp_post_send(%ld): Failed to post send request, %d: '%s'\n",
			thread->get_tid(), WSAGetLastError(), sErr(sErrno));
		buffer_data->status = QT_WAITING_QUEUE;
		buffer_data->operation = IO_NONE;
		VECTOR_PUSH(session->iocp_available_buffer, buffer_data);
		return false;
	}
	// WSASend always send the whole buffer
	return true;
}

/**
 * Posts next receive request for the provided session
 * On failure reinserts buffer_data to available_buffers
 * @mutex session->mutex
 **/
static bool socket_iocp_post_recv(struct socket_data *session, struct s_iocp_buffer_data *buffer_data)
{
	int bytes_received;
	DWORD flags = 0; // No behavioural changes in WSARecv

	socket_iocp_buffer_clear(buffer_data);
	buffer_data->wsa_buffer[0].len = FIFO_SIZE;
	buffer_data->status = QT_WAITING_DEQUEUE;
	buffer_data->operation = IO_RECV;

	session->operations_remaining++;
	bytes_received = WSARecv(session->socket,
		                     &buffer_data->wsa_buffer[0],
							 1,
						     /**
						      * lpNumberOfBytesRecvd should be NULL when lpOverlapped is not
						      * so as to avoid potentially erroneous results
						      **/
							 NULL,
							 &flags,
							 (LPOVERLAPPED)buffer_data,
						     /**
						      * There is no need to set lpCompletionRoutine or to define
						      * context->overlapped.hEvent because the completion notifications
						      * are received via GetQueuedCompletionStatus
						      **/
							 NULL);

	if(bytes_received == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
		ShowError("socket_iocp_post_recv(%d): Failed to post receive request, '%s'\n",
			thread->get_tid(), sErr(sErrno));
		buffer_data->status = QT_WAITING_QUEUE;
		buffer_data->operation = IO_NONE;
		VECTOR_PUSH(session->iocp_available_buffer, buffer_data);
		session->operations_remaining--;
		session_mark_removal(session);
		return false;
	}
	// WSARecv always queues the request, processing will be made on next dequeue
	return true;
}

/**
 * Creates a new connection and sets up completion data
 *
 * @param s      Session socket
 * @param addr   Session address data
 * @param silent Should messages be silenced
 *
 * Upon failure closes provided socket
 * @warning The mutex of the created session is LOCKED and should be freed by the caller!
 **/
static struct socket_data *session_setup(SOCKET s, struct sockaddr_in *addr, bool silent)
{
	struct socket_data *session;

	session = create_session(s);
	if(!session) {
		if(!silent)
			ShowError("make_connection: connect failed, no session data!\n", error_msg());
		closesocket(s);
		return NULL;
	}
	session->client_addr = ntohl(addr->sin_addr.s_addr);

	// Associate io_completion_port to new socket
	HANDLE associate_io;
	associate_io = CreateIoCompletionPort((HANDLE)s,
					                      io_completion_port,
					                      /**
					                       * This session will be passed to the worker thread
					                       * when the completion packets of this socket are dequeued
					                       **/
					                      (DWORD)session,
					                      0); // When associating completion ports this parameter is ignored
	if(associate_io == NULL) {
		if(!silent)
			ShowError("session_setup: Failed to associate socket with completion port (%d: %s)!\n",
				session->id, error_msg());
		close_session(session);
		delete_session(session, true);
		return NULL;
	}
	// Post first receive request
	if(!socket_iocp_post_recv(session, session_buffer_available(session))) {
		if(!silent)
			ShowError("session_setup: Failed to post first receive request (%d: %s)!\n",
				session->id, error_msg());
		close_session(session);
		delete_session(session, true);
		return NULL;
	}
	return session;
}

/**
 * Accepts incoming connection
 * @see socket_listen
 **/
static bool connect_client(SOCKET listen_socket)
{
	struct sockaddr_in incoming_address;
	int incoming_address_len = sizeof(incoming_address);
	SOCKET s;

	s = accept(listen_socket, (struct sockaddr *)&incoming_address, &incoming_address_len);
	if(s == INVALID_SOCKET) {
		int error = WSAGetLastError();
		if(error != WSAEWOULDBLOCK)
			ShowError("connect_client: Failed to accept connection (%s)!\n", error_msg());
		else
			ShowError("connect_client: No connections available\n");
		return false;
	}
	if(action->ready() <= 0) {
		ShowError("connect_client: No action threads available for processing\n");
		closesocket(s);
		return false;
	}
	setsocketopts(s, NULL);

	if(ip_rules && !connect_check(ntohl(incoming_address.sin_addr.s_addr)) ) {
		closesocket(s);
		return false;
	}

	struct socket_data *session;
	session = session_setup(s, &incoming_address, false);
	if(!session) {
		ShowError("connect_client: Failed to setup session\n");
		return false;
	}
	mutex->unlock(session->mutex);
	return true;
}

/*======================================
 * CORE : FIFO
 *--------------------------------------*/

/**
 * Flushes send action
 * @mutex session->mutex
 **/
static void wfifoflush_act(struct s_send_action_data *act)
{
	struct socket_data *session = act->session;
	session->writes_remaining--;

	if(socket_iocp_post_send(session, act->write_buffer, act->write_buffer_pos+1)) {
#ifdef SHOW_SERVER_STATS
		socket_data_o += len;
		socket_data_qo -= len;
		if(!session->flag.server)
			socket_data_co += len;
#endif  // SHOW_SERVER_STATS
		session->wdata_tick = timer->get_server_tick();
	}

	// Disconnect only after sending remaining operations
	if(session->flag.eof || session->flag.wait_removal) {
		session_disconnect(session);
	}

	rwlock->read_lock(ers_collection_lock(ers_socket_collection));
	mutex->lock(ers_receive_action_instance->cache_mutex);
	ers_free(ers_send_action_instance, act);
	mutex->unlock(ers_receive_action_instance->cache_mutex);
	rwlock->read_unlock(ers_collection_lock(ers_socket_collection));
}

/**
 * Flushes all send actions of a given session
 * @mutex session->mutex
 **/
static void wfifoflush(struct socket_data *session)
{
	nullpo_retv(session);
	struct s_send_action_data *act;
	if(!(act = linkdb_search(&l_write_list, session))) {
		ShowDebug("WFIFOFLUSH(%d): Tried to flush empty session (%d)\n",
			thread->get_tid(), session->id);
		return;
	}
	wfifoflush_act(act);
	linkdb_erase(&l_write_list, session);
}

/**
 * Flushes key-value pair
 * @param key  Session object
 * @param data Send action data
 * @see LinkDBFunc
 * @see wfifoflush_all
 * @see wfifoflush_act
 * @return 1 - Delete item
 **/
int wfifoflush_iterator(void *key, void *data, va_list args)
{
	struct socket_data *session = key;
	struct s_send_action_data *act = data;
	mutex->lock(session->mutex);
	wfifoflush_act(act);
	mutex->unlock(session->mutex);
	return 1;
}

/**
 * Flushes all send actions of all sessions
 * @warning No session->mutex should be locked by this thread
 **/
static void wfifoflush_all(void)
{
	linkdb_foreach(&l_write_list, wfifoflush_iterator);
}

/**
 * Ensures that there's enough data for the next operation
 * @param get_mutex Try to acquire mutex
 *                  Even if true mutex is only acquired in the first write of this action.
 **/
static void wfifohead(struct socket_data *session, size_t len, bool get_mutex)
{
	struct s_send_action_data *act;
	if(l_write_cache && l_write_cache->session == session)
		act = l_write_cache;
	else {
		if(!(act = linkdb_search(&l_write_list, session))) {
			rwlock->read_lock(ers_collection_lock(ers_socket_collection));
			mutex->lock(ers_receive_action_instance->cache_mutex);
			act = ers_alloc(ers_send_action_instance);
			mutex->unlock(ers_receive_action_instance->cache_mutex);
			rwlock->read_unlock(ers_collection_lock(ers_socket_collection));

			if(get_mutex) mutex->lock(session->mutex);
			session->writes_remaining++;
			act->write_buffer = session_buffer_available(session);
			act->session_id = session->id;
			act->is_server = session->flag.server;
			act->validate = session->flag.validate;
			if(get_mutex) mutex->unlock(session->mutex);

			act->session = session;
			act->max_wdata = FIFO_SIZE;
			act->wdata = act->write_buffer->wsa_buffer[0].buf;
			act->wdata_size = 0;
			act->last_head_size = 0;
			act->write_buffer_pos = 0;
			linkdb_insert(&l_write_list, session, act);

		}
		l_write_cache = act;
	}

	act->last_head_size = len;
	if(act->wdata_size + len > act->max_wdata) {
		act->write_buffer->wsa_buffer[act->write_buffer_pos].len = act->wdata_size;
		if(++act->write_buffer_pos > act->write_buffer->buffer_count)
			socket_iocp_buffer_grow(act->write_buffer);

		act->wdata = act->write_buffer->wsa_buffer[act->write_buffer_pos].buf;
		act->wdata_size = 0;
	}
}

/**
 * Returns pointer to wdata position for this session in this thread
 * Replaces WFIFOP
 **/
void *wfifop(struct socket_data *session, int pos)
{
	struct s_send_action_data *act;
	if(l_write_cache && l_write_cache->session == session)
		act = l_write_cache;
	else {
		act = linkdb_search(&l_write_list, session);
		assert(act && "All WFIFO operations must be preceded by a WFIFOHEAD!");
		l_write_cache = act;
	}

	return act->wdata + act->wdata_size + pos;
}

/**
 * Validates provided write packet data
 **/
static bool socket_validateWfifo(struct s_send_action_data *act, size_t len)
{
	uint32_t cmd = (uint32)WFIFOW(act->session, 0);
	if(cmd < MIN_PACKET_DB || cmd > MAX_PACKET_DB) {
		ShowError("socket_validateWfifo(%d): packet command outside of range (0x%04X)\n",
			thread->get_tid(),cmd);
		return false;
	}
	int expected_len = packets->db[cmd];
	
	size_t minimum_len;
	if(expected_len == -1) {
		expected_len = (int)WFIFOW(act->session, 2);
		minimum_len = 4; // Dynamic packets must be at least 4 bytes (header + length)
	} else {
		minimum_len = 2;
	}
	if(len < minimum_len) {
		ShowError("socket_validateWfifo(%d): packet (0x%04X) with size smaller than %zd\n",
			thread->get_tid(), cmd, minimum_len);
		return false;
	}
	// Maximum length was already verified in WFIFOSET

	if(len != expected_len) {
		ShowError("socket_validateWfifo(%d): Sent packet 0x%04X with "
			"size %d, but must be size %d\n",
			thread->get_tid(), cmd, len, expected_len);
		return false;
	}
	if(act->last_head_size < (uint32)expected_len) {
		ShowError("socket_validateWfifo(%d): Reserved too small packet buffer "
			"for packet 0x%04X with size %u, but must be size %d\n",
			thread->get_tid(), cmd, act->last_head_size, expected_len);
		return false;
	}
	return true;
}

/**
 * Advances WFIFO cursor (marking 'len' bytes for sending)
 **/
static bool wfifoset(struct socket_data *session, size_t len, bool validate)
{
	struct s_send_action_data *act;
	if(l_write_cache && l_write_cache->session == session)
		act = l_write_cache;
	else {
		act = linkdb_search(&l_write_list, session);
		assert(act && "All WFIFO operations must be preceded by a WFIFOHEAD!");
		l_write_cache = act;
	}

	if(len > act->last_head_size) {
		ShowError("WFIFOSET(%d): WFIFOHEAD(%zd) mismatched with WFIFOSET(%zd)! (session %d)\n",
			thread->get_tid(), act->last_head_size, len, act->session_id);
		ShowDebug("WFIFOSET(%d): Likely command that caused it: 0x%x. Dropped packet.\n",
			thread->get_tid(), (*(uint16*)(act->wdata + act->wdata_size)));
		if(act->wdata_size+len > act->max_wdata) {
			// Can't recover from a buffer overflow
			ShowFatalError("WFIFOSET(%d): Write Buffer Overflow. "
				"Session %d has written %zd bytes on a %zd/%zd bytes buffer.\n",
				thread->get_tid(), act->session_id, len, act->wdata_size, act->max_wdata);
			exit(EXIT_FAILURE);
		}
		return false;
	}

	if(len > 0xFFFF) {
		// dynamic packets allow up to UINT16_MAX bytes (<packet_id>.W <packet_len>.W ...)
		// all known fixed-size packets are within this limit, so use the same limit
		ShowError("WFIFOSET(%d): Packet 0x%x is too big (len=%zd, max=%u). Dropped.\n",
			thread->get_tid(), (*(uint16*)(act->wdata + act->wdata_size)), len, 0xFFFFU);
		return false;
	}
	if(len == 0) {
		// abuses the fact, that the code that did WFIFOHEAD(fd,0), already wrote
		// the packet type into memory, even if it could have overwritten vital data
		// this can happen when a new packet was added on map-server, but packet len table was not updated
		ShowWarning("WFIFOSET(%d): Attempted to send zero-length packet, "
			"most likely 0x%04x (please report this).\n",
			thread->get_tid(), WFIFOW(session,0));
		return false;
	}

	if(!act->is_server && len > socket_max_client_packet) {
		// Packets greater than the maximum length cause stack corruption on the client
		ShowError("WFIFOSET(%d): Dropped too large client packet 0x%04x "
			"(length=%zd, max=%zd).\n",
			thread->get_tid(), WFIFOW(session,0), len, socket_max_client_packet);
		return false;
	}

	if(validate && act->validate == 1) {
		if(!socket_validateWfifo(act, len)) {
			ShowError("WFIFOSET(%d): Invalid packet (0x%04x) dropped.\n",
				thread->get_tid(), WFIFOW(session,0));
			return false;
		}
	}

	act->wdata_size += len;
	act->write_buffer->wsa_buffer[act->write_buffer_pos].len += len;

#ifdef SHOW_SERVER_STATS
	socket_data_qo += len;
#endif  // SHOW_SERVER_STATS
	//If the interserver has 200% of its normal size full, flush the data.
	if(act->is_server && act->wdata_size >= 2*FIFOSIZE_SERVERLINK)
		wfifoflush(session);

	return true;
}

/**
 * Returns pointer to rdata position for this session
 * Replaces RFIFOP
 **/
const void *rfifop(struct s_receive_action_data *act, int pos)
{
	return act->rdata + act->rdata_pos + pos;
}

/**
 * Returns remaining bytes in receive action data
 **/
size_t rfiforest(const struct s_receive_action_data *act)
{
	if(act->session->flag.eof || act->session->flag.wait_removal)
		return 0;
	return act->rdata_size - act->rdata_pos;
}

/**
 * Validates received data
 * TODO: Merge WFIFO and RFIFO validation
 **/
static bool socket_validateRfifo(struct s_receive_action_data *act, size_t len)
{
	size_t len_rest = RFIFOREST(act);
	if(len_rest < 2 || len != len_rest) // Not enough data to validate
		return true;

	uint32 cmd = (uint32)RFIFOW(act, 0);
	if(cmd < MIN_PACKET_DB || cmd > MAX_PACKET_DB) {
		ShowError("socket_validateRfifo(%d): packet command outside of range (0x%04X)\n",
			thread->get_tid(),cmd);
		return false;
	}
	int expected_len = packets->db[cmd];

	size_t minimum_len;
	if(expected_len == -1) {
		expected_len = (int)RFIFOW(act, 2);
		minimum_len = 4; // Dynamic packets must be at least 4 bytes (header + length)
	} else {
		minimum_len = 2;
	}
	if(len < minimum_len) {
		ShowError("socket_validateRfifo(%d): packet (0x%04X) with size smaller than %zd\n",
			thread->get_tid(), cmd, minimum_len);
		return false;
	}

	if(expected_len != len_rest) {
		ShowError("socket_validateRfifo(%d): Received packet 0x%04X with "
			"size %d, but must be size %d\n",
			thread->get_tid(), cmd, len_rest, expected_len);
		return false;
	}
	return true;
}

/**
 * Advances RFIFO cursor (marking 'len' bytes as read)
 **/
void rfifoskip(struct s_receive_action_data *act, size_t len)
{
	if(act->rdata_pos + len > act->rdata_size) {
		ShowError("RFIFOSKIP(%d): skipped past end of read buffer! "
			"Adjusting from %"PRIuS" to %"PRIuS" (session #%d)\n",
			thread->get_tid(), len, RFIFOREST(act), act->session->id);
		Assert_report(0);
		len = RFIFOREST(act);
	} else if(act->validate) {
		if(!socket_validateRfifo(act, len))
			Assert_report(0);
	}
	act->rdata_pos = act->rdata_pos + len;
#ifdef SHOW_SERVER_STATS
	socket_data_qi -= len;
#endif  // SHOW_SERVER_STATS
}

void rfifoflush(struct s_receive_action_data *act)
{
	if(act->rdata_size == act->rdata_pos) {
		act->rdata_size = act->rdata_pos = 0;
		return;
	}
}

/*======================================
 * CORE : Action
 *--------------------------------------*/

/**
 * Point of entry of Receive action in action workers
 * Calls server-specific parsing function (real server entry-point) and then
 * flushes write fifos.
 * @see socket_operation_process
 **/
static void action_receive(void *data)
{
	struct s_receive_action_data *act = data;
	mutex->lock(act->session->mutex);
	act->session->session_counter++;
	mutex->unlock(act->session->mutex);

	act->session->parse(act);

	mutex->lock(act->session->mutex);
	act->session->session_counter--;
	mutex->unlock(act->session->mutex);

	wfifoflush_all(); // Disconnects if necessary
	
	/**
	 * [Packet]
	 * WFIFOHEAD
	 * WFIFO*
	 * ...
	 * WFIFOSET -> verifies length and validates, adds to shortlist
	 *             If there's a certain length flushes (sSend), 
	 *             otherwise the data is sent after all parsing.
	 * #define WFIFOSET(fd, len)  (socket_io->wfifoset(fd, len, true))
	 * #define WFIFOP(fd,pos) ((void *)(socket_io->session[fd]->wdata + socket_io->session[fd]->wdata_size + (pos)))
	 **/
	/**
	 * [I/O Worker]
	 *  Dequeue receive (socket_worker)
	 *  Post receive action (socket_operation_process)
	 *
	 * [Action Worker]
	 *  Dequeue receive action (action_worker)
	 *  Act: action_receive
	 *           |
	 *      default_func_parse -> <server specific functions>
	 *  Flush all write FIFO
	 **/
	/**
	 * Separate session mutex from "session_data" mutex, so we don't block I/O
	 * operations while handling player data.
	 * session_data should be a rwlock, I/O worker locks read
	 **/
}

/*======================================
 * CORE : IOCP Buffers
 *--------------------------------------*/

/**
 * Allocates and adds new buf to buffer_data
 *
 * Acquires all locks required for ers_alloc
 **/
static void socket_iocp_buffer_grow(struct s_iocp_buffer_data *buffer_data)
{
	nullpo_retv(buffer_data);

	char **old_buffer = aMalloc(sizeof(*old_buffer)*buffer_data->buffer_count);
	for(int i = 0; i < buffer_data->buffer_count; i++)
		old_buffer[i] = buffer_data->wsa_buffer[i].buf;

	aFree(buffer_data->wsa_buffer);
	CREATE(buffer_data->wsa_buffer, WSABUF, buffer_data->buffer_count+1);
	for(int i = 0; i < buffer_data->buffer_count; i++)
		buffer_data->wsa_buffer[i].buf = old_buffer[i];

	rwlock->read_lock(ers_buffer_instance->collection_lock);
	mutex->lock(ers_buffer_instance->cache_mutex);
	buffer_data->wsa_buffer[buffer_data->buffer_count].buf = ers_alloc(ers_buffer_instance);
	mutex->unlock(ers_buffer_instance->cache_mutex);
	rwlock->read_unlock(ers_buffer_instance->collection_lock);
	buffer_data->buffer_count++;
	aFree(old_buffer);
}

/**
 * Sets buffer_data to initial state
 **/
static void socket_iocp_buffer_clear(struct s_iocp_buffer_data *buffer_data)
{
	nullpo_retv(buffer_data);
	/**
	 * Any unused members of this structure should always be initialized to zero
	 * before the structure is used in a function call. Otherwise, the function may
	 * fail and return ERROR_INVALID_PARAMETER.
	 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms684342(v=vs.85).aspx
	 **/
	memset(&buffer_data->overlapped, 0, sizeof(buffer_data->overlapped));
	for(int i = 0; i < buffer_data->buffer_count; i++)
		memset(buffer_data->wsa_buffer[i].buf, 0, FIFO_SIZE);
	buffer_data->status = QT_OUTSIDE;
}

/**
 * Frees s_iocp_buffer_data
 *
 * @param buffer_data Buffer to be freed
 * @lock ers_free locks
 **/
static void socket_iocp_buffer_free(struct s_iocp_buffer_data *buffer_data)
{
	nullpo_retv(buffer_data);

	for(int i = 0; i < buffer_data->buffer_count; i++)
		ers_free(ers_buffer_instance, buffer_data->wsa_buffer[i].buf);

	aFree(buffer_data->wsa_buffer);
	aFree(buffer_data);
}

/**
 * Frees s_iocp_buffer_data, acquires required locks
 *
 * @param buffer_data Buffer to be freed
 **/
static void socket_iocp_buffer_free_guard(struct s_iocp_buffer_data *buffer_data)
{
	nullpo_retv(buffer_data);

	rwlock->read_lock(ers_collection_lock(ers_socket_collection));
	mutex->lock(ers_buffer_instance->cache_mutex);
	socket_iocp_buffer_free(buffer_data);
	mutex->unlock(ers_buffer_instance->cache_mutex);
	rwlock->read_unlock(ers_collection_lock(ers_socket_collection));
}

/*======================================
 * CORE : Listen thread
 *--------------------------------------*/

/**
 * Listen worker
 * @param param Listen socket
 **/
static void *socket_listen(void *param)
{
	SOCKET listen_socket = (SOCKET)param;

	while(socket_run) {
		mutex->lock(socket_shutdown_mutex);
		mutex->cond_wait(socket_shutdown_event, socket_shutdown_mutex, 1);
		mutex->unlock(socket_shutdown_mutex);
		DWORD wait_multiple;
		int wsa_ret;
		WSANETWORKEVENTS wsa_events;

		wait_multiple = WSAWaitForMultipleEvents(1,			// Number of events
			                        &io_accept_event,		// Accept event
									FALSE,					// Wait all events?
									// WSA_INFINITE may cause the system to be deadlocked!
									/*TIMEOUT*/100,			// Timeout
									// Alertable? (False = No I/O completion on this socket)
									FALSE);

		if(wait_multiple == WSA_WAIT_TIMEOUT)
			continue;
		wsa_ret = WSAEnumNetworkEvents(listen_socket, io_accept_event, &wsa_events);
		if(wsa_ret == WSA_WAIT_FAILED) {
			ShowError("socket_listen: WSAEnumNetworkEvents wait failed (%s)!\n",
				error_msg());
			break;
		} else {
			// Handle network events
			if((wsa_events.lNetworkEvents&FD_ACCEPT)
			&& (!wsa_events.iErrorCode[FD_ACCEPT_BIT]))
				connect_client(listen_socket);
			else
				ShowError("socket_listen: Unknown error (%s)!\n", error_msg());
		}
	}
	ShowInfo("socket_listen: shutting down\n");
	return NULL;
}

/**
 * Binds listening to provided ip:port and then starts listen thread
 * @param ip   Our IP
 * @param port Listen port
 **/
static bool make_listen_bind(uint32 ip, uint16 port)
{
	struct sockaddr_in server_address = { 0 };
	SOCKET s = WSASocket(AF_INET,				// IPv4 family
					     SOCK_STREAM,			// Two way OOB transmission
					     IPPROTO_TCP,			// TCP Socket
					     NULL,					// Associated with given WSAPROTOCOL_INFO 
					     0,						// No group operation
					     WSA_FLAG_OVERLAPPED);  // Overlapped I/O

	if(s == INVALID_SOCKET) {
		ShowError("make_listen_bind: socket creation failed (%s)!\n", error_msg());
		return false;
	}
	setsocketopts(s, NULL);

	server_address.sin_family      = AF_INET;
	server_address.sin_addr.s_addr = htonl(ip);
	server_address.sin_port        = htons(port);

	if(bind(s, (struct sockaddr *) &server_address, sizeof(server_address)) == SOCKET_ERROR) {
		ShowError("make_listen_bind: bind failed (%s)!\n", error_msg());
		closesocket(s);
		return false;
	}
	/**
	 * Set to SOMAXCONN and let the OS handle the optimal backlog size so we can
	 * be better protected against SYN attacks.
	 **/
	if(listen(s, SOMAXCONN) == SOCKET_ERROR) {
		ShowError("make_listen_bind: listen failed (%s)!\n", error_msg());
		closesocket(s);
		return false;
	}

	if((io_accept_event = WSACreateEvent()) == WSA_INVALID_EVENT) {
		ShowError("make_listen_bind: Couldn't create IO Accept Event (%s)!\n",
			error_msg());
		closesocket(s);
		return false;
	}
	if(WSAEventSelect(s, io_accept_event, FD_ACCEPT) == SOCKET_ERROR) {
		ShowError("make_listen_bind: Couldn't select IO Accept Event (%s)!\n",
			error_msg());
		closesocket(s);
		return false;
	}
	socket_listen_thread = thread->create("Listen", socket_listen, (void*)s);
	if(!socket_listen_thread) {
		ShowError("make_listen_bind: Failed to start listen thread!\n");
		closesocket(s);
		return false;
	}
	return true;
}

/*======================================
 * CORE : Connection
 *--------------------------------------*/

/**
 * Establishes a new connection to provided ip
 * @param ip IP to be connected to
 * @param port Desired port
 * @param opt Socket options
 * @warning The mutex of the created session is LOCKED and should be freed by the caller!
 **/
static struct socket_data *make_connection(uint32 ip, uint16 port, struct hSockOpt *opt)
{
	struct sockaddr_in remote_address = {0};
	SOCKET s = WSASocket(AF_INET,				// IPv4 family
					     SOCK_STREAM,			// Two way OOB transmission
					     IPPROTO_TCP,			// TCP Socket
					     NULL,					// Associated with given WSAPROTOCOL_INFO 
					     0,						// No group operation
					     WSA_FLAG_OVERLAPPED);  // Overlapped I/O

	if(s == INVALID_SOCKET) {
		ShowError("make_connection: socket creation failed (%s)!\n", error_msg());
		return NULL;
	}
	setsocketopts(s, opt);

	remote_address.sin_family      = AF_INET;
	remote_address.sin_addr.s_addr = htonl(ip);
	remote_address.sin_port        = htons(port);

	if(!( opt && opt->silent ))
		ShowStatus("Connecting to %u.%u.%u.%u:%i\n", CONVIP(ip), port);

	//Establish remote connection
	if(WSAConnect(s, (struct sockaddr *)&remote_address, sizeof(remote_address),
		NULL, NULL, NULL, NULL) == SOCKET_ERROR) {
		if(!( opt && opt->silent ))
			ShowError("make_connection: connect failed (%s)!\n", error_msg());
		closesocket(s);
		return NULL;
	}

	struct socket_data *session;
	session = session_setup(s, &remote_address, false);
	if(!session) {
		ShowError("connect_client: connect failed\n");
		return NULL;
	}
	return session;
}

/**
 * Updates parse function for provided session
 * @mutex session->mutex
 **/
static void session_update_parse(struct socket_data *session, ActionParseFunc parse)
{
	session->parse = parse;
}

/**
 * Gets socket_data of provided id
 *
 * @return Socket data (session)
 * @retval NULL failed to find session
 **/
struct socket_data *session_from_id(int32_t id)
{
	struct socket_data *session = NULL;
	mutex->lock(session_db_mutex);
	session = idb_get(session_db, id);
	mutex->unlock(session_db_mutex);
	return session;
}

/**
 * Is session marked for removal?
 * @mutex session->mutex
 **/
static bool session_marked_removal(struct socket_data *session)
{
	return (session->flag.wait_removal || session->flag.eof);
}

/**
 * Marks session for removal
 * @mutex session->mutex
 * @return true No operations remaining (can be removed)
 **/
static bool session_mark_removal(struct socket_data *session)
{
	if(session->flag.eof)
		return true;

	if(session->operations_remaining > 0
	|| session->writes_remaining > 0
	|| session->session_counter > 0
	) {
		session->flag.wait_removal = 1;
		return false;
	}
	session->flag.eof = 1;
	return true;
}

/*======================================
 * CORE : I/O worker
 *--------------------------------------*/

/**
 * Processes dequeued operation
 *
 * @param session           Session attached to this operation
 * @param buffer_data       Buffer information to process (Not safe to be used after calling)
 * @param bytes_transferred Number of bytes transferred in the operation
 * @param socket_tick       Server tick
 * Acquires session->mutex
 **/
static void socket_operation_process(struct socket_data *session,
	struct s_iocp_buffer_data *buffer_data, DWORD bytes_transferred,
	time_t socket_tick
) {
	mutex->lock(session->mutex);

	session->operations_remaining--;

	/**
	 * Prepare data for server handling
	 * Convert to portable format
	 **/
	if(buffer_data->operation == IO_RECV) {
		struct s_receive_action_data *recv_action;

		rwlock->read_lock(ers_collection_lock(ers_socket_collection));
		mutex->lock(ers_receive_action_instance->cache_mutex);
		recv_action = ers_alloc(ers_receive_action_instance);
		mutex->unlock(ers_receive_action_instance->cache_mutex);
		rwlock->read_unlock(ers_collection_lock(ers_socket_collection));

		// Prepare rdata (recv always occurs in one buffer)
		recv_action->session = session;
		recv_action->rdata = buffer_data->wsa_buffer[0].buf;
		recv_action->rdata_size = bytes_transferred;
		recv_action->max_rdata = FIFO_SIZE;
		recv_action->rdata_pos = 0;
		recv_action->read_buffer = buffer_data;
		recv_action->validate = session->flag.validate;

		// Update tick
		session->rdata_tick = timer->gettick_nocache();
		// FIXME: Profile the number of bytes received vs the number of
		// send requests made by the client. Each of these requests now
		// uses a whole buffer of FIFO_SIZE (2*1024), so if there are
		// several requests they could lead to a huge memory waste.
		action->enqueue(action->queue_get(session), action_receive, recv_action);
		socket_iocp_post_recv(session, session_buffer_available(session));
	} else {
		/** IO_SEND
		 * Overlapped WSASend seldom fails, usually because of resource limits
		 * or network errors, either way the failure states are being handled
		 * on the I/O worker thread, in this point of the processing we should just
		 * reinsert the used buffer into the available list.
		 **/

		// Clear and reinsert into available list
		socket_iocp_buffer_clear(buffer_data);
		VECTOR_PUSH(session->iocp_available_buffer, buffer_data);
	}
	mutex->unlock(session->mutex);
}

/**
 * I/O Worker thread
 *
 * Handles established connections, waits on a completion port I/O and then
 * processes it.
 **/
static void *socket_worker(void *param)
{
	thread->flag_set(THREADFLAG_IO);

	while(socket_run) {
		mutex->lock(socket_shutdown_mutex);
		mutex->cond_wait(socket_shutdown_event, socket_shutdown_mutex, 1);
		mutex->unlock(socket_shutdown_mutex);
		DWORD bytes_transferred = 0;

		struct socket_data *session = NULL;
		struct s_iocp_buffer_data *buffer_data = NULL;
		// Associates thread with completion port and gets completion status
		int queued_status = GetQueuedCompletionStatus(io_completion_port,
			                                          &bytes_transferred,
													  (LPDWORD)&session,
													  (LPOVERLAPPED*)&buffer_data,
													  INFINITE);
		if(!queued_status) {
			// The function did not dequeue a completion packet
			// so no information is stored whatsoever
			if(buffer_data == NULL)
				continue;
			// Failed I/O operation from the completion port but
			// a completion packet was dequeued
			// lpNumberOfBytes, lpCompletionKey and lpOverlapped are available
			ShowError("socket_worker(%d): Failed I/O operation, error code %ld\n",
				thread->get_tid(), GetLastError());
			// If a failed I/O operation yields a completion key it should be handled
			// properly as if the connection was lost
			if(session)
				socket_connection_lost(session);
			socket_iocp_buffer_free_guard(buffer_data);
			continue;
		}

		// Shutting down
		if(session == NULL && bytes_transferred == 0)
			break;

		// Failed to post context before posting request
		if(session == NULL) {
			ShowWarning("socket_worker(%d): No context data received, bytes transferred %ld\n",
				thread->get_tid(), bytes_transferred);
			if(buffer_data)
				socket_iocp_buffer_free_guard(buffer_data);
			continue;
		}

		// Server already cleaned up session_data
		if(session->flag.post_eof) {
			close_session(session);
			delete_session(session, true);
			assert(!buffer_data
				&& "Posted EOF with valid buffer data");
			continue;
		}

		// Client connection gone
		if(bytes_transferred == 0 || session->flag.wait_removal) {
			socket_connection_lost(session);
			// Even if no bytes are transferred the attached buffer data is still available
			// and should be handled properly
			socket_iocp_buffer_free_guard(buffer_data);
			continue;
		}

		if(buffer_data->status == QT_OUTSIDE)
			ShowError("socket_worker(%d): Non-queued buffer dequeued!\n",
				thread->get_tid());

		socket_operation_process(session, buffer_data, bytes_transferred,
			timer->gettick_nocache());
#ifdef SHOW_SERVER_STATS
	if (socket_io->last_tick != socket_data_last_tick)
	{
		char buf[1024];

		sprintf(buf, "In: %.03f kB/s (%.03f kB/s, Q: %.03f kB) | Out: %.03f kB/s (%.03f kB/s, Q: %.03f kB) | RAM: %.03f MB", socket_data_i/1024., socket_data_ci/1024., socket_data_qi/1024., socket_data_o/1024., socket_data_co/1024., socket_data_qo/1024., iMalloc->usage()/1024.);
#ifdef _WIN32
		SetConsoleTitle(buf);
#else  // _WIN32
		ShowMessage("\033[s\033[1;1H\033[2K%s\033[u", buf);
#endif  // _WIN32
		socket_data_last_tick = socket_io->last_tick;
		socket_data_i = socket_data_ci = 0;
		socket_data_o = socket_data_co = 0;
	}
#endif  // SHOW_SERVER_STATS

	}
	ShowInfo("socket_worker(%d): shutting down\n", thread->get_tid());
	return NULL;
}

/*======================================
 * CORE : Init
 *--------------------------------------*/

/**
 * Sets up threads and lists worker pool
 *
 * @see IOCP_WORKERS_PER_PROCESSOR
 * @retval False Failed to set up any thread.
 **/
static bool socket_init_thread_pool(void)
{
	socket_shutdown_mutex = mutex->create();
	socket_shutdown_event = mutex->cond_create();
	if(!socket_shutdown_event || !socket_shutdown_mutex) {
		ShowError("socket_init_thread_pool: Failed to setup io shutdown condition\n");
		return false;
	}
	socket_thread_count = IOCP_WORKERS_PER_PROCESSOR*sysinfo->cpucores();
	socket_thread = aMalloc(sizeof(*socket_thread)*socket_thread_count);

	int failed_count = 0;
	for(int i = 0; i < socket_thread_count; i++) {
		socket_thread[i] = thread->create("IO worker", socket_worker, 0);
		if(!socket_thread[i]) {
			ShowError("socket_init_thread_pool: Failed to setup thread %d/%d\n",
				i+1, socket_thread_count);
			failed_count++;
		}
	}
	if(failed_count) {
		// Try to be graceful and continue the start up process
		int new_count = socket_thread_count-failed_count;
		if(new_count == 0) {
			ShowError("socket_init_thread_pool: No threads were created!\n");
			return false;
		}
		struct thread_handle **temp = aMalloc(sizeof(*temp)*new_count);
		int j = 0;
		for(int i = 0; i < socket_thread_count; i++) {
			if(socket_thread[i]) {
				temp[j] = socket_thread[i];
				j++;
			}
		}
		aFree(socket_thread);
		socket_thread_count = new_count;
		socket_thread = temp;
	}
	ShowInfo("Server uses '" CL_WHITE "%d" CL_RESET "' I/O worker threads\n",
		socket_thread_count);
	return true;
}

/**
 * Session cleanup after server shutdown
 * @see socket_final_thread_pool
 * @see session_db
 * @see DBApply
 **/
int socket_final_clear(const struct DBKey_s *key, struct DBData *data, va_list args)
{
	struct socket_data *session = data->u.ptr;
	mutex->lock(session->mutex); // Mutex is unlocked / destroyed upon deletion
	close_session(session);
	delete_session(session, false);
	return 0;
}

/**
 * Sends shutdown signal and waits for I/O thread pool
 **/
static void socket_final_thread_pool(void)
{
	int i;
	// Help threads get out of blocking
	for(i = 0; i < socket_thread_count; i++)
		PostQueuedCompletionStatus(io_completion_port, 0, (DWORD)NULL, NULL);
	// If there are still any threads running broadcast shutdown
	mutex->lock(socket_shutdown_mutex);
	socket_run = false;
	mutex->cond_broadcast(socket_shutdown_event);
	mutex->unlock(socket_shutdown_mutex);
	thread->wait_multiple(socket_thread, socket_thread_count, NULL);
	if(socket_listen_thread)
		thread->wait(socket_listen_thread, NULL);
	mutex->destroy(socket_shutdown_mutex);

	aFree(socket_thread);
	socket_thread_count = 0;
	socket_thread = NULL;
	socket_listen_thread = NULL;
	CloseHandle(io_completion_port);
	WSACloseEvent(io_accept_event);

	mutex->lock(session_db_mutex);
	session_db->clear(session_db, socket_final_clear);
	mutex->unlock(session_db_mutex);
	mutex->destroy(session_db_mutex);
	session_db_mutex = NULL;
	session_db = NULL;

	rwlock->write_lock(ers_collection_lock(ers_socket_collection));
	ers_destroy(ers_session_instance);
	ers_destroy(ers_buffer_instance);
	ers_destroy(ers_receive_action_instance);
	ers_destroy(ers_send_action_instance);
	rwlock->write_unlock(ers_collection_lock(ers_socket_collection));

	ers_collection_destroy(ers_socket_collection);
	ers_socket_collection = NULL;
}

/**
 * Start up windows networking
 **/
static void socket_init_wsa(void)
{
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(HERC_WSA_MAJOR, HERC_WSA_MINOR);
	if( WSAStartup(wVersionRequested, &wsaData) != 0 )
	{
		ShowFatalError("socket_init: WinSock not available!\n");
		exit(EXIT_FAILURE);
	}
	if( LOBYTE(wsaData.wVersion) != HERC_WSA_MAJOR || HIBYTE(wsaData.wVersion) != HERC_WSA_MINOR )
	{
		ShowFatalError("socket_init: WinSock version mismatch (%d.%d or compatible required)!\n",
			HERC_WSA_MAJOR, HERC_WSA_MINOR);
		exit(EXIT_FAILURE);
	}
#ifdef SOCKET_IOCP
	/**
	 * Creates a new completion port without associating it with a handle
	 * @see https://msdn.microsoft.com/en-us/library/windows/desktop/aa363862(v=vs.85).aspx
	 **/
	io_completion_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, // Socket handle
		                                        NULL,				  // Previous completion port (ignored)
												/**
												 * This parameter is ignored when the handle is invalid
												 * it's used to associate client contexts with sockets
												 **/
						                        0,
												IOCP_CONCURRENCY_VALUE); // Concurrent threads
	if(io_completion_port == NULL) {
		ShowFatalError("socket_init: Couldn't start completion port! (error code %ld)\n",
			WSAGetLastError());
		exit(EXIT_FAILURE);
	}
	if(!socket_init_thread_pool()) {
		ShowFatalError("socket_init: Failed to set up thread pool\n");
		exit(EXIT_FAILURE);
	}
#endif // SOCKET_IOCP

	session_db = idb_alloc(DB_OPT_BASE);
	session_db_mutex = mutex->create();
	if(!session_db_mutex) {
		ShowFatalError("socket_init: Failed to set up session db mutex\n");
		exit(EXIT_FAILURE);
	}

	ers_socket_collection = ers_collection_create(MEMORYTYPE_SHARED);
	ers_session_instance = ers_new(ers_socket_collection, sizeof(struct socket_data),
		"socket::session", ERS_OPT_CLEAN);
	ers_buffer_instance = ers_new(ers_socket_collection, FIFO_SIZE,
		"socket::buffer", ERS_OPT_CLEAN);
	ers_receive_action_instance = ers_new(ers_socket_collection,
		sizeof(struct s_receive_action_data), "socket::action:receive",
		ERS_OPT_CLEAN);
	ers_send_action_instance = ers_new(ers_socket_collection,
		sizeof(struct s_send_action_data), "socket::action:send",
		ERS_OPT_CLEAN);
	timer->add_func_list(socket_io->session_timeout, "socket_io->session_timeout");
}

/*======================================
 * CORE : General access handling
 *--------------------------------------*/

// IP rules and DDoS protection

struct connect_history {
	uint32 ip;
	int64 tick;
	int count;
	unsigned ddos : 1;
};

struct access_control {
	uint32 ip;
	uint32 mask;
};

VECTOR_STRUCT_DECL(access_control_list, struct access_control);

enum aco {
	ACO_DENY_ALLOW,
	ACO_ALLOW_DENY,
	ACO_MUTUAL_FAILURE
};

static struct access_control_list access_allow;
static struct access_control_list access_deny;
static int access_order    = ACO_DENY_ALLOW;
static int access_debug    = 0;
static int ddos_count      = 10;
static int ddos_interval   = 3*1000;
static int ddos_autoreset  = 10*60*1000;
static struct DBMap *connect_history = NULL;

static int connect_check_(uint32 ip);

/// Verifies if the IP can connect. (with debug info)
/// @see connect_check_()
static int connect_check(uint32 ip)
{
	int result = connect_check_(ip);
	if( access_debug ) {
		ShowInfo("connect_check: Connection from %u.%u.%u.%u %s\n", CONVIP(ip),result ? "allowed." : "denied!");
	}
	return result;
}

/// Verifies if the IP can connect.
///  0      : Connection Rejected
///  1 or 2 : Connection Accepted
static int connect_check_(uint32 ip)
{
	struct connect_history *hist = NULL;
	int i;
	int is_allowip = 0;
	int is_denyip = 0;
	int connect_ok = 0;

	// Search the allow list
	for (i = 0; i < VECTOR_LENGTH(access_allow); ++i) {
		struct access_control *entry = &VECTOR_INDEX(access_allow, i);
		if (SUBNET_MATCH(ip, entry->ip, entry->mask)) {
			if (access_debug) {
				ShowInfo("connect_check: Found match from allow list:%u.%u.%u.%u IP:%u.%u.%u.%u Mask:%u.%u.%u.%u\n",
					CONVIP(ip),
					CONVIP(entry->ip),
					CONVIP(entry->mask));
			}
			is_allowip = 1;
			break;
		}
	}
	// Search the deny list
	for (i = 0; i < VECTOR_LENGTH(access_deny); ++i) {
		struct access_control *entry = &VECTOR_INDEX(access_deny, i);
		if (SUBNET_MATCH(ip, entry->ip, entry->mask)) {
			if (access_debug) {
				ShowInfo("connect_check: Found match from deny list:%u.%u.%u.%u IP:%u.%u.%u.%u Mask:%u.%u.%u.%u\n",
					CONVIP(ip),
					CONVIP(entry->ip),
					CONVIP(entry->mask));
			}
			is_denyip = 1;
			break;
		}
	}
	// Decide connection status
	//  0 : Reject
	//  1 : Accept
	//  2 : Unconditional Accept (accepts even if flagged as DDoS)
	switch(access_order) {
		case ACO_DENY_ALLOW:
		default:
			if( is_denyip )
				connect_ok = 0; // Reject
			else if( is_allowip )
				connect_ok = 2; // Unconditional Accept
			else
				connect_ok = 1; // Accept
			break;
		case ACO_ALLOW_DENY:
			if( is_allowip )
				connect_ok = 2; // Unconditional Accept
			else if( is_denyip )
				connect_ok = 0; // Reject
			else
				connect_ok = 1; // Accept
			break;
		case ACO_MUTUAL_FAILURE:
			if( is_allowip && !is_denyip )
				connect_ok = 2; // Unconditional Accept
			else
				connect_ok = 0; // Reject
			break;
	}

	// Inspect connection history
	if( ( hist = uidb_get(connect_history, ip)) ) { //IP found
		if( hist->ddos ) {// flagged as DDoS
			return (connect_ok == 2 ? 1 : 0);
		} else if( DIFF_TICK(timer->gettick(),hist->tick) < ddos_interval ) {// connection within ddos_interval
				hist->tick = timer->gettick();
				if( ++hist->count >= ddos_count ) {// DDoS attack detected
					hist->ddos = 1;
					ShowWarning("connect_check: DDoS Attack detected from %u.%u.%u.%u!\n", CONVIP(ip));
					return (connect_ok == 2 ? 1 : 0);
				}
				return connect_ok;
		} else {// not within ddos_interval, clear data
			hist->tick  = timer->gettick();
			hist->count = 0;
			return connect_ok;
		}
	}
	// IP not found, add to history
	CREATE(hist, struct connect_history, 1);
	hist->ip   = ip;
	hist->tick = timer->gettick();
	uidb_put(connect_history, ip, hist);
	return connect_ok;
}

/// Timer function.
/// Deletes old connection history records.
static int connect_check_clear(struct timer_interface *td, int tid, int64 tick, int id, intptr_t data)
{
	int clear = 0;
	int list  = 0;
	struct connect_history *hist = NULL;
	struct DBIterator *iter;

	if( !db_size(connect_history) )
		return 0;

	iter = db_iterator(connect_history);

	for( hist = dbi_first(iter); dbi_exists(iter); hist = dbi_next(iter) ){
		if( (!hist->ddos && DIFF_TICK(tick,hist->tick) > ddos_interval*3) ||
			(hist->ddos && DIFF_TICK(tick,hist->tick) > ddos_autoreset) )
			{// Remove connection history
				uidb_remove(connect_history, hist->ip);
				clear++;
			}
		list++;
	}
	dbi_destroy(iter);

	if( access_debug ){
		ShowInfo("connect_check_clear: Cleared %d of %d from IP list.\n", clear, list);
	}

	return list;
}

/*======================================
 * CORE : Configuration parsing
 *--------------------------------------*/


/**
 * Helper function to read a list of network.conf values.
 *
 * Entries will be appended to the variable-size array pointed to by list/count.
 *
 * @param[in]     t         The list to parse.
 * @param[in,out] list      Vector to append to. Must not be NULL (but the vector may be empty).
 * @param[in]     filename  Current filename, for output/logging reasons.
 * @param[in]     groupname Current group name, for output/logging reasons.
 * @return The amount of entries read, zero in case of errors.
 */
static int socket_net_config_read_sub(struct config_setting_t *t, struct s_subnet_vector *list, const char *filename, const char *groupname)
{
	int i, len;
	char ipbuf[64], maskbuf[64];

	nullpo_retr(0, list);

	if (t == NULL)
		return 0;

	len = libconfig->setting_length(t);

	VECTOR_ENSURE(*list, len, 1);
	for (i = 0; i < len; ++i) {
		const char *subnet = libconfig->setting_get_string_elem(t, i);
		struct s_subnet *entry = NULL;

		if (sscanf(subnet, "%63[^:]:%63[^:]", ipbuf, maskbuf) != 2) {
			ShowWarning("Invalid IP:Subnet entry in configuration file %s: '%s' (%s)\n", filename, subnet, groupname);
			continue;
		}
		VECTOR_PUSHZEROED(*list);
		entry = &VECTOR_LAST(*list);
		entry->ip = socket_io->str2ip(ipbuf);
		entry->mask = socket_io->str2ip(maskbuf);
	}
	return (int)VECTOR_LENGTH(*list);
}

/**
 * Reads the network configuration file.
 *
 * @param filename The filename to read from.
 */
static void socket_net_config_read(const char *filename)
{
	struct config_t network_config;
	int i;
	nullpo_retv(filename);

	if (!libconfig->load_file(&network_config, filename)) {
		ShowError("LAN Support configuration file is not found: '%s'. This server won't be able to accept connections from any servers.\n", filename);
		return;
	}

	VECTOR_CLEAR(socket_io->lan_subnets);
	if (socket_net_config_read_sub(libconfig->lookup(&network_config, "lan_subnets"), &socket_io->lan_subnets, filename, "lan_subnets") > 0)
		ShowStatus("Read information about %d LAN subnets.\n", (int)VECTOR_LENGTH(socket_io->lan_subnets));

	VECTOR_CLEAR(socket_io->trusted_ips);
	if (socket_net_config_read_sub(libconfig->lookup(&network_config, "trusted"), &socket_io->trusted_ips, filename, "trusted") > 0)
		ShowStatus("Read information about %d trusted IP ranges.\n", (int)VECTOR_LENGTH(socket_io->trusted_ips));
	ARR_FIND(0, VECTOR_LENGTH(socket_io->trusted_ips), i, SUBNET_MATCH(0, VECTOR_INDEX(socket_io->trusted_ips, i).ip, VECTOR_INDEX(socket_io->trusted_ips, i).mask));
	if (i != VECTOR_LENGTH(socket_io->trusted_ips)) {
		ShowError("Using a wildcard IP range in the trusted server IPs is NOT RECOMMENDED.\n");
		ShowNotice("Please edit your '%s' trusted list to fit your network configuration.\n", filename);
	}

	VECTOR_CLEAR(socket_io->allowed_ips);
	if (socket_net_config_read_sub(libconfig->lookup(&network_config, "allowed"), &socket_io->allowed_ips, filename, "allowed") > 0)
		ShowStatus("Read information about %d allowed server IP ranges.\n", (int)VECTOR_LENGTH(socket_io->allowed_ips));
	if (VECTOR_LENGTH(socket_io->allowed_ips) + VECTOR_LENGTH(socket_io->trusted_ips) == 0) {
		ShowError("No allowed server IP ranges configured. This server won't be able to accept connections from any char servers.\n");
	}
	ARR_FIND(0, VECTOR_LENGTH(socket_io->allowed_ips), i, SUBNET_MATCH(0, VECTOR_INDEX(socket_io->allowed_ips, i).ip, VECTOR_INDEX(socket_io->allowed_ips, i).mask));
#ifndef BUILDBOT
	if (i != VECTOR_LENGTH(socket_io->allowed_ips)) {
		ShowWarning("Using a wildcard IP range in the allowed server IPs is NOT RECOMMENDED.\n");
		ShowNotice("Please edit your '%s' allowed list to fit your network configuration.\n", filename);
	}
#endif  // BUILDBOT
	libconfig->destroy(&network_config);
	return;
}

/// Parses the ip address and mask and puts it into acc.
/// Returns 1 is successful, 0 otherwise.
static int access_ipmask(const char *str, struct access_control *acc)
{
	uint32 ip;
	uint32 mask;

	nullpo_ret(str);
	nullpo_ret(acc);

	if( strcmp(str,"all") == 0 ) {
		ip   = 0;
		mask = 0;
	} else {
		unsigned int a[4];
		unsigned int m[4];
		int n;
		if( ((n=sscanf(str,"%u.%u.%u.%u/%u.%u.%u.%u",a,a+1,a+2,a+3,m,m+1,m+2,m+3)) != 8 && // not an ip + standard mask
				(n=sscanf(str,"%u.%u.%u.%u/%u",a,a+1,a+2,a+3,m)) != 5 && // not an ip + bit mask
				(n=sscanf(str,"%u.%u.%u.%u",a,a+1,a+2,a+3)) != 4 ) || // not an ip
				a[0] > 255 || a[1] > 255 || a[2] > 255 || a[3] > 255 || // invalid ip
				(n == 8 && (m[0] > 255 || m[1] > 255 || m[2] > 255 || m[3] > 255)) || // invalid standard mask
				(n == 5 && m[0] > 32) ){ // invalid bit mask
			return 0;
		}
		ip = MAKEIP(a[0],a[1],a[2],a[3]);
		if( n == 8 )
		{// standard mask
			mask = MAKEIP(m[0],m[1],m[2],m[3]);
		} else if( n == 5 )
		{// bit mask
			mask = 0;
			while( m[0] ){
				mask = (mask >> 1) | 0x80000000;
				--m[0];
			}
		} else
		{// just this ip
			mask = 0xFFFFFFFF;
		}
	}
	if( access_debug ){
		ShowInfo("access_ipmask: Loaded IP:%u.%u.%u.%u mask:%u.%u.%u.%u\n", CONVIP(ip), CONVIP(mask));
	}
	acc->ip   = ip;
	acc->mask = mask;
	return 1;
}

/**
 * Adds an entry to the access list.
 *
 * @param setting     The setting to read from.
 * @param list_name   The list name (used in error messages).
 * @param access_list The access list to edit.
 *
 * @retval false in case of failure
 */
static bool access_list_add(struct config_setting_t *setting, const char *list_name, struct access_control_list *access_list)
{
	const char *temp = NULL;
	int i, setting_length;

	nullpo_retr(false, setting);
	nullpo_retr(false, list_name);
	nullpo_retr(false, access_list);

	if ((setting_length = libconfig->setting_length(setting)) <= 0)
		return false;

	VECTOR_ENSURE(*access_list, setting_length, 1);
	for (i = 0; i < setting_length; i++) {
		struct access_control acc;
		if ((temp = libconfig->setting_get_string_elem(setting, i)) == NULL) {
			continue;
		}

		if (!access_ipmask(temp, &acc)) {
			ShowError("access_list_add: Invalid ip or ip range %s '%d'!\n", list_name, i);
			continue;
		}
		VECTOR_PUSH(*access_list, acc);
	}

	return true;
}

/**
 * Reads 'socket_configuration/ip_rules' and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool socket_config_read_iprules(const char *filename, struct config_t *config, bool imported)
{
	struct config_setting_t *setting = NULL;
	const char *temp = NULL;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "socket_configuration/ip_rules")) == NULL) {
		if (imported)
			return true;
		ShowError("socket_config_read: socket_configuration/ip_rules was not found in %s!\n", filename);
		return false;
	}
	libconfig->setting_lookup_bool(setting, "enable", &ip_rules);

	if (!ip_rules)
		return true;

	if (libconfig->setting_lookup_string(setting, "order", &temp) == CONFIG_TRUE) {
		if (strcmpi(temp, "deny,allow" ) == 0) {
			access_order = ACO_DENY_ALLOW;
		} else if (strcmpi(temp, "allow, deny") == 0) {
			access_order = ACO_ALLOW_DENY;
		} else if (strcmpi(temp, "mutual-failure") == 0) {
			access_order = ACO_MUTUAL_FAILURE;
		} else {
			ShowWarning("socket_config_read: invalid value '%s' for socket_configuration/ip_rules/order.\n", temp);
		}
	}

	if ((setting = libconfig->lookup(config, "socket_configuration/ip_rules/allow_list")) == NULL) {
		if (!imported)
			ShowError("socket_config_read: socket_configuration/ip_rules/allow_list was not found in %s!\n", filename);
	} else {
		access_list_add(setting, "allow_list", &access_allow);
	}

	if ((setting = libconfig->lookup(config, "socket_configuration/ip_rules/deny_list")) == NULL) {
		if (!imported)
			ShowError("socket_config_read: socket_configuration/ip_rules/deny_list was not found in %s!\n", filename);
	} else {
		access_list_add(setting, "deny_list", &access_deny);
	}

	return true;
}

/**
 * Reads 'socket_configuration/ddos' and initializes required variables.
 *
 * @param filename Path to configuration file (used in error and warning messages).
 * @param config   The current config being parsed.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool socket_config_read_ddos(const char *filename, struct config_t *config, bool imported)
{
	struct config_setting_t *setting = NULL;

	nullpo_retr(false, filename);
	nullpo_retr(false, config);

	if ((setting = libconfig->lookup(config, "socket_configuration/ddos")) == NULL) {
		if (imported)
			return true;
		ShowError("socket_config_read: socket_configuration/ddos was not found in %s!\n", filename);
		return false;
	}

	libconfig->setting_lookup_int(setting, "interval", &ddos_interval);
	libconfig->setting_lookup_int(setting, "count", &ddos_count);
	libconfig->setting_lookup_int(setting, "autoreset", &ddos_autoreset);

	return true;
}

/**
 * Reads 'socket_configuration' and initializes required variables.
 *
 * @param filename Path to configuration file.
 * @param imported Whether the current config is imported from another file.
 *
 * @retval false in case of error.
 */
static bool socket_config_read(const char *filename, bool imported)
{
	struct config_t config;
	struct config_setting_t *setting = NULL;
	const char *import;
	int i32 = 0;
	bool retval = true;

	nullpo_retr(false, filename);

	if (!libconfig->load_file(&config, filename))
		return false;

	if ((setting = libconfig->lookup(&config, "socket_configuration")) == NULL) {
		libconfig->destroy(&config);
		if (imported)
			return true;
		ShowError("socket_config_read: socket_configuration was not found in %s!\n", filename);
		return false;
	}

	if (libconfig->setting_lookup_int(setting, "stall_time", &i32) == CONFIG_TRUE) {
		if (i32 < 3)
			i32 = 3; /* a minimum is required in order to refrain from killing itself */
		socket_io->stall_time = i32;
	}

#ifdef SOCKET_EPOLL
	if (libconfig->setting_lookup_int(setting, "epoll_maxevents", &i32) == CONFIG_TRUE) {
		if (i32 < 16)
			i32 = 16; // minimum that seems to be useful
		epoll_maxevents = i32;
	}
#endif  // SOCKET_EPOLL

	{
		uint32 ui32 = 0;
		libconfig->setting_lookup_bool(setting, "debug", &access_debug);
		if (libconfig->setting_lookup_uint32(setting, "socket_max_client_packet", &ui32) == CONFIG_TRUE) {
			socket_max_client_packet = ui32;
		}
	}

	if (!socket_config_read_iprules(filename, &config, imported))
		retval = false;
	if (!socket_config_read_ddos(filename, &config, imported))
		retval = false;

	// import should overwrite any previous configuration, so it should be called last
	if (libconfig->lookup_string(&config, "import", &import) == CONFIG_TRUE) {
		if (strcmp(import, filename) == 0 || strcmp(import, socket_io->SOCKET_CONF_FILENAME) == 0) {
			ShowWarning("socket_config_read: Loop detected! Skipping 'import'...\n");
		} else {
			if (!socket_config_read(import, true))
				retval = false;
		}
	}

	libconfig->destroy(&config);
	return retval;
}

/*======================================
 * CORE : Initialization and finalization
 *--------------------------------------*/

static void socket_final(void)
{
	socket_final_thread_pool();

	if( connect_history )
		db_destroy(connect_history);
	VECTOR_CLEAR(access_allow);
	VECTOR_CLEAR(access_deny);
/*TODO
	for( i = 1; i < socket_io->fd_max; i++ )
		if(socket_io->session[i])
			socket_io->close(i);

	// socket_io->session[0]
	aFree(socket_io->session[0]->rdata);
	aFree(socket_io->session[0]->wdata);
	aFree(socket_io->session[0]);

	aFree(socket_io->session);*/

	VECTOR_CLEAR(socket_io->lan_subnets);
	VECTOR_CLEAR(socket_io->allowed_ips);
	VECTOR_CLEAR(socket_io->trusted_ips);

#ifdef SOCKET_EPOLL
	if(epfd != SOCKET_ERROR){
		close(epfd);
		epfd = SOCKET_ERROR;
	}
	if(epevents != NULL){
		aFree(epevents);
		epevents = NULL;
	}
#endif  // SOCKET_EPOLL

}

static void socket_init(void)
{
	uint64 rlim_cur = 0;

#ifdef WIN32
	socket_init_wsa();
#endif

	VECTOR_INIT(access_allow);
	VECTOR_INIT(access_deny);

	// Get initial local ips
	socket_io->naddr_ = socket_getips(socket_io->addr_,16);

	socket_config_read(socket_io->SOCKET_CONF_FILENAME, false);

	ShowInfo("Server uses '" CL_WHITE "Completion Ports" CL_RESET "' as event dispatcher\n");

	// initialize last send-receive tick
	socket_io->last_tick = time(NULL);

	// Delete old connection history every 5 minutes
	connect_history = uidb_alloc(DB_OPT_RELEASE_DATA);
	timer->add_func_list(connect_check_clear, "connect_check_clear");
	timer->add_interval(timer->gettick()+1000, connect_check_clear, 0, 0, 5*60*1000);

	ShowInfo("Server supports up to '"CL_WHITE"%"PRIu64""CL_RESET"' concurrent connections.\n", rlim_cur);
}

/*======================================
 * CORE : Utilities
 *--------------------------------------*/

/// Retrieve local ips in host byte order.
/// Uses loopback is no address is found.
static int socket_getips(uint32 *ips, int max)
{
	int num = 0;

	if( ips == NULL || max <= 0 )
		return 0;

#ifdef WIN32
	{
		char fullhost[255];

		// XXX This should look up the local IP addresses in the registry
		// instead of calling gethostbyname. However, the way IP addresses
		// are stored in the registry is annoyingly complex, so I'll leave
		// this as T.B.D. [Meruru]
		if (gethostname(fullhost, sizeof(fullhost)) == SOCKET_ERROR) {
			ShowError("socket_getips: No hostname defined!\n");
			return 0;
		} else {
			u_long** a;
			struct hostent *hent =gethostbyname(fullhost);
			if( hent == NULL ){
				ShowError("socket_getips: Cannot resolve our own hostname to an IP address\n");
				return 0;
			}
			a = (u_long**)hent->h_addr_list;
			for (; num < max && a[num] != NULL; ++num)
				ips[num] = (uint32)ntohl(*a[num]);
		}
	}
#else // not WIN32
	{
		int fd;
		char buf[2*16*sizeof(struct ifreq)];
		struct ifconf ic;
		u_long ad;

		fd = sSocket(AF_INET, SOCK_STREAM, 0);
		if (fd == -1) {
			ShowError("socket_getips: Unable to create a socket!\n");
			return 0;
		}

		memset(buf, 0x00, sizeof(buf));

		// The ioctl call will fail with Invalid Argument if there are more
		// interfaces than will fit in the buffer
		ic.ifc_len = sizeof(buf);
		ic.ifc_buf = buf;
		if (sIoctl(fd, SIOCGIFCONF, &ic) == -1) {
			ShowError("socket_getips: SIOCGIFCONF failed!\n");
			sClose(fd);
			return 0;
		} else {
			int pos;
			for (pos = 0; pos < ic.ifc_len && num < max; ) {
				struct ifreq *ir = (struct ifreq*)(buf+pos);
				struct sockaddr_in *a = (struct sockaddr_in*) &(ir->ifr_addr);
				if (a->sin_family == AF_INET) {
					ad = ntohl(a->sin_addr.s_addr);
					if (ad != INADDR_LOOPBACK && ad != INADDR_ANY)
						ips[num++] = (uint32)ad;
				}
	#if (defined(BSD) && BSD >= 199103) || defined(_AIX) || defined(__APPLE__)
				pos += ir->ifr_addr.sa_len + sizeof(ir->ifr_name);
	#else// not AIX or APPLE
				pos += sizeof(struct ifreq);
	#endif//not AIX or APPLE
			}
		}
		sClose(fd);
	}
#endif // not W32

	// Use loopback if no ips are found
	if( num == 0 )
		ips[num++] = (uint32)INADDR_LOOPBACK;

	return num;
}

// Resolves hostname into a numeric ip.
static uint32 host2ip(const char *hostname)
{
	struct hostent* h;
	nullpo_ret(hostname);
	h = gethostbyname(hostname);
	return (h != NULL) ? ntohl(*(uint32*)h->h_addr) : 0;
}

/**
 * Converts a numeric ip into a dot-formatted string.
 *
 * @param ip     Numeric IP to convert.
 * @param ip_str Output buffer, optional (if provided, must have size greater or equal to 16).
 *
 * @return A pointer to the output string.
 */
static const char *ip2str(uint32 ip, char *ip_str)
{
	struct in_addr addr;
	addr.s_addr = htonl(ip);
	return (ip_str == NULL) ? inet_ntoa(addr) : strncpy(ip_str, inet_ntoa(addr), 16);
}

// Converts a dot-formatted ip string into a numeric ip.
static uint32 str2ip(const char *ip_str)
{
	return ntohl(inet_addr(ip_str));
}

// Reorders bytes from network to little endian (Windows).
// Necessary for sending port numbers to the RO client until Gravity notices that they forgot ntohs() calls.
static uint16 ntows(uint16 netshort)
{
	return ((netshort & 0xFF) << 8) | ((netshort & 0xFF00) >> 8);
}

/* [Ind/Hercules] - socket_datasync */
static void socket_datasync(struct s_receive_action_data *act, bool send)
{
	struct socket_data *session = act->session;
	struct {
		unsigned int length;/* short is not enough for some */
	} data_list[] = {
		{ sizeof(struct mmo_charstatus) },
		{ sizeof(struct quest) },
		{ sizeof(struct item) },
		{ sizeof(struct point) },
		{ sizeof(struct s_skill) },
		{ sizeof(struct status_change_data) },
		{ sizeof(struct storage_data) },
		{ sizeof(struct guild_storage) },
		{ sizeof(struct s_pet) },
		{ sizeof(struct s_mercenary) },
		{ sizeof(struct s_homunculus) },
		{ sizeof(struct s_elemental) },
		{ sizeof(struct s_friend) },
		{ sizeof(struct mail_message) },
		{ sizeof(struct mail_data) },
		{ sizeof(struct party_member) },
		{ sizeof(struct party) },
		{ sizeof(struct guild_member) },
		{ sizeof(struct guild_position) },
		{ sizeof(struct guild_alliance) },
		{ sizeof(struct guild_expulsion) },
		{ sizeof(struct guild_skill) },
		{ sizeof(struct guild) },
		{ sizeof(struct guild_castle) },
		{ sizeof(struct fame_list) },
		{ PACKETVER },
		{ PACKETVER_MAIN_NUM },
		{ PACKETVER_RE_NUM },
		{ PACKETVER_ZERO_NUM },
		{ PACKETVER_AD_NUM },
		{ PACKETVER_SAK_NUM },
	};
	unsigned short i;
	unsigned int alen = ARRAYLENGTH(data_list);
	if( send ) {
		unsigned short p_len = ( alen * 4 ) + 4;
		WFIFOHEAD(session, p_len, true);

		WFIFOW(session, 0) = 0x2b0a;
		WFIFOW(session, 2) = p_len;

		for( i = 0; i < alen; i++ ) {
			WFIFOL(session, 4 + ( i * 4 ) ) = data_list[i].length;
		}

		WFIFOSET2(session, p_len);
	} else {
		for( i = 0; i < alen; i++ ) {
			if( RFIFOL(act, 4 + (i * 4) ) != data_list[i].length ) {
				/* force the other to go wrong too so both are taken down */
				WFIFOHEAD(session, 8, true);
				WFIFOW(session, 0) = 0x2b0a;
				WFIFOW(session, 2) = 8;
				WFIFOL(session, 4) = 0;
				WFIFOSET2(session, 8);
				mutex->lock(session->mutex);
				socket_io->flush(session);
				mutex->unlock(session->mutex);
				/* shut down */
				ShowFatalError("Servers are out of sync! recompile from scratch (%d)\n",i);
				exit(EXIT_FAILURE);
			}
		}
	}
}

/**
 * Checks whether the given IP comes from LAN or WAN.
 *
 * @param[in]  ip   IP address to check.
 * @param[out] info Verbose output, if requested. Filled with the matching entry. Ignored if NULL.
 * @retval 0 if it is a WAN IP.
 * @return the appropriate LAN server address to send, if it is a LAN IP.
 */
static uint32 socket_lan_subnet_check(uint32 ip, struct s_subnet *info)
{
	int i;
	ARR_FIND(0, VECTOR_LENGTH(socket_io->lan_subnets), i, SUBNET_MATCH(ip, VECTOR_INDEX(socket_io->lan_subnets, i).ip, VECTOR_INDEX(socket_io->lan_subnets, i).mask));
	if (i != VECTOR_LENGTH(socket_io->lan_subnets)) {
		if (info) {
			info->ip = VECTOR_INDEX(socket_io->lan_subnets, i).ip;
			info->mask = VECTOR_INDEX(socket_io->lan_subnets, i).mask;
		}
		return VECTOR_INDEX(socket_io->lan_subnets, i).ip;
	}
	if (info) {
		info->ip = info->mask = 0;
	}
	return 0;
}

/**
 * Checks whether the given IP is allowed to connect as a server.
 *
 * @param ip IP address to check.
 * @retval true if we allow server connections from the given IP.
 * @retval false otherwise.
 */
static bool socket_allowed_ip_check(uint32 ip)
{
	int i;
	ARR_FIND(0, VECTOR_LENGTH(socket_io->allowed_ips), i, SUBNET_MATCH(ip, VECTOR_INDEX(socket_io->allowed_ips, i).ip, VECTOR_INDEX(socket_io->allowed_ips, i).mask));
	if (i != VECTOR_LENGTH(socket_io->allowed_ips))
		return true;
	return socket_io->trusted_ip_check(ip); // If an address is trusted, it's automatically also allowed.
}

/**
 * Checks whether the given IP is trusted and can skip ipban checks.
 *
 * @param ip IP address to check.
 * @retval true if we trust the given IP.
 * @retval false otherwise.
 */
static bool socket_trusted_ip_check(uint32 ip)
{
	int i;
	ARR_FIND(0, VECTOR_LENGTH(socket_io->trusted_ips), i, SUBNET_MATCH(ip, VECTOR_INDEX(socket_io->trusted_ips, i).ip, VECTOR_INDEX(socket_io->trusted_ips, i).mask));
	if (i != VECTOR_LENGTH(socket_io->trusted_ips))
		return true;
	return false;
}

// Defaults
void socket_io_defaults(void)
{
	socket_io = &socket_io_s;

	socket_io->SOCKET_CONF_FILENAME = "conf/common/socket.conf";

	socket_io->fd_max = 0;
	/* */
	socket_io->stall_time = 60;
	socket_io->last_tick = 0;
	/* */
	memset(&socket_io->addr_, 0, sizeof(socket_io->addr_));
	socket_io->naddr_ = 0;
	socket_io->validate = false;
	/* */
	VECTOR_INIT(socket_io->lan_subnets);
	VECTOR_INIT(socket_io->allowed_ips);
	VECTOR_INIT(socket_io->trusted_ips);

	socket_io->init = socket_init;
	socket_io->final = socket_final;
	/* */
	socket_io->datasync = socket_datasync;
	/* */
	socket_io->make_listen_bind = make_listen_bind;
	socket_io->make_connection = make_connection;

	socket_io->rfiforest = rfiforest;
	socket_io->rfifoflush = rfifoflush;
	socket_io->wfifop = wfifop;
	socket_io->wfifoset = wfifoset;
	socket_io->wfifohead = wfifohead;
	socket_io->rfifoskip = rfifoskip;

	/* */
	socket_io->wfifoflush = wfifoflush;
	socket_io->wfifoflush_all = wfifoflush_all;
	socket_io->set_defaultparse = set_defaultparse;
	socket_io->host2ip = host2ip;
	socket_io->ip2str = ip2str;
	socket_io->str2ip = str2ip;
	socket_io->ntows = ntows;

	socket_io->lan_subnet_check = socket_lan_subnet_check;
	socket_io->allowed_ip_check = socket_allowed_ip_check;
	socket_io->trusted_ip_check = socket_trusted_ip_check;
	socket_io->net_config_read = socket_net_config_read;

	/* */
	socket_io->session_marked_removal   = session_marked_removal;
	socket_io->session_mark_removal     = session_mark_removal;
	socket_io->session_disconnect       = session_disconnect;
	socket_io->session_disconnect_guard = session_disconnect_guard;
	socket_io->session_from_id          = session_from_id;
	socket_io->session_update_parse     = session_update_parse;
	socket_io->session_timeout          = session_timeout;
}
