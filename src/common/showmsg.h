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
#ifndef COMMON_SHOWMSG_H
#define COMMON_SHOWMSG_H

#include "common/hercules.h"

#include <stdarg.h>

/**
 * Multi-threaded message queue
 *
 * A message thread with a mutex lock is required to display messages because
 * currently no standard guarantees that file operations are atomic.
 * This way we can use only one mutex (showmsg_mutex) instead of a different one for
 * each of the handles.
 * @see showmsg_thread_init
 * @see showmsg_worker
 **/
#define SHOWMSG_USE_THREAD

#ifdef SHOWMSG_USE_THREAD
// Growth factor of message queue (multi-threaded)
#define SHOWMSG_QUEUE_GROWTH_FACTOR 2
// Initial capacity of message queue (multi-threaded)
#define SHOWMSG_QUEUE_INITIAL_CAPACITY 5
#endif

/**
 * Log file names
 *
 * @see showmsg_log_filename
 * @see showmsg_log
 **/
#define SHOWMSG_LOG_LOGIN   "."PATHSEP_STR"log"PATHSEP_STR"login-msg_log.log"
#define SHOWMSG_LOG_CHAR    "."PATHSEP_STR"log"PATHSEP_STR"char-msg_log.log"
#define SHOWMSG_LOG_MAP     "."PATHSEP_STR"log"PATHSEP_STR"map-msg_log.log"
#define SHOWMSG_LOG_UNKNOWN "."PATHSEP_STR"log"PATHSEP_STR"unknown-msg_log.log"

/* Forward Declarations */
struct config_setting_t;

// The console colors are described in the .c file (search for (SGR)),
// along with an explanation on how to use the ANSI escape sequences

#define CL_RESET      "\033[0m" // Reset color parameter
#define CL_CLS        "\033[2J" // Clear screen and go up/left (0, 0 position)
#define CL_CLL        "\033[K"  // Clear line from actual position to end of the line

// font settings
#define CL_BOLD       "\033[1m" // Use bold for font
#define CL_NORM       CL_RESET
#define CL_NORMAL     CL_RESET
#define CL_NONE       CL_RESET

// background color
#define CL_BG_BLACK   "\033[40m"
#define CL_BG_RED     "\033[41m"
#define CL_BG_GREEN   "\033[42m"
#define CL_BG_YELLOW  "\033[43m"
#define CL_BG_BLUE    "\033[44m"
#define CL_BG_MAGENTA "\033[45m"
#define CL_BG_CYAN    "\033[46m"
#define CL_BG_WHITE   "\033[47m"
// foreground color and normal font (normal color on windows)
#define CL_LT_BLACK   "\033[0;30m"
#define CL_LT_RED     "\033[0;31m"
#define CL_LT_GREEN   "\033[0;32m"
#define CL_LT_YELLOW  "\033[0;33m"
#define CL_LT_BLUE    "\033[0;34m"
#define CL_LT_MAGENTA "\033[0;35m"
#define CL_LT_CYAN    "\033[0;36m"
#define CL_LT_WHITE   "\033[0;37m"
// foreground color and bold font (bright color on windows)
#define CL_BT_BLACK   "\033[1;30m"
#define CL_BT_RED     "\033[1;31m"
#define CL_BT_GREEN   "\033[1;32m"
#define CL_BT_YELLOW  "\033[1;33m"
#define CL_BT_BLUE    "\033[1;34m"
#define CL_BT_MAGENTA "\033[1;35m"
#define CL_BT_CYAN    "\033[1;36m"
#define CL_BT_WHITE   "\033[1;37m"

// foreground color and bold font (bright color on windows)
#define CL_WHITE   CL_BT_WHITE
#define CL_GRAY    CL_BT_BLACK
#define CL_RED     CL_BT_RED
#define CL_GREEN   CL_BT_GREEN
#define CL_YELLOW  CL_BT_YELLOW
#define CL_BLUE    CL_BT_BLUE
#define CL_MAGENTA CL_BT_MAGENTA
#define CL_CYAN    CL_BT_CYAN

#define CL_SPACE   "           "   // space aquivalent of the print messages

/**
 * Message types
 *
 * These types are also the flags used in showmsg->silent and showmsg->console_log
 **/
enum msg_type {
	MSG_NONE        = 0x1,
	MSG_STATUS      = 0x2,
	MSG_SQL         = 0x4,
	MSG_INFORMATION = 0x8,
	MSG_NOTICE      = 0x10,
	MSG_WARNING     = 0x20,
	MSG_DEBUG       = 0x40,
	MSG_ERROR       = 0x80,
	MSG_FATALERROR	= 0x100,
};

/**
 * Messages to be treated as errors when displaying
 * These messages are sent to stderr instead of stdout
 **/
#define MSG_ERROR_FLAG (MSG_ERROR|MSG_FATALERROR|MSG_SQL)

/**
 * Equivalent prefix strings
 *
 * @see msg_type
 * @see showmsg_prefix
 **/
#define MSG_STATUS_STR      "Status"
#define MSG_SQL_STR         "SQL"
#define MSG_INFORMATION_STR "Info"
#define MSG_NOTICE_STR      "Notice"
#define MSG_WARNING_STR     "Warning"
#define MSG_DEBUG_STR       "Debug"
#define MSG_ERROR_STR       "Error"
#define MSG_FATALERROR_STR  "Fatal Error"
#define MSG_UNKNOWN_STR     "Unknown"

struct showmsg_interface {
	bool stdout_with_ansisequence; //If the color ANSI sequences are to be used. [flaviojs]
	char timestamp_format[20]; //For displaying Timestamps [Skotlex]
	/**
	 * Console flags
	 * All these flags use msg_type bitwise flags
	 * @see msg_type
	 * @see showmsg_print
	 **/
	int silent;      //Specifies how silent the console is. [Skotlex]
	int console_log; //Specifies what error messages to log. [Ind]

	void (*init) (void);
	void (*final) (void);

	void (*clearScreen) (void);
	int (*showMessageV) (const char *string, va_list ap);

	void (*showMessage) (const char *, ...) __attribute__((format(printf, 1, 2)));
	void (*showStatus) (const char *, ...) __attribute__((format(printf, 1, 2)));
	void (*showSQL) (const char *, ...) __attribute__((format(printf, 1, 2)));
	void (*showInfo) (const char *, ...) __attribute__((format(printf, 1, 2)));
	void (*showNotice) (const char *, ...) __attribute__((format(printf, 1, 2)));
	void (*showWarning) (const char *, ...) __attribute__((format(printf, 1, 2)));
	void (*showDebug) (const char *, ...) __attribute__((format(printf, 1, 2)));
	void (*showError) (const char *, ...) __attribute__((format(printf, 1, 2)));
	void (*showFatalError) (const char *, ...) __attribute__((format(printf, 1, 2)));
	void (*showConfigWarning) (struct config_setting_t *config, const char *string, ...) __attribute__((format(printf, 2, 3)));
};

/* the purpose of these macros is simply to not make calling them be an annoyance */
#define ClearScreen() (showmsg->clearScreen())
#define vShowMessage(fmt, list) (showmsg->showMessageV((fmt), (list)))
#define ShowMessage(fmt, ...) (showmsg->showMessage((fmt), ##__VA_ARGS__))
#define ShowStatus(fmt, ...) (showmsg->showStatus((fmt), ##__VA_ARGS__))
#define ShowSQL(fmt, ...) (showmsg->showSQL((fmt), ##__VA_ARGS__))
#define ShowInfo(fmt, ...) (showmsg->showInfo((fmt), ##__VA_ARGS__))
#define ShowNotice(fmt, ...) (showmsg->showNotice((fmt), ##__VA_ARGS__))
#ifdef BUILDBOT
#define ShowWarning(fmt, ...) (showmsg->showError((fmt), ##__VA_ARGS__))
#else  // BUILDBOT
#define ShowWarning(fmt, ...) (showmsg->showWarning((fmt), ##__VA_ARGS__))
#endif  // BUILDBOT
#define ShowDebug(fmt, ...) (showmsg->showDebug((fmt), ##__VA_ARGS__))
#define ShowError(fmt, ...) (showmsg->showError((fmt), ##__VA_ARGS__))
#define ShowFatalError(fmt, ...) (showmsg->showFatalError((fmt), ##__VA_ARGS__))
#define ShowConfigWarning(config, fmt, ...) (showmsg->showConfigWarning((config), (fmt), ##__VA_ARGS__))

#ifdef HERCULES_CORE
void showmsg_defaults(void);
#endif // HERCULES_CORE

HPShared struct showmsg_interface *showmsg;

#endif /* COMMON_SHOWMSG_H */
