/**
 * This file is part of Hercules.
 * http://herc.ws - http://github.com/HerculesWS/Hercules
 *
 * Copyright (C) 2012-2021 Hercules Dev Team
 * Copyright (C) rAthena Project (www.rathena.org)
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
#ifndef COMMON_THREAD_H
#define COMMON_THREAD_H

#include "common/hercules.h"

/** @file
 * Basic Threading abstraction (for pthread / win32 based systems).
 */

/* Opaque Types */
struct thread_handle;                ///< Thread handle.
typedef void *(*threadFunc)(void *); ///< Thread entry point function.

/* Enums */

/// Thread flag
enum thread_flag {
	THREADFLAG_NONE = 0,
	THREADFLAG_IO = 0x1,
	THREADFLAG_ACTION = 0x2
};

/// Thread priority
enum thread_priority {
	THREADPRIO_IDLE = 0, //< Lowest priority possible (must be the first value)
	THREADPRIO_LOWEST,
	THREADPRIO_LOW,
	THREADPRIO_NORMAL,
	THREADPRIO_HIGH,
	THREADPRIO_HIGHEST,
	THREADPRIO_TIMECRITICAL,
	THREADPRIO_LAST,
};

/// The thread interface
struct thread_interface {
	/// Interface initialization.
	void (*init) (void);

	/// Interface finalization.
	void (*final) (void);

	/**
	 * Returns the number of elements in the internal thread list
	 *
	 * This includes the main thread
	 **/
	int32_t (*count) (void);

	/**
	 * Creates a new Thread.
	 *
	 * @param name       Name used for debugging purposes.
	 * @param enty_point Thread's entry point.
	 * @param param      General purpose parameter, would be given as
	 *                   parameter to the thread's entry point.
	 *
	 * @return The created thread object.
	 * @retval NULL in case of failure.
	 *
	 * @see thread_interface::name_set
	 */
	struct thread_handle *(*create) (const char *name, threadFunc entry_point, void *param);

	/**
	 * Creates a new Thread (with more creation options).
	 *
	 * @param name       Name used for debugging purposes.
	 * @param enty_point Thread's entry point.
	 * @param param      General purpose parameter, would be given as
	 *                   parameter to the thread's entry point.
	 * @param stack_size Stack Size in bytes.
	 * @param prio       Priority of the Thread in the OS scheduler.
	 *
	 * @return The created thread object.
	 * @retval NULL in case of failure.
	 *
	 * @see thread_interface::name_set
	 */
	struct thread_handle *(*create_opt) (const char *name, threadFunc entry_point, void *param, size_t stack_size, enum thread_priority prio);

	/**
	 * Exits current thread immediately.
	 * Doesn't return.
	 *
	 * @param result Value to be reported on thread_join
	 **/
	void (*exit)(void *result);

	/**
	 * Destroys the given Thread immediately.
	 *
	 * @remark
	 *   The Handle gets invalid after call! don't use it afterwards.
	 *
	 * @param handle The thread to destroy.
	 */
	void (*destroy) (struct thread_handle *handle);

	/**
	 * Returns the thread handle of the thread calling this function.
	 *
	 * @remark
	 *   This won't work in the program's main thread.
	 *
	 * @warning
	 *   The underlying implementation might not perform very well, cache
	 *   the value received!
	 *
	 * @return the thread handle.
	 * @retval NULL in case of failure.
	 */
	struct thread_handle *(*self) (void);

	/**
	 * Returns own thread id (TID).
	 *
	 * @remark
	 *   This is an unique identifier for the calling thread, and depends
	 *   on platform/ compiler, and may not be the systems Thread ID!
	 *
	 * @return the thread ID.
	 * @retval -1 in case of failure.
	 */
	int (*get_tid) (void);

	/**
	 * Waits for the given thread to terminate.
	 *
	 * @param[in]  handle        The thread to wait (join) for.
	 * @param[out] out_exit_code Pointer to return the exit code of the
	 *                           given thread after termination (optional).
	 *
	 * @retval true if the given thread has been terminated.
	 */
	bool (*wait) (struct thread_handle *handle, void **out_exit_code);

	
	/**
	 * Waits for multiple threads.
	 *
	 * @param handle[in]         Array of thread_handle pointers
	 * @param count[in]          Length of handle
	 * @param out_exit_code[out] Pointer to array of exit codes
	 * @return Success state
	 *         If all waiting fails returns false, otherwise returns true.
	 */
	bool (*wait_multiple)(struct thread_handle *handle[], int count, void **out_exit_code);

	/**
	 * Sets name of current thread.
	 *
	 * @param name   New name (maximum 16 characters including '\0')
	 *               If NULL uses current name to update system name.
	 * @see thread_handle::name
	 **/
	void (*name_set)(const char *name);

	/**
	 * Returns name of current thread.
	 **/
	const char *(*name_get)(void);

	/**
	 * Sets the given priority in the OS scheduler.
	 *
	 * @param handle The thread to set the priority for.
	 * @param prio   The priority to set (@see enum thread_priority).
	 *
	 * @warning This must only be used for the current thread.
	 */
	void (*prio_set) (struct thread_handle *handle, enum thread_priority prio);

	/**
	 * Gets the current priority of the given thread.
	 *
	 * @param handle The thread to get the priority for.
	 */
	enum thread_priority (*prio_get) (struct thread_handle *handle);

	/**
	 * Sets thread flag to provided value.
	 *
	 * @param flag New flag value
	 **/
	void (*flag_set) (uint32_t flag);

	/**
	 * Gets thread flag
	 **/
	uint32_t (*flag_get) (void);

	/**
	 * Tells the OS scheduler to yield the execution of the calling thread.
	 *
	 * @remark
	 *   This will not "pause" the thread, it just allows the OS to spend
	 *   the remaining time of the slice to another thread.
	 */
	void (*yield) (void);
};

#ifdef HERCULES_CORE
void thread_defaults(void);
#endif // HERCULES_CORE

HPShared struct thread_interface *thread; ///< Pointer to the thread interface.

#endif /* COMMON_THREAD_H */
