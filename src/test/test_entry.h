/**
 * This file is part of Hercules.
 * http://herc.ws - http://github.com/HerculesWS/Hercules
 *
 * Copyright (C) 2021 Hercules Dev Team
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
 *
 * This test sequence is based on Unit tests for GRWLock by Matthias Clasen (c) 2011 LGPL-2.1
 */
#ifndef TEST_ENTRY_H
#define TEST_ENTRY_H

/**
 * Asserts an expression
 * @warning This macro affects the control flow and should only be used in
 * test_function_t functions!
 **/
#define TEST_ASSERT(expr, mes) do {\
	if(!(expr)) {\
		ShowError(__func__":("#expr"), "mes"\n");\
		return false;\
	}\
} while(0)

/**
 * Test function
 *
 * @param data Context information
 * @return Test status
 **/
typedef bool (*test_function_t)(void *data);

struct s_test_suite;

struct s_test_suite *test_add(struct s_test_suite *test, test_function_t function,
	const char *name, void *data
);

// Test suites
struct s_test_suite *test_rwlock_add(struct s_test_suite *test);
struct s_test_suite *test_ers_add(struct s_test_suite *test);
struct s_test_suite *test_timer_add(struct s_test_suite *test);

#endif /* TEST_ENTRY_H */
