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

#include "showmsg.h"

#include "common/cbasetypes.h"
#include "common/conf.h"
#include "common/core.h" //[Ind] - For SERVER_TYPE
#include "common/strlib.h" // StringBuf
#include "common/memmgr.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h> // atexit

#ifdef WIN32
#	include "common/winapi.h"
#else // not WIN32
#	include <unistd.h>
#endif // WIN32

static struct showmsg_interface showmsg_s;
struct showmsg_interface *showmsg;

///////////////////////////////////////////////////////////////////////////////
/// static/dynamic buffer for the messages

#define SBUF_SIZE 2054 // never put less that what's required for the debug message

#define NEWBUF(buf) \
	struct { \
		char s_[SBUF_SIZE]; \
		StringBuf *d_; \
		char *v_; \
		int l_; \
	} buf ={"",NULL,NULL,0}; \
//define NEWBUF

#define BUFVPRINTF(buf,fmt,args) do { \
	(buf).l_ = vsnprintf((buf).s_, SBUF_SIZE, (fmt), args); \
	if( (buf).l_ >= 0 && (buf).l_ < SBUF_SIZE ) \
	{/* static buffer */ \
		(buf).v_ = (buf).s_; \
	} \
	else \
	{/* dynamic buffer */ \
		(buf).d_ = StrBuf->Malloc(); \
		(buf).l_ = StrBuf->Vprintf((buf).d_, (fmt), args); \
		(buf).v_ = StrBuf->Value((buf).d_); \
		ShowDebug("showmsg: dynamic buffer used, increase the static buffer size to %d or more.\n", (buf).l_+1); \
	} \
} while(0) //define BUFVPRINTF

#define BUFVAL(buf) ((buf).v_)
#define BUFLEN(buf) ((buf).l_)

#define FREEBUF(buf) do {\
	if( (buf).d_ ) { \
		StrBuf->Free((buf).d_); \
		(buf).d_ = NULL; \
	} \
	(buf).v_ = NULL; \
} while(0) //define FREEBUF

///////////////////////////////////////////////////////////////////////////////
#ifdef _WIN32
// XXX adapted from eApp (comments are left untouched) [flaviojs]

///////////////////////////////////////////////////////////////////////////////
//  ANSI compatible printf with control sequence parser for windows
//  fast hack, handle with care, not everything implemented
//
// \033[#;...;#m - Set Graphics Rendition (SGR)
//
//  printf("\x1b[1;31;40m"); // Bright red on black
//  printf("\x1b[3;33;45m"); // Blinking yellow on magenta (blink not implemented)
//  printf("\x1b[1;30;47m"); // Bright black (grey) on dim white
//
//  Style           Foreground      Background
//  1st Digit       2nd Digit       3rd Digit      RGB
//  0 - Reset       30 - Black      40 - Black     000
//  1 - FG Bright   31 - Red        41 - Red       100
//  2 - Unknown     32 - Green      42 - Green     010
//  3 - Blink       33 - Yellow     43 - Yellow    110
//  4 - Underline   34 - Blue       44 - Blue      001
//  5 - BG Bright   35 - Magenta    45 - Magenta   101
//  6 - Unknown     36 - Cyan       46 - Cyan      011
//  7 - Reverse     37 - White      47 - White     111
//  8 - Concealed (invisible)
//
// \033[#A - Cursor Up (CUU)
//    Moves the cursor up by the specified number of lines without changing columns.
//    If the cursor is already on the top line, this sequence is ignored. \e[A is equivalent to \e[1A.
//
// \033[#B - Cursor Down (CUD)
//    Moves the cursor down by the specified number of lines without changing columns.
//    If the cursor is already on the bottom line, this sequence is ignored. \e[B is equivalent to \e[1B.
//
// \033[#C - Cursor Forward (CUF)
//    Moves the cursor forward by the specified number of columns without changing lines.
//    If the cursor is already in the rightmost column, this sequence is ignored. \e[C is equivalent to \e[1C.
//
// \033[#D - Cursor Backward (CUB)
//    Moves the cursor back by the specified number of columns without changing lines.
//    If the cursor is already in the leftmost column, this sequence is ignored. \e[D is equivalent to \e[1D.
//
// \033[#E - Cursor Next Line (CNL)
//    Moves the cursor down the indicated # of rows, to column 1. \e[E is equivalent to \e[1E.
//
// \033[#F - Cursor Preceding Line (CPL)
//    Moves the cursor up the indicated # of rows, to column 1. \e[F is equivalent to \e[1F.
//
// \033[#G - Cursor Horizontal Absolute (CHA)
//    Moves the cursor to indicated column in current row. \e[G is equivalent to \e[1G.
//
// \033[#;#H - Cursor Position (CUP)
//    Moves the cursor to the specified position. The first # specifies the line number,
//    the second # specifies the column. If you do not specify a position, the cursor moves to the home position:
//    the upper-left corner of the screen (line 1, column 1).
//
// \033[#;#f - Horizontal & Vertical Position
//    (same as \033[#;#H)
//
// \033[s - Save Cursor Position (SCP)
//    The current cursor position is saved.
//
// \033[u - Restore cursor position (RCP)
//    Restores the cursor position saved with the (SCP) sequence \033[s.
//    (addition, restore to 0,0 if nothing was saved before)
//

// \033[#J - Erase Display (ED)
//    Clears the screen and moves to the home position
//    \033[0J - Clears the screen from cursor to end of display. The cursor position is unchanged. (default)
//    \033[1J - Clears the screen from start to cursor. The cursor position is unchanged.
//    \033[2J - Clears the screen and moves the cursor to the home position (line 1, column 1).
//
// \033[#K - Erase Line (EL)
//    Clears the current line from the cursor position
//    \033[0K - Clears all characters from the cursor position to the end of the line (including the character at the cursor position). The cursor position is unchanged. (default)
//    \033[1K - Clears all characters from start of line to the cursor position. (including the character at the cursor position). The cursor position is unchanged.
//    \033[2K - Clears all characters of the whole line. The cursor position is unchanged.


/*
not implemented

\033[#L
IL: Insert Lines: The cursor line and all lines below it move down # lines, leaving blank space. The cursor position is unchanged. The bottommost # lines are lost. \e[L is equivalent to \e[1L.
\033[#M
DL: Delete Line: The block of # lines at and below the cursor are deleted; all lines below them move up # lines to fill in the gap, leaving # blank lines at the bottom of the screen. The cursor position is unchanged. \e[M is equivalent to \e[1M.
\033[#\@
ICH: Insert CHaracter: The cursor character and all characters to the right of it move right # columns, leaving behind blank space. The cursor position is unchanged. The rightmost # characters on the line are lost. \e[\@ is equivalent to \e[1\@.
\033[#P
DCH: Delete CHaracter: The block of # characters at and to the right of the cursor are deleted; all characters to the right of it move left # columns, leaving behind blank space. The cursor position is unchanged. \e[P is equivalent to \e[1P.

Escape sequences for Select Character Set
*/

#define is_console(handle) (FILE_TYPE_CHAR==GetFileType(handle))

///////////////////////////////////////////////////////////////////////////////
static int VFPRINTF(HANDLE handle, const char *fmt, va_list argptr)
{
	/////////////////////////////////////////////////////////////////
	/* XXX Two streams are being used. Disabled to avoid inconsistency [flaviojs]
	static COORD saveposition = {0,0};
	*/

	/////////////////////////////////////////////////////////////////
	DWORD written;
	char *p, *q;
	NEWBUF(tempbuf); // temporary buffer

	if(!fmt || !*fmt)
		return 0;

	// Print everything to the buffer
	BUFVPRINTF(tempbuf,fmt,argptr);

	if (!is_console(handle) && showmsg->stdout_with_ansisequence) {
		WriteFile(handle, BUFVAL(tempbuf), BUFLEN(tempbuf), &written, 0);
		return 0;
	}

	// start with processing
	p = BUFVAL(tempbuf);
	while ((q = strchr(p, 0x1b)) != NULL) {
		// find the escape character
		if( 0==WriteConsole(handle, p, (DWORD)(q-p), &written, 0) ) // write up to the escape
			WriteFile(handle, p, (DWORD)(q-p), &written, 0);

		if (q[1]!='[') {
			// write the escape char (whatever purpose it has)
			if(0==WriteConsole(handle, q, 1, &written, 0) )
				WriteFile(handle,q, 1, &written, 0);
			p=q+1; //and start searching again
		} else {
			// from here, we will skip the '\033['
			// we break at the first unprocessible position
			// assuming regular text is starting there
			uint8 numbers[16], numpoint=0;
			CONSOLE_SCREEN_BUFFER_INFO info;

			// initialize
			GetConsoleScreenBufferInfo(handle, &info);
			memset(numbers,0,sizeof(numbers));

			// skip escape and bracket
			q=q+2;
			for (;;) {
				if (ISDIGIT(*q)) {
					// add number to number array, only accept 2digits, shift out the rest
					// so // \033[123456789m will become \033[89m
					numbers[numpoint] = (numbers[numpoint]<<4) | (*q-'0');
					++q;
					// and next character
					continue;
				} else if (*q == ';') {
					// delimiter
					if (numpoint < ARRAYLENGTH(numbers)) {
						// go to next array position
						numpoint++;
					} else {
						// array is full, so we 'forget' the first value
						memmove(numbers, numbers+1, ARRAYLENGTH(numbers)-1);
						numbers[ARRAYLENGTH(numbers)-1]=0;
					}
					++q;
					// and next number
					continue;
				} else if (*q == 'm') {
					// \033[#;...;#m - Set Graphics Rendition (SGR)
					uint8 i;
					for (i=0; i<= numpoint; ++i) {
						if (0x00 == (0xF0 & numbers[i])) {
							// upper nibble 0
							if (0 == numbers[i]) {
								// reset
								info.wAttributes = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
							} else if (1 == numbers[i]) {
								// set foreground intensity
								info.wAttributes |= FOREGROUND_INTENSITY;
							} else if (5 == numbers[i]) {
								// set background intensity
								info.wAttributes |= BACKGROUND_INTENSITY;
							} else if (7 == numbers[i]) {
								// reverse colors (just xor them)
								info.wAttributes ^= FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE |
								                    BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE;
							}
							//case '2': // not existing
							//case '3': // blinking (not implemented)
							//case '4': // underline (not implemented)
							//case '6': // not existing
							//case '8': // concealed (not implemented)
							//case '9': // not existing
						} else if (0x20 == (0xF0 & numbers[i])) {
							// off

							if (1 == numbers[i]) {
								// set foreground intensity off
								info.wAttributes &= ~FOREGROUND_INTENSITY;
							} else if (5 == numbers[i]) {
								// set background intensity off
								info.wAttributes &= ~BACKGROUND_INTENSITY;
							} else if (7 == numbers[i]) {
								// reverse colors (just xor them)
								info.wAttributes ^= FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE |
								                    BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE;
							}
						} else if (0x30 == (0xF0 & numbers[i])) {
							// foreground
							uint8 num = numbers[i]&0x0F;
							if(num==9) info.wAttributes |= FOREGROUND_INTENSITY;
							if(num>7) num=7; // set white for 37, 38 and 39
							info.wAttributes &= ~(FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE);
							if( (num & 0x01)>0 ) // lowest bit set = red
								info.wAttributes |= FOREGROUND_RED;
							if( (num & 0x02)>0 ) // second bit set = green
								info.wAttributes |= FOREGROUND_GREEN;
							if( (num & 0x04)>0 ) // third bit set = blue
								info.wAttributes |= FOREGROUND_BLUE;
						} else if (0x40 == (0xF0 & numbers[i])) {
							// background
							uint8 num = numbers[i]&0x0F;
							if(num==9) info.wAttributes |= BACKGROUND_INTENSITY;
							if(num>7) num=7; // set white for 47, 48 and 49
							info.wAttributes &= ~(BACKGROUND_RED|BACKGROUND_GREEN|BACKGROUND_BLUE);
							if( (num & 0x01)>0 ) // lowest bit set = red
								info.wAttributes |= BACKGROUND_RED;
							if( (num & 0x02)>0 ) // second bit set = green
								info.wAttributes |= BACKGROUND_GREEN;
							if( (num & 0x04)>0 ) // third bit set = blue
								info.wAttributes |= BACKGROUND_BLUE;
						}
					}
					// set the attributes
					SetConsoleTextAttribute(handle, info.wAttributes);
				} else if (*q=='J') {
					// \033[#J - Erase Display (ED)
					// \033[0J - Clears the screen from cursor to end of display. The cursor position is unchanged.
					// \033[1J - Clears the screen from start to cursor. The cursor position is unchanged.
					// \033[2J - Clears the screen and moves the cursor to the home position (line 1, column 1).
					uint8 num = (numbers[numpoint]>>4)*10+(numbers[numpoint]&0x0F);
					int cnt;
					DWORD tmp;
					COORD origin = {0,0};
					if (num == 1) {
						// chars from start up to and including cursor
						cnt = info.dwSize.X * info.dwCursorPosition.Y + info.dwCursorPosition.X + 1;
					} else if (num == 2) {
						// Number of chars on screen.
						cnt = info.dwSize.X * info.dwSize.Y;
						SetConsoleCursorPosition(handle, origin);
					} else { /* 0 and default */
						// number of chars from cursor to end
						origin = info.dwCursorPosition;
						cnt = info.dwSize.X * (info.dwSize.Y - info.dwCursorPosition.Y) - info.dwCursorPosition.X;
					}
					FillConsoleOutputAttribute(handle, info.wAttributes, cnt, origin, &tmp);
					FillConsoleOutputCharacter(handle, ' ',              cnt, origin, &tmp);
				} else if (*q=='K') {
					// \033[K  : clear line from actual position to end of the line
					// \033[0K - Clears all characters from the cursor position to the end of the line.
					// \033[1K - Clears all characters from start of line to the cursor position.
					// \033[2K - Clears all characters of the whole line.

					uint8 num = (numbers[numpoint]>>4)*10+(numbers[numpoint]&0x0F);
					COORD origin = {0,info.dwCursorPosition.Y}; //warning C4204
					SHORT cnt;
					DWORD tmp;
					if (num == 1) {
						cnt = info.dwCursorPosition.X + 1;
					} else if (num == 2) {
						cnt = info.dwSize.X;
					} else { /* 0 and default */
						origin = info.dwCursorPosition;
						cnt = info.dwSize.X - info.dwCursorPosition.X; // how many spaces until line is full
					}
					FillConsoleOutputAttribute(handle, info.wAttributes, cnt, origin, &tmp);
					FillConsoleOutputCharacter(handle, ' ',              cnt, origin, &tmp);
				} else if (*q == 'H' || *q == 'f') {
					// \033[#;#H - Cursor Position (CUP)
					// \033[#;#f - Horizontal & Vertical Position
					// The first # specifies the line number, the second # specifies the column.
					// The default for both is 1
					info.dwCursorPosition.X = (numbers[numpoint])?(numbers[numpoint]>>4)*10+((numbers[numpoint]&0x0F)-1):0;
					info.dwCursorPosition.Y = (numpoint && numbers[numpoint-1])?(numbers[numpoint-1]>>4)*10+((numbers[numpoint-1]&0x0F)-1):0;

					if( info.dwCursorPosition.X >= info.dwSize.X ) info.dwCursorPosition.Y = info.dwSize.X-1;
					if( info.dwCursorPosition.Y >= info.dwSize.Y ) info.dwCursorPosition.Y = info.dwSize.Y-1;
					SetConsoleCursorPosition(handle, info.dwCursorPosition);
				} else if (*q=='s') {
					// \033[s - Save Cursor Position (SCP)
					/* XXX Two streams are being used. Disabled to avoid inconsistency [flaviojs]
					CONSOLE_SCREEN_BUFFER_INFO info;
					GetConsoleScreenBufferInfo(handle, &info);
					saveposition = info.dwCursorPosition;
					*/
				} else if (*q=='u') {
					// \033[u - Restore cursor position (RCP)
					/* XXX Two streams are being used. Disabled to avoid inconsistency [flaviojs]
					SetConsoleCursorPosition(handle, saveposition);
					*/
				} else if (*q == 'A') {
					// \033[#A - Cursor Up (CUU)
					// Moves the cursor UP # number of lines
					info.dwCursorPosition.Y -= (numbers[numpoint])?(numbers[numpoint]>>4)*10+(numbers[numpoint]&0x0F):1;

					if( info.dwCursorPosition.Y < 0 )
						info.dwCursorPosition.Y = 0;
					SetConsoleCursorPosition(handle, info.dwCursorPosition);
				} else if (*q == 'B') {
					// \033[#B - Cursor Down (CUD)
					// Moves the cursor DOWN # number of lines
					info.dwCursorPosition.Y += (numbers[numpoint])?(numbers[numpoint]>>4)*10+(numbers[numpoint]&0x0F):1;

					if( info.dwCursorPosition.Y >= info.dwSize.Y )
						info.dwCursorPosition.Y = info.dwSize.Y-1;
					SetConsoleCursorPosition(handle, info.dwCursorPosition);
				} else if (*q == 'C') {
					// \033[#C - Cursor Forward (CUF)
					// Moves the cursor RIGHT # number of columns
					info.dwCursorPosition.X += (numbers[numpoint])?(numbers[numpoint]>>4)*10+(numbers[numpoint]&0x0F):1;

					if( info.dwCursorPosition.X >= info.dwSize.X )
						info.dwCursorPosition.X = info.dwSize.X-1;
					SetConsoleCursorPosition(handle, info.dwCursorPosition);
				} else if (*q == 'D') {
					// \033[#D - Cursor Backward (CUB)
					// Moves the cursor LEFT # number of columns
					info.dwCursorPosition.X -= (numbers[numpoint])?(numbers[numpoint]>>4)*10+(numbers[numpoint]&0x0F):1;

					if( info.dwCursorPosition.X < 0 )
						info.dwCursorPosition.X = 0;
					SetConsoleCursorPosition(handle, info.dwCursorPosition);
				} else if (*q == 'E') {
					// \033[#E - Cursor Next Line (CNL)
					// Moves the cursor down the indicated # of rows, to column 1
					info.dwCursorPosition.Y += (numbers[numpoint])?(numbers[numpoint]>>4)*10+(numbers[numpoint]&0x0F):1;
					info.dwCursorPosition.X = 0;

					if( info.dwCursorPosition.Y >= info.dwSize.Y )
						info.dwCursorPosition.Y = info.dwSize.Y-1;
					SetConsoleCursorPosition(handle, info.dwCursorPosition);
				} else if (*q == 'F') {
					// \033[#F - Cursor Preceding Line (CPL)
					// Moves the cursor up the indicated # of rows, to column 1.
					info.dwCursorPosition.Y -= (numbers[numpoint])?(numbers[numpoint]>>4)*10+(numbers[numpoint]&0x0F):1;
					info.dwCursorPosition.X = 0;

					if( info.dwCursorPosition.Y < 0 )
						info.dwCursorPosition.Y = 0;
					SetConsoleCursorPosition(handle, info.dwCursorPosition);
				} else if (*q == 'G') {
					// \033[#G - Cursor Horizontal Absolute (CHA)
					// Moves the cursor to indicated column in current row.
					info.dwCursorPosition.X = (numbers[numpoint])?(numbers[numpoint]>>4)*10+((numbers[numpoint]&0x0F)-1):0;

					if( info.dwCursorPosition.X >= info.dwSize.X )
						info.dwCursorPosition.X = info.dwSize.X-1;
					SetConsoleCursorPosition(handle, info.dwCursorPosition);
				} else if (*q == 'L' || *q == 'M' || *q == '@' || *q == 'P') {
					// not implemented, just skip
				} else {
					// no number nor valid sequencer
					// something is fishy, we break and give the current char free
					--q;
				}
				// skip the sequencer and search again
				p = q+1;
				break;
			}// end while
		}
	}
	if (*p) // write the rest of the buffer
		if( 0==WriteConsole(handle, p, (DWORD)strlen(p), &written, 0) )
			WriteFile(handle, p, (DWORD)strlen(p), &written, 0);
	FREEBUF(tempbuf);
	return 0;
}

static int FPRINTF(HANDLE handle, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static int FPRINTF(HANDLE handle, const char *fmt, ...)
{
	int ret;
	va_list argptr;
	va_start(argptr, fmt);
	ret = VFPRINTF(handle,fmt,argptr);
	va_end(argptr);
	return ret;
}

#define FFLUSH(handle) (void)(handle)

#define STDOUT GetStdHandle(STD_OUTPUT_HANDLE)
#define STDERR GetStdHandle(STD_ERROR_HANDLE)

#else // not _WIN32


#define is_console(file) (0!=isatty(fileno(file)))

//vprintf_without_ansiformats
static int VFPRINTF(FILE *file, const char *fmt, va_list argptr)
{
	char *p, *q;
	NEWBUF(tempbuf); // temporary buffer

	if(!fmt || !*fmt)
		return 0;

	if (is_console(file) || showmsg->stdout_with_ansisequence) {
		vfprintf(file, fmt, argptr);
		return 0;
	}

	// Print everything to the buffer
	BUFVPRINTF(tempbuf,fmt,argptr);

	// start with processing
	p = BUFVAL(tempbuf);
	while ((q = strchr(p, 0x1b)) != NULL) {
		// find the escape character
		fprintf(file, "%.*s", (int)(q-p), p); // write up to the escape
		if (q[1]!='[') {
			// write the escape char (whatever purpose it has)
			fprintf(file, "%.*s", 1, q);
			p=q+1; //and start searching again
		} else {
			// from here, we will skip the '\033['
			// we break at the first unprocessible position
			// assuming regular text is starting there

			// skip escape and bracket
			q=q+2;
			while(1) {
				if (ISDIGIT(*q)) {
					++q;
					// and next character
					continue;
				} else if (*q == ';') {
					// delimiter
					++q;
					// and next number
					continue;
				} else if (*q == 'm') {
					// \033[#;...;#m - Set Graphics Rendition (SGR)
					// set the attributes
				} else if (*q=='J') {
					// \033[#J - Erase Display (ED)
				}
				else if (*q=='K') {
					// \033[K  : clear line from actual position to end of the line
				} else if (*q == 'H' || *q == 'f') {
					// \033[#;#H - Cursor Position (CUP)
					// \033[#;#f - Horizontal & Vertical Position
				} else if (*q=='s') {
					// \033[s - Save Cursor Position (SCP)
				} else if (*q=='u') {
					// \033[u - Restore cursor position (RCP)
				} else if (*q == 'A') {
					// \033[#A - Cursor Up (CUU)
					// Moves the cursor UP # number of lines
				} else if (*q == 'B') {
					// \033[#B - Cursor Down (CUD)
					// Moves the cursor DOWN # number of lines
				} else if (*q == 'C') {
					// \033[#C - Cursor Forward (CUF)
					// Moves the cursor RIGHT # number of columns
				} else if (*q == 'D') {
					// \033[#D - Cursor Backward (CUB)
					// Moves the cursor LEFT # number of columns
				} else if (*q == 'E') {
					// \033[#E - Cursor Next Line (CNL)
					// Moves the cursor down the indicated # of rows, to column 1
				} else if (*q == 'F') {
					// \033[#F - Cursor Preceding Line (CPL)
					// Moves the cursor up the indicated # of rows, to column 1.
				} else if (*q == 'G') {
					// \033[#G - Cursor Horizontal Absolute (CHA)
					// Moves the cursor to indicated column in current row.
				} else if (*q == 'L' || *q == 'M' || *q == '@' || *q == 'P') {
					// not implemented, just skip
				} else {
					// no number nor valid sequencer
					// something is fishy, we break and give the current char free
					--q;
				}
				// skip the sequencer and search again
				p = q+1;
				break;
			}// end while
		}
	}
	if (*p) // write the rest of the buffer
		fprintf(file, "%s", p);
	FREEBUF(tempbuf);
	return 0;
}
static int FPRINTF(FILE *file, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static int FPRINTF(FILE *file, const char *fmt, ...)
{
	int ret;
	va_list argptr;
	va_start(argptr, fmt);
	ret = VFPRINTF(file,fmt,argptr);
	va_end(argptr);
	return ret;
}

#define FFLUSH fflush

#define STDOUT stdout
#define STDERR stderr

#endif// not _WIN32

/**
 * Formats a string using provided va_list
 * @param format Format
 * @param ap variadic parameter
 * @param out_len output length, when less than 0 output is NULL
 *
 * @return Formatted output (should be rfree by caller)
 **/
char *vshowmsg_(const char *format, va_list ap, int *out_len)
{
	va_list apcopy;
	int len = 0;
	char *buffer = NULL;

	va_copy(apcopy, ap);
	len = vsnprintf(NULL, 0, format, apcopy);
	if(len > 0) {
		len++;
		// Memory management uses showmsg functions and showmsg is used
		// before its startup, so we shouldn't be reliant on it. [Panikon]
		buffer = iMalloc->rmalloc(len);
		if(!buffer) {
			FPRINTF(STDERR, "vshowmsg_: rmalloc out of memory!\n");
			exit(EXIT_FAILURE);
		}
		len = vsnprintf(buffer, len, format, apcopy);
		if(len < 0)
			aFree(buffer);
	}
	va_end(apcopy);
	*out_len = len;
	if(len <= 0)
		return NULL;
	return buffer;
}

/**
 * Appends colored prefix string to 'prefix'
 *
 * @param prefix String target
 * @param prefix_len prefix capacity - 1
 * @param flag Message flag
 * @param color Color the prefix?
 **/
static void showmsg_prefix(char *prefix, size_t prefix_len, enum msg_type flag, bool color)
{
	switch (flag) {
		case MSG_NONE: // direct printf replacement
			break;
		case MSG_STATUS: //Bright Green (To inform about good things)
			strncat(prefix,
				   (flag)?CL_GREEN"["MSG_STATUS_STR"]"CL_RESET":" : MSG_STATUS_STR, prefix_len);
			break;
		case MSG_SQL: //Bright Violet (For dumping out anything related with SQL) 
			// Actually, this is mostly used for SQL errors with the database,
			// as successes can as well just be anything else... [Skotlex]
			strncat(prefix,
				   (flag)?CL_MAGENTA"["MSG_SQL_STR"]"CL_RESET":" : MSG_SQL_STR, prefix_len);
			break;
		case MSG_INFORMATION: //Bright White (Variable information)
			strncat(prefix,
				   (flag)?CL_WHITE"["MSG_INFORMATION_STR"]"CL_RESET":" : MSG_INFORMATION_STR, prefix_len);
			break;
		case MSG_NOTICE: //Bright White (Less than a warning)
			strncat(prefix,
				   (flag)?CL_WHITE"["MSG_NOTICE_STR"]"CL_RESET":" : MSG_NOTICE_STR, prefix_len);
			break;
		case MSG_WARNING: //Bright Yellow
			strncat(prefix,
				   (flag)?CL_YELLOW"["MSG_WARNING_STR"]"CL_RESET":" : MSG_WARNING_STR, prefix_len);
			break;
		case MSG_DEBUG: //Bright Cyan, important stuff!
			strncat(prefix,
				   (flag)?CL_CYAN"["MSG_DEBUG_STR"]"CL_RESET":" : MSG_DEBUG_STR, prefix_len);
			break;
		case MSG_ERROR: //Bright Red  (Regular errors)
			strncat(prefix,
				   (flag)?CL_RED"["MSG_ERROR_STR"]"CL_RESET":" : MSG_ERROR_STR, prefix_len);
			break;
		case MSG_FATALERROR: //Bright Red (Fatal errors, abort(); if possible)
			strncat(prefix,
				   (flag)?CL_RED"["MSG_FATALERROR_STR"]"CL_RESET":" : MSG_FATALERROR_STR, prefix_len);
			break;
		default:
			ShowError("showmsg_prefix_color: Unknown flag %d\n", flag);
			strncat(prefix,
				   (flag)?CL_WHITE"["MSG_UNKNOWN_STR"]"CL_RESET":" : MSG_UNKNOWN_STR, prefix_len);
			break;
	}
}

/**
 * Should this message type be silenced when printing?
 *
 * @see showmsg->silent
 * @see ShowMessageFormat
 **/
static bool showmsg_is_silent(enum msg_type flag)
{
	return ((flag == MSG_INFORMATION && showmsg->silent&1) ||
	        (flag == MSG_STATUS      && showmsg->silent&2) ||
	        (flag == MSG_NOTICE      && showmsg->silent&4) ||
	        (flag == MSG_WARNING     && showmsg->silent&8) ||
	        (flag == MSG_ERROR       && showmsg->silent&16) ||
	        (flag == MSG_SQL         && showmsg->silent&16) ||
	        (flag == MSG_DEBUG       && showmsg->silent&32));
}

/**
 * Should this message flag be logged?
 *
 * @see showmsg->console_log
 * @see showmsg_log
 **/
static bool showmsg_is_log(enum msg_type flag)
{
	return ( ( flag == MSG_WARNING && showmsg->console_log&1 ) ||
	       ( ( flag == MSG_ERROR || flag == MSG_SQL ) && showmsg->console_log&2 ) ||
	       ( flag == MSG_DEBUG && showmsg->console_log&4 ) ); //[Ind]
}

/**
 * Server type to log file name
 **/
const char *showmsg_log_filename(void)
{
	switch(SERVER_TYPE) {
		case SERVER_TYPE_LOGIN: return SHOWMSG_LOG_LOGIN;
		case SERVER_TYPE_CHAR:  return SHOWMSG_LOG_CHAR;
		case SERVER_TYPE_MAP:   return SHOWMSG_LOG_MAP;
		default:                return SHOWMSG_LOG_UNKNOWN;
	}
}

/**
 * Logs formatted string
 *
 * @see showmsg_is_log
 **/
static void showmsg_log(enum msg_type flag, const char *string)
{
	FILE *log = NULL;
	char timestring[255];
	time_t curtime;

	log = fopen(showmsg_log_filename(), "a+");
	if(!log) {
		ShowMessage("showmsg_log: Failed to log message\n!");
		return;
	}

	time(&curtime);
	strftime(timestring, 254, "%m/%d/%Y %H:%M:%S", localtime(&curtime));
	char prefix[100];
	showmsg_prefix(prefix, sizeof(prefix), flag, false);
	fprintf(log,"(%s) [ %s ] : %s",
		timestring, prefix, string);
	fclose(log);
}

/**
 * Prints pre formatted message
 **/
static int showmsg_print(enum msg_type flag, const char *string, int str_len)
{
	char prefix[100];
	if(!string || *string == '\0' || !str_len) {
		ShowError("showmsg_print: string was empty\n");
		return 1;
	}
	if(showmsg_is_log(flag))
		showmsg_log(flag, string);
	if(showmsg_is_silent(flag))
		return 0; // Do not display this message

	if (showmsg->timestamp_format[0] && flag != MSG_NONE) {
		//Display time format. [Skotlex]
		time_t t = time(NULL);
		strftime(prefix, 80, showmsg->timestamp_format, localtime(&t));
	} else prefix[0]='\0';
	showmsg_prefix(prefix, sizeof(prefix), flag, true);

	// Print message
	if(flag == MSG_ERROR || flag == MSG_FATALERROR || flag == MSG_SQL) {
		//Send Errors to StdErr [Skotlex]
		FPRINTF(STDERR, "%s %s", prefix, string);
		FFLUSH(STDERR);
	} else {
		if(flag != MSG_NONE)
			FPRINTF(STDOUT, "%s %s", prefix, string);
		else
			FPRINTF(STDOUT, "%s", string);
		FFLUSH(STDOUT);
	}
	return 0;
}

static int vShowMessage_(enum msg_type flag, const char *string, va_list ap)
{
	int ret;
	va_list apcopy;
	int len = 0;
	va_copy(apcopy, ap);
	char *buffer = vshowmsg_(string, apcopy, &len);
	ret = showmsg_print(flag, buffer, len);
	if(buffer)
		iMalloc->rfree(buffer);
	va_end(apcopy);
	return ret;
}

static int showmsg_vShowMessage(const char *string, va_list ap)
{
	int ret;
	va_list apcopy;
	va_copy(apcopy, ap);
	ret = vShowMessage_(MSG_NONE, string, apcopy);
	va_end(apcopy);
	return ret;
}

static void showmsg_clearScreen(void)
{
#ifndef _WIN32
	ShowMessage(CL_CLS); // to prevent empty string passed messages
#endif
}

// direct printf replacement
static void showmsg_showMessage(const char *string, ...) __attribute__((format(printf, 1, 2)));
static void showmsg_showMessage(const char *string, ...)
{
	va_list ap;
	va_start(ap, string);
	vShowMessage_(MSG_NONE, string, ap);
	va_end(ap);
}
static void showmsg_showStatus(const char *string, ...) __attribute__((format(printf, 1, 2)));
static void showmsg_showStatus(const char *string, ...)
{
	va_list ap;
	va_start(ap, string);
	vShowMessage_(MSG_STATUS, string, ap);
	va_end(ap);
}
static void showmsg_showSQL(const char *string, ...) __attribute__((format(printf, 1, 2)));
static void showmsg_showSQL(const char *string, ...)
{
	va_list ap;
	va_start(ap, string);
	vShowMessage_(MSG_SQL, string, ap);
	va_end(ap);
}
static void showmsg_showInfo(const char *string, ...) __attribute__((format(printf, 1, 2)));
static void showmsg_showInfo(const char *string, ...)
{
	va_list ap;
	va_start(ap, string);
	vShowMessage_(MSG_INFORMATION, string, ap);
	va_end(ap);
}
static void showmsg_showNotice(const char *string, ...) __attribute__((format(printf, 1, 2)));
static void showmsg_showNotice(const char *string, ...)
{
	va_list ap;
	va_start(ap, string);
	vShowMessage_(MSG_NOTICE, string, ap);
	va_end(ap);
}
static void showmsg_showWarning(const char *string, ...) __attribute__((format(printf, 1, 2)));
static void showmsg_showWarning(const char *string, ...)
{
	va_list ap;
	va_start(ap, string);
	vShowMessage_(MSG_WARNING, string, ap);
	va_end(ap);
}
static void showmsg_showConfigWarning(struct config_setting_t *config, const char *string, ...) __attribute__((format(printf, 2, 3)));
static void showmsg_showConfigWarning(struct config_setting_t *config, const char *string, ...)
{
	StringBuf buf;
	va_list ap;
	StrBuf->Init(&buf);
	StrBuf->AppendStr(&buf, string);
	StrBuf->Printf(&buf, " (%s:%u)\n", config_setting_source_file(config), config_setting_source_line(config));
	va_start(ap, string);
#ifdef BUILDBOT
	vShowMessage_(MSG_ERROR, StrBuf->Value(&buf), ap);
#else  // BUILDBOT
	vShowMessage_(MSG_WARNING, StrBuf->Value(&buf), ap);
#endif  // BUILDBOT
	va_end(ap);
	StrBuf->Destroy(&buf);
}
static void showmsg_showDebug(const char *string, ...) __attribute__((format(printf, 1, 2)));
static void showmsg_showDebug(const char *string, ...)
{
	va_list ap;
	va_start(ap, string);
	vShowMessage_(MSG_DEBUG, string, ap);
	va_end(ap);
}
static void showmsg_showError(const char *string, ...) __attribute__((format(printf, 1, 2)));
static void showmsg_showError(const char *string, ...)
{
	va_list ap;
	va_start(ap, string);
	vShowMessage_(MSG_ERROR, string, ap);
	va_end(ap);
}
static void showmsg_showFatalError(const char *string, ...) __attribute__((format(printf, 1, 2)));
static void showmsg_showFatalError(const char *string, ...)
{
	va_list ap;
	va_start(ap, string);
	vShowMessage_(MSG_FATALERROR, string, ap);
	va_end(ap);
}

static void showmsg_init(void)
{
}

static void showmsg_final(void)
{
}

void showmsg_defaults(void)
{
	showmsg = &showmsg_s;

	///////////////////////////////////////////////////////////////////////////////
	/// behavioral parameter.
	/// when redirecting output:
	/// if true prints escape sequences
	/// if false removes the escape sequences
	showmsg->stdout_with_ansisequence = false;

	showmsg->silent = 0; //Specifies how silent the console is.

	showmsg->console_log = 0;//[Ind] msg error logging

	memset(showmsg->timestamp_format, '\0', sizeof(showmsg->timestamp_format));

	showmsg->init = showmsg_init;
	showmsg->final = showmsg_final;

	showmsg->clearScreen = showmsg_clearScreen;
	showmsg->showMessageV = showmsg_vShowMessage;

	showmsg->showMessage = showmsg_showMessage;
	showmsg->showStatus = showmsg_showStatus;
	showmsg->showSQL = showmsg_showSQL;
	showmsg->showInfo = showmsg_showInfo;
	showmsg->showNotice = showmsg_showNotice;
	showmsg->showWarning = showmsg_showWarning;
	showmsg->showDebug = showmsg_showDebug;
	showmsg->showError = showmsg_showError;
	showmsg->showFatalError = showmsg_showFatalError;
	showmsg->showConfigWarning = showmsg_showConfigWarning;
}
