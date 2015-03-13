/* A Bison parser, made by GNU Bison 3.0.2.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2013 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.0.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1




/* Copy the first part of user declarations.  */
#line 20 "quote_fmt_parse.y" /* yacc.c:339  */


#include "defs.h"

#include <glib.h>
#include <glib/gi18n.h>

#include <ctype.h>

#include "procmsg.h"
#include "procmime.h"
#include "utils.h"
#include "codeconv.h"
#include "procheader.h"
#include "addr_compl.h"
#include "gtk/inputdialog.h"

#include "quote_fmt.h"
#include "quote_fmt_lex.h"
#include "account.h"

/* decl */
/*
flex quote_fmt.l
bison -p quote_fmt quote_fmt.y
*/

int yylex(void);

static MsgInfo *msginfo = NULL;
static PrefsAccount *account = NULL;
#ifdef USE_ENCHANT
static gchar default_dictionary[BUFFSIZE];
#endif
static gboolean *visible = NULL;
static gboolean dry_run = FALSE;
static gint maxsize = 0;
static gint stacksize = 0;
static GHashTable *var_table = NULL;
static GList *attachments = NULL;

typedef struct st_buffer
{
	gchar *buffer;
	gint bufsize;
	gint bufmax;
} st_buffer;

static struct st_buffer main_expr = { NULL, 0, 0 };
static struct st_buffer sub_expr = { NULL, 0, 0 };
static struct st_buffer* current = NULL;

static const gchar *quote_str = NULL;
static const gchar *body = NULL;
static gint error = 0;

static gint cursor_pos = -1;

extern int quote_fmt_firsttime;
extern int line;
extern int escaped_string;

static void add_visibility(gboolean val)
{
	stacksize++;
	if (maxsize < stacksize) {
		maxsize += 128;
		visible = g_realloc(visible, maxsize * sizeof(gboolean));
		if (visible == NULL)
			maxsize = 0;
	}
	if (visible != NULL)
		visible[stacksize - 1] = val;
}

static void remove_visibility(void)
{
	stacksize--;
	if (stacksize < 0) {
		g_warning("Error: visibility stack underflow\n");
		stacksize = 0;
	}
}

static void add_buffer(const gchar *s)
{
	gint len;

	if (s == NULL)
		return;

	len = strlen(s);
	if (current->bufsize + len + 1 > current->bufmax) {
		if (current->bufmax == 0)
			current->bufmax = 128;
		while (current->bufsize + len + 1 > current->bufmax)
			current->bufmax *= 2;
		current->buffer = g_realloc(current->buffer, current->bufmax);
	}
	strcpy(current->buffer + current->bufsize, s);
	current->bufsize += len;
}

static void clear_buffer(void)
{
	if (current->buffer)
		*current->buffer = '\0';
	else
		/* force to an empty string, as buffer should not be left unallocated */
		add_buffer("");
	current->bufsize = 0;
}

gchar *quote_fmt_get_buffer(void)
{
	if (current != &main_expr)
		g_warning("Error: parser still in sub-expr mode\n");

	if (error != 0)
		return NULL;
	else
		return current->buffer;
}

GList *quote_fmt_get_attachments_list(void)
{
	return attachments;
}

gint quote_fmt_get_line(void)
{
	return line;
}

gint quote_fmt_get_cursor_pos(void)
{
	return cursor_pos;	
}

#define INSERT(buf) \
	if (stacksize != 0 && visible[stacksize - 1])\
		add_buffer(buf); \

#define INSERT_CHARACTER(chr) \
	if (stacksize != 0 && visible[stacksize - 1]) { \
		gchar tmp[2]; \
		tmp[0] = (chr); \
		tmp[1] = '\0'; \
		add_buffer(tmp); \
	}

void quote_fmt_reset_vartable(void)
{
	if (var_table) {
		g_hash_table_destroy(var_table);
		var_table = NULL;
	}
	if (attachments) {
		GList *cur = attachments;
		while (cur) {
			g_free(cur->data);
			cur = g_list_next(cur);
		}
		g_list_free(attachments);
		attachments = NULL;
	}
}

#ifdef USE_ENCHANT
void quote_fmt_init(MsgInfo *info, const gchar *my_quote_str,
		    const gchar *my_body, gboolean my_dry_run,
			PrefsAccount *compose_account,
			gboolean string_is_escaped,
			GtkAspell *compose_gtkaspell)
#else
void quote_fmt_init(MsgInfo *info, const gchar *my_quote_str,
		    const gchar *my_body, gboolean my_dry_run,
			PrefsAccount *compose_account,
			gboolean string_is_escaped)
#endif
{
	quote_str = my_quote_str;
	body = my_body;
	msginfo = info;
	account = compose_account;
#ifdef USE_ENCHANT
	gchar *dict = gtkaspell_get_default_dictionary(compose_gtkaspell);
	if (dict)
		strncpy2(default_dictionary, dict, sizeof(default_dictionary));
	else
		*default_dictionary = '\0';
#endif
	dry_run = my_dry_run;
	stacksize = 0;
	add_visibility(TRUE);
	main_expr.bufmax = 0;
	sub_expr.bufmax = 0;
	current = &main_expr;
	clear_buffer();
	error = 0;
	line = 1;
	escaped_string = string_is_escaped;

	if (!var_table)
		var_table = g_hash_table_new_full(g_str_hash, g_str_equal, 
				g_free, g_free);

        /*
         * force LEX initialization
         */
	quote_fmt_firsttime = 1;
	cursor_pos = -1;
}

void quote_fmterror(char *str)
{
	g_warning("Error: %s at line %d\n", str, line);
	error = 1;
}

int quote_fmtwrap(void)
{
	return 1;
}

static int isseparator(int ch)
{
	return g_ascii_isspace(ch) || ch == '.' || ch == '-';
}

static void quote_fmt_show_date(const MsgInfo *msginfo, const gchar *format)
{
	char  result[100];
	char *rptr;
	char  zone[6];
	struct tm lt;
	const char *fptr;
	const char *zptr;

	if (!msginfo->date)
		return;
	
	/* 
	 * ALF - GNU C's strftime() has a nice format specifier 
	 * for time zone offset (%z). Non-standard however, so 
	 * emulate it.
	 */

#define RLEFT (sizeof result) - (rptr - result)	
#define STR_SIZE(x) (sizeof (x) - 1)

	zone[0] = 0;

	if (procheader_date_parse_to_tm(msginfo->date, &lt, zone)) {
		/*
		 * break up format string in tiny bits delimited by valid %z's and 
		 * feed it to strftime(). don't forget that '%%z' mean literal '%z'.
		 */
		for (rptr = result, fptr = format; fptr && *fptr && rptr < &result[sizeof result - 1];) {
			int	    perc;
			const char *p;
			char	   *tmp;
			
			if (NULL != (zptr = strstr(fptr, "%z"))) {
				/*
				 * count nr. of prepended percent chars
				 */
				for (perc = 0, p = zptr; p && p >= format && *p == '%'; p--, perc++)
					;
				/*
				 * feed to strftime()
				 */
				tmp = g_strndup(fptr, zptr - fptr + (perc % 2 ? 0 : STR_SIZE("%z")));
				if (tmp) {
					rptr += strftime(rptr, RLEFT, tmp, &lt);
					g_free(tmp);
				}
				/*
				 * append time zone offset
				 */
				if (zone[0] && perc % 2) 
					rptr += g_snprintf(rptr, RLEFT, "%s", zone);
				fptr = zptr + STR_SIZE("%z");
			} else {
				rptr += strftime(rptr, RLEFT, fptr, &lt);
				fptr  = NULL;
			}
		}
		
		if (g_utf8_validate(result, -1, NULL)) {
			INSERT(result);
		} else {
			gchar *utf = conv_codeset_strdup(result, 
				conv_get_locale_charset_str_no_utf8(),
				CS_INTERNAL);
			if (utf == NULL || 
			    !g_utf8_validate(utf, -1, NULL)) {
				g_free(utf);
				utf = g_malloc(strlen(result)*2+1);
				conv_localetodisp(utf, 
					strlen(result)*2+1, result);
			}
			if (g_utf8_validate(utf, -1, NULL)) {
				INSERT(utf);
			}
			g_free(utf);
		}
	}
#undef STR_SIZE			
#undef RLEFT			
}		

static void quote_fmt_show_first_name(const MsgInfo *msginfo)
{
	guchar *p;
	gchar *str;

	if (!msginfo->fromname)
		return;	
	
	p = (guchar*)strchr(msginfo->fromname, ',');
	if (p != NULL) {
		/* fromname is like "Duck, Donald" */
		p++;
		while (*p && isspace(*p)) p++;
		str = alloca(strlen((char *)p) + 1);
		if (str != NULL) {
			strcpy(str, (char *)p);
			INSERT(str);
		}
	} else {
		/* fromname is like "Donald Duck" */
		str = alloca(strlen(msginfo->fromname) + 1);
		if (str != NULL) {
			strcpy(str, msginfo->fromname);
			p = (guchar *)str;
			while (*p && !isspace(*p)) p++;
			*p = '\0';
			INSERT(str);
		}
	}
}

static void quote_fmt_show_last_name(const MsgInfo *msginfo)
{
	gchar *p;
	gchar *str;

	/* This probably won't work together very well with Middle
           names and the like - thth */
	if (!msginfo->fromname) 
		return;

	str = alloca(strlen(msginfo->fromname) + 1);
	if (str != NULL) {
		strcpy(str, msginfo->fromname);
		p = strchr(str, ',');
		if (p != NULL) {
			/* fromname is like "Duck, Donald" */
			*p = '\0';
			INSERT(str);
		} else {
			/* fromname is like "Donald Duck" */
			p = str;
			while (*p && !isspace(*p)) p++;
			if (*p) {
			    /* We found a space. Get first 
			     none-space char and insert
			     rest of string from there. */
			    while (*p && isspace(*p)) p++;
			    if (*p) {
				INSERT(p);
			    } else {
				/* If there is no none-space 
				 char, just insert whole 
				 fromname. */
				INSERT(str);
			    }
			} else {
			    /* If there is no space, just 
			     insert whole fromname. */
			    INSERT(str);
			}
		}
	}
}

static void quote_fmt_show_sender_initial(const MsgInfo *msginfo)
{
#define MAX_SENDER_INITIAL 20
	gchar tmp[MAX_SENDER_INITIAL];
	guchar *p;
	gchar *cur;
	gint len = 0;

	if (!msginfo->fromname) 
		return;

	p = (guchar *)msginfo->fromname;
	cur = tmp;
	while (*p) {
		if (*p && g_utf8_validate((gchar *)p, 1, NULL)) {
			*cur = toupper(*p);
				cur++;
			len++;
			if (len >= MAX_SENDER_INITIAL - 1)
				break;
		} else
			break;
		while (*p && !isseparator(*p)) p++;
		while (*p && isseparator(*p)) p++;
	}
	*cur = '\0';
	INSERT(tmp);
}

static void quote_fmt_show_msg(MsgInfo *msginfo, const gchar *body,
			       gboolean quoted, gboolean signature,
			       const gchar *quote_str)
{
	gchar buf[BUFFSIZE];
	FILE *fp;

	if (!(msginfo->folder || body))
		return;

	if (body)
		fp = str_open_as_stream(body);
	else {
		if (MSG_IS_ENCRYPTED(msginfo->flags))
			fp = procmime_get_first_encrypted_text_content(msginfo);
		else
			fp = procmime_get_first_text_content(msginfo);
	}

	if (fp == NULL)
		g_warning("Can't get text part\n");
	else {
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			strcrchomp(buf);
			
			if (!signature && strncmp(buf, "-- \n", 4) == 0)
				break;
		
			if (quoted && quote_str)
				INSERT(quote_str);
			
			INSERT(buf);
		}
		fclose(fp);
	}
}

static void quote_fmt_insert_file(const gchar *filename)
{
	FILE *file;
	char buffer[256];
	
	if ((file = g_fopen(filename, "rb")) != NULL) {
		while (fgets(buffer, sizeof(buffer), file)) {
			INSERT(buffer);
		}
		fclose(file);
	}

}

static void quote_fmt_insert_program_output(const gchar *progname)
{
	FILE *file;
	char buffer[256];

	if ((file = popen(progname, "r")) != NULL) {
		while (fgets(buffer, sizeof(buffer), file)) {
			INSERT(buffer);
		}
		pclose(file);
	}
}

static void quote_fmt_insert_user_input(const gchar *varname)
{
	gchar *buf = NULL;
	gchar *text = NULL;
	
	if (dry_run) 
		return;

	if ((text = g_hash_table_lookup(var_table, varname)) == NULL) {
		buf = g_strdup_printf(_("Enter text to replace '%s'"), varname);
		text = input_dialog(_("Enter variable"), buf, "");
		g_free(buf);
		if (!text)
			return;
		g_hash_table_insert(var_table, g_strdup(varname), g_strdup(text));
	} else {
		/* don't free the one in hashtable at the end */
		text = g_strdup(text);
	}

	if (!text)
		return;
	INSERT(text);
	g_free(text);
}

static void quote_fmt_attach_file(const gchar *filename)
{
	attachments = g_list_append(attachments, g_strdup(filename));
}

static gchar *quote_fmt_complete_address(const gchar *addr)
{
	gint count;
	gchar *res, *tmp, *email_addr;
	gchar **split;

	debug_print("quote_fmt_complete_address: %s\n", addr);
	if (addr == NULL)
		return NULL;

	/* if addr is a list of message, try the 1st element only */
	split = g_strsplit(addr, ",", -1);
	if (!split || !split[0] || *split[0] == '\0') {
		g_strfreev(split);
		return NULL;
	}

	Xstrdup_a(email_addr, split[0], return NULL);
	extract_address(email_addr);
	if (!*email_addr) {
		g_strfreev(split);
		return NULL;
	}

	res = NULL;
	start_address_completion(NULL);
	if (1 < (count = complete_address(email_addr))) {
		tmp = get_complete_address(1);
		res = procheader_get_fromname(tmp);
		g_free(tmp);
	}
	end_address_completion();
	g_strfreev(split);

	debug_print("quote_fmt_complete_address: matched %s\n", res);
	return res;
}


#line 617 "quote_fmt_parse.c" /* yacc.c:339  */

# ifndef YY_NULLPTR
#  if defined __cplusplus && 201103L <= __cplusplus
#   define YY_NULLPTR nullptr
#  else
#   define YY_NULLPTR 0
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* In a future release of Bison, this section will be replaced
   by #include "y.tab.h".  */
#ifndef YY_YY_QUOTE_FMT_PARSE_H_INCLUDED
# define YY_YY_QUOTE_FMT_PARSE_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    SHOW_NEWSGROUPS = 258,
    SHOW_DATE = 259,
    SHOW_FROM = 260,
    SHOW_FULLNAME = 261,
    SHOW_FIRST_NAME = 262,
    SHOW_LAST_NAME = 263,
    SHOW_SENDER_INITIAL = 264,
    SHOW_SUBJECT = 265,
    SHOW_TO = 266,
    SHOW_MESSAGEID = 267,
    SHOW_PERCENT = 268,
    SHOW_CC = 269,
    SHOW_REFERENCES = 270,
    SHOW_MESSAGE = 271,
    SHOW_QUOTED_MESSAGE = 272,
    SHOW_BACKSLASH = 273,
    SHOW_TAB = 274,
    SHOW_MAIL_ADDRESS = 275,
    SHOW_QUOTED_MESSAGE_NO_SIGNATURE = 276,
    SHOW_MESSAGE_NO_SIGNATURE = 277,
    SHOW_EOL = 278,
    SHOW_QUESTION_MARK = 279,
    SHOW_EXCLAMATION_MARK = 280,
    SHOW_PIPE = 281,
    SHOW_OPARENT = 282,
    SHOW_CPARENT = 283,
    SHOW_ACCOUNT_FULL_NAME = 284,
    SHOW_ACCOUNT_MAIL_ADDRESS = 285,
    SHOW_ACCOUNT_NAME = 286,
    SHOW_ACCOUNT_ORGANIZATION = 287,
    SHOW_ACCOUNT_DICT = 288,
    SHOW_ACCOUNT_SIG = 289,
    SHOW_ACCOUNT_SIGPATH = 290,
    SHOW_DICT = 291,
    SHOW_TAGS = 292,
    SHOW_ADDRESSBOOK_COMPLETION_FOR_CC = 293,
    SHOW_ADDRESSBOOK_COMPLETION_FOR_FROM = 294,
    SHOW_ADDRESSBOOK_COMPLETION_FOR_TO = 295,
    QUERY_DATE = 296,
    QUERY_FROM = 297,
    QUERY_FULLNAME = 298,
    QUERY_SUBJECT = 299,
    QUERY_TO = 300,
    QUERY_NEWSGROUPS = 301,
    QUERY_MESSAGEID = 302,
    QUERY_CC = 303,
    QUERY_REFERENCES = 304,
    QUERY_ACCOUNT_FULL_NAME = 305,
    QUERY_ACCOUNT_ORGANIZATION = 306,
    QUERY_ACCOUNT_DICT = 307,
    QUERY_ACCOUNT_SIG = 308,
    QUERY_ACCOUNT_SIGPATH = 309,
    QUERY_DICT = 310,
    QUERY_CC_FOUND_IN_ADDRESSBOOK = 311,
    QUERY_FROM_FOUND_IN_ADDRESSBOOK = 312,
    QUERY_TO_FOUND_IN_ADDRESSBOOK = 313,
    QUERY_NOT_DATE = 314,
    QUERY_NOT_FROM = 315,
    QUERY_NOT_FULLNAME = 316,
    QUERY_NOT_SUBJECT = 317,
    QUERY_NOT_TO = 318,
    QUERY_NOT_NEWSGROUPS = 319,
    QUERY_NOT_MESSAGEID = 320,
    QUERY_NOT_CC = 321,
    QUERY_NOT_REFERENCES = 322,
    QUERY_NOT_ACCOUNT_FULL_NAME = 323,
    QUERY_NOT_ACCOUNT_ORGANIZATION = 324,
    QUERY_NOT_ACCOUNT_DICT = 325,
    QUERY_NOT_ACCOUNT_SIG = 326,
    QUERY_NOT_ACCOUNT_SIGPATH = 327,
    QUERY_NOT_DICT = 328,
    QUERY_NOT_CC_FOUND_IN_ADDRESSBOOK = 329,
    QUERY_NOT_FROM_FOUND_IN_ADDRESSBOOK = 330,
    QUERY_NOT_TO_FOUND_IN_ADDRESSBOOK = 331,
    INSERT_FILE = 332,
    INSERT_PROGRAMOUTPUT = 333,
    INSERT_USERINPUT = 334,
    ATTACH_FILE = 335,
    OPARENT = 336,
    CPARENT = 337,
    CHARACTER = 338,
    SHOW_DATE_EXPR = 339,
    SET_CURSOR_POS = 340
  };
#endif
/* Tokens.  */
#define SHOW_NEWSGROUPS 258
#define SHOW_DATE 259
#define SHOW_FROM 260
#define SHOW_FULLNAME 261
#define SHOW_FIRST_NAME 262
#define SHOW_LAST_NAME 263
#define SHOW_SENDER_INITIAL 264
#define SHOW_SUBJECT 265
#define SHOW_TO 266
#define SHOW_MESSAGEID 267
#define SHOW_PERCENT 268
#define SHOW_CC 269
#define SHOW_REFERENCES 270
#define SHOW_MESSAGE 271
#define SHOW_QUOTED_MESSAGE 272
#define SHOW_BACKSLASH 273
#define SHOW_TAB 274
#define SHOW_MAIL_ADDRESS 275
#define SHOW_QUOTED_MESSAGE_NO_SIGNATURE 276
#define SHOW_MESSAGE_NO_SIGNATURE 277
#define SHOW_EOL 278
#define SHOW_QUESTION_MARK 279
#define SHOW_EXCLAMATION_MARK 280
#define SHOW_PIPE 281
#define SHOW_OPARENT 282
#define SHOW_CPARENT 283
#define SHOW_ACCOUNT_FULL_NAME 284
#define SHOW_ACCOUNT_MAIL_ADDRESS 285
#define SHOW_ACCOUNT_NAME 286
#define SHOW_ACCOUNT_ORGANIZATION 287
#define SHOW_ACCOUNT_DICT 288
#define SHOW_ACCOUNT_SIG 289
#define SHOW_ACCOUNT_SIGPATH 290
#define SHOW_DICT 291
#define SHOW_TAGS 292
#define SHOW_ADDRESSBOOK_COMPLETION_FOR_CC 293
#define SHOW_ADDRESSBOOK_COMPLETION_FOR_FROM 294
#define SHOW_ADDRESSBOOK_COMPLETION_FOR_TO 295
#define QUERY_DATE 296
#define QUERY_FROM 297
#define QUERY_FULLNAME 298
#define QUERY_SUBJECT 299
#define QUERY_TO 300
#define QUERY_NEWSGROUPS 301
#define QUERY_MESSAGEID 302
#define QUERY_CC 303
#define QUERY_REFERENCES 304
#define QUERY_ACCOUNT_FULL_NAME 305
#define QUERY_ACCOUNT_ORGANIZATION 306
#define QUERY_ACCOUNT_DICT 307
#define QUERY_ACCOUNT_SIG 308
#define QUERY_ACCOUNT_SIGPATH 309
#define QUERY_DICT 310
#define QUERY_CC_FOUND_IN_ADDRESSBOOK 311
#define QUERY_FROM_FOUND_IN_ADDRESSBOOK 312
#define QUERY_TO_FOUND_IN_ADDRESSBOOK 313
#define QUERY_NOT_DATE 314
#define QUERY_NOT_FROM 315
#define QUERY_NOT_FULLNAME 316
#define QUERY_NOT_SUBJECT 317
#define QUERY_NOT_TO 318
#define QUERY_NOT_NEWSGROUPS 319
#define QUERY_NOT_MESSAGEID 320
#define QUERY_NOT_CC 321
#define QUERY_NOT_REFERENCES 322
#define QUERY_NOT_ACCOUNT_FULL_NAME 323
#define QUERY_NOT_ACCOUNT_ORGANIZATION 324
#define QUERY_NOT_ACCOUNT_DICT 325
#define QUERY_NOT_ACCOUNT_SIG 326
#define QUERY_NOT_ACCOUNT_SIGPATH 327
#define QUERY_NOT_DICT 328
#define QUERY_NOT_CC_FOUND_IN_ADDRESSBOOK 329
#define QUERY_NOT_FROM_FOUND_IN_ADDRESSBOOK 330
#define QUERY_NOT_TO_FOUND_IN_ADDRESSBOOK 331
#define INSERT_FILE 332
#define INSERT_PROGRAMOUTPUT 333
#define INSERT_USERINPUT 334
#define ATTACH_FILE 335
#define OPARENT 336
#define CPARENT 337
#define CHARACTER 338
#define SHOW_DATE_EXPR 339
#define SET_CURSOR_POS 340

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE YYSTYPE;
union YYSTYPE
{
#line 571 "quote_fmt_parse.y" /* yacc.c:355  */

	char chr;
	char str[256];

#line 832 "quote_fmt_parse.c" /* yacc.c:355  */
};
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;

int yyparse (void);

#endif /* !YY_YY_QUOTE_FMT_PARSE_H_INCLUDED  */

/* Copy the second part of user declarations.  */

#line 847 "quote_fmt_parse.c" /* yacc.c:358  */

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

#ifndef YY_ATTRIBUTE
# if (defined __GNUC__                                               \
      && (2 < __GNUC__ || (__GNUC__ == 2 && 96 <= __GNUC_MINOR__)))  \
     || defined __SUNPRO_C && 0x5110 <= __SUNPRO_C
#  define YY_ATTRIBUTE(Spec) __attribute__(Spec)
# else
#  define YY_ATTRIBUTE(Spec) /* empty */
# endif
#endif

#ifndef YY_ATTRIBUTE_PURE
# define YY_ATTRIBUTE_PURE   YY_ATTRIBUTE ((__pure__))
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# define YY_ATTRIBUTE_UNUSED YY_ATTRIBUTE ((__unused__))
#endif

#if !defined _Noreturn \
     && (!defined __STDC_VERSION__ || __STDC_VERSION__ < 201112)
# if defined _MSC_VER && 1200 <= _MSC_VER
#  define _Noreturn __declspec (noreturn)
# else
#  define _Noreturn YY_ATTRIBUTE ((__noreturn__))
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")\
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif


#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYSIZE_T yynewbytes;                                            \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / sizeof (*yyptr);                          \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, (Count) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYSIZE_T yyi;                         \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  133
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   256

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  86
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  54
/* YYNRULES -- Number of rules.  */
#define YYNRULES  137
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  262

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   340

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, without out-of-bounds checking.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      85
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   627,   627,   630,   633,   634,   637,   638,   641,   642,
     643,   644,   645,   648,   649,   655,   659,   664,   678,   683,
     687,   692,   697,   706,   711,   715,   719,   723,   728,   733,
     738,   742,   747,   756,   760,   764,   768,   772,   777,   782,
     787,   792,   798,   803,   813,   819,   827,   831,   835,   839,
     843,   847,   851,   855,   859,   866,   874,   882,   893,   892,
     901,   900,   909,   908,   917,   916,   925,   924,   933,   932,
     941,   940,   949,   948,   957,   956,   972,   971,   980,   979,
     988,   987,   998,   997,  1007,  1006,  1020,  1019,  1032,  1031,
    1042,  1041,  1052,  1051,  1064,  1063,  1072,  1071,  1080,  1079,
    1088,  1087,  1096,  1095,  1104,  1103,  1112,  1111,  1120,  1119,
    1128,  1127,  1143,  1142,  1151,  1150,  1159,  1158,  1169,  1168,
    1178,  1177,  1191,  1190,  1203,  1202,  1213,  1212,  1223,  1222,
    1235,  1234,  1247,  1246,  1259,  1258,  1273,  1272
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "SHOW_NEWSGROUPS", "SHOW_DATE",
  "SHOW_FROM", "SHOW_FULLNAME", "SHOW_FIRST_NAME", "SHOW_LAST_NAME",
  "SHOW_SENDER_INITIAL", "SHOW_SUBJECT", "SHOW_TO", "SHOW_MESSAGEID",
  "SHOW_PERCENT", "SHOW_CC", "SHOW_REFERENCES", "SHOW_MESSAGE",
  "SHOW_QUOTED_MESSAGE", "SHOW_BACKSLASH", "SHOW_TAB", "SHOW_MAIL_ADDRESS",
  "SHOW_QUOTED_MESSAGE_NO_SIGNATURE", "SHOW_MESSAGE_NO_SIGNATURE",
  "SHOW_EOL", "SHOW_QUESTION_MARK", "SHOW_EXCLAMATION_MARK", "SHOW_PIPE",
  "SHOW_OPARENT", "SHOW_CPARENT", "SHOW_ACCOUNT_FULL_NAME",
  "SHOW_ACCOUNT_MAIL_ADDRESS", "SHOW_ACCOUNT_NAME",
  "SHOW_ACCOUNT_ORGANIZATION", "SHOW_ACCOUNT_DICT", "SHOW_ACCOUNT_SIG",
  "SHOW_ACCOUNT_SIGPATH", "SHOW_DICT", "SHOW_TAGS",
  "SHOW_ADDRESSBOOK_COMPLETION_FOR_CC",
  "SHOW_ADDRESSBOOK_COMPLETION_FOR_FROM",
  "SHOW_ADDRESSBOOK_COMPLETION_FOR_TO", "QUERY_DATE", "QUERY_FROM",
  "QUERY_FULLNAME", "QUERY_SUBJECT", "QUERY_TO", "QUERY_NEWSGROUPS",
  "QUERY_MESSAGEID", "QUERY_CC", "QUERY_REFERENCES",
  "QUERY_ACCOUNT_FULL_NAME", "QUERY_ACCOUNT_ORGANIZATION",
  "QUERY_ACCOUNT_DICT", "QUERY_ACCOUNT_SIG", "QUERY_ACCOUNT_SIGPATH",
  "QUERY_DICT", "QUERY_CC_FOUND_IN_ADDRESSBOOK",
  "QUERY_FROM_FOUND_IN_ADDRESSBOOK", "QUERY_TO_FOUND_IN_ADDRESSBOOK",
  "QUERY_NOT_DATE", "QUERY_NOT_FROM", "QUERY_NOT_FULLNAME",
  "QUERY_NOT_SUBJECT", "QUERY_NOT_TO", "QUERY_NOT_NEWSGROUPS",
  "QUERY_NOT_MESSAGEID", "QUERY_NOT_CC", "QUERY_NOT_REFERENCES",
  "QUERY_NOT_ACCOUNT_FULL_NAME", "QUERY_NOT_ACCOUNT_ORGANIZATION",
  "QUERY_NOT_ACCOUNT_DICT", "QUERY_NOT_ACCOUNT_SIG",
  "QUERY_NOT_ACCOUNT_SIGPATH", "QUERY_NOT_DICT",
  "QUERY_NOT_CC_FOUND_IN_ADDRESSBOOK",
  "QUERY_NOT_FROM_FOUND_IN_ADDRESSBOOK",
  "QUERY_NOT_TO_FOUND_IN_ADDRESSBOOK", "INSERT_FILE",
  "INSERT_PROGRAMOUTPUT", "INSERT_USERINPUT", "ATTACH_FILE", "OPARENT",
  "CPARENT", "CHARACTER", "SHOW_DATE_EXPR", "SET_CURSOR_POS", "$accept",
  "quote_fmt", "sub_expr", "character_or_special_or_insert_or_query_list",
  "character_or_special_list", "character_or_special_or_insert_or_query",
  "character_or_special", "character", "string", "special", "query", "$@1",
  "$@2", "$@3", "$@4", "$@5", "$@6", "$@7", "$@8", "$@9", "$@10", "$@11",
  "$@12", "$@13", "$@14", "$@15", "$@16", "$@17", "$@18", "query_not",
  "$@19", "$@20", "$@21", "$@22", "$@23", "$@24", "$@25", "$@26", "$@27",
  "$@28", "$@29", "$@30", "$@31", "$@32", "$@33", "$@34", "$@35", "$@36",
  "insert", "$@37", "$@38", "$@39", "attach", "$@40", YY_NULLPTR
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   327,   328,   329,   330,   331,   332,   333,   334,
     335,   336,   337,   338,   339,   340
};
# endif

#define YYPACT_NINF -50

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-50)))

#define YYTABLE_NINF -1

#define yytable_value_is_error(Yytable_value) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
      -3,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
      40,   -50,   162,   -50,    -3,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,    89,    90,    91,    92,    93,    94,    95,    96,
      97,    98,    99,   100,   101,   102,   103,   104,   105,   106,
     107,   108,   109,   110,   111,   112,   113,   114,   115,   116,
     117,   118,   119,   120,   121,   122,   123,   124,   125,   126,
     127,   128,   129,   -50,   -50,    -3,    -3,    -3,    -3,    -3,
      -3,    -3,    -3,    -3,    -3,    -3,    -3,    -3,    -3,    -3,
      -3,    -3,    -3,    -3,    -3,    -3,    -3,    -3,    -3,    -3,
      -3,    -3,    -3,    -3,    -3,    -3,    -3,    -3,    -3,    -3,
      -3,    80,    80,    80,    80,   -50,    -4,   131,   132,   133,
     134,   135,   136,   137,   138,   139,   140,   141,   142,   143,
     144,   145,   146,   147,   148,   149,   150,   151,   152,   153,
     154,   155,   156,   157,   158,   159,   160,   161,   163,   164,
     165,   166,   167,   168,   -50,    80,   169,   170,   171,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       0,    18,    20,    21,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    46,    47,    22,    36,
      35,    48,    49,    50,    51,    52,    53,    37,    38,    39,
      40,    43,    41,    42,    44,    45,    55,    56,    57,    58,
      60,    62,    64,    66,    68,    70,    72,    74,    76,    78,
      84,    80,    82,    86,    88,    90,    92,    94,    96,    98,
     100,   102,   104,   106,   108,   110,   112,   114,   120,   116,
     118,   122,   124,   126,   128,   130,   132,   134,   136,    15,
       0,    54,     0,     2,     5,     8,    14,    13,     9,    10,
      11,    12,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     1,     4,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    16,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     3,     7,     0,     0,     0,    19,
      17,    59,    61,    63,    65,    67,    69,    71,    73,    75,
      77,    79,    85,    81,    83,    87,    89,    91,    93,    95,
      97,    99,   101,   103,   105,   107,   109,   111,   113,   115,
     121,   117,   119,   123,   125,   127,   129,   131,     6,   133,
     135,   137
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
     -50,    -9,    -5,   172,    29,   -50,   -49,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,    82,   213,    83,   214,    84,    85,    86,   176,    87,
      88,    92,    93,    94,    95,    96,    97,    98,    99,   100,
     101,   102,   104,   105,   103,   106,   107,   108,   109,    89,
     110,   111,   112,   113,   114,   115,   116,   117,   118,   119,
     120,   122,   123,   121,   124,   125,   126,   127,    90,   128,
     129,   130,    91,   131
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_uint16 yytable[] =
{
       1,     2,     3,     4,     5,     6,     7,     8,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39,    40,
      41,    42,    43,    44,    45,    46,    47,    48,    49,    50,
      51,    52,    53,    54,    55,    56,    57,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    67,    68,    69,    70,
      71,    72,    73,    74,    75,    76,    77,    78,   219,   220,
      79,    80,    81,     1,     2,     3,     4,     5,     6,     7,
       8,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,   132,   215,   215,   215,   215,   177,   178,   179,   180,
     181,   182,   183,   184,   185,   186,   187,   188,   189,   190,
     191,   192,   193,   194,   195,   196,   197,   198,   199,   200,
     201,   202,   203,   204,   205,   206,   207,   208,   209,   210,
     211,   212,   133,    79,    80,    81,   215,   216,   217,   218,
     135,   136,   137,   138,   139,   140,   141,   142,   143,   144,
     145,   146,   147,   148,   149,   150,   151,   152,   153,   154,
     155,   156,   157,   158,   159,   160,   161,   162,   163,   164,
     165,   166,   167,   168,   169,   170,   171,   172,   173,   174,
       0,     0,   175,   221,   222,   223,   224,   225,   226,   227,
     228,   229,   230,   231,   232,   233,   234,   235,   236,   237,
     238,   239,   240,   241,   242,   243,   244,   245,   246,   247,
     248,   249,   250,   251,   258,   252,   253,   254,   255,   256,
     257,   259,   260,   261,     0,     0,   134
};

static const yytype_int16 yycheck[] =
{
       3,     4,     5,     6,     7,     8,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,    40,    41,    42,
      43,    44,    45,    46,    47,    48,    49,    50,    51,    52,
      53,    54,    55,    56,    57,    58,    59,    60,    61,    62,
      63,    64,    65,    66,    67,    68,    69,    70,    71,    72,
      73,    74,    75,    76,    77,    78,    79,    80,    82,    83,
      83,    84,    85,     3,     4,     5,     6,     7,     8,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,    81,   171,   172,   173,   174,   135,   136,   137,   138,
     139,   140,   141,   142,   143,   144,   145,   146,   147,   148,
     149,   150,   151,   152,   153,   154,   155,   156,   157,   158,
     159,   160,   161,   162,   163,   164,   165,   166,   167,   168,
     169,   170,     0,    83,    84,    85,   215,   172,   173,   174,
      81,    81,    81,    81,    81,    81,    81,    81,    81,    81,
      81,    81,    81,    81,    81,    81,    81,    81,    81,    81,
      81,    81,    81,    81,    81,    81,    81,    81,    81,    81,
      81,    81,    81,    81,    81,    81,    81,    81,    81,    81,
      -1,    -1,    83,    82,    82,    82,    82,    82,    82,    82,
      82,    82,    82,    82,    82,    82,    82,    82,    82,    82,
      82,    82,    82,    82,    82,    82,    82,    82,    82,    82,
      82,    82,    82,    82,   215,    82,    82,    82,    82,    82,
      82,    82,    82,    82,    -1,    -1,    84
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,     3,     4,     5,     6,     7,     8,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      42,    43,    44,    45,    46,    47,    48,    49,    50,    51,
      52,    53,    54,    55,    56,    57,    58,    59,    60,    61,
      62,    63,    64,    65,    66,    67,    68,    69,    70,    71,
      72,    73,    74,    75,    76,    77,    78,    79,    80,    83,
      84,    85,    87,    89,    91,    92,    93,    95,    96,   115,
     134,   138,    97,    98,    99,   100,   101,   102,   103,   104,
     105,   106,   107,   110,   108,   109,   111,   112,   113,   114,
     116,   117,   118,   119,   120,   121,   122,   123,   124,   125,
     126,   129,   127,   128,   130,   131,   132,   133,   135,   136,
     137,   139,    81,     0,    89,    81,    81,    81,    81,    81,
      81,    81,    81,    81,    81,    81,    81,    81,    81,    81,
      81,    81,    81,    81,    81,    81,    81,    81,    81,    81,
      81,    81,    81,    81,    81,    81,    81,    81,    81,    81,
      81,    81,    81,    81,    81,    83,    94,    87,    87,    87,
      87,    87,    87,    87,    87,    87,    87,    87,    87,    87,
      87,    87,    87,    87,    87,    87,    87,    87,    87,    87,
      87,    87,    87,    87,    87,    87,    87,    87,    87,    87,
      87,    87,    87,    88,    90,    92,    88,    88,    88,    82,
      83,    82,    82,    82,    82,    82,    82,    82,    82,    82,
      82,    82,    82,    82,    82,    82,    82,    82,    82,    82,
      82,    82,    82,    82,    82,    82,    82,    82,    82,    82,
      82,    82,    82,    82,    82,    82,    82,    82,    90,    82,
      82,    82
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    86,    87,    88,    89,    89,    90,    90,    91,    91,
      91,    91,    91,    92,    92,    93,    94,    94,    95,    95,
      95,    95,    95,    95,    95,    95,    95,    95,    95,    95,
      95,    95,    95,    95,    95,    95,    95,    95,    95,    95,
      95,    95,    95,    95,    95,    95,    95,    95,    95,    95,
      95,    95,    95,    95,    95,    95,    95,    95,    97,    96,
      98,    96,    99,    96,   100,    96,   101,    96,   102,    96,
     103,    96,   104,    96,   105,    96,   106,    96,   107,    96,
     108,    96,   109,    96,   110,    96,   111,    96,   112,    96,
     113,    96,   114,    96,   116,   115,   117,   115,   118,   115,
     119,   115,   120,   115,   121,   115,   122,   115,   123,   115,
     124,   115,   125,   115,   126,   115,   127,   115,   128,   115,
     129,   115,   130,   115,   131,   115,   132,   115,   133,   115,
     135,   134,   136,   134,   137,   134,   139,   138
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     1,     1,     2,     1,     2,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     2,     1,     4,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     0,     5,
       0,     5,     0,     5,     0,     5,     0,     5,     0,     5,
       0,     5,     0,     5,     0,     5,     0,     5,     0,     5,
       0,     5,     0,     5,     0,     5,     0,     5,     0,     5,
       0,     5,     0,     5,     0,     5,     0,     5,     0,     5,
       0,     5,     0,     5,     0,     5,     0,     5,     0,     5,
       0,     5,     0,     5,     0,     5,     0,     5,     0,     5,
       0,     5,     0,     5,     0,     5,     0,     5,     0,     5,
       0,     5,     0,     5,     0,     5,     0,     5
};


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                  \
do                                                              \
  if (yychar == YYEMPTY)                                        \
    {                                                           \
      yychar = (Token);                                         \
      yylval = (Value);                                         \
      YYPOPSTACK (yylen);                                       \
      yystate = *yyssp;                                         \
      goto yybackup;                                            \
    }                                                           \
  else                                                          \
    {                                                           \
      yyerror (YY_("syntax error: cannot back up")); \
      YYERROR;                                                  \
    }                                                           \
while (0)

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256



/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)

/* This macro is provided for backward compatibility. */
#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*----------------------------------------.
| Print this symbol's value on YYOUTPUT.  |
`----------------------------------------*/

static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
{
  FILE *yyo = yyoutput;
  YYUSE (yyo);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
  YYUSE (yytype);
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyoutput, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yytype_int16 *yyssp, YYSTYPE *yyvsp, int yyrule)
{
  unsigned long int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       yystos[yyssp[yyi + 1 - yynrhs]],
                       &(yyvsp[(yyi + 1) - (yynrhs)])
                                              );
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
yystrlen (const char *yystr)
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            /* Fall through.  */
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
  int yycount = 0;

  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYSIZE_T yysize1 = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (! (yysize <= yysize1
                         && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                    return 2;
                  yysize = yysize1;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    YYSIZE_T yysize1 = yysize + yystrlen (yyformat);
    if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
      return 2;
    yysize = yysize1;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
{
  YYUSE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}




/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Number of syntax errors so far.  */
int yynerrs;


/*----------.
| yyparse.  |
`----------*/

int
yyparse (void)
{
    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */
  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        YYSTYPE *yyvs1 = yyvs;
        yytype_int16 *yyss1 = yyss;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * sizeof (*yyssp),
                    &yyvs1, yysize * sizeof (*yyvsp),
                    &yystacksize);

        yyss = yyss1;
        yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yytype_int16 *yyss1 = yyss;
        union yyalloc *yyptr =
          (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
                  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 14:
#line 650 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		INSERT_CHARACTER((yyvsp[0].chr));
	}
#line 2145 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 16:
#line 660 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		(yyval.str)[0] = (yyvsp[0].chr);
		(yyval.str)[1] = '\0';
	}
#line 2154 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 17:
#line 665 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		size_t len;
		
		strncpy((yyval.str), (yyvsp[-1].str), sizeof((yyval.str)));
		(yyval.str)[sizeof((yyval.str)) - 1] = '\0';
		len = strlen((yyval.str));
		if (len + 1 < sizeof((yyval.str))) {
			(yyval.str)[len + 1] = '\0';
			(yyval.str)[len] = (yyvsp[0].chr);
		}
	}
#line 2170 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 18:
#line 679 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		if (msginfo->newsgroups)
			INSERT(msginfo->newsgroups);
	}
#line 2179 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 19:
#line 684 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		quote_fmt_show_date(msginfo, (yyvsp[-1].str));
	}
#line 2187 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 20:
#line 688 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		if (msginfo->date)
			INSERT(msginfo->date);
	}
#line 2196 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 21:
#line 693 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		if (msginfo->from)
			INSERT(msginfo->from);
	}
#line 2205 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 22:
#line 698 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		if (msginfo->from) {
			gchar *stripped_address = g_strdup(msginfo->from);
			extract_address(stripped_address);
			INSERT(stripped_address);
			g_free(stripped_address);
		}
	}
#line 2218 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 23:
#line 707 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		if (msginfo->fromname)
			INSERT(msginfo->fromname);
	}
#line 2227 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 24:
#line 712 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		quote_fmt_show_first_name(msginfo);
	}
#line 2235 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 25:
#line 716 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		quote_fmt_show_last_name(msginfo);
	}
#line 2243 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 26:
#line 720 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		quote_fmt_show_sender_initial(msginfo);
	}
#line 2251 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 27:
#line 724 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		if (msginfo->subject)
			INSERT(msginfo->subject);
	}
#line 2260 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 28:
#line 729 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		if (msginfo->to)
			INSERT(msginfo->to);
	}
#line 2269 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 29:
#line 734 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		if (msginfo->msgid)
			INSERT(msginfo->msgid);
	}
#line 2278 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 30:
#line 739 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		INSERT("%");
	}
#line 2286 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 31:
#line 743 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		if (msginfo->cc)
			INSERT(msginfo->cc);
	}
#line 2295 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 32:
#line 748 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		GSList *item;

		INSERT(msginfo->inreplyto);
		for (item = msginfo->references; item != NULL; item = g_slist_next(item))
			if (item->data)
				INSERT(item->data);
	}
#line 2308 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 33:
#line 757 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		quote_fmt_show_msg(msginfo, body, FALSE, TRUE, quote_str);
	}
#line 2316 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 34:
#line 761 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		quote_fmt_show_msg(msginfo, body, TRUE, TRUE, quote_str);
	}
#line 2324 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 35:
#line 765 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		quote_fmt_show_msg(msginfo, body, FALSE, FALSE, quote_str);
	}
#line 2332 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 36:
#line 769 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		quote_fmt_show_msg(msginfo, body, TRUE, FALSE, quote_str);
	}
#line 2340 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 37:
#line 773 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		if (account && account->name)
			INSERT(account->name);
	}
#line 2349 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 38:
#line 778 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		if (account && account->address)
			INSERT(account->address);
	}
#line 2358 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 39:
#line 783 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		if (account && account->account_name)
			INSERT(account->account_name);
	}
#line 2367 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 40:
#line 788 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		if (account && account->organization)
			INSERT(account->organization);
	}
#line 2376 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 41:
#line 793 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		gchar *str = account_get_signature_str(account);
		INSERT(str);
		g_free(str);
	}
#line 2386 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 42:
#line 799 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		if (account && account->sig_path)
			INSERT(account->sig_path);
	}
#line 2395 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 43:
#line 804 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
#ifdef USE_ENCHANT
		if (account && account->enable_default_dictionary) {
			gchar *dictname = g_path_get_basename(account->default_dictionary);
			INSERT(dictname);
			g_free(dictname);
		}
#endif
	}
#line 2409 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 44:
#line 814 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
#ifdef USE_ENCHANT
		INSERT(default_dictionary);
#endif
	}
#line 2419 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 45:
#line 820 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		gchar *tags = procmsg_msginfo_get_tags_str(msginfo);
		if (tags) {
			INSERT(tags);
		}
		g_free(tags);
	}
#line 2431 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 46:
#line 828 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		INSERT("\\");
	}
#line 2439 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 47:
#line 832 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		INSERT("\t");
	}
#line 2447 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 48:
#line 836 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		INSERT("\n");
	}
#line 2455 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 49:
#line 840 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		INSERT("?");
	}
#line 2463 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 50:
#line 844 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		INSERT("!");
	}
#line 2471 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 51:
#line 848 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		INSERT("|");
	}
#line 2479 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 52:
#line 852 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		INSERT("{");
	}
#line 2487 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 53:
#line 856 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		INSERT("}");
	}
#line 2495 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 54:
#line 860 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		if (current->buffer)
			cursor_pos = g_utf8_strlen(current->buffer, -1);
		else
			cursor_pos = 0;
	}
#line 2506 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 55:
#line 867 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		gchar *tmp = quote_fmt_complete_address(msginfo->cc);
		if (tmp) {
			INSERT(tmp);
			g_free(tmp);
		}
	}
#line 2518 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 56:
#line 875 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		gchar *tmp = quote_fmt_complete_address(msginfo->from);
		if (tmp) {
			INSERT(tmp);
			g_free(tmp);
		}
	}
#line 2530 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 57:
#line 883 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		gchar *tmp = quote_fmt_complete_address(msginfo->to);
		if (tmp) {
			INSERT(tmp);
			g_free(tmp);
		}
	}
#line 2542 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 58:
#line 893 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		add_visibility(msginfo->date != NULL);
	}
#line 2550 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 59:
#line 897 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2558 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 60:
#line 901 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		add_visibility(msginfo->from != NULL);
	}
#line 2566 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 61:
#line 905 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2574 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 62:
#line 909 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		add_visibility(msginfo->fromname != NULL);
	}
#line 2582 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 63:
#line 913 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2590 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 64:
#line 917 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		add_visibility(msginfo->subject != NULL);
	}
#line 2598 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 65:
#line 921 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2606 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 66:
#line 925 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		add_visibility(msginfo->to != NULL);
	}
#line 2614 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 67:
#line 929 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2622 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 68:
#line 933 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		add_visibility(msginfo->newsgroups != NULL);
	}
#line 2630 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 69:
#line 937 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2638 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 70:
#line 941 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		add_visibility(msginfo->msgid != NULL);
	}
#line 2646 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 71:
#line 945 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2654 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 72:
#line 949 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		add_visibility(msginfo->cc != NULL);
	}
#line 2662 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 73:
#line 953 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2670 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 74:
#line 957 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		gboolean found;
		GSList *item;

		found = (msginfo->inreplyto != NULL);
		for (item = msginfo->references; found == FALSE && item != NULL; item = g_slist_next(item))
			if (item->data)
				found = TRUE;
		add_visibility(found == TRUE);
	}
#line 2685 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 75:
#line 968 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2693 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 76:
#line 972 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		add_visibility(account != NULL && account->name != NULL);
	}
#line 2701 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 77:
#line 976 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2709 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 78:
#line 980 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		add_visibility(account != NULL && account->organization != NULL);
	}
#line 2717 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 79:
#line 984 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2725 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 80:
#line 988 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		gchar *str = account_get_signature_str(account);
		add_visibility(str != NULL && * str != '\0');
		g_free(str);
	}
#line 2735 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 81:
#line 994 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2743 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 82:
#line 998 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		add_visibility(account != NULL && account->sig_path != NULL
				&& *account->sig_path != '\0');
	}
#line 2752 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 83:
#line 1003 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2760 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 84:
#line 1007 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
#ifdef USE_ENCHANT
		add_visibility(account != NULL && account->enable_default_dictionary == TRUE &&
				account->default_dictionary != NULL && *account->default_dictionary != '\0');
#else
		add_visibility(FALSE);
#endif
	}
#line 2773 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 85:
#line 1016 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2781 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 86:
#line 1020 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
#ifdef USE_ENCHANT
		add_visibility(*default_dictionary != '\0');
#else
		add_visibility(FALSE);
#endif
	}
#line 2793 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 87:
#line 1028 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2801 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 88:
#line 1032 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		gchar *tmp = quote_fmt_complete_address(msginfo->cc);
		add_visibility(tmp != NULL && *tmp != '\0');
		g_free(tmp);
	}
#line 2811 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 89:
#line 1038 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2819 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 90:
#line 1042 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		gchar *tmp = quote_fmt_complete_address(msginfo->from);
		add_visibility(tmp != NULL && *tmp != '\0');
		g_free(tmp);
	}
#line 2829 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 91:
#line 1048 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2837 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 92:
#line 1052 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		gchar *tmp = quote_fmt_complete_address(msginfo->to);
		add_visibility(tmp != NULL && *tmp != '\0');
		g_free(tmp);
	}
#line 2847 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 93:
#line 1058 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2855 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 94:
#line 1064 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		add_visibility(msginfo->date == NULL);
	}
#line 2863 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 95:
#line 1068 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2871 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 96:
#line 1072 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		add_visibility(msginfo->from == NULL);
	}
#line 2879 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 97:
#line 1076 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2887 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 98:
#line 1080 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		add_visibility(msginfo->fromname == NULL);
	}
#line 2895 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 99:
#line 1084 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2903 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 100:
#line 1088 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		add_visibility(msginfo->subject == NULL);
	}
#line 2911 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 101:
#line 1092 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2919 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 102:
#line 1096 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		add_visibility(msginfo->to == NULL);
	}
#line 2927 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 103:
#line 1100 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2935 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 104:
#line 1104 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		add_visibility(msginfo->newsgroups == NULL);
	}
#line 2943 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 105:
#line 1108 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2951 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 106:
#line 1112 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		add_visibility(msginfo->msgid == NULL);
	}
#line 2959 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 107:
#line 1116 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2967 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 108:
#line 1120 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		add_visibility(msginfo->cc == NULL);
	}
#line 2975 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 109:
#line 1124 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 2983 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 110:
#line 1128 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		gboolean found;
		GSList *item;

		found = (msginfo->inreplyto != NULL);
		for (item = msginfo->references; found == FALSE && item != NULL; item = g_slist_next(item))
			if (item->data)
				found = TRUE;
		add_visibility(found == FALSE);
	}
#line 2998 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 111:
#line 1139 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 3006 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 112:
#line 1143 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		add_visibility(account == NULL || account->name == NULL);
	}
#line 3014 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 113:
#line 1147 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 3022 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 114:
#line 1151 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		add_visibility(account == NULL || account->organization == NULL);
	}
#line 3030 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 115:
#line 1155 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 3038 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 116:
#line 1159 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		gchar *str = account_get_signature_str(account);
		add_visibility(str == NULL || *str == '\0');
		g_free(str);
	}
#line 3048 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 117:
#line 1165 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 3056 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 118:
#line 1169 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		add_visibility(account == NULL || account->sig_path == NULL
				|| *account->sig_path == '\0');
	}
#line 3065 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 119:
#line 1174 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 3073 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 120:
#line 1178 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
#ifdef USE_ENCHANT
		add_visibility(account == NULL || account->enable_default_dictionary == FALSE
				|| *account->default_dictionary == '\0');
#else
		add_visibility(FALSE);
#endif
	}
#line 3086 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 121:
#line 1187 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 3094 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 122:
#line 1191 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
#ifdef USE_ENCHANT
		add_visibility(*default_dictionary == '\0');
#else
		add_visibility(FALSE);
#endif
	}
#line 3106 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 123:
#line 1199 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 3114 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 124:
#line 1203 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		gchar *tmp = quote_fmt_complete_address(msginfo->cc);
		add_visibility(tmp == NULL || *tmp == '\0');
		g_free(tmp);
	}
#line 3124 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 125:
#line 1209 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 3132 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 126:
#line 1213 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		gchar *tmp = quote_fmt_complete_address(msginfo->from);
		add_visibility(tmp == NULL || *tmp == '\0');
		g_free(tmp);
	}
#line 3142 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 127:
#line 1219 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 3150 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 128:
#line 1223 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		gchar *tmp = quote_fmt_complete_address(msginfo->to);
		add_visibility(tmp == NULL || *tmp == '\0');
		g_free(tmp);
	}
#line 3160 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 129:
#line 1229 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		remove_visibility();
	}
#line 3168 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 130:
#line 1235 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		current = &sub_expr;
		clear_buffer();
	}
#line 3177 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 131:
#line 1240 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		current = &main_expr;
		if (!dry_run) {
			quote_fmt_insert_file(sub_expr.buffer);
		}
	}
#line 3188 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 132:
#line 1247 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		current = &sub_expr;
		clear_buffer();
	}
#line 3197 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 133:
#line 1252 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		current = &main_expr;
		if (!dry_run) {
			quote_fmt_insert_program_output(sub_expr.buffer);
		}
	}
#line 3208 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 134:
#line 1259 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		current = &sub_expr;
		clear_buffer();
	}
#line 3217 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 135:
#line 1264 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		current = &main_expr;
		if (!dry_run) {
			quote_fmt_insert_user_input(sub_expr.buffer);
		}
	}
#line 3228 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 136:
#line 1273 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		current = &sub_expr;
		clear_buffer();
	}
#line 3237 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;

  case 137:
#line 1278 "quote_fmt_parse.y" /* yacc.c:1646  */
    {
		current = &main_expr;
		if (!dry_run) {
			quote_fmt_attach_file(sub_expr.buffer);
		}
	}
#line 3248 "quote_fmt_parse.c" /* yacc.c:1646  */
    break;


#line 3252 "quote_fmt_parse.c" /* yacc.c:1646  */
      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYTERROR;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  yystos[yystate], yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  yystos[*yyssp], yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  return yyresult;
}
