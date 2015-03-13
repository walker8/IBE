/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Configuration directory */
#define CFG_RC_DIR ".claws-mail"

/* client id */
/* #undef CM_GDATA_CLIENT_ID */

/* Pop up crash dialog */
/* #undef CRASH_DIALOG */

/* Define to one of `_getb67', `GETB67', `getb67' for Cray-2 and Cray-YMP
   systems. This function is required for `alloca.c' support on those systems.
   */
/* #undef CRAY_STACKSEG_END */

/* Define to 1 if using `alloca.c'. */
/* #undef C_ALLOCA */

/* Define to 1 if translation of program messages to the user's native
   language is requested. */
#define ENABLE_NLS 1

/* Enable Python support */
/* #undef ENABLE_PYTHON */

/* Generic UMPC code */
/* #undef GENERIC_UMPC */

/* Define text domain. */
#define GETTEXT_PACKAGE "claws-mail"

/* Define to 1 if you have `alloca', as a function or macro. */
#define HAVE_ALLOCA 1

/* Define to 1 if you have <alloca.h> and it should be used (not on Ultrix).
   */
#define HAVE_ALLOCA_H 1

/* Define if you need to work around apache regex/fnmatch !KLUDGE! */
/* #undef HAVE_APACHE_FNMATCH */

/* Has backtrace*() needed for retrieving stack traces */
#define HAVE_BACKTRACE 1

/* Define to 1 if you have the `bind_textdomain_codeset' function. */
#define HAVE_BIND_TEXTDOMAIN_CODESET 1

/* Define to 1 if you have the Mac OS X function CFLocaleCopyCurrent in the
   CoreFoundation framework. */
/* #undef HAVE_CFLOCALECOPYCURRENT */

/* Define to 1 if you have the Mac OS X function CFPreferencesCopyAppValue in
   the CoreFoundation framework. */
/* #undef HAVE_CFPREFERENCESCOPYAPPVALUE */

/* Define if glib bindings of D-Bus are available */
/* #undef HAVE_DBUS_GLIB */

/* Define if the GNU dcgettext() function is already present or preinstalled.
   */
#define HAVE_DCGETTEXT 1

/* Define to 1 if you have the <direct.h> header file. */
/* #undef HAVE_DIRECT_H */

/* Define if `struct dirent' has `d_type' member. */
#define HAVE_DIRENT_D_TYPE 1

/* Define to 1 if you have the <dirent.h> header file, and it defines `DIR'.
   */
#define HAVE_DIRENT_H 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define if expat is available */
#define HAVE_EXPAT 1

/* HAVE_EX__MAX */
#define HAVE_EX__MAX 1

/* Define to 1 if you have the `fchmod' function. */
#define HAVE_FCHMOD 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the `fgets_unlocked' function. */
#define HAVE_FGETS_UNLOCKED 1

/* Define to 1 if you have the `flock' function. */
#define HAVE_FLOCK 1

/* Define to 1 if you have the `fwrite_unlocked' function. */
#define HAVE_FWRITE_UNLOCKED 1

/* at least version 0.9 of libgdata is available */
/* #undef HAVE_GDATA_VERSION_0_9 */

/* at least version 0.9.1 of libgdata is available */
/* #undef HAVE_GDATA_VERSION_0_9_1 */

/* Define to 1 if you have the `gethostname' function. */
#define HAVE_GETHOSTNAME 1

/* Define if the GNU gettext() function is already present or preinstalled. */
#define HAVE_GETTEXT 1

/* Define to 1 if you have the `getuid' function. */
#define HAVE_GETUID 1

/* Define if GPGME supports PKA. */
#define HAVE_GPGME_PKA_TRUST 1

/* HAVE_H_ERRNO */
#define HAVE_H_ERRNO 1

/* Define if you have the iconv() function and it works. */
#define HAVE_ICONV 1

/* HAVE_INADDR_NONE */
#define HAVE_INADDR_NONE 1

/* Define to 1 if you have the `inet_addr' function. */
#define HAVE_INET_ADDR 1

/* Define to 1 if you have the `inet_aton' function. */
#define HAVE_INET_ATON 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <lber.h> header file. */
#define HAVE_LBER_H 1

/* Define to 1 if you have the <ldap.h> header file. */
#define HAVE_LDAP_H 1

/* Define if libcanberra-gtk support is enabled */
/* #undef HAVE_LIBCANBERRA_GTK */

/* Define if you want compface support. */
/* #undef HAVE_LIBCOMPFACE */

/* Define if you want IMAP and/or NNTP support. */
#define HAVE_LIBETPAN 1

/* Define if libnotify support is enabled */
/* #undef HAVE_LIBNOTIFY */

/* Check for libperl. */
/* #undef HAVE_LIBPERL */

/* Define to 1 if you have the <libpisock/pi-address.h> header file. */
/* #undef HAVE_LIBPISOCK_PI_ADDRESS_H */

/* Define to 1 if you have the <libpisock/pi-appinfo.h> header file. */
/* #undef HAVE_LIBPISOCK_PI_APPINFO_H */

/* Define to 1 if you have the <libpisock/pi-args.h> header file. */
/* #undef HAVE_LIBPISOCK_PI_ARGS_H */

/* Define to 1 if you have the <libpisock/pi-version.h> header file. */
/* #undef HAVE_LIBPISOCK_PI_VERSION_H */

/* Define to 1 if you have libSM installed */
#define HAVE_LIBSM 1

/* Define if libsoup is available */
/* #undef HAVE_LIBSOUP */

/* Define if libsoup_gnome is available */
/* #undef HAVE_LIBSOUP_GNOME */

/* Define to 1 if you have the `xpg4' library (-lxpg4). */
/* #undef HAVE_LIBXPG4 */

/* Define to 1 if you have the <locale.h> header file. */
#define HAVE_LOCALE_H 1

/* Define to 1 if you have the `lockf' function. */
#define HAVE_LOCKF 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `mkdir' function. */
#define HAVE_MKDIR 1

/* Define to 1 if you have the `mkstemp' function. */
#define HAVE_MKSTEMP 1

/* Define to 1 if you have the `mktime' function. */
#define HAVE_MKTIME 1

/* Define to 1 if you have the <ndir.h> header file, and it defines `DIR'. */
/* #undef HAVE_NDIR_H */

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* Define if NetworkManager support is to be included. */
/* #undef HAVE_NETWORKMANAGER_SUPPORT */

/* Define to 1 if you have the <paths.h> header file. */
#define HAVE_PATHS_H 1

/* Define to 1 if you have the <pi-address.h> header file. */
/* #undef HAVE_PI_ADDRESS_H */

/* Define to 1 if you have the <pi-appinfo.h> header file. */
/* #undef HAVE_PI_APPINFO_H */

/* Define to 1 if you have the <pi-args.h> header file. */
/* #undef HAVE_PI_ARGS_H */

/* Define to 1 if you have the <pi-version.h> header file. */
/* #undef HAVE_PI_VERSION_H */

/* Description */
/* #undef HAVE_POPPLER_DEST_NAMED */

/* Description */
/* #undef HAVE_POPPLER_DEST_XYZ */

/* Define to 1 if you have the <pthread.h> header file. */
#define HAVE_PTHREAD_H 1

/* Define to 1 if you have the `regcomp' function. */
#define HAVE_REGCOMP 1

/* Define to 1 if you have the `shutdown' function. */
#define HAVE_SHUTDOWN 1

/* HAVE_SHUT_RD */
#define HAVE_SHUT_RD 1

/* Define to 1 if you have the `snprintf' function. */
#define HAVE_SNPRINTF 1

/* Define to 1 if you have the `socket' function. */
#define HAVE_SOCKET 1

/* Define if we're using libstartup-notification. */
/* #undef HAVE_STARTUP_NOTIFICATION */

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strchr' function. */
#define HAVE_STRCHR 1

/* Define to 1 if you have the `strdup' function. */
#define HAVE_STRDUP 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strstr' function. */
#define HAVE_STRSTR 1

/* Define to 1 if you have the `strtod' function. */
#define HAVE_STRTOD 1

/* Define to 1 if you have the `strtol' function. */
#define HAVE_STRTOL 1

/* Define to 1 if you have the <sysexits.h> header file. */
#define HAVE_SYSEXITS_H 1

/* Define to 1 if you have the <syslog.h> header file. */
#define HAVE_SYSLOG_H 1

/* Define to 1 if you have the <sys/dir.h> header file, and it defines `DIR'.
   */
/* #undef HAVE_SYS_DIR_H */

/* Define to 1 if you have the <sys/errno.h> header file. */
#define HAVE_SYS_ERRNO_H 1

/* Define to 1 if you have the <sys/file.h> header file. */
#define HAVE_SYS_FILE_H 1

/* Define to 1 if you have the <sys/ndir.h> header file, and it defines `DIR'.
   */
/* #undef HAVE_SYS_NDIR_H */

/* Define to 1 if you have the <sys/param.h> header file. */
#define HAVE_SYS_PARAM_H 1

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/utsname.h> header file. */
#define HAVE_SYS_UTSNAME_H 1

/* Define to 1 if you have <sys/wait.h> that is POSIX.1 compatible. */
#define HAVE_SYS_WAIT_H 1

/* Define to 1 if you have the <time.h> header file. */
#define HAVE_TIME_H 1

/* Define to 1 if you have the `truncate' function. */
#define HAVE_TRUNCATE 1

/* Used to test for a u32 typedef */
/* #undef HAVE_U32_TYPEDEF */

/* Define to 1 if you have the `uname' function. */
#define HAVE_UNAME 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define if you want valgrind support */
/* #undef HAVE_VALGRIND */

/* Define to 1 if you have the <wchar.h> header file. */
#define HAVE_WCHAR_H 1

/* Define to 1 if you have the <wctype.h> header file. */
#define HAVE_WCTYPE_H 1

/* Define to 1 if you have the <X11/SM/SMlib.h> header file. */
#define HAVE_X11_SM_SMLIB_H 1

/* Define as const if the declaration of iconv() needs const. */
#define ICONV_CONST 

/* Define if you want IPv6 support. */
#define INET6 1

/* Define to activate deprecated features in OpenLDAP */
/* #undef LDAP_DEPRECATED */

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* Defined if mkdir() does not take permission flags */
/* #undef MKDIR_TAKES_ONE_ARG */

/* Activate notification banner */
#define NOTIFICATION_BANNER 1

/* Activate notification shell command */
#define NOTIFICATION_COMMAND 1

/* Activate support for global hotkeys */
#define NOTIFICATION_HOTKEYS 1

/* Activate support for indicators */
/* #undef NOTIFICATION_INDICATOR */

/* Activate lcdproc support */
#define NOTIFICATION_LCDPROC 1

/* Activate notification popup */
#define NOTIFICATION_POPUP 1

/* Activate notification trayicon */
#define NOTIFICATION_TRAYICON 1

/* Define if OpenLDAP API is at least version 3000. */
#define OPEN_LDAP_API_AT_LEAST_3000 1

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* PACKAGE_DATA_DIR */
#define PACKAGE_DATA_DIR "/usr/local/share/claws-mail"

/* Define to the full name of this package. */
#define PACKAGE_NAME ""

/* Define to the full name and version of this package. */
#define PACKAGE_STRING ""

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME ""

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION ""

/* The size of `unsigned int', as computed by sizeof. */
#define SIZEOF_UNSIGNED_INT 4

/* The size of `unsigned long', as computed by sizeof. */
#define SIZEOF_UNSIGNED_LONG 8

/* The size of `unsigned short', as computed by sizeof. */
#define SIZEOF_UNSIGNED_SHORT 2

/* If using the C implementation of alloca, define if you know the
   direction of stack growth for your system; otherwise it will be
   automatically deduced at runtime.
	STACK_DIRECTION > 0 => grows toward higher addresses
	STACK_DIRECTION < 0 => grows toward lower addresses
	STACK_DIRECTION = 0 => direction of growth unknown */
/* #undef STACK_DIRECTION */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to 1 if your <sys/time.h> declares `struct tm'. */
/* #undef TM_IN_SYS_TIME */

/* enchant */
/* #undef USE_ENCHANT */

/* gnutls */
#define USE_GNUTLS 1

/* Define if you use GPGME to support OpenPGP. */
#define USE_GPGME 1

/* Define if you want JPilot support in addressbook. */
/* #undef USE_JPILOT */

/* Define if you want LDAP support in addressbook. */
#define USE_LDAP 1

/* Define if you want LDAP TLS support in addressbook. */
#define USE_LDAP_TLS 1

/* Define if new address book is to be activated. */
/* #undef USE_NEW_ADDRBOOK */

/* Define if you have pthread */
#define USE_PTHREAD 1

/* Define to 1 if `lex' declares `yytext' as a `char *' by default, not a
   `char[]'. */
#define YYTEXT_POINTER 1

/* Enable large inode numbers on Mac OS X 10.5.  */
#ifndef _DARWIN_USE_64_BIT_INODE
# define _DARWIN_USE_64_BIT_INODE 1
#endif

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to `unsigned long' if <sys/types.h> does not define. */
/* #undef in_addr_t */

/* Define to `long int' if <sys/types.h> does not define. */
/* #undef off_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef pid_t */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to `unsigned int' if <stddef.h> or <wchar.h> doesn't define. */
/* #undef wint_t */
