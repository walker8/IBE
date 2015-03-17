INCLUDES = -I /usr/local/include -I /usr/local/include/pbc

plugindir = $(CLAWS_MAIL_PLUGINDIR)

plugin_LTLIBRARIES = ibe.la

ibe_la_SOURCES = \
				 ibe_full_ident.c \
				 ibe_full_ident.h \
				 sha1.c \
				 sha1.h \
				 utils.c \
				 utils.h

ibe_la_LDFLAGS = \
				 -avoid-version -module \
				 $(GTK_LIBS)

AM_CPPFLAGS = \
			$(CLAWS_MAIL_CFLAGS) \
			$(GLIB_CFLAGS) \
			$(GTK_CFLAGS)

EXTRA_DIST=
