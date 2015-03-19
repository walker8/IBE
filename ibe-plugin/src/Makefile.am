INCLUDES = -I /usr/local/include \
		   -I /usr/local/include/pbc

plugindir = $(CLAWS_MAIL_PLUGINDIR)

plugin_LTLIBRARIES = myibe.la

myibe_la_SOURCES = \
				 ibe.c \
				 ibe_full_ident.c \
				 ibe_full_ident.h \
				 sha1.c \
				 sha1.h \
				 utils.c \
				 utils.h

myibe_la_LDFLAGS = \
				 -avoid-version -module \
				 $(GTK_LIBS)

myibe_la_LIBADD = \
			   -L/usr/local/lib \
			   -lgmp \
			   -lpbc

myibe_la_CPPFLAGS = \
			$(CLAWS_MAIL_CFLAGS) \
			$(GLIB_CFLAGS) \
			$(GTK_CFLAGS)
