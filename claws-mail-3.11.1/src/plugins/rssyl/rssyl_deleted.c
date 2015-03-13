/*
 * Claws-Mail-- a GTK+ based, lightweight, and fast e-mail client
 * Copyright (C) 1999-2004 Hiroyuki Yamamoto
 * This file (C) 2005 Andrej Kacian <andrej@kacian.sk>
 *
 * - handling of info about user-deleted feed items
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

/* Global includes */
#include <glib.h>
#include <string.h>

/* Claws Mail includes */
#include <codeconv.h>
#include <common/utils.h>

/* Local includes */
#include "rssyl.h"
#include "parse822.h"
#include "strutils.h"

static RDeletedItem *_new_deleted_item()
{
	RDeletedItem *ditem = g_new0(RDeletedItem, 1);

	ditem->id = NULL;
	ditem->title = NULL;
	ditem->date_published = -1;
	ditem->date_modified = -1;

	return ditem;
}

static void _free_deleted_item(gpointer d, gpointer user_data)
{
	RDeletedItem *ditem = (RDeletedItem *)d;

	if (ditem == NULL)
		return;

	g_free(ditem->id);
	g_free(ditem->title);
	g_free(ditem);
}

void rssyl_deleted_free(GSList *deleted_items)
{
	if (deleted_items != NULL) {
		debug_print("RSSyl: releasing list of deleted items\n");
		g_slist_foreach(deleted_items, _free_deleted_item, NULL);
		g_slist_free(deleted_items);
		deleted_items = NULL;
	}
}

static gchar * _deleted_file_path(RFolderItem *ritem)
{
	gchar *itempath, *deleted_file;

	itempath = folder_item_get_path(&ritem->item);
	deleted_file = g_strconcat(itempath, G_DIR_SEPARATOR_S, RSSYL_DELETED_FILE, NULL);
	g_free(itempath);

	return deleted_file;
}

/***************************************************************/
GSList *rssyl_deleted_update(RFolderItem *ritem)
{
	gchar *deleted_file, *contents, **lines, **line;
	GError *error = NULL;
	guint i = 0;
	RDeletedItem *ditem = NULL;
	GSList *deleted_items = NULL;

	g_return_val_if_fail(ritem != NULL, NULL);

	deleted_file = _deleted_file_path(ritem);

	debug_print("RSSyl: getting list of deleted items from '%s'\n", deleted_file);

	if (!g_file_test(deleted_file, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR)) {
		debug_print("RSSyl: '%s' doesn't exist, ignoring\n", deleted_file);
		return NULL;
	}

	g_file_get_contents(deleted_file, &contents, NULL, &error);

	if (error)
		g_warning("GError: '%s'\n", error->message);

	if (contents != NULL) {
		lines = strsplit_no_copy(contents, '\n');
	} else {
		g_warning("Couldn't read '%s', ignoring\n", deleted_file);
		g_free(deleted_file);
		return NULL;
	}

	g_free(deleted_file);

	while (lines[i]) {
		line = g_strsplit(lines[i], ": ", 2);
		if (line[0] && line[1] && strlen(line[0]) && strlen(line[1])) {
			if (!strcmp(line[0], "ID")) {
				ditem = _new_deleted_item();
				ditem->id = g_strdup(line[1]);
			} else if (ditem != NULL && !strcmp(line[0], "TITLE")) {
				ditem->title = g_strdup(line[1]);
			} else if (ditem != NULL && !strcmp(line[0], "DPUB")) {
				ditem->date_published = atoi(line[1]);
			} else if (ditem != NULL && !strcmp(line[0], "DMOD")) {
				ditem->date_modified = atoi(line[1]);
				deleted_items = g_slist_prepend(deleted_items, ditem);
				ditem = NULL;
			}
		}

		g_strfreev(line);
		i++;
	}

	g_free(lines);
	g_free(contents);

	debug_print("RSSyl: got %d deleted items\n", g_slist_length(deleted_items));
	return deleted_items;
}

static void _store_one_deleted_item(gpointer data, gpointer user_data)
{
	RDeletedItem *ditem = (RDeletedItem *)data;
	FILE *f = (FILE *)user_data;
	gboolean err = FALSE;

	if (ditem == NULL || ditem->id == NULL)
		return;

	err |= (fprintf(f,
			"ID: %s\n"
			"TITLE: %s\n"
			"DPUB: %ld\n"
			"DMOD: %ld\n",
			ditem->id, ditem->title,
			ditem->date_published, ditem->date_modified) < 0);

	if (err)
		debug_print("RSSyl: Error during writing deletion file.\n");
}

static void rssyl_deleted_store_internal(GSList *deleted_items, const gchar *deleted_file)
{
	FILE *f;

	if (g_file_test(deleted_file, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR)) {
		if (g_remove(deleted_file) != 0) {
			debug_print("RSSyl: Oops, couldn't delete '%s', bailing out\n",
					deleted_file);
			return;
		}
	}

	if (g_slist_length(deleted_items) == 0)
		return;

	if ((f = g_fopen(deleted_file, "w")) == NULL) {
		debug_print("RSSyl: Couldn't open '%s', bailing out.\n", deleted_file);
		return;
	}

	g_slist_foreach(deleted_items, (GFunc)_store_one_deleted_item,
			(gpointer)f);

	fclose(f);
	debug_print("RSSyl: written and closed deletion file\n");
}

void rssyl_deleted_store(RFolderItem *ritem)
{
	gchar *path;

	g_return_if_fail(ritem != NULL);

	path = _deleted_file_path(ritem);
	rssyl_deleted_store_internal(ritem->deleted_items, path);
}


/* Creates a FeedItem from a message file and uses the data to add a item
 * to the list of deleted stuff. */
void rssyl_deleted_add(RFolderItem *ritem, gchar *path)
{
	FeedItem *fitem = NULL;
	RDeletedItem *ditem = NULL;
	GSList *deleted_items = rssyl_deleted_update(ritem);
	gchar *deleted_file = NULL;

	if (!(fitem = rssyl_parse_folder_item_file(path)))
		return;

	ditem = _new_deleted_item();
	ditem->id = g_strdup(feed_item_get_id(fitem));
	ditem->title = conv_unmime_header(feed_item_get_title(fitem),
			CS_UTF_8, FALSE);
	ditem->date_published = feed_item_get_date_published(fitem);
	ditem->date_modified = feed_item_get_date_modified(fitem);

	deleted_items = g_slist_prepend(deleted_items, ditem);

	deleted_file = _deleted_file_path(ritem);
	rssyl_deleted_store_internal(deleted_items, deleted_file);
	g_free(deleted_file);

	rssyl_deleted_free(deleted_items);
	feed_item_free(fitem);
}

static gint _rssyl_deleted_check_func(gconstpointer a, gconstpointer b)
{
	RDeletedItem *ditem = (RDeletedItem *)a;
	FeedItem *fitem = (FeedItem *)b;

	g_return_val_if_fail(ditem != NULL, -10);
	g_return_val_if_fail(fitem != NULL, -20);

	/* Following must match:
	 * ID, ... */
	if (!ditem->id || !feed_item_get_id(fitem) ||
			strcmp(ditem->id, feed_item_get_id(fitem)))
		return -1;

	/* title, ... */
	if (!ditem->title || !feed_item_get_title(fitem) ||
			strcmp(ditem->title, feed_item_get_title(fitem)))
		return -2;

	/* time of publishing, ... */
	if (ditem->date_published != -1 &&
			ditem->date_published != feed_item_get_date_published(fitem))
		return -3;

	/* and the time of last modification must be greater
	 * (this means that the item was updated since deletion, and possibly
	 * contains new data, so we add it again) */
	if (ditem->date_modified != -1 &&
			ditem->date_modified < feed_item_get_date_modified(fitem))
		return -4;

	return 0;
}

/* Returns TRUE if fitem is found among the deleted stuff. */
gboolean rssyl_deleted_check(GSList *deleted_items, FeedItem *fitem)
{
	if (g_slist_find_custom(deleted_items, (gconstpointer)fitem,
				_rssyl_deleted_check_func) != NULL)
		return TRUE;

	return FALSE;
}

/******** Expiring ********/
struct _RDelExpireCtx {
	RDeletedItem *ditem;
	gboolean delete;
};

typedef struct _RDelExpireCtx RDelExpireCtx;

static void _rssyl_deleted_expire_func_f(gpointer data, gpointer user_data)
{
	FeedItem *fitem = (FeedItem *)data;
	RDelExpireCtx *ctx = (RDelExpireCtx *)user_data;

	/* Following must match:
	 * ID, ... */
	if (!ctx->ditem->id || !feed_item_get_id(fitem) ||
			strcmp(ctx->ditem->id, feed_item_get_id(fitem)))
		return;

	/* title, ... */
	if (!ctx->ditem->title || !feed_item_get_title(fitem) ||
			strcmp(ctx->ditem->title, feed_item_get_title(fitem)))
		return;

	/* time of publishing, ... */
	if (ctx->ditem->date_published != feed_item_get_date_published(fitem))
		return;

	/* and the time of last modification must be greater
	 * (this means that the item was updated since deletion, and possibly
	 * contains new data, so we add it again) */
	if (ctx->ditem->date_modified != feed_item_get_date_modified(fitem))
		return;

	ctx->delete = FALSE;
}

/* Checks each item in deleted items list against feed and removes it if
 * it is not found there anymore. */
void rssyl_deleted_expire(RFolderItem *ritem, Feed *feed)
{
	GSList *d = NULL, *d2;
	RDelExpireCtx *ctx = NULL;
	RDeletedItem *ditem;

	g_return_if_fail(ritem != NULL);
	g_return_if_fail(feed != NULL);

	ritem->deleted_items = rssyl_deleted_update(ritem);

	/* Iterate over all items in the list */
	d = ritem->deleted_items;
	while (d) {
		ditem = (RDeletedItem *)d->data;
		ctx = g_new0(RDelExpireCtx, 1);
		ctx->ditem = ditem;
		ctx->delete = TRUE;

		/* Adjust ctx->delete accordingly */
		feed_foreach_item(feed, _rssyl_deleted_expire_func_f, (gpointer)ctx);

		/* Remove the item if necessary */
		if (ctx->delete) {
			debug_print("RSSyl: (DELETED) removing '%s' from list\n", ditem->title);
			d2 = d->next;
			ritem->deleted_items = g_slist_remove_link(ritem->deleted_items, d);
			d = d2;
			continue;
		} else {
			d = d->next;
		}

		g_free(ctx);
	}

	/* Write the new list to disk */
	rssyl_deleted_store(ritem);

	/* And clean up after myself */
	rssyl_deleted_free(ritem->deleted_items);
}
