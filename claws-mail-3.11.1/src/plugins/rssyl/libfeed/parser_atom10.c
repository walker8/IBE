/*
 * Copyright (C) 2006 Andrej Kacian <andrej@kacian.sk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */
#define __USE_GNU

#include <glib.h>
#include <expat.h>
#include <string.h>
#include <stdio.h>

#include "feed.h"
#include "feeditem.h"
#include "date.h"
#include "parser.h"
#include "parser_atom10.h"

void feed_parser_atom10_start(void *data, const gchar *el, const gchar **attr)
{
	FeedParserCtx *ctx = (FeedParserCtx *)data;
	gchar *a = NULL;

	if( ctx->depth == 1 ) {

		if( !strcmp(el, "entry") ) {
			/* Start of new feed item found.
			 * Create a new FeedItem, freeing the one we already have, if any. */
			if( ctx->curitem != NULL )
				feed_item_free(ctx->curitem);
			ctx->curitem = feed_item_new(ctx->feed);
			ctx->location = FEED_LOC_ATOM10_ENTRY;
		} else if( !strcmp(el, "author") ) {
			/* Start of author info for the feed found.
			 * Set correct location. */
			ctx->location = FEED_LOC_ATOM10_AUTHOR;
		} else ctx->location = FEED_LOC_ATOM10_NONE;

	} else if( ctx->depth == 2 ) {

		/* Make sure we are in one of known locations within the XML structure.
		 * This condition should never be true on a valid Atom feed. */
		if (ctx->location != FEED_LOC_ATOM10_AUTHOR &&
				ctx->location != FEED_LOC_ATOM10_ENTRY) {
			ctx->depth++;
			return;
		}

		if( !strcmp(el, "author") ) {
			/* Start of author info for current feed item.
			 * Set correct location. */
			ctx->location = FEED_LOC_ATOM10_AUTHOR;
		} else if( !strcmp(el, "link") ) {
			/* Capture item URL, from the "url" XML attribute. */
			if (ctx->curitem && ctx->location == FEED_LOC_ATOM10_ENTRY)
  		  ctx->curitem->url = g_strdup(feed_parser_get_attribute_value(attr, "href"));
		} else if( !strcmp(el, "source") ) {
			ctx->location = FEED_LOC_ATOM10_SOURCE;
		} else ctx->location = FEED_LOC_ATOM10_ENTRY;

		if( !strcmp(el, "title") ) {
			a = feed_parser_get_attribute_value(attr, "type");
			if( !a || !strcmp(a, "text") )
				ctx->curitem->title_format = FEED_ITEM_TITLE_TEXT;
			else if( !strcmp(a, "html") )
				ctx->curitem->title_format = FEED_ITEM_TITLE_HTML;
			else if( !strcmp(a, "xhtml") )
				ctx->curitem->title_format = FEED_ITEM_TITLE_XHTML;
			else
				ctx->curitem->title_format = FEED_ITEM_TITLE_UNKNOWN;
		} else if (!strcmp(el, "content") ) {
			a = feed_parser_get_attribute_value(attr, "type");
			if (a && !strcmp(a, "xhtml")) {
				ctx->curitem->xhtml_content = TRUE;
				ctx->location = FEED_LOC_ATOM10_CONTENT;
			}
		}
	}

	ctx->depth++;
}

void feed_parser_atom10_end(void *data, const gchar *el)
{
	FeedParserCtx *ctx = (FeedParserCtx *)data;
	Feed *feed = ctx->feed;
	gchar *text = NULL;

	if( ctx->str != NULL )
		text = ctx->str->str;
	else
		text = "";

	switch( ctx->depth ) {

		case 0:
			/* Just in case. */
			break;

		case 1:

			if( !strcmp(el, "feed") ) {
				/* We have finished parsing the feed, reverse the list
				 * so it's not upside down. */
				feed->items = g_slist_reverse(ctx->feed->items);
			}

			break;

		case 2:

			/* decide if we just received </entry>, so we can
			 * add a complete item to feed */
			if( !strcmp(el, "entry") ) {

				/* append the complete feed item */
				if( ctx->curitem->id && ctx->curitem->title
						&& ctx->curitem->date_modified ) {
					feed->items = 
						g_slist_prepend(feed->items, (gpointer)ctx->curitem);
				}
				
				/* since it's in the linked list, lose this pointer */
				ctx->curitem = NULL;

			} else if( !strcmp(el, "title") ) {	/* so it wasn't end of item */
				FILL(feed->title)
			} else if( !strcmp(el, "summary" ) ) {
				FILL(feed->description)
			} else if( !strcmp(el, "updated" ) ) {
				feed->date = parseISO8601Date(text);
			}
			/* FIXME: add more later */

			break;

		case 3:

			if( ctx->curitem == NULL )
				break;

			switch(ctx->location) {

				/* We're in feed/entry */
				case FEED_LOC_ATOM10_ENTRY:
					if( !strcmp(el, "title") ) {
						FILL(ctx->curitem->title)
					} else if( !strcmp(el, "summary") ) {
						FILL(ctx->curitem->summary)
					} else if( !strcmp(el, "content") ) {
						if (!ctx->curitem->xhtml_content)
							FILL(ctx->curitem->text)
					} else if( !strcmp(el, "id") ) {
						FILL(ctx->curitem->id)
						feed_item_set_id_permalink(ctx->curitem, TRUE);
					} else if( !strcmp(el, "published") ) {
						ctx->curitem->date_published = parseISO8601Date(text);
					} else if( !strcmp(el, "updated") ) {
						ctx->curitem->date_modified = parseISO8601Date(text);
					}

					break;

				/* We're in feed/author or about to leave feed/entry/author */
				case FEED_LOC_ATOM10_AUTHOR:
					if( !strcmp(el, "author" ) ) {
						/* We just finished parsing <author> */
						ctx->curitem->author = g_strdup_printf("%s%s%s%s%s",
								ctx->name ? ctx->name : "",
								ctx->name && ctx->mail ? " <" : ctx->mail ? "<" : "",
								ctx->mail ? ctx->mail : "",
								ctx->mail ? ">" : "",
								!ctx->name && !ctx->mail ? "N/A" : "");
						ctx->location = FEED_LOC_ATOM10_ENTRY;
					} else if( !strcmp(el, "name") ) {
						FILL(feed->author)
					}

					break;
			}

			break;

		case 4:

			if( ctx->curitem == NULL )
				break;

			switch(ctx->location) {

				/* We're in feed/entry/author */
				case FEED_LOC_ATOM10_AUTHOR:
					if( !strcmp(el, "name") ) {
						FILL(ctx->name)
					} else if( !strcmp(el, "email") ) {
						FILL(ctx->mail)
					}

					break;

				/* We're in feed/entry/source */
				case FEED_LOC_ATOM10_SOURCE:
					if( !strcmp(el, "title" ) ) {
						FILL(ctx->curitem->sourcetitle)
					} else if( !strcmp(el, "id" ) ) {
						FILL(ctx->curitem->sourceid)
					} else if( !strcmp(el, "updated" ) ) {
						ctx->curitem->sourcedate = parseISO8601Date(text);
					}

					break;

				case FEED_LOC_ATOM10_CONTENT:
					if (!strcmp(el, "div") && ctx->curitem->xhtml_content)
						FILL(ctx->curitem->text)
					break;

				}


			break;
	}

	if( ctx->str != NULL ) {
		g_string_free(ctx->str, TRUE);
		ctx->str = NULL;
	}
	ctx->str = NULL;

	ctx->depth--;
}
