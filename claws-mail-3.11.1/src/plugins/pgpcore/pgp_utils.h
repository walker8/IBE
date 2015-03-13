/*
 * Claws Mail -- a GTK+ based, lightweight, and fast e-mail client
 * Copyright (C) 1999-2013 Colin Leroy <colin@colino.net> and 
 * the Claws Mail team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 * 
 */

#ifndef __PGP_UTILS_H__
#define __PGP_UTILS_H__

#ifdef HAVE_CONFIG_H
#include "claws-features.h"
#endif

#include "procmime.h"

gchar *fp_read_noconv(FILE *fp);
gchar *get_part_as_string(MimeInfo *mimeinfo);
gchar *pgp_locate_armor_header(gchar *textdata, const gchar *armor_header);

#endif /* __PGP_UTILS_H__ */
