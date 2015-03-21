/*
 * Program: Identity-Based Encryption - Plugin for Claws Mail
 * Author: Zhang Lin <zhanglin9833@gmail.com>
 * Depends: Claws Mail, GMP, PBC 
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <glib/gi18n.h>

#include "defs.h"
#include "version.h"
#include "claws.h"
#include "plugin.h"
#include "utils.h"
#include "hooks.h"
#include "pop.h"

#define PLUGIN_NAME (_("Identity-Based Encryption"))

gboolean ibe_decrypt_hook(gpointer source, gpointer data)
{
    MailReceiveData *mail_receive_data = (MailReceiveData *)source;
    gchar *mail_msg = NULL;
    g_return_val_if_fail(
            mail_receive_data &&
            mail_receive_data->session &&
            mail_receive_data->data,
            FALSE);

    gchar *headend = g_strstr_len(mail_receive_data->data, -1, "\r\n\r\n");
    if (headend != NULL)
    {
        mail_msg = headend + 4;
        g_warning("\n%s", mail_msg);
    }
	return FALSE;
}

static guint ibe_decrypt_hook_id;

gint plugin_init(gchar **error)
{
	if (!check_plugin_version(MAKE_NUMERIC_VERSION(2,9,2,72),
				VERSION_NUMERIC, PLUGIN_NAME, error))
		return -1;

	ibe_decrypt_hook_id = hooks_register_hook(MAIL_RECEIVE_HOOKLIST, ibe_decrypt_hook, NULL);
	if (ibe_decrypt_hook_id == -1) {
		*error = g_strdup(_("Failed to register ibe decrypt hook"));
		return -1;
	}

	g_print("Identity-Based Encryption plugin loaded\n");

	return 0;
}

gboolean plugin_done(void)
{
	hooks_unregister_hook(MAIL_RECEIVE_HOOKLIST, ibe_decrypt_hook_id);

	g_print("Identity-Based Encryption plugin unloaded\n");
	return TRUE;
}

const gchar *plugin_name(void)
{
	return PLUGIN_NAME;
}

const gchar *plugin_desc(void)
{
	return _("This Plugin encrypt/decrypt the email using IBE, "
	         "Identity-Based Encryption from the Weil Pairing."
	         );
}

const gchar *plugin_type(void)
{
	return "Common";
}

const gchar *plugin_licence(void)
{
	return "GPL3+";
}

const gchar *plugin_version(void)
{
	return VERSION;
}

struct PluginFeature *plugin_provides(void)
{
	static struct PluginFeature features[] = 
		{ {PLUGIN_OTHER, N_("Identity-Based Encryption")},
		  {PLUGIN_NOTHING, NULL}};
	return features;
}
