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
#include "hooks.h"
#include "pop.h"
#include "procmsg.h"
#include "utils.h"
#include "ibe_full_ident.h"

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
        g_warning("\n%s\nlen = %d\n", mail_msg, strlen(mail_msg));
        
        int mail_msg_len = strlen(mail_msg);
        mail_msg[mail_msg_len-1] = '\0';
        mail_msg[mail_msg_len-2] = '\0';
        gchar *decrypted_mail_msg = decrypt_mail_msg(mail_msg);
        
        int i;
        int decrypted_mail_msg_len = strlen(decrypted_mail_msg);
        /*decrypted_mail_msg[decrypted_mail_msg_len] = '\r';
        decrypted_mail_msg[decrypted_mail_msg_len] = '\n';
        decrypted_mail_msg_len += 2;*/
        strncpy(mail_msg, decrypted_mail_msg, decrypted_mail_msg_len);

        for (i = decrypted_mail_msg_len; i < mail_msg_len; ++i)
            strncpy(mail_msg+i, "\0", 1);
        
        printf("\n\n###decrypt_mail_msg: \n%s\n\n", mail_msg);
    }
	return FALSE;
}

gboolean ibe_encrypt_hook(gpointer source, gpointer data)
{
    gchar *mail_send_data = (gchar *)source;
    g_return_val_if_fail(source != NULL, FALSE);

    gchar *headend = g_strstr_len(mail_send_data, -1, "\r\n\r\n");
    gchar *send_mail_msg = NULL;
    if (headend != NULL)
    {
        send_mail_msg = headend + 4;
        printf("\n**********************send_mail_msg = ****************\n%s\n", send_mail_msg);

        gchar ID[100] = {'\0'};
        gchar *mail_to = g_strstr_len(mail_send_data, -1, "To: ");
        int i;
        for (mail_to = mail_to + 4, i = 0; *mail_to != '\r'; ++mail_to)
        {
            ID[i++] = *mail_to;
        }
        printf("\nID is:%s\n", ID);

        gchar *encrypted_mail_msg = encrypt_mail_msg(send_mail_msg, ID);

        printf("\n\n^^^encrypt_mail_msg: \n%s\n\n", encrypted_mail_msg);

        strncpy(send_mail_msg, encrypted_mail_msg, strlen(encrypted_mail_msg));

        printf("\n**********************send_mail_msg_change = ****************\n%s\n", send_mail_msg);
    }
    return FALSE;
}


static guint ibe_decrypt_hook_id;
static guint ibe_encrypt_hook_id;

gint plugin_init(gchar **error)
{
	if (!check_plugin_version(MAKE_NUMERIC_VERSION(2,9,2,72),
				VERSION_NUMERIC, PLUGIN_NAME, error))
		return -1;

	ibe_decrypt_hook_id = hooks_register_hook(MAIL_RECEIVE_HOOKLIST, ibe_decrypt_hook, NULL);
    ibe_encrypt_hook_id = hooks_register_hook(MAIL_SEND_HOOKLIST, ibe_encrypt_hook, NULL);
	if (ibe_decrypt_hook_id == -1) {
		*error = g_strdup(_("Failed to register ibe decrypt hook"));
		return -1;
	}
    if (ibe_encrypt_hook_id == -1) {
        *error = g_strdup(_("Failed to register ibe encrypt hook"));
        return -1;
    }

	g_print("Identity-Based Encryption plugin loaded\n");

	return 0;
}

gboolean plugin_done(void)
{
	hooks_unregister_hook(MAIL_RECEIVE_HOOKLIST, ibe_decrypt_hook_id);
    hooks_unregister_hook(MAIL_POSTFILTERING_HOOKLIST, ibe_encrypt_hook_id);
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
