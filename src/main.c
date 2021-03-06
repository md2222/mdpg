#include <gtk/gtk.h>
#include "crypto_scrypt.h"
#include "base91.h"


#define KEY_SIZE 32

enum
{
    FID_BASE91,
    FID_BASE64  
};

static GtkBuilder *builder = NULL;
GtkWidget *window = NULL;

struct Params
{
    GtkEntry* edMaster;
    GtkEntry* edMaster2;
    GtkEntry* edPassw;
    const gchar *obj;
    const gchar *master;
    int format;
    //const gchar *len;
    guint64 len;
} params;

typedef struct 
{
    int x;
    int y;
    int w;
    int h;
} Rect;

const gchar* appName = "MDPG";
const gchar* wipeStr = "###############################################";
gboolean isNewMaster = FALSE;


char *base91(const unsigned char *data, int size)
{
    struct basE91 b91;
    size_t bufSize = 256;
    char* buf = (char *)malloc(bufSize);
    memset(buf, 0, bufSize);

    basE91_init(&b91);
    size_t b91len = basE91_encode(&b91, data, size, buf);
    
    return buf;
}


void zeroAndFree(unsigned char *data, int size)
{
	if (!data || size <= 0)  return;
    memset(data, 0, size);
    g_free(data);
}


void wipeEntry(GtkEntry* ed)
{
    const gchar* sz = gtk_entry_get_text(ed);
    if (sz && strlen(sz))
    {
        gtk_entry_set_text(ed, g_strnfill(strlen(sz), '#'));
        gtk_main_iteration_do(FALSE);
        gtk_entry_set_text(ed, "");
    }
}


void message(const gchar* text)
{
    gtk_entry_set_text(params.edPassw, text);
}
//----------------------------------------------------------------------------------------------------------------------

gint messageBox(GtkWidget *parent, const char* text, const char* caption, uint type, Rect* rect)
{
   GtkWidget *dialog ;

   if (type & GTK_BUTTONS_YES_NO)
       dialog = gtk_message_dialog_new(GTK_WINDOW(parent), GTK_DIALOG_MODAL, GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO, text);
   else
       dialog = gtk_message_dialog_new(GTK_WINDOW(parent), GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK, text);


   gtk_window_set_title(GTK_WINDOW(dialog), caption);

   if (rect && rect->x)
       gtk_window_move(GTK_WINDOW(dialog), rect->x, rect->y);

   gint result = gtk_dialog_run(GTK_DIALOG(dialog));

   gtk_widget_destroy( GTK_WIDGET(dialog) );

   return result;
}
//----------------------------------------------------------------------------------------------------------------------

void setCursor(GtkWidget *w, char *curName)
{
    GdkDisplay *display = gtk_widget_get_display (w);
    GdkCursor *cursor;

    if(curName)
        cursor = gdk_cursor_new_from_name(display, curName);
    else
        cursor = gdk_cursor_new_from_name (display, "default");
        
    GdkWindow *gdkWin = gtk_widget_get_window(w);
    gdk_window_set_cursor(gdkWin, cursor);
}


gboolean makePassw(gpointer data)
{
    gchar *salt = g_utf8_strdown(params.obj, -1);
    int saltLen = strlen(salt);
    //g_print("salt=%s\n", salt); 
    
	unsigned char key[KEY_SIZE];
    
    // 32768, 65536, 131072
	if (crypto_scrypt((uint8_t *)params.master, (size_t)strlen(params.master), (uint8_t *)salt, (size_t)saltLen, 131072, 8, 1, key, KEY_SIZE)) 
    {
    	//fprintf(stderr, "crypto_scrypt() error\n");
        //messageBox(window, "crypto_scrypt() error.", appName, 0, 0);
        message("crypto_scrypt() error [Program error]");
        return FALSE; 
   	}   
     
    zeroAndFree(salt, saltLen);
    
    gchar* passw = NULL;
    
    if (params.format == FID_BASE91 || isNewMaster)
    {    
        passw = base91(key, KEY_SIZE);
    }
    else if (params.format == FID_BASE64)
    {
        passw = g_base64_encode(key, KEY_SIZE);
        //g_print("passw=%s\n", passw);
        gchar* p1 = passw;
        gchar* p2 = p1;
        while (*p1)
        {
            if (*p1 != '/' && *p1 != '+' && *p1 != '=')
                *p2++ = *p1;
            p1++;
        }
        *p2 = 0;
    } 

    memset(key, 0, KEY_SIZE);
        
    if (passw)
    {
        //g_print("passw=%s\n", passw);

        int passwLen = strlen(passw);

        if (params.len > 0 && params.len < passwLen)
            memset(passw + params.len, 0, passwLen - params.len);
            
        if (isNewMaster)
        {
            wipeEntry(params.edMaster);
            gtk_entry_set_text(params.edMaster, passw);
            wipeEntry(params.edMaster2);
            gtk_entry_set_text(params.edPassw, "New Master is done!");
        }
        else
            gtk_entry_set_text(params.edPassw, passw);
        
        zeroAndFree(passw, passwLen);
    }

    setCursor(window, NULL);

    return FALSE;
}


static void onMake(GtkWidget *widget, gpointer data)
{
    wipeEntry(params.edPassw); 
    gtk_main_iteration_do(FALSE);
    
    GtkEntry* edObj = (GtkEntry*)gtk_builder_get_object(builder, "edObj");
    params.obj = gtk_entry_get_text(edObj);
    
    params.master = gtk_entry_get_text(params.edMaster);
    
    const gchar *master2 = gtk_entry_get_text(params.edMaster2);
    
    GtkComboBox* cbFormat = (GtkComboBox*)gtk_builder_get_object(builder, "cbFormat");
    params.format = gtk_combo_box_get_active(cbFormat);
    
    GtkEntry* edLen = (GtkEntry*)gtk_builder_get_object(builder, "edLen");
    const gchar* len = gtk_entry_get_text(edLen);
    
    //g_print("fields:    %s    %s    %s    %s    %d\n", params.obj, params.master, master2, len, params.format);
    
    GError *err = NULL;
    
    if (!g_ascii_string_to_signed(len, 10, 0, 99, &params.len, &err))
    {
        //messageBox(window, "Bad Length format.", appName, 0, 0);
        message("Bad Length format");
        return; 
    }
    //g_print("len=%ld\n", params.len);
    
    if (strlen(params.obj) < 4)
    {
        //messageBox(window, "Object length must be at least 4 characters.", appName, 0, 0);
        message("Object length must be at least 4 characters");
        return; 
    }
    
    if (strlen(params.master) < 8)
    {
        //messageBox(window, "Password length must be at least 8 characters.", appName, 0, 0);
        message("Password length must be at least 8 characters");
        return; 
    }
    
    if (strlen(master2) > 0 && g_strcmp0(master2, params.master))
    {
        //messageBox(window, "Master passwords are not identical.", appName, 0, 0);
        message("Master passwords are not identical");
        return; 
    }
    
    if (params.format != FID_BASE64 && params.format != FID_BASE91)
    {
        //messageBox(window, "Bad format index.", appName, 0, 0);
        message("Bad format index [Program error]");
        return; 
    }
    
    setCursor(window, "wait");
    
    g_idle_add(makePassw, NULL);
}


static void onCopy(GtkWidget *widget, gpointer data)
{
    //g_print("onCopy\n");
    GtkClipboard* cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(cb, gtk_entry_get_text(params.edPassw), -1);
}


static void onClose(GtkWidget *object, gpointer data)
{
    //g_print("onClose\n");
    wipeEntry(params.edMaster);
    wipeEntry(params.edMaster2);    
    wipeEntry(params.edPassw);
   
    gtk_main_iteration_do(FALSE);

    gtk_main_quit();
}

/*
static gboolean onClose(GtkWidget *widget, GdkEvent *event, gpointer data)
{
    return FALSE;
}
*/


gboolean onMakePress(GtkWidget *widget, GdkEvent  *event,  gpointer data)
{
    //printf("onMakePress\n");
    isNewMaster = FALSE;
    
    GdkModifierType modifiers = gtk_accelerator_get_default_mod_mask ();

    if ((((GdkEventButton*)event)->state & modifiers) == GDK_CONTROL_MASK)
    {
        //g_print ("Control pressed\n");
        isNewMaster = TRUE;
    }            

    return FALSE;
}


int main(int argc, char **argv)
{
    gtk_init(&argc, &argv);
    g_print("MDPG 2.2.1    20.04.2021\n");   // and title
    g_print("Keep it simple ...\n");
    
    gchar *baseName = g_path_get_basename(argv[0]);
    
    //gchar *dataDir = g_strconcat(g_get_user_data_dir(), "/", baseName, NULL);
    gchar *dataDir = g_strconcat("/usr/local/share/", baseName, NULL);
    g_print("dataDir=%s\n", dataDir);
    

    builder = gtk_builder_new();
    GError *error = NULL;	

    //gchar *filePath = g_strconcat(dataDir, "/mainWin.glade", NULL);

    //if (gtk_builder_add_from_file(builder, filePath, &error) == 0)
    if (gtk_builder_add_from_resource(builder, "/app/mainWin.glade", &error) == 0)
    {
        g_printerr("Error loading glade file: %s\n", error->message);
        g_clear_error(&error);
        return 1;
    }
    
    window = GTK_WIDGET(gtk_builder_get_object(builder, "mainWin"));
    gtk_window_set_title(GTK_WINDOW(window), "MDPG 2.2.1");
    GdkPixbuf *pixbuf = gdk_pixbuf_new_from_resource ("/app/mdpg.png", NULL);
    if (pixbuf)
        gtk_window_set_icon (GTK_WINDOW(window), pixbuf);

    //g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL); 
    //g_signal_connect(window, "delete-event", G_CALLBACK(onClose), NULL);
    g_signal_connect(window, "destroy", G_CALLBACK(onClose), NULL); 
    
    GObject *btMake = gtk_builder_get_object(builder, "btMake");
    g_signal_connect(btMake, "clicked", G_CALLBACK(onMake), NULL);    
    g_signal_connect(btMake, "button-press-event", G_CALLBACK(onMakePress), NULL);    
    
    GObject *btCopy = gtk_builder_get_object(builder, "btCopy");
    g_signal_connect(btCopy, "clicked", G_CALLBACK(onCopy), NULL);   
    
    params.edPassw = (GtkEntry*)gtk_builder_get_object(builder, "edPassw");
    params.edMaster = (GtkEntry*)gtk_builder_get_object(builder, "edMaster");
    params.edMaster2 = (GtkEntry*)gtk_builder_get_object(builder, "edMaster2");

    
    gtk_window_present(GTK_WINDOW (window));

    gtk_main ();

    return 0;    
}
