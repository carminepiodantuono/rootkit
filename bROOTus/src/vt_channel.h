#ifndef VT_CHANNEL_H
#define VT_CHANNEL_H

#define VT_BUFFER_LENGTH 1024

#define CMD_LENGTH 1024

// comandi per il canale coperto
struct command {
  char* name;
  void (*f)(char*);
};

// buffer per ogni terminale
struct vt_buffer {
  char buffer[VT_BUFFER_LENGTH + 1];
  int buffer_pos;
  char* vt;
  struct list_head list;
};


// aggiungere nuovo comando
extern void add_command(char* name, void (*f)(char*));

// inizializza il canale coperto
extern void init_vt_channel(void);

// rimuove il canale coperto
extern void finalize_vt_channel(void);

#endif