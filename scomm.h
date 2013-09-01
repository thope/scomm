#ifndef SCOMM_H
#define SCOMM_H

#include <tomcrypt.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

#define zalloc(size)	calloc(size, 1)
#define _strlen(s)      strlen((char*)(s))       
#define BSIZE 1024

#define dbg(format, arg...)						              \
	do {								                      \
		if (debug)						                      \
			fprintf(stdout, "scomm: %s: " format , __func__ , \
				## arg);				                      \
	} while (0)

#define die(format, arg...)						              \
	do {								                      \
			fprintf(stderr, "scomm: %s: " format , __func__ , \
				## arg);				                      \
			exit(1);                                          \
	} while (0)	

typedef unsigned char uchar;

//connection instance
typedef struct connection Cxn;
struct connection {
	int sock;
	time_t ts;
	char *ip;
	uchar *key;
	uchar *IV;
	char *name;
	symmetric_CTR ctr;
};

//Connection list
typedef struct node Node;
struct node {
	Cxn c;
	Node *next;
};

//big num
typedef struct bn BN;
struct bn {
	void *n;
	uint32_t len;
};

//diffie-helman parameters
typedef struct dh_params DH_Params;
struct dh_params {
	BN g;
	BN p;
	BN a;
	BN g_exp_a;
	uchar *packed;
	uint32_t packed_len;
};

//crypto context
typedef struct crypto_ctx CryptoCtx;
struct crypto_ctx {
	prng_state prng;
	int hash_idx;
	int cipher_idx;
	int ks;
	unsigned long ivsize;
	DH_Params dhp;
};

typedef struct proc Proc;
struct proc {
	int fds[2];
	int busy;
	char port[8];
};

//globals
extern CryptoCtx ctx;
extern int debug;
extern char *start_port;
extern char *listen_port;
extern char *username;
extern char *received_files;
enum {
	NUM_SENDERS = 2,
	NUM_RECEIVERS = 2
};

//list.c
Cxn * add_cxn_to_list(int, time_t, char *, char *, uchar *, uchar *);
Cxn * find_cxn_sock(int);
Cxn * find_cxn_name(char *);
void free_all_cxns();
void free_cxn(int);
void print_cxns();

//socket.c
void run();

//crypto.c
void init_crypto();
int parse_dh_args( uchar *, char **, uchar **, int *);
int get_key(uchar *, int , uchar *, unsigned long *);
int get_iv(uchar *);
int init_send(Cxn *);
int encrypt_msg(Cxn *, uchar *, uchar *, int);
int decrypt_msg(Cxn *, uchar *, uchar *, int);
void clean_ctx();

#endif
