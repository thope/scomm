#include "scomm.h"

int debug;
char *start_port = NULL;
char *listen_port = NULL;
char *username = NULL;
char *received_files = NULL;

int main(int argc, char *argv[])
{
	int i, c;
	debug = 0;

	if (argc != 9) {
		fprintf(stderr, "Usage: ./scomm -u <username> -s <start_port> -p <listen_port> -o <output_dir>\n");
		fprintf(stderr, "\tusername\t- Give yourself a name\n");
		fprintf(stderr, "\tstart_port\t- Port to start listening for file requests\n");
		fprintf(stderr, "\tlisten_port\t- Port to listen for messages\n");
		fprintf(stderr, "\toutput_dir\t- Directory where files will be saved\n");
		return 1;
	}

	for(i = 1; i < argc; i++) {
		c = argv[i][1];
		if(argv[i][0] != '-' || argv[i][2])
			c = -1;
		switch(c) {
		case 'u':
			if(++i < argc) username = argv[i];
			break;
		case 's':
			if(++i < argc) start_port = argv[i];
			break;
		case 'p':
			if(++i < argc) listen_port = argv[i];
			break;
		case 'o':
			if(++i < argc) received_files = argv[i];
			break;
		default:
			break;
		}
	}

	init_crypto();

	// run server
	run();

	// clean up
	clean_ctx();
	free_all_cxns();
	
	return 0;	
}
