#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>

#include "scomm.h"

static uchar ciphertext[BSIZE];
static uchar plaintext[BSIZE];
static char inbuf[BSIZE];
static char *names[16];
static Proc send_procs[NUM_SENDERS];
static Proc recv_procs[NUM_RECEIVERS];
static int running;

char *
tstamp(void) {
    static char res[25];
    time_t t = time(NULL);

    memcpy(res, asctime(gmtime(&t)), 24);
    res[24] = 0;
    return res;
}

static ssize_t 
writedata(int fd, uchar *buf, size_t buf_len)
{
    ssize_t r, offset = 0;
    uint32_t n;

    n = htonl(buf_len);
    write(fd, &n, sizeof(uint32_t));

    while (offset < buf_len) {
        if ((r = write(fd, buf + offset, buf_len - offset)) == -1) {
            return -1;
        }
        offset += r;
    }
    return offset;
}

static ssize_t 
readdata(int fd, uchar *buf, size_t buf_len)
{
    ssize_t r, offset = 0;
    uint32_t s, len;

    if ((r = read(fd, buf, sizeof(uint32_t))) <= 0)
        return r;
    s = ntohl(*(uint32_t *)buf);
    len = (buf_len < s) ? buf_len : s;

    while (offset < len) {
        if ((r = read(fd, buf + offset, s - offset)) > 0)
            offset += r;
        else
            break;
    }
    return offset;
}

static int 
get_sock(const char *addr, const char *lport)
{
	int sockfd, rv;
	struct addrinfo hints, *servinfo, *p;
	int yes = 1;

	memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (addr == NULL)
        hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(addr, lport, &hints, &servinfo)) != 0)
    	return -1;
    
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
            continue;

        if (addr == NULL) {
        	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
            	return -1;

        	if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            	close(sockfd);
            	continue;
        	}
        } else {
	        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
	            close(sockfd);
	            continue;
	        }
	    }

        break;
    }

    if (p == NULL) 
    	return -1;

    freeaddrinfo(servinfo);

    if (addr == NULL) {
    	if (listen(sockfd, 10) == -1)
    		return -1;
    }

    return sockfd;
}

static Cxn *  
add_cxn(int newfd, char *ip, char *name, uchar *key, uchar *iv, fd_set *set, int *maxfd)
{
    time_t t;
    Cxn *c;

    time(&t);
    if ((c = add_cxn_to_list(newfd, t, ip, name, key, iv)) == NULL) {
        fprintf(stderr, "add_cxn: Failed to add new connection to list\n");
        return NULL;
    }

    if (newfd > *maxfd)
        *maxfd = newfd;
    FD_SET(newfd, set);

    return c;
}

static int 
new_connection(int listenfd, int *maxfd, fd_set *set)
{
    int newfd, soi;
    uint32_t n;
    unsigned long outlen;
    struct sockaddr_in cliaddr; //xx ipv6
    socklen_t clilen;
    uchar buf[128], keytmp[128], *ptr;
    uchar *key=NULL, *iv=NULL;
    char *name=NULL, *ip=NULL;
    Cxn *c;

again:
    clilen = sizeof(struct sockaddr);
    newfd = accept(listenfd, (struct sockaddr *)&cliaddr, &clilen);
    if (newfd < 0) {
        if (errno == EINTR)
            goto again;
        return -1;
    }

    soi = sizeof(uint32_t);

    //send diffie-helman params g,p,g^a
    writedata(newfd, ctx.dhp.packed, ctx.dhp.packed_len);

    //recv g^b mod p and get (g^b)^a mod p and hash it to get key
    if (readdata(newfd, buf, sizeof(buf)) == -1)
        goto err_exit;

    //get key
    ptr = buf;
    n = ntohl( *(uint32_t *)ptr ); ptr += soi;
    outlen = sizeof(keytmp);
    if (get_key(ptr, n, keytmp, &outlen) == -1)
        goto err_exit;
    ptr += n;
    key = zalloc(outlen);
    if (key == NULL)
        goto err_exit;
    memcpy(key, keytmp, outlen);

    //get name
    n = _strlen( ptr );
    name = zalloc(n+1);
    if (name == NULL)
        goto err_exit;
    memcpy(name, ptr, n);

    //generate initialisation vector
    iv = zalloc(ctx.ivsize);
    if (iv == NULL)
        goto err_exit;
    if (get_iv(iv) == -1)
        goto err_exit;

    //send iv
    writedata(newfd, iv, ctx.ivsize);

    //get peer ip
    ip = zalloc(16);
    if (ip == NULL)
        goto err_exit;
    inet_ntop(AF_INET, &cliaddr.sin_addr, ip, 16);

    //add connection to list
    if ((c = add_cxn(newfd, ip, name, key, iv, set, maxfd)) == NULL) {
        fprintf(stderr, "Failed to add new connection\n");
        goto err_exit;
    }

    if (init_send(c) == -1)
        goto err_exit;

    printf("New connection from (%s, %s)\n", name, ip);

    return 0;

err_exit:
    close(newfd);
    if (key != NULL)
        free(key);
    if (iv != NULL)
        free(iv);
    if (ip != NULL)
        free(ip);
    if (name != NULL)
        free(name);
    return -1;
}

//:c 127.0.0.1:9000 - connect to 127.0.0.1 on port 9000
static int 
init_new_connection(char *addr, int *maxfd, fd_set *set)
{
    int newfd, outlen;
    uint32_t ivsize;
    uchar buf[128];
    uchar *key=NULL, *iv=NULL;
    char *name=NULL, *prt=NULL, *ip=NULL;
    Cxn *c;

    prt = strchr(addr, ':');
    if (prt == NULL)
        return -1;

    *prt++ = '\0';
    for (;*addr == ' '; addr++)
        ; //skip leading spaces


    if ((newfd = get_sock(addr, prt)) == -1) {
        fprintf(stderr, "Couldn't connect to %s on port %s\n", addr, prt);
        return -1;
    }

    //recv g,p,g^a mod p & name
    if (readdata(newfd, buf, sizeof(buf)) == -1)
        goto err_exit;

    if (parse_dh_args(buf, &name, &key, &outlen) == -1)
        goto err_exit;

    //send g^b and name
    writedata(newfd, buf, outlen);

    //recv iv
    if ((ivsize = readdata(newfd, buf, sizeof(buf))) == -1)
        goto err_exit;
    iv = zalloc(ivsize);
    if (iv == NULL)
        goto err_exit;
    memcpy(iv, buf, ivsize);

    ip = strdup(addr);
    if ((c = add_cxn(newfd, ip, name, key, iv, set, maxfd)) == NULL) {
        fprintf(stderr, "Failed to add new connection\n");
        goto err_exit;
    }

    if (init_send(c) == -1)
        goto err_exit;

    printf("New connection to %s\n", addr);

    return 0;

err_exit:
    close(newfd);
    if (key != NULL)
        free(key);
    if (iv != NULL)
        free(iv);
    if (ip != NULL)
        free(ip);
    if (name != NULL)
        free(name);
    return -1;

}

//parse ':m @name1,name2,...,namek message' OR ':f @name path/to/local/file'
//rcpt = name(s), tosend = message/file to encrypt and send
static int 
parse_send_cmd(char **rcpts, char **tosend)
{
    for (; **rcpts != '\0' && **rcpts == ' '; (*rcpts)++)
        ; //skip white space
    if (**rcpts == '\0' || *((*rcpts)++) != '@')
        return -1;
    
    for (*tosend = *rcpts; **tosend != '\0' && **tosend != ' '; (*tosend)++)
        ;
    if (**tosend == '\0')
        return -1;
    *((*tosend)++) = '\0';
    return 0;
}

//:m @fred,barny "come pick up wilma, she's wasted" - encrypt string and send to fred & barny
static int 
send_msg(char *rcpt)
{
    if (!rcpt) 
        return -1;

    char *tosend;
    Cxn *c;
    int i, len;

    if (parse_send_cmd(&rcpt, &tosend) == -1)
        return -1;

    for (i = 0; i<16 && *rcpt != '\0';) {
        names[i++] = rcpt;
        rcpt = strchr(rcpt, ',');
        if (rcpt == NULL)
            break;
        *rcpt++ = '\0';
    }

    len = _strlen(tosend);
    while (--i >= 0) {
        c = find_cxn_name(names[i]);
        if (c == NULL) {
            fprintf(stderr, "Couldn't find connection with name %s\n", names[i]);
            continue;
        }

        ciphertext[0] = 'a'; //ascii
        if (encrypt_msg(c, ciphertext+1, (uchar *)tosend, len) == -1) {
            fprintf(stderr, "Failed to encrypt message\n");
            continue;
        }

        writedata(c->sock, ciphertext, len+1);
    }

    return 0;
}

static char * 
basename(char *filename)
{
    if (filename == NULL)
        return NULL;

    char *e;

    e = filename + _strlen(filename) - 1;
    while (*e != '/' && e > filename)
        e--;
    return e + 1;
}

static int 
send_file(char *rcpt)
{
    if (!rcpt) 
        return -1;

    char *tosend; 
    uchar *ptr, *peer_buf_start;
    uchar pt[BSIZE], ct[BSIZE], iv[ctx.ivsize];
    Cxn *c;
    struct stat st;
    int soi;
    uint32_t n, sz, i;

    //Any free processes?
    for (i = 0; i < NUM_SENDERS; i++) {
        if (send_procs[i].busy == 0)
            break;
    }
    if (i == NUM_SENDERS) {
        fprintf(stderr, "No sender processes are free\n");
        return -1;
    }

    if (parse_send_cmd(&rcpt, &tosend) == -1)
        return -1;

    if (stat(tosend, &st) == -1) {
        fprintf(stderr, "Couldn't stat file \"%s\": %s\n", tosend, strerror(errno));
        return -1;
    }

    c = find_cxn_name(rcpt);
    if (c == NULL) {
        fprintf(stderr, "Couldn't find connection with name %s\n", rcpt);
        return -1;
    }

    // new iv for file send
    if (get_iv(iv) == -1)
        return -1;

    //send [process idx,key,iv,filename] to sender process
    //send [iv,filename,filesize,port] to peer
    //build buffer to accomodate both scenarios

    ptr = pt;
    soi = sizeof(uint32_t);
    memcpy(ptr, &i, soi); ptr += soi;
    memcpy(ptr, c->key, ctx.ks); ptr += ctx.ks;
    peer_buf_start = ptr; //save where we want buffer to peer to start
    memcpy(ptr, iv, ctx.ivsize); ptr += ctx.ivsize;
    sz = _strlen(tosend) + 1;
    memcpy(ptr, tosend, sz); ptr += sz;

    //send buffer so far to sender process
    sz = ptr - pt;
    write(send_procs[i].fds[1], pt, sz);

    n = htonl(st.st_size);
    memcpy(ptr, &n, soi); ptr += soi;
    sz = _strlen(send_procs[i].port) + 1;
    memcpy(ptr, send_procs[i].port, sz); ptr += sz;

    sz = ptr - peer_buf_start;

    //encrypt and send rest to receiver (omit process idx + key)
    ct[0] = 'b'; //binary
    if (encrypt_msg(c, ct+1, peer_buf_start, sz) == -1) {
        fprintf(stderr, "Failed to encrypt file info\n");
        return -1;
    }

    writedata(c->sock, ct, sz+1);

    return 0;
}

static int 
handle_stdin(int *maxfd, fd_set *set)
{
    char *p;

    if (!fgets(inbuf, sizeof(inbuf)-1, stdin))
        return -1;

    p = strchr(inbuf, '\n');
    if (p != NULL)
        *p = '\0';

    if (inbuf[0] == ':' && (inbuf+2)) {
        switch (inbuf[1]) {
            case 'c':
                //connect
                init_new_connection( inbuf+2, maxfd, set );
                break;
            case 'm':
                //message
                send_msg( inbuf + 2 );
                break;
            case 'f':
                send_file( inbuf + 2 );
                break;
            case 'q':
                //quit
                running = 0;
                break;
            case 'i':
                //print active connections
                print_cxns();
                break;
            default:
                return -1;
        }
    } else return -1; //invalid command

    return 0;
}

// either an encrypted ascii message (first byte 'a')
// or file send request (first byte 'b')
static int 
recv_message(int s, int sz)
{
    Cxn *c;
    uint32_t filesize, i;
    uchar pt[BSIZE], iv[16], *ptr;
    char intmp[8], *filename;

    c = find_cxn_sock(s);
    if (c == NULL) {
        fprintf(stderr, "Couldn't find connection with socket %d\n", s);
        return -1;
    }

    sz--;
    if (ciphertext[0] == 'b') {
        //binary

        //Any free processes?
        for (i = 0; i < NUM_RECEIVERS; i++) {
            if (recv_procs[i].busy == 0)
                break;
        }
        if (i == NUM_RECEIVERS) {
            fprintf(stderr, "No receiver processes free\n");
            return -1;
        }

        if (decrypt_msg(c, pt, ciphertext+1, sz) == -1) {
            fprintf(stderr, "Failed to decrypt message\n");
            return -1;
        }

        //recv [iv, filename, filesize, port]
        ptr = pt;
        memcpy(iv, ptr, ctx.ivsize); ptr += ctx.ivsize;
        filename = basename((char*) ptr);
        ptr += _strlen(ptr) + 1;
        filesize = ntohl(*(uint32_t *)ptr); ptr += sizeof(uint32_t);
        printf("%s wants to send you the file \"%s\" (%d bytes). ", c->name, filename, filesize);

        intmp[0] = '\0';
        while (intmp[0] != 'y' && intmp[0] != 'n') {
            printf("Accept [y/n]? \n");
            fgets(intmp, sizeof(intmp)-1, stdin);
        }

        if (intmp[0] == 'y') {
            // add process index, key, peer ip to buffer
            ptr += _strlen(ptr) + 1; //skip port
            memcpy(ptr, &i, sizeof(uint32_t)); ptr += sizeof(uint32_t); // process index
            memcpy(ptr, c->key, ctx.ks); ptr += ctx.ks; // key
            sz = _strlen(c->ip) + 1;
            memcpy(ptr, c->ip, sz); ptr += sz; // peer ip
            sz = ptr - pt;

            // send info to receiver process and let it do its thing
            write(recv_procs[i].fds[1], pt, sz);
        }
    } else if (ciphertext[0] == 'a') {
        //ascii
        if (decrypt_msg(c, plaintext, ciphertext+1, sz) == -1) {
            fprintf(stderr, "Failed to decrypt message\n");
            return -1;
        }

        plaintext[sz] = '\0';
        printf("[%s %s] %s\n", tstamp(), c->name, plaintext);
    } else {
        fprintf(stderr, "Unknown message format received from %s\n", c->name);
    }
    
    return 0;
}

void
sighandler(int sig)
{
    switch (sig) {
        case SIGTERM:
            running = 0;
            break;
        case SIGCHLD:
            while(0 < waitpid(-1, NULL, WNOHANG));
            break;
    }
}

static int 
init_loop(int srv, int *signal_fds_s, int *signal_fds_r)
{
    int rv, maxfd, i;
    fd_set master, rset;
    uchar buf[128];
    uint32_t idx;

    FD_ZERO(&master);
    FD_ZERO(&rset);

    FD_SET(0, &master);
    FD_SET(srv, &master);

    maxfd = srv;
    FD_SET(signal_fds_s[0], &master);
    if (signal_fds_s[0] > maxfd)
        maxfd = signal_fds_s[0];
    FD_SET(signal_fds_r[0], &master);
    if (signal_fds_r[0] > maxfd)
        maxfd = signal_fds_r[0];

    // Close write-end of signal pipe
    close(signal_fds_s[1]);
    close(signal_fds_r[1]);

    while (running) {
        rset = master;
        rv = select(maxfd+1, &rset, NULL, NULL, NULL);

        if (rv == -1) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "select(): %s\n", strerror(errno));
            break;
        }

        if (FD_ISSET(0, &rset)) {
            handle_stdin(&maxfd, &master);
        } else if (FD_ISSET(srv, &rset)) {
            if((rv = new_connection(srv, &maxfd, &master)) == -1)
               fprintf(stderr, "New connection failed: %s\n", strerror(errno)); 
        } else if (FD_ISSET(signal_fds_s[0], &rset)) {
            // a sender process sent us a signal
            read(signal_fds_s[0], buf, sizeof(uint32_t)+1);
            idx = *(uint32_t *)buf;
            send_procs[idx].busy = (buf[sizeof(uint32_t)] == '1') ? 1 : 0;
        } else if (FD_ISSET(signal_fds_r[0], &rset)) {
            // a receiver process sent us a signal
            read(signal_fds_r[0], buf, sizeof(uint32_t)+1);
            idx = *(uint32_t *)buf;
            recv_procs[idx].busy = (buf[sizeof(uint32_t)] == '1') ? 1 : 0;
        } else {
            //existing connection
            for (i = 1; i <= maxfd; i++) {
                if (FD_ISSET(i, &rset)) {
                    rv = readdata(i, ciphertext, sizeof(ciphertext));
                    if (rv <= 0) {
                        FD_CLR(i, &master);
                        free_cxn(i);
                    } else {
                        recv_message(i, rv);
                    }
                }
            }
        }
    }

    // Done with signal pipes
    close(signal_fds_s[0]);
    close(signal_fds_r[0]);

    return 0;
}

//file sender process
static void 
init_send_proc(int *fds, int *signal_fds, char *prt)
{
    int n, s, pid, fd, newfd, maxfdp1;
    struct sockaddr_in cliaddr;
    socklen_t clilen;
    uchar *ptr, pt[BSIZE], ct[BSIZE], key[128], iv[16], sig[8];
    Cxn dummy;
    fd_set rset, master;

    pid = fork();
    if (pid == 0) {
        close(fds[1]);
        close(signal_fds[0]);

        if ((s = get_sock(NULL, prt)) == -1) {
            fprintf(stderr, "get_sock: %s\n", strerror(errno));
            exit(1);
        }

        FD_ZERO(&rset);
        FD_ZERO(&master);
        FD_SET(s, &master);
        FD_SET(fds[0], &master);
        maxfdp1 = (s > fds[0]) ? s : fds[0]; maxfdp1++;

        for (;;) {
            rset = master;
            if (select(maxfdp1, &rset, NULL, NULL, NULL) == -1) {
                fprintf(stderr, "select: %s\n", strerror(errno));
                close(s);
                break;
            }

            if (FD_ISSET(fds[0], &rset)) {
                //get key/iv/filename
                if ((n = read(fds[0], pt, sizeof(pt))) <= 0)
                    break;

                ptr = pt;

                // fill 'sig' with idx of process in array along with 1 or 0.
                // 1=busy sending, 0=free
                memcpy(sig, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);

                memcpy(key, ptr, ctx.ks); ptr += ctx.ks;
                memcpy(iv, ptr, ctx.ivsize); ptr += ctx.ivsize;

                dummy.IV = iv;
                dummy.key = key;

                if (init_send(&dummy) == -1)
                    continue;
            } else if (FD_ISSET(s, &rset)) {
                clilen = sizeof(struct sockaddr);
                newfd = accept(s, (struct sockaddr *)&cliaddr, &clilen);
                if (newfd < 0) {
                    fprintf(stderr, "accept: %s\n", strerror(errno));
                    close(s);
                    exit(1);
                }

                if ((fd = open((char *)ptr, O_RDONLY)) == -1) {
                    fprintf(stderr, "sender: Couldn't open %s: %s\n", ptr, strerror(errno));
                    continue;
                }

                // Send 'busy' signal
                sig[sizeof(uint32_t)] = '1';
                write(signal_fds[1], sig, sizeof(uint32_t)+1); //tell parent we're busy sending

                printf("File \"%s\" sending...\n", ptr);

                // Start sending
                while ((n = read(fd, pt, sizeof(pt))) > 0) {
                    if (encrypt_msg(&dummy, ct, pt, n) == -1) {
                        fprintf(stderr, "failed to encrypt file\n");
                        break;
                    }
                    write(newfd, ct, n);
                }

                // Send 'done' signal
                sig[sizeof(uint32_t)] = '0';
                write(signal_fds[1], sig, sizeof(uint32_t)+1);

                printf("File sent\n");

                close(newfd);
                close(fd);
            }
        }

        close(s);
        close(fds[0]);
        exit(0);
    } else if (pid == -1) {
        die("fork: %s\n", strerror(errno));
    }
    close(fds[0]);
}

//file receiver process
static void 
init_recv_proc(int *fds, int *signal_fds)
{
    int s, fd, pid, r;
    uchar *ptr, sig[8], iv[16], key[128], pt[BSIZE], ct[BSIZE];
    char *lport, *filename, *ip;
    uint32_t filesize;
    Cxn dummy;

    // create new file mode
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;

    chdir(received_files);

    pid = fork();
    if (pid == 0) {
        close(fds[1]);
        close(signal_fds[0]);

        for (;;) {
            if ((r = read(fds[0], pt, sizeof(pt))) <= 0) {
                if (r < 0)
                    fprintf(stderr, "read: %s\n", strerror(errno));
                break;
            }

            //receive [iv,filename,filesize,port,proc idx,key,peerip]
            ptr = pt;
            memcpy(iv, ptr, ctx.ivsize); ptr += ctx.ivsize; //iv
            filename = basename((char *)ptr); //filename
            ptr += _strlen(ptr) + 1;
            filesize = ntohl(*(uint32_t *)ptr); //filesize
            ptr += sizeof(uint32_t);
            lport = (char*) ptr; //port
            ptr += _strlen(ptr) + 1;
            memcpy(sig, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t); // process index
            memcpy(key, ptr, ctx.ks); ptr += ctx.ks; // key
            ip = (char *)ptr; // peer ip

            dummy.IV = iv;
            dummy.key = key;

            if (init_send(&dummy) == -1) {
                fprintf(stderr, "failed to init crypto to receive file\n");
                continue;
            }

            if ((s = get_sock(ip, lport)) == -1) {
                fprintf(stderr, "Couldn't connect to %s on port %s\n", ip, lport);
                continue;
            }

            if ((fd = open(filename, O_WRONLY | O_EXCL | O_CREAT, mode)) == -1) {
                close(s);
                fprintf(stderr, "receiver: Couldn't open %s\n", filename);
                continue;
            }  

            // Send 'busy' signal
            sig[sizeof(uint32_t)] = '1';
            write(signal_fds[1], sig, sizeof(uint32_t)+1);

            printf("Receiving file \"%s\"...\n", filename);

            // Start saving file
            uint32_t offset = 0;
            while (offset < filesize) {
                if ((r = read(s, ct, sizeof(ct))) <= 0) {
                    fprintf(stderr, "read failed");
                    break;
                }

                if (decrypt_msg(&dummy, pt, ct, r) == -1) {
                    fprintf(stderr, "decrypt failed");
                    break;
                }

                write(fd, pt, r);

                offset += r;
            }

            // Send 'done' signal
            sig[sizeof(uint32_t)] = '0';
            write(signal_fds[1], sig, sizeof(uint32_t)+1);

            printf("File received\n");

            close(s);
            close(fd);
        }

        close(fds[0]);
        close(signal_fds[1]);
        exit(0);
    } else if (pid == -1) {
        die("fork: %s\n", strerror(errno));
    }
    close(fds[0]);
}

void 
run()
{
    int i, srv, signal_fds_s[2], signal_fds_r[2];
    unsigned int prt;
    char buf[32];

    running = 1;

    if (pipe(signal_fds_s) < 0)
        return;
    if (pipe(signal_fds_r) < 0)
        return;

    // Initialise sender processes
    strncpy(buf, start_port, sizeof(buf));
    prt = strtoul(buf, NULL, 10);
    for (i = 0; i < NUM_SENDERS; i++) {
        send_procs[i].busy = 0;
        strncpy(send_procs[i].port, buf, sizeof(send_procs[i].port));
        pipe(send_procs[i].fds);
        init_send_proc(send_procs[i].fds, signal_fds_s, buf);
        snprintf(buf, sizeof(buf), "%u", ++prt);

    }

    //Initialise receiver processes
    for (i = 0; i < NUM_RECEIVERS; i++) {
        recv_procs[i].busy = 0;
        pipe(recv_procs[i].fds);
        init_recv_proc(recv_procs[i].fds, signal_fds_r);
    }

    signal(SIGCHLD, sighandler);
    signal(SIGTERM, sighandler);

    // Setup parent listening socket
    if ((srv = get_sock(NULL, listen_port)) == -1)
        die("init_sock failed: %s\n", strerror(errno));
    
    init_loop(srv, signal_fds_s, signal_fds_r);

    //close write-end of sender/receiver process pipe fds
    for (i = 0; i < NUM_SENDERS; i++)
        close(send_procs[i].fds[1]);
    for (i = 0; i < NUM_RECEIVERS; i++)
        close(recv_procs[i].fds[1]);
}
