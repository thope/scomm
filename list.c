#include "scomm.h"

static Node *head = NULL;

static Node *
new_node(int s, time_t t, char *ip, char *name, uchar *key, uchar *iv)
{
	Node *n = zalloc(sizeof(Node));
	if (n == NULL)
		return NULL;
	n->c.sock = s;
	n->c.ts = t;
	n->c.ip = ip;
	n->c.name = name;
	n->c.key = key;
	n->c.IV = iv;
	n->next = NULL;
	return n;
}

static void 
insert_node(Node *n)
{
	if (head == NULL) {
		head = n;
	} else {
		Node *tmp;
		for (tmp = head; tmp->next != NULL; tmp = tmp->next)
			;
		tmp->next = n;
	}
}

Cxn * 
add_cxn_to_list(int s, time_t t, char *ip, char *name, uchar *key, uchar *iv)
{
	Node *new = new_node(s, t, ip, name, key, iv);
	if (new == NULL)
		return NULL;
	insert_node(new);
	return &(new->c);
}

Cxn * 
find_cxn_sock(int s)
{
	Node *tmp;
	for (tmp = head; tmp != NULL; tmp = tmp->next) {
		if (tmp->c.sock == s)
			return &(tmp->c);
	}
	return NULL;
}

Cxn * 
find_cxn_name(char *name)
{
	Node *tmp;
	for (tmp = head; tmp != NULL; tmp = tmp->next) {
		if (!strcmp(name, tmp->c.name))
			return &(tmp->c);
	}
	return NULL;
}

static void 
free_node(Node *n)
{
	if (n != NULL) {
		printf("Connection to %s lost\n", n->c.name);
		close(n->c.sock);
		free(n->c.name);
		free(n->c.ip);
		free(n->c.IV);
		free(n->c.key);
		free(n);
	}
}

void 
free_all_cxns()
{
	Node *tmp, *prev;
	tmp = head;
	for (;;) {
		if (tmp == NULL)
			break;
		prev = tmp;
		tmp = tmp->next;
		free_node(prev);
	}
}


void 
free_cxn(int s)
{
	Node *tmp, *prev;

	if (head == NULL)
		return;

	if (head->c.sock == s) {
		tmp = head;
		head = head->next;
		free_node(tmp);
	} else {
		for (prev = head, tmp = head->next; tmp != NULL; prev = tmp, tmp = tmp->next) {
			if (tmp->c.sock == s) {
				prev->next = tmp->next;
				free_node(tmp);
				break;
			}
		}
	}
}

void 
print_cxns()
{
	Node *tmp;
	printf("Active connections:\n");
	for (tmp = head; tmp != NULL; tmp = tmp->next) {
		printf("  * NAME=\"%s\" on ADDRESS=\"%s\" SOCKET %d\n", tmp->c.name, tmp->c.ip, tmp->c.sock);
	}
}
