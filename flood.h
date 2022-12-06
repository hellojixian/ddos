
/* return random number (0-65535) for spoof source port */
int randomPort(void);

/* return a random valid ip for spoof source ip */
char *randomIp(void);

/* check if the ipv4 is possible not if active */
int validIp(char *ip);

/* Calculate Checksum */
unsigned short checksum(unsigned short *ptr, int nbytes);
