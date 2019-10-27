#include<arpa/inet.h>
#include<netinet/in.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/socket.h>

typedef unsigned int dns_rr_ttl;
typedef unsigned short dns_rr_type;
typedef unsigned short dns_rr_class;
typedef unsigned short dns_rdata_len;
typedef unsigned short dns_rr_count;
typedef unsigned short dns_query_id;
typedef unsigned short dns_flags;

typedef struct {
	char *name;
	dns_rr_type type;
	dns_rr_class class;
	dns_rr_ttl ttl;
	dns_rdata_len rdata_len;
	unsigned char *rdata;
} dns_rr;

struct dns_answer_entry;
struct dns_answer_entry {
	char *value;
	struct dns_answer_entry *next;
};
typedef struct dns_answer_entry dns_answer_entry;

const int MAXLENGTH = 2000;

void free_answer_entries(dns_answer_entry *ans) {
	dns_answer_entry *next;
	while (ans != NULL) {
		next = ans->next;
		free(ans->value);
		free(ans);
		ans = next;
	}
}

void print_bytes(unsigned char *bytes, int byteslen) {
	int i, j, byteslen_adjusted;
	unsigned char c;

	if (byteslen % 8) {
		byteslen_adjusted = ((byteslen / 8) + 1) * 8;
	} else {
		byteslen_adjusted = byteslen;
	}
	for (i = 0; i < byteslen_adjusted + 1; i++) {
		if (!(i % 8)) {
			if (i > 0) {
				for (j = i - 8; j < i; j++) {
					if (j >= byteslen_adjusted) {
						printf("  ");
					} else if (j >= byteslen) {
						printf("  ");
					} else if (bytes[j] >= '!' && bytes[j] <= '~') {
						printf(" %c", bytes[j]);
					} else {
						printf(" .");
					}
				}
			}
			if (i < byteslen_adjusted) {
				printf("\n%02X: ", i);
			}
		} else if (!(i % 4)) {
			printf(" ");
		}
		if (i >= byteslen_adjusted) {
			continue;
		} else if (i >= byteslen) {
			printf("   ");
		} else {
			printf("%02X ", bytes[i]);
		}
	}
	printf("\n");
}

void canonicalize_name(char *name) {
	/*
	 * Canonicalize name in place.  Change all upper-case characters to
	 * lower case and remove the trailing dot if there is any.  If the name
	 * passed is a single dot, "." (representing the root zone), then it
	 * should stay the same.
	 *
	 * INPUT:  name: the domain name that should be canonicalized in place
	 */

	int namelen, i;

	// leave the root zone alone
	if (strcmp(name, ".") == 0) {
		return;
	}

	namelen = strlen(name);
	// remove the trailing dot, if any
	if (name[namelen - 1] == '.') {
		name[namelen - 1] = '\0';
	}

	// make all upper-case letters lower case
	for (i = 0; i < namelen; i++) {
		if (name[i] >= 'A' && name[i] <= 'Z') {
			name[i] += 32;
		}
	}
}


int name_ascii_to_wire(char *name, unsigned char *wire)
{
	const char separator[2] = ".";
	int offset = 0;

	char *token;

	//get first token
	token = strtok(name, separator);

	//add to wire and then get rest of tokens
	while (token)
	{
		//add length of next section to wire
		unsigned char tokenLength = (unsigned char)strlen(token);
		*wire = tokenLength;
		wire++;
		offset++;

		//add each character to wire
		for (unsigned char i = 0; i < tokenLength; i++)
		{
			*wire = (unsigned char)token[i];
			wire++;
			offset++;
		}

		token = strtok(NULL, separator);
	}

	return offset;
}

//Helper function to convert the next two unsigned chars in network order (by placement) to an unsigned short in host order.
unsigned short charsToShort(unsigned char *wire, int byteOffset)
{
	unsigned char toJoin[] = {wire[byteOffset++], wire[byteOffset]};

	unsigned short beforeEndianConversion;

	memcpy(&beforeEndianConversion, toJoin, 2);

	return ntohs(beforeEndianConversion);
}

/* 
	 * Extract the wire-formatted DNS name at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return its string
	 * representation (dot-separated labels) in a char array allocated for
	 * that purpose.  Update the value pointed to by indexp to the next
	 * value beyond the name.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp, a pointer to the index in the wire where the wire-formatted name begins
	 * OUTPUT: a string containing the string representation of the name, allocated on the heap.
	 */
char *name_ascii_from_wire(unsigned char *wire, int *indexp)
{
	char *name = (char *)malloc(/*sizeof(char) * */ 200);
	int nameIndex = 0;

	while (wire[*indexp])
	{
		//This section of name is compresed and must be extracted from elsewhere in the wire.
		if (wire[*indexp] >= 192)
		{
			(*indexp)++;
			unsigned char beginningIndex = wire[*indexp];
			
			while (wire[beginningIndex])
			{
				if (wire[beginningIndex] >= 192) ///Need to add recursive decompression
				{
					beginningIndex++;
					int offset = (int)wire[beginningIndex];
					char *compressedSection = name_ascii_from_wire(wire, &offset);
					int sectionLength = strlen(compressedSection);
					for(int i = 0; i < sectionLength; i++)
					{
						name[nameIndex++] = compressedSection[i];
					}
					
					break;
				}

				else
				{
					char sectionLength = wire[beginningIndex++];
					
					for (int i = 0; i < sectionLength; i++)
					{
						name[nameIndex++] = wire[beginningIndex++];
					}
					name[nameIndex++] = '.';
				}
			}
			//Once you go to compression then you are done with the name.
			break;
		}
		else //This section of the name is not compressed.
		{
			char sectionLength = wire[(*indexp)++];

			for (int i = 0; i < sectionLength; i++)
			{
				name[nameIndex++] = wire[(*indexp)++];
			}
			name[nameIndex++] = '.';
		}
	}
	(*indexp)++;

	return name;
}

/* 
	 * Extract the wire-formatted resource record at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return a 
	 * dns_rr (struct) populated with its contents. Update the value
	 * pointed to by indexp to the next value beyond the resource record.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp: a pointer to the index in the wire where the wire-formatted resource record begins
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether we are extracting a full resource record or only a query (i.e., in the question section
	 *  of the DNS message).  In the case of the latter, the ttl, rdata_len, and rdata are skipped.
	 * OUTPUT: the resource record (struct)
	 */
dns_rr rr_from_wire(unsigned char *wire, int *indexp, int query_only)
{
	dns_rr resourceRecord;

	resourceRecord.name = name_ascii_from_wire(wire, indexp);
	
	resourceRecord.type = charsToShort(wire, *indexp);
	*indexp += 2;
	
	resourceRecord.class = charsToShort(wire, *indexp);
	*indexp += 2;

	unsigned char TTLBytes[4];

	TTLBytes[0] = wire[(*indexp)++];
	TTLBytes[1] = wire[(*indexp)++];
	TTLBytes[2] = wire[(*indexp)++];
	TTLBytes[3] = wire[(*indexp)++];

	int ttl;

	memcpy(&ttl, TTLBytes, 4);

	resourceRecord.ttl = ntohl(ttl);

	resourceRecord.rdata_len = charsToShort(wire, *indexp);
	*indexp += 2;

	unsigned char *rData = (unsigned char *)malloc(resourceRecord.rdata_len);

if(resourceRecord.type == 1)
{
	for (int i = 0; i < resourceRecord.rdata_len; i++)
	{
		rData[i] = wire[(*indexp)++];
	}
}
else if(resourceRecord.type == 5)
{
	rData = (unsigned char *) name_ascii_from_wire(wire, indexp);
}
	resourceRecord.rdata = rData;

	return resourceRecord;
}

/* 
	 * Convert a DNS resource record struct to DNS wire format, using the
	 * provided byte array (wire).  Return the number of bytes used by the
	 * name in wire format.
	 *
	 * INPUT:  rr: the dns_rr struct containing the rr record
	 * INPUT:  wire: a pointer to the array of bytes where the
	 *             wire-formatted resource record should be constructed
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are constructing a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the length of the wire-formatted resource record.
	 *
	 */
int rr_to_wire(dns_rr rr, unsigned char *wire, int query_only)
{

	if (query_only)
	{
		dns_rr_class class = rr.class;

		unsigned char class1 = *((unsigned char *)&class);
		unsigned char class2 = *((unsigned char *)&class + 1);
		unsigned char type1 = 0; 
		unsigned char type2 = 1; 

		*wire = type1;
		wire++;
		*wire = type2;
		wire++;
		*wire = class1;
		wire++;
		*wire = class2;

		return 4;
	}
	else
	{
		fprintf(stderr, "rr_to_wire was somehow called for a non-query RR.\n");
		return 0;
	}
}

/* 
	* Create a wire-formatted DNS (query) message using the provided byte
	* array (wire).  Create the header and question sections, including
	* the qname and qtype.
	*
	* INPUT:  qname: the string containing the name to be queried
	* INPUT:  qtype: the integer representation of type of the query (type A == 1)
	* INPUT:  wire: the pointer to the array of bytes where the DNS wire message should be constructed
	* OUTPUT: the length of the DNS wire message
*/
unsigned short create_dns_query(char *qname, dns_rr_type qtype, unsigned char *wire){
	unsigned short wireLen = 0;
	dns_flags flags = htons(0x0100);

	//Create random queryID
	srand(time(NULL));
	dns_query_id queryID = (unsigned short)rand();

	unsigned char ID1 = *((unsigned char *)&queryID);
	unsigned char ID2 = *((unsigned char *)&queryID + 1);
	unsigned char flags1 = *((unsigned char *)&flags);
	unsigned char flags2 = *((unsigned char *)&flags + 1);

	//add queryID
	*wire = ID1;
	wire++;
	wireLen++;
	*wire = ID2;
	wire++;
	wireLen++;

	//add flags
	*wire = flags1;
	wire++;
	wireLen++;
	*wire = flags2;
	wire++;
	wireLen++;

	//Add question (1)
	*wire = 0;
	wire++;
	wireLen++;
	*wire = 0x01;
	wire++;
	wireLen++;

	//No RR's
	for (int i = 0; i < 6; i++){
		*wire = 0;
		wire++;
		wireLen++;
	}

	//convert query name to unsigned char array
	int numNameBytes = name_ascii_to_wire(qname, wire);
	//add them to array
	wireLen += numNameBytes;
	wire += numNameBytes;

	dns_rr rr;
	rr.class = htons(0x0001);
	rr.type = qtype;

	int numRRBytes = rr_to_wire(rr, wire, 1);
	if(numRRBytes == 0){
		fprintf(stderr, "Failed to convert resource record to DNS format!\n");
		exit(-1);
	}
	wireLen += (unsigned short)numRRBytes;
	wire += numRRBytes;

	return wireLen;
}

/* 
	 * Extract the IPv4 address from the answer section, following any
	 * aliases that might be found, and return the string representation of
	 * the IP address.  If no address is found, then return NULL.
	 *
	 * INPUT:  qname: the string containing the name that was queried
	 * INPUT:  qtype: the integer representation of type of the query (type A == 1)
	 * INPUT:  wire: the pointer to the array of bytes representing the DNS wire message
	 * OUTPUT: a linked list of dns_answer_entrys the value member of each
	 * reflecting either the name or IP address.  If
	 */
dns_answer_entry *get_answer_address(char *qname, dns_rr_type qtype, unsigned char *wire)
{
	//remove header and check for proper response
	int byteOffset = 0;
	//skip identification
	byteOffset += 2;

	//Test beginning of header
	if (wire[byteOffset++] != 0x81 || wire[byteOffset++] != 0x80 || wire[byteOffset++] != 0 || wire[byteOffset++] != 0x01)
	{
		//fprintf(stderr, "Beginning of response header is incorrect!\n");
	}

	//Get RR count
	unsigned short RRCount = charsToShort(wire, byteOffset);
	byteOffset += 2;
	unsigned short authorityRRCount = charsToShort(wire, byteOffset);
	byteOffset += 2;
	unsigned short additionalRRCount = charsToShort(wire, byteOffset);
	byteOffset += 2;

	unsigned short totalRRCount = RRCount + authorityRRCount + additionalRRCount;
	//If no RR's found then we return NULL
	if (!totalRRCount)
	{
		return NULL;
	}
	//we can skip the question header we don't need it
	while (wire[byteOffset] != 0x00)
	{
		unsigned char sectionLength = wire[byteOffset++];
		byteOffset += sectionLength;
	}

	byteOffset += 5;

	//Now we begin extracting RR's
	dns_rr RRarray[totalRRCount];
	int arrayIndex = 0;

	dns_answer_entry *answerEntries = NULL;
	dns_answer_entry *nextEntry = NULL;

	//Gather all RR's
	for (; arrayIndex < totalRRCount; arrayIndex++)
	{
		RRarray[arrayIndex] = rr_from_wire(wire, &byteOffset, 0);
	}

	//Initialize RR list
	if (arrayIndex)
	{
		if (RRarray[0].type == qtype || RRarray[0].type == 5)
		{
			nextEntry = (dns_answer_entry *)malloc(sizeof(dns_answer_entry));
		
			answerEntries = nextEntry;

			if (RRarray[0].type == qtype)
			{
				nextEntry->value = (char *)malloc(INET_ADDRSTRLEN);
				inet_ntop(AF_INET, RRarray[0].rdata, nextEntry->value, INET_ADDRSTRLEN);
			}
			else if (RRarray[0].type == 5) //Name is an alias
			{
				canonicalize_name((char *)RRarray[0].rdata);
				nextEntry->value = (char *)RRarray[0].rdata;
			}
		}
	}

	//Create rest of list
	for (int i = 1; i < arrayIndex; i++)
	{
		if (RRarray[i].type == qtype || RRarray[i].type == 5)
		{
			nextEntry->next = (dns_answer_entry *)malloc(sizeof(dns_answer_entry));
			nextEntry = nextEntry->next;

			nextEntry->next = NULL;

			if (RRarray[i].type == qtype)
			{
				nextEntry->value = (char *)malloc(INET_ADDRSTRLEN);
				inet_ntop(AF_INET, RRarray[i].rdata, nextEntry->value, INET_ADDRSTRLEN);
				}
			else if (RRarray[i].type == 5) //Name is an alias
			{
				canonicalize_name((char *)RRarray[i].rdata);
				nextEntry->value = (char *)RRarray[i].rdata;
			}
		}
	}
	return answerEntries;
}

/* 
	 * Send a message (request) over UDP to a server (server) and port
	 * (port) and wait for a response, which is placed in another byte
	 * array (response).  Create a socket, "connect()" it to the
	 * appropriate destination, and then use send() and recv();
	 *
	 * INPUT:  request: a pointer to an array of bytes that should be sent
	 * INPUT:  requestlen: the length of request, in bytes.
	 * INPUT:  response: a pointer to an array of bytes in which the response should be received
	 * OUTPUT: the size (bytes) of the response received
	 */
int send_recv_message(unsigned char *request, int requestlen, unsigned char *response, char *server, unsigned short port)
{
	struct sockaddr_in ip4addr;

	ip4addr.sin_family = AF_INET;
	ip4addr.sin_port = htons(port);

	inet_pton(AF_INET, server, &ip4addr.sin_addr);

	int sfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (connect(sfd, (struct sockaddr *)&ip4addr, sizeof(struct sockaddr_in)) < 0)
	{
		fprintf(stderr, "Could not connect!\n");
		exit(EXIT_FAILURE);
	}

	if (write(sfd, request, requestlen) != requestlen)
	{
		fprintf(stderr, "Partial or failed transmission to DNS server!\n");
		exit(EXIT_FAILURE);
	}

	int nread = read(sfd, response, MAXLENGTH);

	if (nread == -1)
	{
		perror("read");
		exit(EXIT_FAILURE);
	}

	return nread;
}

dns_answer_entry *resolve(char *qname, char *server, char* port){
	unsigned char initQWire[MAXLENGTH];
	dns_rr_type qtype = 1;
	//Create DNS-friendly query
	unsigned short wireLength = create_dns_query(qname, qtype, initQWire);

	unsigned char finalQWire[wireLength];

	for (int i = 0; i < wireLength; i++){
		finalQWire[i] = initQWire[i];
	}

	//Send query
	unsigned char responseWire[MAXLENGTH];
	send_recv_message(finalQWire, wireLength, responseWire, server, 53);

	return get_answer_address(qname, qtype, responseWire);
}

int main(int argc, char *argv[]){
	char *port;
	dns_answer_entry *ans_list, *ans;
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <domain name> <server> [ <port> ]\n", argv[0]);
		exit(1);
	}
	if (argc > 3) {
		port = argv[3];
	} else {
		port = "53";
	}
	ans = ans_list = resolve(argv[1], argv[2], port);
	while (ans != NULL) {
		printf("%s\n", ans->value);
		ans = ans->next;
	}
	if (ans_list != NULL) {
		free_answer_entries(ans_list);
	}
}