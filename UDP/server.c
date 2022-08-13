// Server side implementation of UDP client-server model
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define PORT 8080
#define MAXLINE 1024

int main() {
    int sockfd;
    char buffer[MAXLINE];  // Create buffer of size MAXLINE to hold 1024 characters
    char *message = "This is a test message from server";

    // Socket addresses to hold the server address and client address
    struct sockaddr_in serveraddr, clientaddr;

    // AF_INET means IPv4 address and SOCK_DGRAM means UDP Connection
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        printf("ERROR creating socket");
        exit(1);
    }

    // Clear garbage memory of both address variables
    memset(&serveraddr, 0, sizeof(serveraddr));
    memset(&clientaddr, 0, sizeof(clientaddr));

    // Configure the server address, INADDR_ANY means that sockets from any IP can connect to it
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = INADDR_ANY;
    serveraddr.sin_port = PORT;

    if (bind(sockfd, (const struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
        printf("BIND failed");
        exit(1);
    }

    int len, n;

    // Recieve a message from the client and store the client address
    n = recvfrom(sockfd, (char *)buffer, MAXLINE, MSG_WAITALL, (struct sockaddr *)&clientaddr, &len);
    buffer[n] = '\0';
    printf("CLIENT SAID: %s\n", buffer);

    // Send a message back to the client using the given client address
    sendto(sockfd, (const char *)message, strlen(message), MSG_CONFIRM, (struct sockaddr *)&clientaddr, len);
    printf("MESSAGE SENT TO CLIENT\n");

    return 0;
}
