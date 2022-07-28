// Client side implementation of UDP client-server model 
// Run this file after compiling and running the server.c file
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
    
#define PORT    8080 
#define MAXLINE 1024 
    
int main(){
    int sockfd;
    char buffer[MAXLINE];  // Create buffer of size MAXLINE to hold 1024 characters
    char *message = "This is a test message from server";

    struct sockaddr_in serveraddr;

    // Create the socket: AF_INET indicates that we are using IPv4 addresses and SOCK_DGRAM means UDP connection
    // The last 0 can be ignored as it is always included
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) { // THe socket function returns -1 if it got an error
        printf("ERROR creating socket");
        exit(1);
    }

    // Clear the bits of the serveraddr to avoid garbage memory
    memset(&serveraddr, 0, sizeof(serveraddr));
    
    serveraddr.sin_family = AF_INET;
    // INADDR_ANY tells it to send the packets to any socket with the correct PORT
    serveraddr.sin_addr.s_addr = INADDR_ANY;
    serveraddr.sin_port = PORT;

    int n, len;

    // Send and recieve messages
    sendto(sockfd, (const char *) message, strlen(message), MSG_CONFIRM, (const struct sockaddr *) &serveraddr, sizeof(serveraddr));
    printf("MESSAGE SENT\n");

    n = recvfrom(sockfd, (char *) buffer, MAXLINE, MSG_WAITALL, (struct sockaddr *) &serveraddr, &len);
    buffer[n] = '\0';
    printf("SERVER SAID: %s\n", buffer);
    
    // Close the socket
    close(sockfd);

    return 0;
}