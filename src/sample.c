/* Copyright (c) 2016, Jaguar Land Rover. All Rights Reserved.
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0.
 */

#include <string.h>
#include <time.h>

#include "rvi.h"
#include "jansson.h"

#define BUFSIZE 256
#define LEN 10

void callbackFunc(int fd, void *service_data, json_t *parameters);

void waitFor(unsigned int secs);

void processChoice( int choice );
 
void listChoices(void); 

void smpl_initialize(void);

void smpl_connect(void);

void smpl_disconnect(void);

void get_connections(void);

void register_service(void);

void unregister_service(void);

void get_services(void);

void smpl_invoke(void);

void smpl_process(void);

void smpl_shutdown(void);

rvi_handle myHandle = {0};

int main(int argc, char *argv[])
{
    int choice;

    listChoices();

    while ( scanf("%d", &choice) ) {
        processChoice( choice );
        printf("Make a choice: ");
    }

    return 0;
}

void callbackFunc(int fd, void *service_data, json_t *parameters)
{
    printf("inside the callback function\n");
}

void waitFor(unsigned int secs) 
{
    unsigned int retTime = time(0) + secs;  /* Get end time */
    while( time(0) < retTime);              /* Loop until it arrives */
}

void processChoice( int choice ) 
{
    switch( choice ) {
        case 0:
            printf("You chose to initialize RVI.\n");
            smpl_initialize();
            break;
        case 1:
            printf("You chose to connect to a remote node.\n");
            smpl_connect();
            break;
        case 2:
            printf("Which RVI node would you like to disconnect from? ");
            smpl_disconnect();
            break;
        case 3:
            printf("You chose to get a list of connections.\n");
            get_connections();
            break;
        case 4:
            printf("You chose to register a service.\n");
            register_service();
            break;
        case 5:
            printf("You chose to unregister a service.\n");
            unregister_service();
            break;
        case 6:
            printf("You chose to get a list of services.\n");
            get_services();
            break;
        case 7:
            printf("What service would you like to invoke?\n");
            smpl_invoke();
            break;
        case 8:
            printf("You chose to process input.\n");
            smpl_process();
            break;
        case 9:
            printf("You chose to shutdown RVI.\n");
            smpl_shutdown();
            break;
        case 10:
            printf("Goodbye!\n");
            exit(0);
        default:
            printf("That's not a valid choice.\n");
            break;
    }
}

void listChoices(void) {
    printf("\t[0]: Initialize RVI\n"
           "\t[1]: Connect to remote node\n"
           "\t[2]: Disconnect from remote node\n"
           "\t[3]: Get a list of connections\n"
           "\t[4]: Register a service\n"
           "\t[5]: Unregister a service\n"
           "\t[6]: Get a list of services\n"
           "\t[7]: Invoke remote service\n"
           "\t[8]: Process input\n"
           "\t[9]: Shutdown RVI\n"
           "\t[10]: Close program.\n"
           "Make a choice: "
           );
}

void smpl_initialize(void)
{
    char input[BUFSIZE] = {0};
    printf("Config file: ");
    scanf("%s", input);
    myHandle = rvi_init(input);
    if( !myHandle ) exit(1);
    printf("RVI initialized!\n");
}

void smpl_connect(void)
{
    if(!myHandle) {
        printf("Please initialize RVI first!\n");
        return;
    }

    char addr[BUFSIZE] = {0};
    char port[BUFSIZE] = {0};

    printf("Connect to address (ip:port): ");

    scanf("%s:%s", addr, port);

    if( addr == NULL || port == NULL ) {
        printf("That's not a valid address.\n");
        return;
    }

    int stat = rvi_connect(myHandle, addr, port);
    if( stat > 0 ) {
        printf("Connected to remote node on fd %d!\n", stat);
    } else {
        printf("Failed to connect to remote node.\n");
    }
    printf("stat after connect is %d\n", stat);
}

void smpl_disconnect(void)
{
    if(!myHandle) {
        printf("Please initialize RVI first!\n");
        return;
    }
    int fd;
    scanf("%d", &fd);
    int stat = rvi_disconnect(myHandle, fd);
    printf("stat after disconnecting file descriptor %d is %d\n", fd, stat);
}

void get_connections(void)
{
    if(!myHandle) {
        printf("Please initialize RVI first!\n");
        return;
    }
    int *connections = malloc( LEN * sizeof(int *) );
    int len = LEN;
    int *conn = connections;
    
    for(int i = 0; i < len; i++) {
        connections[i] = 0;
    }

    int stat = rvi_get_connections(myHandle, connections, &len);

    printf("stat after get connections is %d\n", stat);
    while(*connections != 0) {
        printf("\tconnection on fd %d\n", *connections++);
    }
    free(conn);
}

void register_service(void)
{
    if(!myHandle) {
        printf("Please initialize RVI first!\n");
        return;
    }
    char service[BUFSIZE] = {0};
    printf("What service would you like to register? ");
    scanf("%s", service);
    int stat = rvi_register_service(myHandle, service, callbackFunc, NULL);
    printf("stat after register service is %d\n", stat);
}

void unregister_service(void)
{
    if(!myHandle) {
        printf("Please initialize RVI first!\n");
        return;
    }
    char service[BUFSIZE] = {0};
    printf("What service would you like to unregister? ");
    scanf("%s", service);
    int stat = rvi_unregister_service(myHandle, service);
    printf("stat after unregister service is %d\n", stat);
}

void get_services(void)
{
    if(!myHandle) {
        printf("Please initialize RVI first!\n");
        return;
    }
    int len = LEN;
    char **services = malloc( LEN * sizeof( char * ) );

    for(int i = 0; i < len; i++) {
        services[i] = NULL;
    }

    int stat = rvi_get_services(myHandle, services, &len);
    printf("stat after get services is %d\n", stat);
    for(int i = 0; i < len; i++) {
        printf("\t\%s\n", services[i]);
    }
            
    char **svcs = services;
    while(*services != NULL) {
        free(*services++);
    }
    free(svcs);
}

void smpl_invoke(void)
{
    if(!myHandle) {
        printf("Please initialize RVI first!\n");
        return;
    }
    char input[BUFSIZE] = {0};
    char params[BUFSIZE] = {0};
    json_t *parameters = {0};

    scanf("%s", input);
    fflush(stdin);
    printf("Okay, you chose to invoke %s. Any parameters?\n"
                    "Please supply a JSON object: ", input);
    scanf("%s", params);
    parameters = json_loads(params, 0, NULL);
    int stat = rvi_invoke_remote_service(myHandle, input, parameters);
    printf("stat after invoking remote service %s is %d\n", input, stat);
}

void smpl_process(void)
{
    if(!myHandle) {
        printf("Please initialize RVI first!\n");
        return;
    }
    int len;
    printf("How many connections? ");
    scanf("%d*[^\n]", &len);

    int *connections = malloc( len * sizeof(int *) );

    printf("Which connections? ");
    for(int i = 0; i < len; i++) {
        scanf("%d", &connections[i]);
    }

    int stat = rvi_process_input(myHandle, connections, len);
    printf("stat after process input is %d\n", stat);
}

void smpl_shutdown(void)
{
    if(!myHandle) {
        printf("Please initialize RVI first!\n");
        return;
    }
    int stat = rvi_cleanup(myHandle);
    if(stat == RVI_OK) {
        myHandle = NULL; 
    }
    printf("stat after cleanup is %d\n", stat);
}
