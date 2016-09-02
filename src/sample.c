/* Copyright (c) 2016, Jaguar Land Rover. All Rights Reserved.
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0.
 */

#include "rvi.h"

void callbackFunc(int fd, void *service_data, json_t *parameters)
{
    printf("inside the callback function\n");
}

int main(int argc, char *argv[])
{
    if ( argc != 2 ) {
        printf ( "Usage: %s [config_file]\n", argv[0] );
        exit(1); 
    }

    int stat = 0;
    int *connections = {0};
    rvi_handle myHandle;
    char **services = malloc( 20 * sizeof( char * ) );
    int len = 20;
    json_t *parameters = {0};
    int fd = 0;

    for(int i = 0; i < len; i++) {
        services[i] = NULL;
    }

    myHandle = rvi_init(argv[1]);

    if( !myHandle ) exit(1);

    stat = rvi_connect(myHandle, "192.168.18.76", "9007");
    printf("\nstat after connect is %d\n", stat);

    stat = rvi_disconnect(myHandle, fd);
    printf("stat after disconnect is %d\n", stat);

    stat = rvi_get_connections(myHandle, connections, &len);
    printf("stat after get connections is %d\n", stat);

    stat = rvi_register_service(myHandle, "genivi.org/test", 
                                callbackFunc, NULL);
    printf("stat after register service is %d\n", stat);

    stat = rvi_unregister_service(myHandle, "genivi.org/test");
    printf("stat after unregister service is %d\n", stat);

    stat = rvi_get_services(myHandle, services, &len);
    printf("stat after get services is %d\n", stat);
    printf("services:\n");
    for(int i = 0; i < len; i++) {
        printf("\t\%s\n", services[i]);
    }
    
    char **svcs = services;
    while(*services != NULL) {
        free(*services++);
    }
    free(svcs);

    stat = rvi_invoke_remote_service(myHandle, "genivi.org/test", parameters);
    printf("stat after invoke remote is %d\n", stat);

    stat = rvi_process_input(myHandle, connections, len);
    printf("stat after process input is %d\n", stat);

    stat = rvi_cleanup(myHandle);
    printf("stat after cleanup is %d\n", stat);

    return 0;
}
