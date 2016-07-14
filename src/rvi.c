/* Copyright (c) 2016, Jaguar Land Rover. All Rights Reserved.
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0.
 */

/** @file rvi.c
 *
 * This is an initial prototype of the RVI library in C and is subject to
 * change. The intended use is to allow a calling application to connect to a
 * remote RVI node, discover services, register additional services, and invoke
 * remote services.
 *
 * The RVI library depends on the following libraries:
 *
 * libJWT: https://github.com/benmcollins/libjwt/
 * Jansson: http://www.digip.org/jansson/
 * OpenSSL: https://www.openssl.org/
 * mpack: http://ludocode.github.io/mpack/
 *
 * @author Tatiana Jamison &lt;tjamison@jaguarlandrover.com&gt;
 */

#include <stddef.h>
#include <stdio.h>
#include <regex.h>
#include <openssl/ssl.h>

#include "rvi.h"

// ***************
// DATA STRUCTURES
// ***************

/** @brief RVI context */
typedef struct rvi_context_t {
    // lookup tree to remote nodes by fd
    // lookup tree to remote nodes by right_to_register
    // lookup tree to remote nodes by right_to_invoke
    // lookup tree to services by fully-qualified service name
    // lookup tree to services by registrant
    // own credentials
    char *cred;
    // SSL context for spawning new sessions. 
    // Contains X509 certs, config settings, etc
    SSL_CTX *ctx;
    // SSL socket to listen for incoming connections
    SSL *listen;
    // own right_to_register
    regex_t *right_to_register;
    // own right_to_invoke
    regex_t *right_to_invoke;
} rvi_context_t, *rvi_context_p;

/** @brief Data for connection to remote node */
typedef struct rvi_remote_t {
    /** File descriptor for the connection */
    int fd;
    /** Regex(es) for remote node's right(s) to register */
    regex_t *right_to_register;
    /** Regex(es) for remote node's right(s) to invoke */
    regex_t *right_to_invoke;
    /** RVI log ID assigned on per-connection basis */
    char *rvi_log_id;
    /** Pointer to data buffer for partial I/O operations */
    void *buf;
    /** Pointer to ssl connection */
    SSL *ssl;
} rvi_remote_t, *rvi_remote_p;

/** @brief Data for service */
typedef struct rvi_service_t {
    /** The fully-qualified service name */
    char *name;
    /** Array of file descriptors for remote nodes that may register service */
    int *may_register;
    /** Array of file descriptors for remote nodes that may invoke service */
    int *may_invoke;
    /** File descriptor of remote node that registered service */
    int registrant;
    /** Callback function to execute upon service invocation */
    rvi_callback_t callback;
} rvi_service_t, *rvi_service_p;

// ***************************
// INITIALIZATION AND TEARDOWN
// ***************************

/** @brief Initialize the RVI library. Call before using any other functions.
 *
 * @param config_filename - Path to the file containing RVI config options:
 *                          credentials - JWT encoded string
 *                          device_cert - file with device's X.509 cert
 *                          device_key - file with device's private key
 *                          intermediateCA - file with intermediate CA certs
 *                          root_cert - file with root cert
 *
 * @return A handle for the API. On failure, a NULL pointer will be returned.
 */

rvi_handle rvi_init(char *config_filename)
{
    // set alloc funcs for Jansson
    // initialize OpenSSL
    // parse config file
    // create an rvi_context structure containing:
    //      * rvi_remote trees (fd, right_to_invoke, right_to_register)
    //      * rvi_service trees (registrant, fully qualified service name)
    //      * local credentials
    //      * SSL context
    printf("Write the init function.\n");
    return NULL;
}

/** @brief Tear down the API.
 *
 * Calling applications are expected to call this to cleanly tear down the API.
 *
 * @param handle - The handle for the RVI context to clean up.
 *
 * @return 0 (RVI_OK) on success
 *         Error code on failure.
 */

int rvi_cleanup(rvi_handle handle)
{
    // if there are any open connections, disconnect them
    // destroy each tree, including all structs pointed to
    // free memory used for credential
    // free all SSL structs
    printf("Write the cleanup function.\n");
    return RVI_OK;
}

// *************************
// RVI CONNECTION MANAGEMENT
// *************************

/** @brief Connect to a remote node at a specified address and port. 
 *
 * @param handle - The handle to the RVI context.
 * @param addr - The address of the remote connection.
 * @param port - The target port for the connection.
 *
 * @return A file descriptor for the new socket on success.
 *         A negative error value on failure.
 */
int rvi_connect(rvi_handle handle, const char *addr, const short port)
{
    // sanity check args
    // if count of remotes == MAX_CONNECTIONS, return error
    // malloc new rvi_remote_t
    // spawn new SSL session from handle->ctx
    // set remote->fd = connect to specified addr:port
    // if remote->fd <= 0
    //      free rvi_remote_t, ssl
    //      return error
    // do a bunch of stuff for nonblocking i/o including error handling
    // set remote->rvi_log_id
    // prepare "au" message
    //      populate cmd
    //      populate version
    //      fill with handle->credentials
    //      fill with remote->rvi_log_id
    // send "au" message
    // parse incoming "au" message
    //      parse right_to_register to regex_t
    //      set remote->right_to_register to returned value
    //      parse right_to_invoke to regex_t
    //      set remote->right_to_invoke to returned value
    // prepare "sa" reply
    //      search services_by_may_register to match remote->right_to_invoke
    //      if the registrant is local, add service name to "sa" reply
    // send "sa" reply
    // parse incoming "sa" message
    //      for each service in services array, create new rvi_service_t
    //      set new_service->name to service string
    //      set new_service->registrant to remote->fd
    //      search connections_by_right_to_register to match name
    //          for each match, add to new_service->may_register
    //      search connections_by_right_to_invoke to match name
    //          for each match, add to new_service->may_invoke
    // return remote->fd
    printf("Write the connect function.\n");
    return RVI_OK;
}

/** @brief Disconnect from a remote node with a specified file descriptor. 
 *
 * @param handle - The handle to the RVI context.
 * @param fd - The file descriptor for the connection to terminate.
 *
 * @return 0 (RVI_OK)  on success.
 *         Error code on failure.
 */
int rvi_disconnect(rvi_handle handle, int *fd)
{
    // find the remote connection from connections_by_fd
    // if not found, return error
    // shut down remote->ssl
    // while there's a match for fd in services_by_registrant...
    //      free service_match
    // free remote->right_to_register
    // free remote->right_to_invoke
    // free remote->rvi_log_id
    // free remote->ssl
    // free remote->ctx
    // free remote
    printf("Write the disconnect function.\n");
    return RVI_OK;
}

/** @brief Return all file descriptors in the RVI context
 *
 * @param handle - The handle to the RVI context.
 *
 * @return descriptors An array of file descriptors on success.
 *                     NULL on failure.
 */
int *rvi_get_connections(rvi_handle handle)
{
    // allocate a memory area big enough to store MAX_CONNECTIONS pointers
    // if connections tree is empty, return NULL
    // traverse any connections tree and add fd to memory area
    // return pointer to start of connections
    printf("Write the get connections function.\n");
    return NULL;
}

// **********************
// RVI SERVICE MANAGEMENT
// **********************

/** @brief Register a service with a callback function
 *
 * @param handle - The handle to the RVI context.
 * @param service_name - The fully-qualified service name to register
 * @param callback - The callback function to be executed upon service
 *                   invocation.
 *
 * @return 0 (RVI_OK) on success 
 *         Error code on failure.
 */
int rvi_register_service(rvi_handle handle, const char *service_name, 
                         rvi_callback_t callback)
{
    // Execute callback whenever we receive an invoke message from remote RVI
    // Actually belongs to a separate (private?) function, the I/O loop
    json_t *parameters;
    (*callback)(parameters);
    /****************************************************************/

    // Compare service name to handle->right_to_register
    // If no match, return error
    // Create a new rvi_service_t structure
    // Set service->name to service_name
    // Set service->callback to callback
    // Set service->registrant to $LOCAL
    // Add $LOCAL to service->may_register
    // Search remotes by right_to_invoke; add to service->may_invoke
    // Search remotes by right_to_register; add to service->may_register
    // If service->may_invoke is non-empty, prepare sa message
    //      For each fd in service->may_invoke,
    //      send sa message making service stat av
    // Add service to services_by_name
    // Add service to services_by_registrant
    printf("Write the register service function.\n");
    return 0;
}

/** @brief Unregister a previously registered service
 *
 * @param handle - The handle to the RVI context
 * @param service_name The fully-qualified service name to deregister
 *
 * @return 0 (RVI_OK) on success. 
 *         Error code on failure.
 */
int rvi_unregister_service(rvi_handle handle, const char *service_name)
{
    // if service_name is not in services_by_name, return error
    // if service->registrant is not $LOCAL, return error
    // if service->may_invoke is not empty, prepare sa message
    //      for each fd in service->may_invoke
    //      send sa message making service_name stat un
    // Remove service from services_by_name
    // Remove service from services_by_fd
    // Free service
    printf("Write the unregister service function.\n");
    return 0;
}

/** @brief Get list of services available
 *
 * @param handle - The handle to the RVI context.
 *
 * @return A list of fully-qualified service names. The calling application is
 *         responsible for freeing this memory. 
 */
char **rvi_get_services(rvi_handle handle)
{
    // malloc a chunk of memory for pointers to strings (how many?)
    // traverse services_by_name
    //      for each service, point to name string from malloc'd chunk
    // return pointer to start of chunk
    printf("Write the get services function.\n");
    return NULL;
}

/** @brief Invoke a remote service
 *
 * @param handle - The handle to the RVI context.
 * @param service_name - The fully-qualified service name to invoke 
 * @param parameters - A JSON structure containing the named parameter pairs
 *
 * @return 0 on success. Error code on failure.
 */
int rvi_invoke_remote_service(rvi_handle handle, const char *service_name, 
                              const json_t *parameters)
{
    // if service_name not in services_by_name, return error
    // get fd/SSL session for remote node to send message to
    // prepare rcv message
    // send rcv message
    printf("Write the invoke service function.\n");
    return 0;
}

// ****************
// ASYNCHRONOUS I/O
// ****************

/* If a send or receive operation failed, the partial message will be stored in
 * a temporary buffer and the function will return a value of RVI_WANT_READ or
 * RVI_WANT_WRITE.  
 * 
 * It is the calling application's responsibility to poll before calling
 * either.
 */

/** @brief Retry a read operation on a file descriptor.
 *
 * @param handle - The handle for the RVI context.
 * @param fd - The file descriptor to retry the read operation.
 *
 * @return 0 (RVI_OK) on success.
 *         Error code on failure.
 */
int rvi_retry_read(rvi_handle handle, int fd)
{
    printf("Write the retry read function.\n");
    return RVI_OK;
}

/** @brief Retry a write operation on a file descriptor.
 *
 * @param handle - The handle for the RVI context.
 * @param fd - The file descriptor to retry the write operation.
 *
 * @return 0 (RVI_OK) on success.
 *         Error code on failure.
 */
int rvi_retry_write(rvi_handle handle, int fd)
{
    printf("Write the retry write function.\n");
    return RVI_OK;
}
