/* Copyright (c) 2016, Jaguar Land Rover. All Rights Reserved.
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0.
 */

/** @file rvi.h
 * @brief API for the Remote Vehicle Interaction library.
 *
 * This file is responsible for exposing all available function prototypes and
 * data types for the RVI library.
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

#ifndef _RVI_H
#define _RVI_H

#include <jansson.h>

// **********
// DATA TYPES
// **********

/** Application handle used to interact with RVI */
typedef void *rvi_handle;

/** Function signature for RVI callback functions */
typedef void (*rvi_callback_t) (json_t *);

/** Function return status codes */
typedef enum {
    RVI_OK                  = 0,    /* Success */
    RVI_WANT_READ           = 1,    /* Retry read operation */ 
    RVI_WANT_WRITE          = 2,    /* Retry write operation */
    RVI_ERROR_NOCONFIG      = 1001, /* Configuration error */
    RVI_ERROR_JSON          = 1002, /* Error in JSON */
    RVI_ERROR_SERVCERT      = 1003, /* Server certificate is missing */
    RVI_ERROR_CLIENTCERT    = 1004, /* Client certificate is missing */
    RVI_ERROR_NORCVCERT     = 1005, /* Client did not receive server cert */
    RVI_ERROR_STREAMEND     = 1006, /* Stream end encountered unexpectedly */
    RVI_ERROR_NOCRED        = 1007, /* No credentials */
} rvi_status;

// ***************************
// INITIALIZATION AND TEARDOWN
// ***************************

/** @brief Initialize the RVI library. Call before using any other functions.
 *
 * @param credentials - The JWT-encoded string containing the application's
 *                      credentials, as prepared and signed by the 
 *                      provisioning server.
 *
 * @return A handle for the API. On failure, a NULL pointer will be returned.
 */

rvi_handle rvi_init(char *credentials);

/** @brief Tear down the API.
 *
 * Calling applications are expected to call this to cleanly tear down the API.
 *
 * @param handle - The handle for the RVI context to clean up.
 *
 * @return 0 (RVI_OK) on success
 *         Error code on failure.
 */

int rvi_cleanup(rvi_handle handle);

// *************************
// RVI CONNECTION MANAGEMENT
// *************************

/** @brief Load a connection from a file descriptor into the RVI context
 *
 * @param handle - The handle to the RVI context.
 * @param addr - The address of the remote connection.
 * @param port - The target port for the connection.
 *
 * @return A file descriptor for the new socket on success.
 *         A negative error value on failure.
 */
int rvi_connect(rvi_handle handle, const char *addr, const short port);

/** @brief Unload a file descriptor from the RVI context
 *
 * @param handle - The handle to the RVI context.
 * @param fd - The file descriptor to be unloaded.
 *
 * @return 0 (RVI_OK)  on success.
 *         Error code on failure.
 */
int rvi_disconnect(rvi_handle handle, int *fd);

/** @brief Return all file descriptors in the RVI context
 *
 * @param handle - The handle to the RVI context.
 *
 * @return descriptors An array of file descriptors on success.
 *                     NULL on failure.
 */
int *rvi_get_connections(rvi_handle handle);

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
                         rvi_callback_t callback);

/** @brief Unregister a previously registered service
 *
 * @param handle - The handle to the RVI context
 * @param service_name The fully-qualified service name to deregister
 *
 * @return 0 (RVI_OK) on success. 
 *         Error code on failure.
 */
int rvi_unregister_service(rvi_handle handle, const char *service_name);

/** @brief Get list of services available
 *
 * @param handle - The handle to the RVI context.
 *
 * @return A list of fully-qualified service names. The calling application is
 *         responsible for freeing this memory. 
 */
char **rvi_get_services(rvi_handle handle);

/** @brief Invoke a remote service
 *
 * @param handle - The handle to the RVI context.
 * @param service_name - The fully-qualified service name to invoke 
 * @param parameters - A JSON structure containing the named parameter pairs
 *
 * @return 0 on success. Error code on failure.
 */
int rvi_invoke_remote_service(rvi_handle handle, const char *service_name, 
                              const json_t *parameters);

// ****************
// ASYNCHRONOUS I/O
// ****************

/* If a send or receive operation failed, the leftover data will be stored in a
 * buffer and the calling application will receive an error code with a note to
 * send at a later time.
 * 
 * It is the calling application's responsibility to poll before calling either.
 */

/** @brief Retry a read operation on a file descriptor.
 *
 * @param handle - The handle for the RVI context.
 * @param fd - The file descriptor to retry the read operation.
 *
 * @return 0 (RVI_OK) on success.
 *         Error code on failure.
 */
int rvi_retry_read(rvi_handle handle, int fd);

/** @brief Retry a write operation on a file descriptor.
 *
 * @param handle - The handle for the RVI context.
 * @param fd - The file descriptor to retry the write operation.
 *
 * @return 0 (RVI_OK) on success.
 *         Error code on failure.
 */
int rvi_retry_write(rvi_handle handle, int fd);

#endif /* _RVI_H */
