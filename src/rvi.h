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
typedef void (*rvi_callback_t) (int fd, void* service_data, json_t *);

/** Function return status codes */
typedef enum {
    RVI_OK                  = 0,    /* Success */
    RVI_WANT_READ           = 1,    /* Retry read operation */ 
    RVI_WANT_WRITE          = 2,    /* Retry write operation */
    RVI_ERROR_OPENSSL       = 100,  /* Unhandled error from OpenSSL */
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
 * @param config_filename - Path to the file containing RVI config options:
 *                          credentials - JWT encoded string
 *                          device_cert - file with device's X.509 cert
 *                          device_key - file with device's private key
 *                          intermediateCA - file with intermediate CA certs
 *                          root_cert - file with root cert
 *
 * @return A handle for the API. On failure, a NULL pointer will be returned.
 */

rvi_handle rvi_init(char *config_filename);

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

/** @brief Connect to a remote node at a specified address and port. 
 *
 * @param handle - The handle to the RVI context.
 * @param addr - The address of the remote connection.
 * @param port - The target port for the connection. This can be a numeric
 *               value or a string such as "http." Allowed values (inherited
 *               from OpenSSL) are http, telnet, socks, https, ssl, ftp, and
 *               gopher.
 *
 * @return A file descriptor for the new socket on success.
 *         A negative error value on failure.
 */
int rvi_connect(rvi_handle handle, const char *addr, const char *port);

/** @brief Unload a file descriptor from the RVI context
 *
 * @param handle - The handle to the RVI context.
 * @param fd - The file descriptor to be unloaded.
 *
 * @return 0 (RVI_OK)  on success.
 *         Error code on failure.
 */
int rvi_disconnect(rvi_handle handle, int fd);

// Separate call to disconnect multiple file descriptors:
// int rvi_disconnect_multiple(rvi_handle handle, int* fd, int fd_len);


/** @brief Return all file descriptors in the RVI context
 *
 * @param handle    - The handle to the RVI context.
 * @param conn      - Pointer to a buffer to store file descriptors (small
 *                    integers) for each remote RVI node.  
 * @param conn_size - Pointer to size of 'conn' buffer. This should be
 *                    initialized to the size of the conn buffer. On success,
 *                    it will be updated with the number of file descriptors
 *                    updated.
 *
 * This function will fill the conn buffer with active file descriptors from
 * the RVI context and update conn_size to indicate the final size.
 *
 * @return 0 (RVI_OK) on success.
 *         Error code on failure.
 */
int rvi_get_connections(rvi_handle handle, int *conn, int *conn_size);

// **********************
// RVI SERVICE MANAGEMENT
// **********************

/** @brief Register a service with a callback function
 *
 * @param handle - The handle to the RVI context.
 * @param service_name - The fully-qualified service name to register
 * @param callback - The callback function to be executed upon service
 *                   invocation.
 * @param service_data - Parameters to be passed to the callback function (in
 *                       addition to any JSON parameters from the remote node)
 *
 * @return 0 (RVI_OK) on success 
 *         Error code on failure.
 */
int rvi_register_service(rvi_handle handle, const char *service_name, 
                         rvi_callback_t callback, void* service_data);

/** @brief Unregister a previously registered service
 *
 * This function unregisters a service that was previously registered by the
 * calling application. If service_name does not exist, or was registered by a
 * remote node, it does nothing and returns an error code.
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
 * This function fills the buffer at result with pointers to strings, up to the
 * value indicated by len. Memory for each string is dynamically allocated by
 * the library and must be freed by the calling application. Before returning,
 * len is updated with the actual number of strings.
 * 
 * @param handle - The handle to the RVI context.
 * @param result - A pointer to a block of pointers for storing strings
 * @param len - The maximum number of pointers allocated in result
 *
 * @return 0 (RVI_OK) on success
 *         Error code on failure.
 */
int rvi_get_services(rvi_handle handle, char **result, int* len);
// Use strdup() to duplicate string:
// char *caller_res[10];
// int result_len = 0;
// get_services(handle, caller_res, 10, &result_len);
// // Inside the library
// for(i=0; i < service_array_len; ++i) {
//   char* svc_name = get_service_by_index(i);
//   *result = strdup(svc_name); // strdup() does the malloc
//   *result++;
// }

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


// ******************
// RVI I/O MANAGEMENT
// ******************

/** @brief Handle input on remote connection(s).
 *
 * This function will read data from each of the file descriptors in fd_arr (up
 * to fd_len elements long). The calling application must ensure that fd_arr is
 * populated only with read-ready descriptors (returned by, e.g., (e)poll() or
 * select()).
 *
 * This is a blocking operation. If any descriptor in fd_arr is not read-ready,
 * the operation will block until data becomes available to read on the
 * descriptor.
 *
 * @param handle - The handle to the RVI context.
 * @param fd_arr - An array of file descriptors with read operations pending
 * @param fd_len - The length of the file descriptor array
 *
 * @return 0 (RVI_OK) on success.
 *         Error code on failure.
 */
int rvi_process_input(rvi_handle handle, int* fd_arr, int fd_len);

#endif /* _RVI_H */
