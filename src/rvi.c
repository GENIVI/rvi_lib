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

#include <dirent.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <jwt.h>

#include "rvi.h"
#include "btree.h"

#define BUFLEN 4096

/* *************** */
/* DATA STRUCTURES */
/* *************** */

/** @brief RVI context */
typedef struct rvi_context_t {

    /* 
     * Btrees for indexing remote connections, RVI services by name, and RVI 
     * services by registrant. 
     */
    btree_t *remote_idx;        /* Remote connections by fd */
    btree_t *service_name_idx;  /* Services by fully qualified service name */
    btree_t *service_reg_idx;   /* Services by fd of registering node ---*/
                                /*  note: local services registered by stdin */

    /* Properties set in configuration file */
    char *cadir; /* Directory containing the trusted certificate store */
    char *creddir; /* Directory containing base64-encoded JWT credentials */
    char *certfile; /* File containing X.509 public key certificate (PKC) */
    char *keyfile;  /* File containing corresponding private key */
    char *cafile;   /* File containing CA public key certificate(s) */

    /* Array of RVI credentials loaded into memory for quick access when 
     * negotiating connections */
    char **cred;

    /* SSL context for spawning new sessions.  */
    /* Contains X509 certs, config settings, etc */
    SSL_CTX *ssl_ctx;

    /* own right_to_receive */
    json_t *right_to_receive;
    /* own right_to_invoke */
    json_t *right_to_invoke;
} rvi_context_t, *rvi_context_p;

/** @brief Data for connection to remote node */
typedef struct rvi_remote_t {
    /** File descriptor for the connection */
    int fd;
    /* own right_to_receive */
    json_t *right_to_receive;
    /* own right_to_invoke */
    json_t *right_to_invoke;
    /** List of rvi_rights_t structures, containing receive & invoke rights and
     * expiration */
//    rvi_rights_t *rightsHead;
    /** Pointer to data buffer for partial I/O operations */
    void *buf;
    /** Pointer to BIO chain from OpenSSL library */
    BIO *sbio;
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

/** Data structure for rights parsed from validated credential */
typedef struct rvi_rights_t {
    json_t *receive;    /* json array for right(s) to receive */
    json_t *invoke;     /* json array for right(s) to invoke */
    int expiration;     /* unix epoch time for jwt's validity.end */
} rvi_rights_t, *rvi_rights_p;

/* 
 * Declarations for internal functions not exposed in the API 
 */

rvi_service_t *rvi_service_create ( const char *name, const int registrant, 
                                    const rvi_callback_t callback );

void rvi_service_destroy ( rvi_service_t *service );

rvi_remote_t *rvi_remote_create ( BIO *sbio, const int fd );

void rvi_remote_destroy ( rvi_remote_t *remote );

rvi_rights_t *rvi_rights_create (   const char *right_to_receive, 
                                    const char *right_to_invoke, 
                                    const char *validity );

void rvi_rights_destroy ( rvi_rights_t *rights );

/* Comparison functions for constructing btrees and retrieving values */
int compare_fd ( void *a, void *b );

int compare_registrant ( void *a, void *b );

int compare_name ( void *a, void *b );

/* Utility functions related to OpenSSL library */
int ssl_verify_callback ( int ok, X509_STORE_CTX *store );

SSL_CTX *setup_client_ctx ( rvi_handle handle );

/* Additional utility functions */

int read_json_config ( rvi_handle handle, const char * filename );

char *get_pubkey_file( char *filename );

int validate_credential( rvi_handle handle, const char *cred, X509 *cert );

int get_credential_rights( rvi_handle handle, const char *cred, 
                           json_t **rec_arr, json_t **inv_arr );

/****************************************************************************/

/* 
 * This function compares 2 pointers to rvi_remote_t structures on the basis of
 * the remote's file descriptor. It is used for building the index for remote
 * connections. 
 */
int compare_fd ( void *a, void *b )
{
    rvi_remote_t *remote_a = a;
    rvi_remote_t *remote_b = b;

    return ( remote_a->fd - remote_b->fd );
}

/* 
 * This function compares 2 pointers to rvi_service_t structures on the basis
 * of the registrant (i.e., file descriptor). For services registered by the
 * same remote RVI node, the service name is used to guarantee a unique
 * position in the b-tree. 
 */
int compare_registrant ( void *a, void *b )
{
    rvi_service_t *service_a = a;
    rvi_service_t *service_b = b;

    int result;
    if ((( result = ( service_a->registrant - service_b->registrant)) == 0 ) &&
            service_a->name && service_b->name ) {
        result = strcmp ( service_a->name, service_b->name );
    }

    return result;
}

/* 
 * This function will compare 2 pointers to rvi_service_t structures on the
 * basis of the unique fully-qualified service name. 
 */
int compare_name ( void *a, void *b )
{
    rvi_service_t *service_a = a;
    rvi_service_t *service_b = b;

    return strcmp ( service_a->name, service_b->name );
}

/* 
 * This function initializes a new service struct and sets the name,
 * registrant, and callback to the specified values. 
 *
 * If service name is null or registrant is negative, this returns NULL and
 * performs no operations. 
 */

rvi_service_t *rvi_service_create ( const char *name, const int registrant, 
                                    const rvi_callback_t callback )
{
    /* If name is NULL or registrant is negative, there's an error */
    if ( !name || (registrant < 0) )
        return NULL;

    /* Zero-initialize the struct */
    rvi_service_t *service = malloc( sizeof ( rvi_service_t ) );
    memset(service, 0, sizeof ( rvi_service_t ) );

    /* Set the service name */
    service->name = strdup ( name );

    /* Set the service registrant */
    service->registrant = registrant;

    /* Set the callback. NULL is valid. */
    service->callback = callback;

    /* TODO: Walk the tree of remotes to check for matches in may_register and
     * may_invoke to add to array 
     */

    /* Return the address of the new service */
    return service;
}

/* 
 * This function frees all memory allocated by a service struct. 
 * 
 * If service is null, no operations are performed. 
 */
void rvi_service_destroy ( rvi_service_t *service )
{
     if ( !service ) {
         return;
     }

     free ( service->name );
     if( service->may_register )
         free ( service->may_register );
     if( service->may_invoke )
         free ( service->may_invoke );
     free ( service );
}

/*  
 * This function initializes a new remote struct and sets the file descriptor
 * and BIO chain to the specified values. 
 * 
 * If sbio is null or fd is negative, this returns NULL and performs no
 * operations. 
 */

rvi_remote_t *rvi_remote_create ( BIO *sbio, const int fd )
{
    /* If sbio is null or fd is negative, there's a problem */
    if ( !sbio || fd < 0 ) {
        return NULL;
    }
    
    /* Create a new data structure and zero-initialize it */
    rvi_remote_t *remote = malloc ( sizeof ( rvi_remote_t ) );
    memset ( remote, 0, sizeof ( rvi_remote_t ) );

    /* */
    /* Set the file descriptor and BIO chain */
    /* */
    remote->fd = fd;
    remote->sbio = sbio;

    /* Note that we do NOT need to populate right_to_receive or 
     * right_to_invoke at this time. Those will be populated by parsing the au 
     * message. */

    return remote;
}

/* 
 * This function frees all memory allocated by a remote struct. 
 * 
 * If remote is null, no operations are performed. 
 */
void rvi_remote_destroy ( rvi_remote_t *remote)
{
    if ( !remote ) {
        return;
    }

    BIO_free_all ( remote->sbio );
    json_decref ( remote->right_to_receive );
    json_decref ( remote->right_to_invoke );
    free ( remote->buf );
    free ( remote );
}

/* *************************** */
/* INITIALIZATION AND TEARDOWN */
/* *************************** */


int ssl_verify_callback ( int ok, X509_STORE_CTX *store )
{
    char data[256];

    if(!ok) {
        X509 *cert = X509_STORE_CTX_get_current_cert(store);
        int depth = X509_STORE_CTX_get_error_depth(store);
        int err = X509_STORE_CTX_get_error(store);

        fprintf(stderr, "-Error with certificate at depth: %i\n", depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        fprintf(stderr, " issuer = %s\n", data);
        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        fprintf(stderr, " subject = %s\n", data);
        fprintf(stderr, " err %i:%s\n", err, 
                X509_verify_cert_error_string(err));
    }

    return ok;
}

/* 
 * Set up the SSL context. Configure for outbound connections only. 
 */
SSL_CTX *setup_client_ctx ( rvi_handle handle )
{
    if ( !handle ) {
        return NULL;
    }

    rvi_context_t *rvi_ctx = (rvi_context_t *)handle;

    SSL_CTX *ssl_ctx;

    /* Use generic SSL/TLS so we can easily add additional future protocols */
    ssl_ctx = SSL_CTX_new( SSLv23_method() );
    /* Do not permit the deprecated SSLv2 or SSLv3 to be used. Also prohibit 
     * TLSv1.0 and TLSv1.1. */
    SSL_CTX_set_options( ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                             SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 );

    /* Specify winnowed cipher list here */
    const char *cipher_list = "HIGH";
    if(SSL_CTX_set_cipher_list(ssl_ctx, cipher_list) != 1) { 
        SSL_CTX_free( ssl_ctx );
        return NULL; 
    } 

    if( SSL_CTX_load_verify_locations(ssl_ctx, rvi_ctx->cafile, 
                                      rvi_ctx->cadir) != 1 ) {
        SSL_CTX_free( ssl_ctx );
        return NULL;
    }
    if( SSL_CTX_set_default_verify_paths(ssl_ctx) != 1 ) {
        SSL_CTX_free( ssl_ctx );
        return NULL;
    }
    if( SSL_CTX_use_certificate_chain_file(ssl_ctx, 
                                           rvi_ctx->certfile) != 1 ) {
        SSL_CTX_free( ssl_ctx );
        return NULL;
    }
    if( SSL_CTX_use_PrivateKey_file(ssl_ctx, rvi_ctx->keyfile, 
                                    SSL_FILETYPE_PEM) != 1 ) {
        SSL_CTX_free( ssl_ctx );
        return NULL;
    }

    /* Set internal callback for peer verification on SSL connection attempts.
     */
    SSL_CTX_set_verify ( ssl_ctx, SSL_VERIFY_PEER, ssl_verify_callback );

    /* Set the maximum depth for certificates to be used. Additional
     * certificates are ignored. Error messages will be generated as if the
     * certificates are not present. 
     * 
     * Permits a maximum of 4 CA certificates, i.e., 3 intermediate CAs and the
     * root CA. 
     */
    SSL_CTX_set_verify_depth ( ssl_ctx, 4 );

    return ssl_ctx;
}
 
/**
 * This function will parse a JSON configuration file to retrieve the filenames
 * for the device certificate and key, as well as the directory names for CA
 * certificates and RVI credentials.
 *
 * On success, this function returns 0. On error, it will return a positive
 * error code.
 */
int read_json_config ( rvi_handle handle, const char * filename )
{
    if ( !handle || !filename )
        return EINVAL;

    json_error_t    errjson;
    json_t          *conf;
    json_t          *tmp;
    DIR             *d;
    struct dirent   *dir;
    FILE            *fp;
    rvi_context_t   *ctx;
    BIO             *certbio;
    X509            *cert;
    char            *cred = NULL;

    ctx = ( rvi_context_t * )handle;

    conf = json_load_file( filename, 0, &errjson );
    if( !conf ) {
        fprintf(stderr, "error: on line %d: %s\n", errjson.line, errjson.text);
        return 1;
    }

    tmp = json_object_get( conf, "dev" );
    if(!tmp) {
        fprintf(stderr, "could not get device info\n");
        return 1;
    }
    ctx->keyfile = strdup( json_string_value( 
                json_object_get( tmp, "key" ) ) );
    ctx->certfile = strdup( json_string_value( 
                json_object_get( tmp, "cert" ) ) );

    tmp = json_object_get ( conf, "ca" );
    if(!tmp) {
        fprintf(stderr, "could not get certification authority info\n");
        return 1;
    }
    ctx->cadir = strdup( json_string_value( 
                json_object_get( tmp, "dir" ) ) );
    ctx->cafile = strdup( json_string_value( 
                json_object_get( tmp, "cert" ) ) );

    ctx->creddir = strdup( json_string_value( 
                json_object_get ( conf, "creddir" ) ) );

    json_decref(conf);

    if( !(ctx->creddir) ) {
        return RVI_ERROR_NOCRED;
    }

    d = opendir( ctx->creddir );
    if (!d) {
        return RVI_ERROR_NOCRED;
    }

    certbio = BIO_new_file( ctx->certfile, "r" );
    if( !certbio ) {
        return RVI_ERROR_NOCRED;
    }
    cert = PEM_read_bio_X509( certbio, NULL, 0, NULL);
    if( !cert ) {
        return RVI_ERROR_NOCRED;
    }

    BIO_free_all( certbio );

    int i = 0;
    while ( ( dir = readdir( d ) ) ) {
        if ( strstr( dir->d_name, ".jwt" ) ) {
            /* if it's a jwt file, open it */
            fp = fopen( dir->d_name, "r" );
            if( !fp ) return RVI_ERROR_NOCRED;
            /* go to end of file */
            if( fseek( fp, 0L, SEEK_END ) != 0 ) return RVI_ERROR_NOCRED;
            /* get value of file position indicator */
            long bufsize = ftell(fp);
            if( bufsize == -1 ) return RVI_ERROR_NOCRED;
            cred = malloc(sizeof(char) * (bufsize + 1));
            if( !cred ) return ENOMEM;
            /* go back to start of file */
            rewind( fp );
            /* read the entire file into memory */
            size_t len = fread( cred, sizeof(char), bufsize, fp );
            if( ferror( fp ) != 0) {
                fputs("Error reading credential file", stderr);
            } else {
                cred[len++] = '\0'; /* Ensure string is null-terminated */
            }
            if( validate_credential( handle, cred, cert ) == RVI_OK ) {
                ctx->cred[i] = strdup( cred );
            }
            free(cred);
            fclose( fp );
            i++;
        }
    }

    X509_free( cert );
    closedir( d );

    return RVI_OK;
}

/** Get arrays of right_to_receive and right_to_invoke */
int get_credential_rights( rvi_handle handle, const char *cred, 
                           json_t **rec_arr, json_t **inv_arr )
{
    if( !handle || !cred || /* !rights */ !rec_arr || !inv_arr )
        return EINVAL;

    rvi_context_p   ctx = (rvi_context_p)handle;
    jwt_t           *jwt;
    json_error_t    jsonerr;
    char            *key;
    int             ret;
    time_t          rawtime;

    if( !( key = get_pubkey_file( ctx->cafile ) ) ) {
        ret = -1;
        goto exit;
    }

    /* Load the JWT into memory from base64-encoded string */
    ret = jwt_decode(&jwt, cred, (unsigned char *)key, strlen(key));
    if( ret != 0 )
        goto exit;

    /* Check that we are using public/private key cryptography */
    if( jwt_get_alg( jwt ) != JWT_ALG_RS256 ) {
        ret = 1; 
        goto exit;
    }
    
    /* Check validity: start/stop */
    time(&rawtime);
    char *validity_str = (char *)jwt_get_grant( jwt, "validity" );
    json_t *validity = json_loads(validity_str, 0, NULL);

    int start = json_integer_value( json_object_get( validity, "start" ) );
    int stop = json_integer_value( json_object_get( validity, "stop" ) );

    if( ( start > rawtime ) || ( stop < rawtime ) ) {
        ret = -1;
        goto exit;
    }
    
    //rights->expiration = stop;


    /* Load the rights to receive */
    char *rcv = (char *)jwt_get_grant( jwt, "right_to_receive" );

//    rights->receive = json_loads( rcv, 0, &jsonerr );
    *rec_arr = json_loads( rcv, 0, &jsonerr );
 
    free( rcv );

    /* Load the right to invoke */
    char *inv = (char *)jwt_get_grant( jwt, "right_to_invoke" );

    *inv_arr = json_loads( inv, 0, &jsonerr );

//    rights->invoke = json_loads( inv, 0, &jsonerr );

    free( inv );

    if (ret != 0) 
        goto exit;

exit:
    free(key);
    jwt_free(jwt);
    if ( validity ) json_decref( validity );
    if ( validity_str ) free( validity_str );

    return ret;
}

/** Get the public key from a certificate file */
char *get_pubkey_file( char *filename )
{
    if( !filename )
        return NULL;

    EVP_PKEY    *pkey       = NULL;
    BIO         *certbio    = NULL;
    BIO         *mbio       = NULL;
    X509        *cert       = NULL;
    char        *key;
    long        length;
    int         ret = RVI_OK;

    /* Get public key from root certificate */
    /* First, load root certificate into memory */
    if( !( certbio = BIO_new_file( filename, "r" ) ) ) {
        ret = ENOMEM; 
        goto exit;
    }
    if( !( cert = PEM_read_bio_X509( certbio, NULL, 0, NULL ) ) ) {
        ret = 1; 
        goto exit; 
    }
    if( !( pkey = X509_get_pubkey(cert) ) ) {
        ret = 1; 
        goto exit;
    }
    if( !( mbio = BIO_new(BIO_s_mem() ) ) ) {
        ret = ENOMEM;
        goto exit;
    }
    ret = PEM_write_bio_PUBKEY(mbio, pkey);
    if( ret == 0 ) {
        ret = RVI_ERROR_OPENSSL;
        goto exit;
    }

    length = BIO_ctrl_pending(mbio);
    if( !( key = malloc( length + 1 ) ) ) {
        ret = ENOMEM;
        goto exit;
    }

    if( (ret = BIO_read(mbio, key, length)) != length) {
        goto exit;
    }

    key[length] = '\0';

    ret = RVI_OK;

exit:
    EVP_PKEY_free(pkey);
    X509_free(cert);
    BIO_free_all(certbio);
    BIO_free_all(mbio);

    if( ret != RVI_OK )
        return NULL;
    else
        return key;
}

/** 
 * This function tests whether a credential is valid.
 *
 * Tests:
 *  * Signed by trusted authority
 *  * Timestamp is valid
 *  * Embedded device cert matches supplied cert
 *
 * @param[in] handle    - handle to the RVI context
 * @param[in] cred      - JWT-encoded RVI credential
 * @param[in] cert      - the expected certificate for the device, e.g., peer certificate
 *
 * @return RVI_OK (0) on success, or an error code on failure.
 */
int validate_credential( rvi_handle handle, const char *cred, X509 *cert )
{
    if( !handle || !cred )
        return EINVAL;

    int             ret;
    rvi_context_p   ctx = (rvi_context_p)handle;
    char            *key;
    jwt_t           *jwt;
    long            length;
    time_t          rawtime;
    BIO             *bio = {0};
    X509            *dcert = {0};
    const char      certHead[] = "-----BEGIN CERTIFICATE-----\n";
    const char      certFoot[] = "\n-----END CERTIFICATE-----";

    ret = RVI_OK;

    key = get_pubkey_file( ctx->cafile );

    if( !key ) {
        ret = -1;
        goto exit;
    }

    length = strlen(key) + 1;

    if( ( ret = jwt_decode( &jwt, cred, (unsigned char *)key, length ) ) ) {
        goto exit;
    }

    if( jwt_get_alg( jwt ) != JWT_ALG_RS256 ) {
        ret = 1; 
        goto exit;
    }

    /* Check validity: start/stop */
    time(&rawtime);
    char *validity_str = (char *)jwt_get_grant( jwt, "validity" );
    json_t *validity = json_loads(validity_str, 0, NULL);

    int start = json_integer_value( json_object_get( validity, "start" ) );
    int stop = json_integer_value( json_object_get( validity, "stop" ) );

    if( ( start > rawtime ) || ( stop < rawtime ) ) {
        ret = -1;
        goto exit;
    }

    const char *device_cert = jwt_get_grant( jwt, "device_cert" );
    char *tmp = malloc( strlen( device_cert ) + strlen( certHead ) 
                        + strlen ( certFoot ) + 1 );
    sprintf(tmp, "%s%s%s", certHead, device_cert, certFoot);

    /* Check that certificate in credential matches expected cert */
    bio = BIO_new( BIO_s_mem() );
    BIO_puts( bio, (const char *)tmp );
    dcert = PEM_read_bio_X509( bio, NULL, 0, NULL );
    ret = X509_cmp( dcert, cert );

exit:
    jwt_free( jwt );
    if( key ) free( key );
    if( validity ) json_decref( validity );
    if( validity_str ) free( validity_str );
    if( tmp ) free( tmp );
    BIO_free_all( bio );
    X509_free( dcert );

    return ret;
}

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

rvi_handle rvi_init ( char *config_filename )
{
    /* set alloc funcs for Jansson */
    /* json_set_alloc_funcs(s_malloc, s_free); */

    /* initialize OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    
    /* Allocate memory for an RVI context structure. 
     * This structure contains:
     *      lookup trees for services and remote connections
     *      shared SSL context factory object for generating new SSL sessions
     *      this node's permissions in the RVI architecture
     */
    rvi_context_t *ctx = malloc(sizeof(rvi_context_t));
    if(!ctx) {
        fprintf(stderr, "Unable to allocate memory\n");
        return NULL;
    }
    ctx = memset ( ctx, 0, sizeof ( rvi_context_t ) );

    /* Allocate a block of memory for storing credentials, then initialize each 
     * pointer to null */
    ctx->cred = malloc ( 20 * sizeof ( char * ));
    int i;
    for ( i = 0; i < 20; i ++) {
        ctx->cred[i] = NULL;
    }

    /* parse config file */
    /* need: device cert; root cert; device key; credential */
    
    if ( read_json_config ( ctx, config_filename ) != 0 ) {
        fprintf(stderr, "Error reading config file\n");
        goto err;
    }

    i = 0;
    while( ctx->cred[i] != NULL ) {
        int ret = get_credential_rights( ctx, ctx->cred[i], 
                &ctx->right_to_receive, &ctx->right_to_invoke
                );
        if( ret != RVI_OK )
            goto err;
        i++;
    }

    /* Create generic SSL context configured for client access */
    ctx->ssl_ctx = setup_client_ctx(ctx);
    if(!ctx->ssl_ctx) {
        fprintf(stderr, "Error setting up SSL context\n");
        goto err;
    }

    /*  
     * Create empty btrees for indexing remote connections and services. 
     * 
     * Since we expect that records will frequently be added and removed, use a 
     * small order for each tree. This means that the tree will be deeper, but 
     * addition/deletion will usually result in simply changing pointers rather 
     * than copying data. 
     */
    
    /*   
     * Remote connections will be indexed by the socket's file descriptor.    
     */  
    ctx->remote_idx = btree_create(2, compare_fd);

    /*   
     * Services will be indexed by the fully-qualified service name, which is
     * unique across the RVI infrastructure. 
     */  
    ctx->service_name_idx = btree_create(2, compare_name);

    /*
     * Services will also be indexed by the file descriptor of the entity 
     * registering the service. Service names are used as a tie-breaker to 
     * ensure each record has a unique position in the tree. 
     */
    ctx->service_reg_idx = btree_create(2, compare_registrant);
    
    return (rvi_handle)ctx;

err:
    rvi_cleanup(ctx);

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
    if( !handle )
        return EINVAL;

    rvi_context_t * ctx = (rvi_context_p)handle;
    rvi_remote_t *  rtmp;
    rvi_service_t * stmp;

    /* free all SSL structs */
    SSL_CTX_free(ctx->ssl_ctx);

    /*  
     * Destroy each tree, including all structs pointed to 
     */
    
    /*  
     * As long as the context contains remote connections, find the first 
     * struct in the tree, and disconnect the corresponding file descriptor. 
     * The disconnect function removes the entry from the tree and frees the 
     * underlying memory. 
     */

    if(ctx->remote_idx) {
        while(ctx->remote_idx->count != 0) {
            rtmp = (rvi_remote_t *)ctx->remote_idx->root->dataRecords[0];
            if(!rtmp) {
                perror("Getting remote data in cleanup"); 
                break;
            }
            /* Disconnect the remote SSL connection, delete the entry from the 
            * tree & free the remote struct */
            rvi_disconnect(handle, rtmp->fd);
        }
        btree_destroy(ctx->remote_idx);
    }

    /* 
     * As long as the context contains services, find the first struct from 
     * either service tree. Delete the entry from each service tree, then free 
     * the underlying memory. 
     */
    if(ctx->service_name_idx) {
        while(ctx->service_name_idx->count != 0) {
            /* Delete the first data record in the root node */
            stmp = (rvi_service_t *)ctx->service_name_idx->root->dataRecords[0];
            if ( !stmp ) {
                perror("Getting service data in cleanup"); 
                break;
            }
            /* Delete the entry from the service name index */
            btree_delete ( ctx->service_name_idx, 
                           ctx->service_name_idx->root, stmp);
            /* Delete the entry from the service registrant index */
            btree_delete ( ctx->service_reg_idx, 
                           ctx->service_reg_idx->root, stmp);
            /* Free the service memory */
            rvi_service_destroy ( stmp );
        }

        /* Destroy both service trees */
        btree_destroy(ctx->service_name_idx);

        btree_destroy(ctx->service_reg_idx);
    }

    /* Free all credentials and other entities set when parsing config */
    if(ctx->cred) {
        int i = 0;
        while ( ctx->cred[i] != NULL ) {
            free ( ctx->cred[i] );
            i++;
        }
        free ( ctx->cred );
    }

    if( ctx->certfile )
        free ( ctx->certfile );
    if( ctx->keyfile )
        free ( ctx->keyfile );
    if( ctx->cafile )
        free ( ctx->cafile );
    if( ctx->cadir )
        free ( ctx->cadir );
    if( ctx->creddir )
        free ( ctx->creddir );

    if( ctx->right_to_receive )
        json_decref ( ctx->right_to_receive );
    if( ctx->right_to_invoke )
        json_decref ( ctx->right_to_invoke );

    /* Free the memory allocated to the rvi_context_t struct */
    free(ctx);

    return RVI_OK;
}

/* ************************* */
/* RVI CONNECTION MANAGEMENT */
/* ************************* */

/** @brief Connect to a remote node at a specified address and port. 
 *
 * This function will attempt to connect to a remote node at the specified addr
 * and port. It will spawn a new connection and block until all handshake and
 * RVI negotiations are complete. On success, it will return the file
 * descriptor for the new socket. On failure, it will return a negative error
 * value. 
 *
 * New services may become immediately available upon connecting to a remote
 * node. To discover the services that are currently available, use the
 * rvi_get_services() function. Services may be invoked via
 * rvi_invoke_remote_service() using the fully-qualified service name.
 *
 * @param handle - The handle to the RVI context.
 * @param addr - The address of the remote connection.
 * @param port - The target port for the connection.
 *
 * @return A file descriptor for the new socket on success.
 *         A negative error value on failure.
 */
int rvi_connect(rvi_handle handle, const char *addr, const char *port)
{
    /* Ensure that we have received valid arguments */
    if( !handle || !addr || !port ) {
        return -EINVAL;
    }

    BIO*            sbio;
    SSL*            ssl;
    X509            *peercert;
    rvi_remote_t*   remote;
    rvi_context_t*  rvi;
    int             len;
    char            tmpbuf[BUFLEN] = {0};
    json_t          *json;
    json_error_t    jsonerr;
    int ret;

    ret = RVI_OK;
    rvi = (rvi_context_t *)handle;

    /* 
     * Spawn new SSL session from handle->ctx. BIO_new_ssl_connect spawns a new 
     * chain including a BIO and an SSL object 
     */
    sbio = BIO_new_ssl_connect(rvi->ssl_ctx);
    if(!sbio) {
        ret = -RVI_ERROR_OPENSSL;
        goto err;
    }
    BIO_get_ssl(sbio, &ssl);
    if(!ssl) {
        ret = -RVI_ERROR_OPENSSL;
        goto err;
    }

    /* 
     * When performing I/O, automatically retry all reads and complete 
     * negotiations before returning. Note that all BIOs have their I/O flag 
     * set to blocking by default. 
     */
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    /* 
     * Set the addr and port 
     */
    BIO_set_conn_hostname(sbio, addr);
    BIO_set_conn_port(sbio, port);

    /* check if we're already connected to that host... */
    if( rvi->remote_idx->count ) {
        btree_iter iter = btree_iter_begin( rvi->remote_idx );
        while( !btree_iter_at_end( iter ) ) {
            rvi_remote_t *rtmp = btree_iter_data( iter );
            if( strcmp( BIO_get_conn_hostname ( sbio ), 
                        BIO_get_conn_hostname( rtmp->sbio )
                      ) == 0 ) { /* We already have a connection to that host */
                ret = -1;
                break;
            }
            btree_iter_next( iter );
        }
        btree_iter_cleanup( iter );
    }
    if( ret != RVI_OK ) goto err;

    if(BIO_do_connect(sbio) <= 0) {
        ret = -RVI_ERROR_OPENSSL;
        goto err;
    }

    if(BIO_do_handshake(sbio) <= 0) {
        ret = -RVI_ERROR_OPENSSL;
        goto err;
    }

    remote = rvi_remote_create ( sbio, SSL_get_fd ( ssl ) );

    /* Add this data structure to our lookup tree */
    btree_insert(rvi->remote_idx, remote);
    
    /* prepare "au" message */
    json_t *creds = json_array();

    /* create JSON array of all credentials */
    if(rvi->cred) {
        int i = 0;
        while ( rvi->cred[i] != NULL ) {
            json_array_append_new( creds, json_string(rvi->cred[i]) );
            i++;
        }
    }

    json_t *au = json_pack( "{s:s, s:s, s:o}", 
            "cmd", "au",            /* populate cmd */
            "ver", "1.1",           /* populate version */
            "creds", creds   /* fill with json array */
            ); 
    if( !au ) {
        ret = RVI_ERROR_JSON;
        goto err;
    }

    char *auString = json_dumps(au, JSON_COMPACT);

    /* send "au" message */
    BIO_puts(sbio, auString);

    free(auString);
    json_decref(au);

    /* parse incoming "au" message */
    if( ( len = BIO_read(sbio, tmpbuf, BUFLEN) ) <= 0 ) {
        ret = -RVI_ERROR_OPENSSL;
        goto err;
    }
    /*
    * We received a reply from the server, we expect it to be an "au" msg
    */ 
    json = json_loads( tmpbuf, 0, &jsonerr );
    if( !json ) {
            ret = -RVI_ERROR_JSON;
            goto err;
    }

    memset( tmpbuf, 0, BUFLEN );

    if( strcmp(
                json_string_value( json_object_get( json, "cmd" ) ),
                "au" 
              ) != 0) {
        ret = -RVI_ERROR_JSON;
        goto err;
    }

    size_t index;
    json_t *value;

    peercert = SSL_get_peer_certificate( ssl );

    json_t *tmp = json_object_get(json, "creds");
    json_array_foreach(tmp, index, value) {
        const char *val = json_string_value ( value );
        if( ! ( validate_credential ( handle, val, peercert ) == RVI_OK ) ) {
            continue;
        }
        ret = get_credential_rights( 
                    handle, val, 
                    &remote->right_to_receive, &remote->right_to_invoke 
                  );
    }

    json_decref( json );
    X509_free( peercert );
    

    /* create JSON array of all services */
    json_t *svcs = json_array();
    if( rvi->service_name_idx->count ) {
        btree_iter iter = btree_iter_begin( rvi->service_name_idx );
        while ( !btree_iter_at_end( iter ) ) {
            rvi_service_t *stmp = btree_iter_data( iter );
            json_array_append_new( svcs, json_string( stmp->name ) );
            btree_iter_next( iter );
        }
        btree_iter_cleanup( iter );
    }

    /* prepare "sa" reply */
    /*      search services_by_may_register to match remote->right_to_invoke */
    /*      if the registrant is local, add service name to "sa" reply */
    json_t *sa = json_pack( "{s:s, s:s, s:o}", 
            "cmd", "sa",            /* populate cmd */
            "stat", "av",           /* populate status */
            "svcs", svcs              /* fill with array of services */
            ); /* TODO: Fill with full array of services */
    if( !sa ) {
        ret = RVI_ERROR_JSON;
        goto err;
    }

    /* send "sa" reply */
    char *saString = json_dumps(sa, JSON_COMPACT);

    BIO_puts(sbio, saString);

    free(saString);
    json_decref(sa);

    /* parse incoming "sa" message */
    if( ( len = BIO_read( sbio, tmpbuf, BUFLEN ) ) <= 0 ) {
        ret = -RVI_ERROR_OPENSSL;
        goto err;
    }
    json = json_loads( tmpbuf, 0, &jsonerr );
    if( !json ) {
        ret = -RVI_ERROR_JSON;
        goto err;
    }

    memset( tmpbuf, 0, BUFLEN );

    if( strcmp(
                json_string_value( json_object_get( json, "cmd" ) ),
                "sa" 
              ) != 0) {
        ret = -RVI_ERROR_JSON;
        goto err;
    }

    tmp = json_object_get(json, "svcs");
    /* for each service in services array, create new rvi_service_t */
    json_array_foreach(tmp, index, value) {
        /* set new_service->name to service string */
        const char *val = json_string_value( value );
        /* set new_service->registrant to remote->fd */
        rvi_service_t *service = rvi_service_create( val, remote->fd, NULL );
        
        btree_insert( rvi->service_name_idx, service );
        btree_insert( rvi->service_reg_idx, service );
    }

    json_decref(json);

    /*      search connections_by_right_to_receive to match name */
    /*          for each match, add to new_service->may_register */
    /*      search connections_by_right_to_invoke to match name */
    
    /*      for each match, add to new_service->may_invoke */
    /* return remote->fd */

    return remote->fd;

err:
    ERR_print_errors_fp( stderr );
    if( remote ) {
        rvi_remote_destroy( remote );
    } else {
        BIO_free_all( sbio );
    }

    return ret;
}

/** @brief Disconnect from a remote node with a specified file descriptor. 
 *
 * @param handle - The handle to the RVI context.
 * @param fd - The file descriptor for the connection to terminate.
 *
 * @return 0 (RVI_OK)  on success.
 *         Error code on failure.
 */
int rvi_disconnect(rvi_handle handle, int fd)
{
    rvi_context_t * ctx = (rvi_context_t *)handle;
    rvi_remote_t    rkey = {0};
    rvi_remote_t *  rtmp;
    rvi_service_t   skey = {0};
    rvi_service_t * stmp;
    int             res;
    
    rkey.fd = fd;

    rtmp = btree_search(ctx->remote_idx, &rkey);
    if(!rtmp) {
        printf("No such connection\n");
        return -1;
    }

    if( ( res = btree_delete(ctx->remote_idx, 
                             ctx->remote_idx->root, rtmp ) ) < 0 ) {
        printf("Error deleting remote key from tree\n");
        return -1;
    } 
    /* Search the service tree for any services registered by the remote */
    skey.registrant = fd;
    while((stmp = btree_search(ctx->service_reg_idx, &skey))) {
        /* We have a match, so delete the service and free the node from
        * the tree */
        btree_delete(ctx->service_name_idx, ctx->service_name_idx->root, stmp);
        btree_delete(ctx->service_reg_idx, ctx->service_reg_idx->root, stmp);
        /* Close connection & free memory for the service structure */
        rvi_service_destroy(stmp);
    }

    rvi_remote_destroy( rtmp );

    return RVI_OK;
}

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
int rvi_get_connections(rvi_handle handle, int *conn, int *conn_size)
{
    if( !handle || !conn || !conn_size )
        return EINVAL;

    rvi_context_t *ctx = (rvi_context_t *)handle;

    if( ctx->remote_idx->count == 0 ) {
        *conn_size = 0;
        return RVI_OK;
    }
    btree_iter iter = btree_iter_begin( ctx->remote_idx );
    int i = 0;
    while( ! btree_iter_at_end( iter ) ) {
        if( i == *conn_size )
            break;
        rvi_remote_t *remote = btree_iter_data( iter );
        if( ! remote )
            break;
        *conn++ = remote->fd ;
        i++;
        btree_iter_next( iter );
    }
    *conn_size = i;
    btree_iter_cleanup( iter );

    return RVI_OK;
}


/* ********************** */
/* RVI SERVICE MANAGEMENT */
/* ********************** */

/** Internal utility functions for services not exposed in public API */

int remove_service(rvi_handle handle, const char *service_name);

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
                         rvi_callback_t callback, void *service_data)
{
    /* Compare service name to handle->right_to_receive */
    /* If no match, return error */
    /* Create a new rvi_service_t structure */
    /* Set service->name to service_name */
    /* Set service->callback to callback */
    /* Set service->registrant to stdin */
    /* Add stdin to service->may_register */
    /* Search remotes by right_to_invoke; add to service->may_invoke */
    /* Search remotes by right_to_receive; add to service->may_register */
    /* If service->may_invoke is non-empty, prepare sa message */
    /*      For each fd in service->may_invoke, */
    /*      send sa message making service stat av */
    /* Add service to services_by_name */
    /* Add service to services_by_registrant */
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
    if( !handle || !service_name )
        return EINVAL;
    /* if service_name is not in services_by_name, return error */
    /* if service->registrant is not stdin, return error */
    return remove_service(handle, service_name);
}

int remove_service(rvi_handle handle, const char *service_name)
{
    if( !handle || !service_name )
        return EINVAL;
    /* if service->may_invoke is not empty, prepare sa message */
    /*      for each fd in service->may_invoke */
    /*      send sa message making service_name stat un */
    /* Remove service from services_by_name */
    /* Remove service from services_by_fd */
    /* Free service */

   printf("Write the unregister service function.\n");
   return 0;
}

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
int rvi_get_services(rvi_handle handle, char **result, int *len)
{
    if( !handle || !result || !len )
        return EINVAL;

    rvi_context_t *ctx = (rvi_context_t *)handle;

    if( ctx->service_name_idx->count == 0 ) {
        *len = 0;
        return RVI_OK;
    }

    btree_iter iter = btree_iter_begin( ctx->service_name_idx );
    int i = 0;
    while( ! btree_iter_at_end( iter ) ) {
        if( i == *len )
            break;
        rvi_service_t *service = btree_iter_data( iter );
        if( ! service )
            break;
        *result++ = strdup( service->name );
        i++;
        btree_iter_next( iter );
    }
    *len = i;
    btree_iter_cleanup( iter );

    return RVI_OK;
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
    if( !handle || !service_name )
        return EINVAL;
    /* get service from service name index */

    rvi_context_t *ctx = (rvi_context_t *)handle;
    rvi_service_t skey = {0};
    rvi_service_t *stmp = NULL;
    rvi_remote_t rkey = {0};
    rvi_remote_t *rtmp = NULL;
    time_t rawtime; /* the unix epoch time for the current time */
    int wait = 1000; /* the timeout length in ms */
    long long timeout;
    json_t *params = NULL;
    json_t *rcv;
    int ret;
    
    skey.name = strdup(service_name);

    stmp = btree_search(ctx->service_name_idx, &skey);
    if( !stmp ) { /* if not found, return error */
        printf("No such service\n");
        ret = ENOENT;
        goto exit;
    }

    /* identify registrant, get SSL session from remote index */
    rkey.fd = stmp->registrant;

    rtmp = btree_search(ctx->remote_idx, &rkey);
    if( !rtmp ) { /* if not found, return error */
        printf("No such connection\n");
        ret = ENXIO;
        goto exit;
    }

    time(&rawtime);
    timeout = rawtime + wait;

    /* prepare rcv message */

    rcv = json_pack( 
            "{s:s, s:i, s:s, s:{s:s, s:i, s:o}}",
            "cmd", "rcv",
            "tid", 1, /* TODO: talk to Ulf about tid */
            "mod", "proto_json_rpc",
            "data", "service", service_name,
                    "timeout", timeout,
                    "parameters", 
                    parameters ? parameters : (params = json_object())
            );
    if( ! rcv ) {
        printf("JSON error");
        ret = RVI_ERROR_JSON;
        goto exit;
    }

    char *rcvString = json_dumps(rcv, JSON_COMPACT);

    /* send rcv message to registrant */
    printf("Send: %s\n", rcvString);
    BIO_puts(rtmp->sbio, rcvString);

    free(rcvString);
    json_decref(rcv);

    ret = 0;

exit:
    free(skey.name);

    return ret;
}

/* ************** */
/* I/O MANAGEMENT */
/* ************** */

int rvi_process_input(rvi_handle handle, int *fd_arr, int fd_len)
{
    if( !handle || !fd_arr || ( fd_len < 1 ) )
        return EINVAL;

    rvi_context_t   *ctx    = (rvi_context_t *)handle;
    rvi_remote_t    rkey    = {0};
    rvi_remote_t    *rtmp   = NULL;
    char            cmd[5]  = {0};

    SSL             *ssl    = NULL;
    json_t          *root   = NULL;
    json_error_t    jserr   = {0};

    int             len     = 1024 * 8;
    int             read    = 0;
    char            *buf    = {0};
    long            mode    = 0;
    int             i       = 0;
    int             err     = 0;

    BIO             *out = BIO_new_fp( stdout, BIO_NOCLOSE );

    /* For each file descriptor we've received */
    while( i < fd_len ) {
        rkey.fd = fd_arr[i]; /* Set the key to the requested fd */
        i++;
        rtmp = btree_search( ctx->remote_idx, &rkey ); /* Find the connection */
        BIO_get_ssl( rtmp->sbio, &ssl );
        if( !ssl ) {
            printf( "Error reading on fd %d, try again\n", rtmp->fd );
            continue;
        }
        /* Grab the current mode flags from the session */
        mode = SSL_get_mode ( ssl );
        /* Ensure our mode is blocking */
        SSL_set_mode( ssl, SSL_MODE_AUTO_RETRY );
        
        if( !( buf = malloc( len + 1 ) ) ) {
            err = ENOMEM;
            goto exit;
        }

        memset( buf, 0, len );

        while( ( read = BIO_read( rtmp->sbio, buf, len ) ) >= 0 ) {
            BIO_printf( out, "RECEIVED: %s\n", buf );

            root = json_loads( buf, 0, &jserr ); /* RVI commands are JSON structs */
            if( !root ) {
                err = RVI_ERROR_JSON;
                goto exit;
            }

            /* We no longer need the string we received */
            memset( buf, 0, len );

            /* Get RVI cmd from string */
            strcpy( cmd, json_string_value( json_object_get( root, "cmd" ) ) );


            if( strcmp( cmd, "au" ) ) {
                /* Process "au" */
                BIO_printf( out, "Got cmd: %s\n", cmd ); 
            } else if( strcmp( cmd, "sa" ) ) {
                /* Process "sa" */
                BIO_printf( out, "Got cmd: %s\n", cmd ); 
            } else if( strcmp( cmd, "rcv" ) ) {
                /* Process "rcv" */
                BIO_printf( out, "Got cmd: %s\n", cmd ); 
            } else if( strcmp( cmd, "ping" ) ) {
                /* Reply to a ping */
                BIO_printf( out, "Got cmd: %s\n", cmd ); 
            } else { /* UNKNOWN RVI COMMAND */
                BIO_printf( out, "Unknown command: %s\n", cmd ); 
                err = -1; /* TODO: Change error */
                goto exit;
            }

            json_decref( root );
        }
        
        free( buf );

        /* Set the mode back to its original bitmask */
        SSL_set_mode( ssl, mode );
    }

    /*      Perform SSL_read */
    /*          if au: */
    /*              perform all au work */
    /*          if sa: */
    /*              validate service name(s) against remote's right_to_receive */
    /*              update service list */
    /*          if rcv: */
    /*              validate service name(s) against remote's right_to_invoke */
    /*              look up service by name */
    /*              invoke callback, passing parameters (if any) */
    /*          if ping: */
    /*              return ping */
    /*       */
    /*      Set fd to stored blocking/nonblocking status */

exit:
    BIO_free_all( out );

    return err;
}
