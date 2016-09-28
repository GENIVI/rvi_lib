/* Copyright (c) 2016, Jaguar Land Rover. All Rights Reserved.
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0. 
 */

/** @file rvi.c
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

#include <jansson.h>
#include <jwt.h>

#include "rvi.h"
#include "rvi_list.h"
#include "btree.h"

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
                            /*  note: local services designated 0 (stdin)  */

    /* Properties set in configuration file */
    char *cadir;    /* Directory containing the trusted certificate store */
    char *creddir;  /* Directory containing base64-encoded JWT credentials */
    char *certfile; /* File containing X.509 public key certificate (PKC) */
    char *keyfile;  /* File containing corresponding private key */
    char *cafile;   /* File containing CA public key certificate(s) */
    char *id;       /* Unique device ID. Format is "domain/type/uuid", e.g.: */
                    /* genivi.org/node/839fc839-5fab-472f-87b3-a8fbbd7e3935 */

    /* List of RVI credentials loaded into memory for quick access when
     * negotiating connections */
    rvi_list *creds;

    /* SSL context for spawning new sessions.  */
    /* Contains X509 certs, config settings, etc */
    SSL_CTX *ssl_ctx;

    rvi_list *rights;
} rvi_context_t, *rvi_context_p;

/** @brief Data for connection to remote node */
typedef struct rvi_remote_t {
    /** File descriptor for the connection */
    int fd;
    /** List of rvi_rights_t structures, containing receive & invoke rights and
     * expiration */
    rvi_list *rights;
    /** Pointer to data buffer for partial I/O operations */
    void *buf;
    /** Pointer to BIO chain from OpenSSL library */
    BIO *sbio;
} rvi_remote_t, *rvi_remote_p;

/** @brief Data for service */
typedef struct rvi_service_t {
    /** The fully-qualified service name */
    char *name;
    /** File descriptor of remote node that registered service */
    int registrant;
    /** Callback function to execute upon service invocation */
    rvi_callback_t callback;
    /** Service data to be passed to the callback */
    void *data;
} rvi_service_t, *rvi_service_p;

/** Data structure for rights parsed from validated credential */
typedef struct rvi_rights_t {
    json_t *receive;    /* json array for right(s) to receive */
    json_t *invoke;     /* json array for right(s) to invoke */
    long expiration;     /* unix epoch time for jwt's validity.end */
} rvi_rights_t, *rvi_rights_p;

/* 
 * Declarations for internal functions not exposed in the API 
 */

rvi_service_t *rvi_service_create ( const char *name, const int registrant, 
                                    const rvi_callback_t callback, 
                                    const void *service_data, size_t n );

void rvi_service_destroy ( rvi_service_t *service );

rvi_remote_t *rvi_remote_create ( BIO *sbio, const int fd );

void rvi_remote_destroy ( rvi_remote_t *remote );

rvi_rights_t *rvi_rights_create (   const char *right_to_receive, 
                                    const char *right_to_invoke, 
                                    long validity );

void rvi_rights_destroy ( rvi_rights_t *rights );

void rvi_rights_ldestroy ( rvi_list *list );

void rvi_creds_ldestroy ( rvi_list *list );

char *rvi_fqsn_get( rvi_handle handle, const char *service_name );

/* Comparison functions for constructing btrees and retrieving values */
int compare_fd ( void *a, void *b );

int compare_registrant ( void *a, void *b );

int compare_name ( void *a, void *b );

int compare_pattern ( const char *pattern, const char *fqsn );

/* Utility functions related to OpenSSL library */
int ssl_verify_callback ( int ok, X509_STORE_CTX *store );

SSL_CTX *setup_client_ctx ( rvi_handle handle );

/* Additional utility functions */

int read_json_config ( rvi_handle handle, const char * filename );

char *get_pubkey_file( char *filename );

int validate_credential( rvi_handle handle, const char *cred, X509 *cert );

int get_credential_rights( rvi_handle handle, const char *cred, 
                           rvi_list *rights );

int rvi_rrcv_err( rvi_list *rlist, const char *service_name );

int rvi_rinv_err( rvi_list *rlist, const char *service_name );

int rvi_remove_service(rvi_handle handle, const char *service_name);

int rvi_read_au( rvi_handle handle, json_t *msg, rvi_remote_t *remote );

int rvi_write_au( rvi_handle handle, rvi_remote_t *remote );

int rvi_read_sa( rvi_handle handle, json_t *msg, rvi_remote_t *remote );

int rvi_all_service_announce( rvi_handle handle, rvi_remote_t *remote );

int rvi_service_announce( rvi_handle handle, rvi_service_t *service, int available );

int rvi_read_rcv( rvi_handle handle, json_t *msg, rvi_remote_t *remote );

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
 * This function compares an RVI pattern to a fully-qualified service name. If
 * the service name matches the pattern, it returns RVI_OK or an error
 * otherwise.
 */
int compare_pattern ( const char *pattern, const char *fqsn )
{
    /* Check input */
    if( !pattern || !fqsn )
        return EINVAL;
    /* While there are bytes to compare */
    while( *pattern != '\0' && *fqsn != '\0' ) {
        /* If there's a topic wildcard... */
        if( *pattern == '+' ) {
            /* Advance topic in pattern */
            while( *pattern++ != '/' && *pattern != '\0' );
            /* Advance topic in fqsn */
            while( *fqsn++ != '/' && *fqsn != '\0' );
        }
        /* If the bytes don't match, return error */
        if( *pattern++ != *fqsn++ )
            return -1;
    }
    /* If the pattern still has characters, the fqsn doesn't match */
    if( *pattern != '\0' )
        return -1;

    /* Otherwise, the fqsn matches the pattern */
    return RVI_OK;
}

/* 
 * This function initializes a new service struct and sets the name,
 * registrant, and callback to the specified values. 
 *
 * If service name is null or registrant is negative, this returns NULL and
 * performs no operations. 
 */

rvi_service_t *rvi_service_create ( const char *name, const int registrant, 
                                    const rvi_callback_t callback, 
                                    const void *service_data, size_t n )
{
    /* If name is NULL or registrant is negative, there's an error */
    if ( !name || (registrant < 0) ) return NULL;

    /* Zero-initialize the struct */
    rvi_service_t *service = malloc( sizeof ( rvi_service_t ) );
    if( !service ) return NULL;
    memset(service, 0, sizeof ( rvi_service_t ) );

    /* Set the service name */
    service->name = strdup ( name );

    /* Set the service registrant */
    service->registrant = registrant;

    /* Set the callback. NULL is valid. */
    service->callback = callback;

    /* Set the data to pass to the callback. NULL is valid */
    if( n ) {
        service->data = malloc( n );
        if(! service->data ) {
            free( service->name );
            free( service );
            return NULL;
        }
        memcpy( service->data, service_data, n );
    }

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

     if( service->data )
         free ( service->data );
     free ( service->name );
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
    if( !remote ) return NULL;
    memset ( remote, 0, sizeof ( rvi_remote_t ) );

    /* */
    /* Set the file descriptor and BIO chain */
    /* */
    remote->fd = fd;
    remote->sbio = sbio;

    /* Note that we do NOT need to populate right_to_receive or 
     * right_to_invoke at this time. Those will be populated by parsing the au 
     * message. */
    remote->rights = malloc( sizeof( rvi_list ) );
    if( !remote->rights ) {
        free( remote );
        return NULL;
    }
    rvi_list_initialize( remote->rights );

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

    rvi_rights_ldestroy( remote->rights );

    BIO_free_all ( remote->sbio );

    free ( remote->buf );
    free ( remote );
}

/* This function creates a new rights struct for the given rights and
 * expiration */
rvi_rights_t *rvi_rights_create (   const char *right_to_receive, 
                                    const char *right_to_invoke, 
                                    long validity )
{
    if( !right_to_receive || !right_to_invoke || validity < 1 )
        return NULL;

    rvi_rights_t *new = NULL;
    new = malloc( sizeof( rvi_rights_t ) );
    if( !new) return NULL;
    new->receive = json_loads( right_to_receive, 0, NULL);
    new->invoke = json_loads( right_to_invoke, 0, NULL);
    new->expiration = validity;

    return new;
}

/* This function destroys a rights struct and frees all allocated memory */
void rvi_rights_destroy ( rvi_rights_t *rights ) 
{
    if( !rights )
        return;
    json_decref( rights->receive );
    json_decref( rights->invoke );
    free( rights );
}

/* This function destroys a list containing rights structures and frees all
 * allocated memory */
void rvi_rights_ldestroy ( rvi_list *list )
{
    rvi_list_entry *ptr = list->listHead;
    rvi_list_entry *tmp;
    rvi_rights_t *rights = NULL;
    while( ptr ) {
        tmp = ptr;
        rights = (rvi_rights_t *)ptr->pointer;
        rvi_rights_destroy( rights );
        ptr = ptr->next;
        free( tmp );
    }
    free( list );
}

void rvi_creds_ldestroy ( rvi_list *list )
{
    rvi_list_entry *ptr = list->listHead;
    rvi_list_entry *tmp;
    while( ptr ) {
        tmp = ptr;
        free( ptr->pointer );
        ptr = ptr->next;
        free( tmp );
    }
    free( list );
}

/* This returns a new buffer with the fully-qualified service name using this
 * node's own ID. The memory must be freed by the calling function. Returns
 * NULL on failure. */
char *rvi_fqsn_get( rvi_handle handle, const char *service_name )
{
    if( !handle || !service_name )
        return NULL;

    rvi_context_t   *ctx    = (rvi_context_t *)handle;
    char            *fqsn   = NULL;

    size_t idlen = strlen( ctx->id );
    if( strncmp( service_name, ctx->id, idlen ) != 0 ) {
        size_t namelen = strlen( service_name );
        fqsn = malloc( namelen + idlen + 2 );
        if( !fqsn ) return NULL;
        sprintf( fqsn, "%s/%s", ctx->id, service_name );
    } else {
        fqsn = strdup( service_name );
    }

    return fqsn;
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

    int             err         = RVI_OK;
    json_error_t    errjson;
    json_t          *conf       = NULL;
    json_t          *tmp        = NULL;
    DIR             *d          = NULL;
    struct dirent   *dir        = {0};
    FILE            *fp         = NULL;
    rvi_context_t   *ctx        = (rvi_context_t *)handle;
    BIO             *certbio    = NULL;
    X509            *cert       = NULL;
    char            *cred       = NULL;

    conf = json_load_file( filename, 0, &errjson );
    if( !conf ) {
        err = RVI_ERR_JSON;
        goto exit;
    }

    tmp = json_object_get( conf, "dev" );
    if(!tmp) { err = RVI_ERR_JSON; goto exit; }

    ctx->keyfile = strdup( json_string_value( 
                json_object_get( tmp, "key" ) ) );
    ctx->certfile = strdup( json_string_value( 
                json_object_get( tmp, "cert" ) ) );
    ctx->id = strdup( json_string_value(
                json_object_get ( tmp, "id" ) ) );


    tmp = json_object_get ( conf, "ca" );
    if(!tmp) { err = RVI_ERR_JSON; goto exit; }

    ctx->cadir = strdup( json_string_value( 
                json_object_get( tmp, "dir" ) ) );
    ctx->cafile = strdup( json_string_value( 
                json_object_get( tmp, "cert" ) ) );

    const char *creddir = json_string_value(
                json_object_get ( conf, "creddir" ) );
    
    if( creddir[ strlen( creddir ) ] == '/' ) {
        /* If the final character of the directory is a forward slash */
        ctx->creddir = strdup( creddir );
    } else {
        /* Otherwise, add a trailing slash */
        ctx->creddir = malloc( strlen( creddir ) + 2 );
        if(! ctx->creddir ) {
            err = ENOMEM;
            goto exit;
        }
        sprintf( ctx->creddir, "%s/", creddir );
    }

    json_decref(conf);

    if( !(ctx->creddir) ) { err = RVI_ERR_NOCRED; goto exit; }

    d = opendir( ctx->creddir );
    if (!d) { err = RVI_ERR_NOCRED; goto exit; }

    certbio = BIO_new_file( ctx->certfile, "r" );
    if( !certbio ) { err = RVI_ERR_NOCRED; goto exit; }
    cert = PEM_read_bio_X509( certbio, NULL, 0, NULL);
    if( !cert ) { err = RVI_ERR_NOCRED; goto exit; }

    int i = 0;
    char *path = NULL;
    size_t path_size;
    while ( ( dir = readdir( d ) ) ) {
        if ( strstr( dir->d_name, ".jwt" ) ) {
            /* if it's a jwt file, open it */
            path_size = strlen(ctx->creddir) + strlen(dir->d_name) + 1;
            path = malloc(path_size);
            if(!path) { err = ENOMEM; goto exit; }
            sprintf(path, "%s%s", ctx->creddir, dir->d_name );
            fp = fopen( path, "r" );
            if( !fp ) return RVI_ERR_NOCRED;
            /* go to end of file */
            if( fseek( fp, 0L, SEEK_END ) != 0 ) return RVI_ERR_NOCRED;
            /* get value of file position indicator */
            long bufsize = ftell(fp);
            if( bufsize == -1 ) return RVI_ERR_NOCRED;
            cred = malloc(sizeof(char) * (bufsize + 1));
            if( !cred ) { err = ENOMEM; goto exit; }
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
                rvi_list_insert( ctx->creds, cred );
            }
            fclose( fp );
            free(path);
            i++;
        }
    }

exit:
    BIO_free_all( certbio );
    X509_free( cert );
    if( d ) closedir( d );

    return err;
}

/** Get arrays of right_to_receive and right_to_invoke */
int get_credential_rights( rvi_handle handle, const char *cred, 
                           rvi_list *rights )
{
    if( !handle || !cred ||  !rights /*!rec_arr || !inv_arr */ )
        return EINVAL;

    rvi_context_p   ctx = (rvi_context_p)handle;
    jwt_t           *jwt;
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
    
    /* Load the rights to receive */
    char *rcv = (char *)jwt_get_grant( jwt, "right_to_receive" );
    /* Load the right to invoke */
    char *inv = (char *)jwt_get_grant( jwt, "right_to_invoke" );

    rvi_rights_t *new = rvi_rights_create( rcv, inv, stop );

    rvi_list_insert( rights, new );
 
    free( rcv );

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

int rvi_rrcv_err( rvi_list *rlist, const char *service_name )
{
    if( !rlist || !service_name )
        return EINVAL;

    int     err     = -1; /* By default, assume no rights */
    json_t  *value  = NULL;
    size_t  index;

    rvi_list_entry *ptr = rlist->listHead;
    while( ptr ) {
        rvi_rights_t *tmp = (rvi_rights_t *)ptr->pointer;
        if( !tmp ) goto exit;
        json_array_foreach( tmp->receive, index, value ) {
            const char *pattern = json_string_value( value );
            if( ( err = compare_pattern( pattern, service_name ) ) == RVI_OK )
                goto exit; /* We found a match, exit immediately */
        }
        ptr = ptr->next;
    }

exit:
    return err;
}

int rvi_rinv_err( rvi_list *rlist, const char *service_name )
{
    if( !rlist || !service_name )
        return EINVAL;

    int     err     = -1; /* By default, assume no rights */
    json_t  *value  = NULL;
    size_t  index;

    rvi_list_entry *ptr = rlist->listHead;
    while( ptr ) {
        rvi_rights_t *tmp = (rvi_rights_t *)ptr->pointer;
        json_array_foreach( tmp->invoke, index, value ) {
            const char *pattern = json_string_value( value );
            if( ( err = compare_pattern( pattern, service_name ) ) == RVI_OK )
                goto exit; /* We found a match, exit immediately */
        }
        ptr = ptr->next;
    }

exit:
    return err;

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
    /* First, load PEM string into memory */
    if( !( certbio = BIO_new_file( filename, "r" ) ) ) {
        ret = ENOMEM; 
        goto exit;
    }
    /* Then read the certificate from the string */
    if( !( cert = PEM_read_bio_X509( certbio, NULL, 0, NULL ) ) ) {
        ret = 1; 
        goto exit; 
    } 
    /* Get the public key from the certificate */
    if( !( pkey = X509_get_pubkey(cert) ) ) {
        ret = 1; 
        goto exit;
    }
    /* Make a new memory BIO */
    if( !( mbio = BIO_new(BIO_s_mem() ) ) ) {
        ret = ENOMEM;
        goto exit;
    }
    /* Write the pubkey to the new BIO as a PEM-formatted string */
    ret = PEM_write_bio_PUBKEY(mbio, pkey);

    if( ret == 0 ) {
        ret = RVI_ERR_OPENSSL;
        goto exit;
    }
    /* Find out how long our new string is */
    length = BIO_ctrl_pending(mbio);
    /* Allocate a buffer for the key string... */
    if( !( key = malloc( length + 1 ) ) ) {
        ret = ENOMEM;
        goto exit;
    }
    /* Load the string into memory */
    if( (ret = BIO_read(mbio, key, length)) != length) {
        goto exit;
    }
    /* Make sure it's null-formatted, just in case */
    key[length] = '\0';

    ret = RVI_OK;

exit:
    /* Free all the memory */
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

    /* Get the public key from the trusted CA */
    key = get_pubkey_file( ctx->cafile );

    if( !key ) {
        ret = -1;
        goto exit;
    }

    length = strlen(key) + 1;

    /* If token does not pass sig check, libjwt supplies errno */
    if( ( ret = jwt_decode( &jwt, cred, (unsigned char *)key, length ) ) ) {
        goto exit;
    }

    /* RVI credentials use RS256 */
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
    if( !tmp ) { ret = ENOMEM; goto exit; }
    sprintf(tmp, "%s%s%s", certHead, device_cert, certFoot);

    /* Check that certificate in credential matches expected cert */
    bio = BIO_new( BIO_s_mem() );
    BIO_puts( bio, (const char *)tmp );
    dcert = PEM_read_bio_X509( bio, NULL, 0, NULL );
    if( !dcert ) {
        ret = RVI_ERR_OPENSSL;
        goto exit;
    }
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

/*
 * Initialize the RVI library. Call before using any other functions.
 */

rvi_handle rvi_init ( char *config_filename )
{
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
    ctx->creds = malloc( sizeof( rvi_list ) );
    ctx->rights = malloc( sizeof( rvi_list ) );

    if( !ctx->creds || !ctx->rights ) {
        fprintf(stderr, "Unable to allocate memory\n");
        return NULL;
    }

    rvi_list_initialize( ctx->creds );
    rvi_list_initialize( ctx->rights );
    
    if ( read_json_config ( ctx, config_filename ) != 0 ) {
        fprintf(stderr, "Error reading config file\n");
        goto err;
    }

    rvi_list_entry *ptr = ctx->creds->listHead;
    while( ptr ) {
        int ret = get_credential_rights( ctx, (char *)ptr->pointer, 
                                         ctx->rights );
        if( ret != RVI_OK )
            goto err;
        ptr = ptr->next;
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

/* 
 * Tear down the API.
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
    rvi_creds_ldestroy( ctx->creds );

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
    if( ctx->id )
        free ( ctx->id );

    rvi_rights_ldestroy( ctx->rights );

    /* Free the memory allocated to the rvi_context_t struct */
    free(ctx);

    return RVI_OK;
}

/* ************************* */
/* RVI CONNECTION MANAGEMENT */
/* ************************* */

/* 
 * Connect to a remote node at a specified address and port. 
 */
int rvi_connect(rvi_handle handle, const char *addr, const char *port)
{
    /* Ensure that we have received valid arguments */
    if( !handle || !addr || !port ) {
        return -EINVAL;
    }

    BIO             *sbio   = NULL;
    SSL             *ssl    = NULL;
    rvi_remote_t    *remote = NULL;
    rvi_context_t   *ctx    = (rvi_context_t *)handle;
    int ret;

    ret = RVI_OK;

    /* 
     * Spawn new SSL session from handle->ctx. BIO_new_ssl_connect spawns a new
     * chain including a SSL BIO (using ctx) and a connect BIO
     */
    sbio = BIO_new_ssl_connect(ctx->ssl_ctx);
    if(!sbio) {
        ret = -RVI_ERR_OPENSSL;
        goto err;
    }
    BIO_get_ssl(sbio, &ssl);
    if(!ssl) {
        ret = -RVI_ERR_OPENSSL;
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
    if( ctx->remote_idx->count ) {
        btree_iter iter = btree_iter_begin( ctx->remote_idx );
        while( !btree_iter_at_end( iter ) ) {
            rvi_remote_t *rtmp = btree_iter_data( iter );
            if( 0 == strcmp( BIO_get_conn_hostname ( sbio ), 
                             BIO_get_conn_hostname( rtmp->sbio )
                           )  
              ) { /* We already have a connection to that host */
                ret = -1;
                break;
            }
            btree_iter_next( iter );
        }
        btree_iter_cleanup( iter );
    }
    if( ret != RVI_OK ) goto err;

    if(BIO_do_connect(sbio) <= 0) {
        ret = -RVI_ERR_OPENSSL;
        goto err;
    }

    if(BIO_do_handshake(sbio) <= 0) {
        ret = -RVI_ERR_OPENSSL;
        goto err;
    }

    remote = rvi_remote_create ( sbio, SSL_get_fd ( ssl ) );

    /* Add this data structure to our lookup tree */
    btree_insert(ctx->remote_idx, remote);
    
    rvi_write_au( handle, remote ); 
    
    /* parse incoming "au" message */
    rvi_process_input( handle, &remote->fd, 1 );

    /* create JSON array of all services */
    rvi_all_service_announce( handle, remote );

    /* parse incoming "sa" message */
    rvi_process_input( handle, &remote->fd, 1 );

    return remote->fd;

err:
    ERR_print_errors_fp( stderr );
    rvi_remote_destroy( remote );
    BIO_free_all( sbio );

    return ret;
}

/* 
 * Disconnect from a remote node with a specified file descriptor. 
 */
int rvi_disconnect(rvi_handle handle, int fd)
{
    if( !handle || fd < 3 ) 
        return -EINVAL;
    
    rvi_context_t * ctx = (rvi_context_t *)handle;
    rvi_remote_t    rkey = {0};
    rvi_remote_t *  rtmp;
    rvi_service_t   skey = {0};
    rvi_service_t * stmp;
    int             res;
    
    rkey.fd = fd;

    rtmp = btree_search(ctx->remote_idx, &rkey);
    if(!rtmp) {
        return -ENXIO;
    }

    if( ( res = btree_delete(ctx->remote_idx, 
                             ctx->remote_idx->root, rtmp ) ) < 0 ) {
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

/* 
 * Return all file descriptors in the RVI context
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


/* 
 * Register a service with a callback function
 */
int rvi_register_service( rvi_handle handle, const char *service_name, 
                          rvi_callback_t callback, 
                          void *service_data, size_t n )
{
    if( !handle || !service_name )
        return EINVAL;

    int             err         = 0;
    rvi_context_t   *ctx        =   (rvi_context_t *)handle;
    rvi_service_t   *service    = NULL;
    char            *fqsn       = NULL;

    fqsn = rvi_fqsn_get( handle, service_name );
    if( !fqsn )
        return ENOMEM;
    
    if( (err = rvi_rrcv_err( ctx->rights, fqsn ) ) ) {
        goto exit;
    }

    /* Create a new rvi_service_t structure */
    service = rvi_service_create( fqsn, 0, callback, service_data, n );

    /* Add service to services_by_name */
    btree_insert( ctx->service_name_idx, service );
    /* Add service to services_by_registrant */
    btree_insert( ctx->service_reg_idx, service );

    rvi_service_announce( handle, service, 1 );

exit:
    free( fqsn );

    return err;
}

/* 
 * Unregister a previously registered service
 */
int rvi_unregister_service(rvi_handle handle, const char *service_name)
{
    if( !handle || !service_name )
        return EINVAL;

    int             err     = RVI_OK;
    rvi_context_t   *ctx    = ( rvi_context_t * )handle;
    rvi_service_t   skey    = {0};
    
    skey.name = rvi_fqsn_get( handle, service_name );
    rvi_service_t *stmp = btree_search( ctx->service_name_idx, &skey );
    
    if( !stmp ) {
        err = -ENXIO;
        goto exit;
    }

    if( stmp->registrant != 0 ) {
        err = -RVI_ERR_RIGHTS;
        goto exit;
    }

    rvi_service_announce( handle, stmp, 0 );

    err = rvi_remove_service( handle, skey.name );

exit:
    free( skey.name );

    return err;
}

int rvi_remove_service(rvi_handle handle, const char *service_name)
{
    if( !handle || !service_name )
        return EINVAL;

    rvi_context_t   *ctx    = ( rvi_context_t * )handle;
    rvi_service_t   skey    = {0};
    
    skey.name = strdup( service_name );
    rvi_service_t *stmp = btree_search( ctx->service_name_idx, &skey );

    free( skey.name );
    
    if( !stmp )
        return -ENOENT;
    btree_delete( ctx->service_name_idx, 
                          ctx->service_name_idx->root, stmp );
    btree_delete( ctx->service_reg_idx, 
                          ctx->service_reg_idx->root, stmp );
    rvi_service_destroy( stmp );

    return RVI_OK;
}

/* 
 * Get list of services available
 */
int rvi_get_services(rvi_handle handle, char **result, int *len)
{
    if( !handle || !result || ( *len < 1 ) )
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

/* 
 * Invoke a remote service
 */
int rvi_invoke_remote_service(rvi_handle handle, const char *service_name, 
                              const char *parameters)
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
        ret = ENOENT;
        goto exit;
    }

    /* identify registrant, get SSL session from remote index */
    rkey.fd = stmp->registrant;

    rtmp = btree_search(ctx->remote_idx, &rkey);
    if( !rtmp ) { ret = ENXIO; goto exit; }

    time(&rawtime);
    timeout = rawtime + wait;

    /* prepare rcv message */
    if( parameters ) {
        params = json_loads( parameters, 0, NULL );
    }
    if ( !params ) { ret = RVI_ERR_JSON; goto exit; }

    rcv = json_pack( 
            "{s:s, s:i, s:s, s:{s:s, s:i, s:o}}",
            "cmd", "rcv",
            "tid", 1, /* TODO: talk to Ulf about tid */
            "mod", "proto_json_rpc",
            "data", "service", service_name,
                    "timeout", timeout,
                    "parameters", params
            );
    if( ! rcv ) {
        printf("JSON error\n");
        ret = RVI_ERR_JSON;
        goto exit;
    }

    char *rcvString = json_dumps(rcv, JSON_COMPACT);

    /* send rcv message to registrant */
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

    /* For each file descriptor we've received */
    while( i < fd_len ) {
        rkey.fd = fd_arr[i]; /* Set the key to the requested fd */
        i++;
        rtmp = btree_search( ctx->remote_idx, &rkey ); /* Find the connection */
        if( !rtmp ) {
            err = ENXIO;
            printf( "No connection on %d\n", rkey.fd );
            continue;
        }
        BIO_get_ssl( rtmp->sbio, &ssl );
        if( !ssl ) {
            err = RVI_ERR_OPENSSL;
            printf( "Error reading on fd %d, try again\n", rtmp->fd );
            continue;
        }
        /* Grab the current mode flags from the session */
        mode = SSL_get_mode ( ssl );
        /* Ensure our mode is blocking */
        SSL_set_mode( ssl, SSL_MODE_AUTO_RETRY );

        buf = malloc( len + 1 );
        if( !buf ) { err = ENOMEM; goto exit; }

        memset( buf, 0, len );

        read = BIO_read( rtmp->sbio, buf, len );
        if( read  <= 0 )  { err = EIO; goto exit; } 

        root = json_loads( buf, 0, &jserr ); /* RVI commands are JSON structs */
        if( !root ) { err = RVI_ERR_JSON; goto exit; }

        /* Get RVI cmd from string */
        strcpy( cmd, json_string_value( json_object_get( root, "cmd" ) ) );

        if( strcmp( cmd, "au" ) == 0 ) {
            rvi_read_au( handle, root, rtmp );
        } else if( strcmp( cmd, "sa" ) == 0 ) {
            rvi_read_sa( handle, root, rtmp );
        } else if( strcmp( cmd, "rcv" ) == 0 ) {
            rvi_read_rcv( handle, root, rtmp );
        } else if( strcmp( cmd, "ping" ) == 0 ) {
            /* Echo the ping back */
            BIO_puts( rtmp->sbio, buf );
        } else { /* UNKNOWN RVI COMMAND */
            err = -RVI_ERR_NOCMD; 
            goto exit;
        }

        /* Set the mode back to its original bitmask */
        SSL_set_mode( ssl, mode );

        /* We no longer need the string we received */
        memset( buf, 0, len );

        json_decref( root );
    }
        
    free( buf );


exit:
    return err;
}

int rvi_read_au( rvi_handle handle, json_t *msg, rvi_remote_t *remote )
{
    if( !handle || !msg || !remote )
        return EINVAL;

    int             err     = 0;
    SSL             *ssl    = NULL;
    size_t          index;
    json_t          *value  = NULL;
    X509            *cert   = NULL;
    json_t          *tmp    = NULL;

    tmp = json_object_get( msg, "creds" );
    if( !tmp ) {
        err = RVI_ERR_JSON;
        goto exit;
    }

    BIO_get_ssl( remote->sbio, &ssl );
    if( !ssl ) {
        err = RVI_ERR_OPENSSL;
        goto exit;
    }

    if( ! ( cert = SSL_get_peer_certificate( ssl ) ) ) {
        err = RVI_ERR_OPENSSL;
        goto exit;
    }

    json_array_foreach( tmp, index, value ) {
        const char *val = json_string_value( value );
        if(  validate_credential( handle, val, cert ) != RVI_OK ) {
            continue;
        }
        err = get_credential_rights( handle, val, remote->rights );
        if( err ) goto exit;
    }

exit:
    if( cert ) X509_free( cert );
    return err;
}

int rvi_write_au( rvi_handle handle, rvi_remote_t *remote )
{
    if( !handle || !remote )
        return EINVAL;

    int             err     = RVI_OK;
    rvi_context_t   *ctx    = ( rvi_context_t * )handle;
    json_t          *creds  = NULL;
    json_t          *au     = NULL;


    creds = json_array();
    rvi_list_entry *ptr = ctx->creds->listHead;
    while( ptr ) {
        json_array_append_new( creds, json_string( (char *)ptr->pointer ) );
        ptr = ptr->next;
    }

    au = json_pack( "{s:s, s:s, s:o}", 
                    "cmd", "au",            /* populate cmd */
                    "ver", "1.1",           /* populate version */
                    "creds", creds   /* fill with json array */
                  ); 
    if( !au ) {
        err = RVI_ERR_JSON;
        goto exit;
    }

    char *auString = json_dumps(au, JSON_COMPACT);

    /* send "au" message */
    BIO_puts( remote->sbio, auString );

exit:
    free( auString );
    json_decref( au );

    return err;
}

int rvi_read_sa( rvi_handle handle, json_t *msg, rvi_remote_t *remote )
{
    if( !handle || !msg || !remote )
        return EINVAL;

    int             err     = 0;
    rvi_context_t   *ctx    = ( rvi_context_t * )handle;
    size_t          index;
    json_t          *value  = NULL;
    json_t          *tmp    = NULL;
    int             av      = 0;

    tmp = json_object_get( msg, "svcs" );
    if( !tmp ) {
        err = RVI_ERR_JSON;
        goto exit;
    }

    const char *stat = json_string_value( json_object_get( msg, "stat" ) );
    if( strcmp( stat, "av" ) == 0 ) {
        av = 1;
    }

    json_array_foreach( tmp, index, value ) {
        const char *val = json_string_value( value );
        if( av ) { /* Service newly available */
            /* If remote doesn't have right to receive, discard */
            if ( ( err = rvi_rrcv_err( remote->rights, val ) ) ) 
                continue;
            /* If we don't have right to invoke, discard */
            if ( ( err = rvi_rinv_err( ctx->rights, val ) ) )
                continue;
            
            /* Otherwise, add the service to services available */
            rvi_service_t *service = rvi_service_create( 
                                                 val, remote->fd, 
                                                 NULL, NULL, 0
                                                       );
            btree_insert( ctx->service_name_idx, service );
            btree_insert( ctx->service_reg_idx, service );
        } else { /* Service not available, find it and remove it */
            /* If remote doesn't have right to receive, ignore this message */
            if ( ( err = rvi_rrcv_err( remote->rights, val ) ) ) 
                continue;
            rvi_remove_service( handle, val );
        }
    }

exit:
    return err;
}

int rvi_all_service_announce( rvi_handle handle, rvi_remote_t *remote )
{
    if( !handle || !remote )
        return EINVAL;


    int             err     = RVI_OK;
    rvi_context_t   *ctx    = ( rvi_context_t * )handle;
    json_t          *svcs   = NULL;
    json_t          *sa     = NULL;


    svcs = json_array();
    if( ctx->service_name_idx->count ) {
        btree_iter iter = btree_iter_begin( ctx->service_name_idx );
        while ( !btree_iter_at_end( iter ) ) {
            rvi_service_t *stmp = btree_iter_data( iter );
            if ( /* The remote is allowed to invoke it */
                 !( err = rvi_rinv_err( remote->rights, stmp->name ) ) &&
                 /* The service was registered locally */
                 stmp->registrant == 0
               ) {
                json_array_append_new( svcs, json_string( stmp->name ) );
            }
            btree_iter_next( iter );
        }
        btree_iter_cleanup( iter );
    }

    sa = json_pack( "{s:s, s:s, s:o}", 
            "cmd", "sa",            /* populate cmd */
            "stat", "av",           /* populate status */
            "svcs", svcs              /* fill with array of services */
            ); 
    if( !sa ) {
        err = RVI_ERR_JSON;
        goto exit;
    }

    /* send "sa" reply */
    char *saString = json_dumps(sa, JSON_COMPACT);

    BIO_puts( remote->sbio, saString );

exit:
    free(saString);
    json_decref(sa);

    return err;
}

int rvi_service_announce( rvi_handle handle, rvi_service_t *service, int available )
{
    if( !handle || !service )
        return EINVAL;

    int             err     = RVI_OK;
    rvi_context_t   *ctx    = (rvi_context_t *)handle;
    json_t          *svcs   = NULL;
    json_t          *sa     = NULL;
    char            *saString = NULL;

    svcs = json_array();
    json_array_append_new( svcs, json_string( service->name ) );
    if( ( err = rvi_rrcv_err( ctx->rights, service->name ) ) ) {
        err = -RVI_ERR_RIGHTS; 
        goto exit;
    }

    if( service->registrant != 0 ) {
        err = -RVI_ERR_RIGHTS; 
        goto exit;
    }

    if( !(ctx->remote_idx->count) ) {
        err = -ENXIO; 
        goto exit;
    }

    sa = json_pack( "{s:s, s:s, s:o}",
            "cmd", "sa",                        /* populate cmd */
            "stat", (available ? "av" : "un"),  /* populate status */
            "svcs", svcs                        /* fill with services */
            );

    saString = json_dumps(sa, JSON_COMPACT);

    btree_iter iter = btree_iter_begin( ctx->remote_idx );
        while( !btree_iter_at_end( iter  ) ) {
            rvi_remote_t *remote = btree_iter_data( iter );
            if( ( err = rvi_rinv_err( remote->rights, service->name ) ) ) {
                continue; /* If the remote can't invoke, don't announce */
            }
            BIO_puts( remote->sbio, saString );
            btree_iter_next( iter );
        }
    btree_iter_cleanup( iter );


exit:
    if( saString ) free( saString );
    json_decref(svcs);
    json_decref(sa);

    return err;
}

int rvi_read_rcv( rvi_handle handle, json_t *msg, rvi_remote_t *remote )
{
    if( !handle || !msg || !remote )
        return EINVAL;

    int             err     = 0;
    rvi_context_t   *ctx    = ( rvi_context_t * )handle;
    json_t          *tmp    = NULL;
    json_t          *params = NULL;
    rvi_service_t   skey    = {0};
    rvi_service_t   *stmp   = NULL;
    char            *parameters = NULL;
    time_t          rawtime;
    const char      *sname;

    tmp = json_object_get( msg, "data" );
    if( !tmp ) {
        err = RVI_ERR_JSON;
        goto exit;
    }

    long timeout = json_integer_value( json_object_get( tmp, "timeout" ) );
    time(&rawtime);
    if( rawtime > timeout ) { /* Service invocation timed out, discard */
        goto exit;
    }

    sname = json_string_value( json_object_get( tmp, "service" ) );
    if( ( err = rvi_rinv_err( remote->rights, sname ) ) )
        goto exit; /* Remote does not have right to invoke */
    if( ( err = rvi_rrcv_err( ctx->rights, sname ) ) )
        goto exit; /* This node does not have the right to receive */

    skey.name = strdup( sname );
    stmp = btree_search( ctx->service_name_idx, &skey );
    if( !stmp ) {
        err = ENXIO; 
        goto exit;
    }

    params = json_object_get( tmp, "parameters" );
    if( !params ) {
        err = RVI_ERR_JSON;
        goto exit;
    }
    parameters = json_dumps( params, JSON_COMPACT );

    stmp->callback( remote->fd, stmp->data, parameters );

exit:
    if( skey.name ) free( skey.name );
    return err;
}
