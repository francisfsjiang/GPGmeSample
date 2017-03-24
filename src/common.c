#include "common.h"

#include <memory.h>
#include <errno.h>


gpgme_key_t get_key(gpgme_ctx_t context, const char* user_id) {
    gpgme_error_t err;

    gpgme_key_t key = NULL;
    err = gpgme_op_keylist_start (context, user_id, 0);
    while (!err)
    {
        err = gpgme_op_keylist_next (context, &key);
        if (err)
            break;

        //NOTICE: gpgme_key_t is a pointer
        return key;
    }

    if (gpg_err_code (err) != GPG_ERR_NO_ERROR)
    {
        fprintf (stderr, "Get key failed: %s\n", gpgme_strerror (err));
        return NULL;
    }

    return NULL;
}


gpgme_ctx_t init_context() {
    gpgme_ctx_t context;
    gpgme_error_t err;
    gpgme_check_version(NULL);

    err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
    if (gpg_err_code(err) != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "Check version failed.");
        return NULL;
    }

    err = gpgme_new(&context);
    if (gpg_err_code(err) != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "Create context failed.");
        return NULL;
    }

    err = gpgme_set_protocol(context, GPGME_PROTOCOL_OpenPGP);
    if (gpg_err_code(err) != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "Get protocol failed.");
        gpgme_release(context);
        return NULL;
    }

    return context;
}

gpgme_data_t get_gpgme_data_from_file(const char* path, const char* mode) {

    FILE* file = fopen(path, mode);
    if (!file) {
        fprintf (stderr, "Open file failed.");
        return NULL;
    }
    gpgme_data_t data = NULL;
    gpgme_error_t err = gpgme_data_new_from_stream(&data, file);
    if (gpg_err_code (err) != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "GPGme data new failed. %s", strerror(errno));
        data = NULL;
    }
    return data;
}
