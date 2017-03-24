#include <stdio.h>
#include <stdlib.h>

#include <gpgme.h>

#include "common.h"

int main(const int argc, const char* argv[]) {

    if (argc < 4) {
        printf("Usage: encrypt_sign USER-ID plain_file cipher_file");
        exit(1);
    }

    gpgme_error_t err;

    gpgme_ctx_t context = init_context();
    if (!context) {
        fprintf(stderr, "gpgme context init failed.");
        exit(-1);
    }

    gpgme_key_t key = get_key(context, argv[1]);
    if (!key) {
        fprintf(stderr, "get key failed.");
        exit(-1);
    }

    //read plain text
    gpgme_data_t plain_data = get_gpgme_data_from_file(
            argv[2],
            "r"
    );

    //write cipher text
    gpgme_data_t cipher_data = get_gpgme_data_from_file(
            argv[3],
            "w+"
    );

    //encrypt
    gpgme_key_t recp[] = {key, NULL};
    err = gpgme_op_encrypt_sign(context, recp, 0, plain_data, cipher_data);
    if (gpg_err_code (err) != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "GPGme encrypt failed. %s", gpgme_strerror(err));
        exit(-1);
    }

    gpgme_data_release(plain_data);
    gpgme_data_release(cipher_data);

    gpgme_key_release(key);
    gpgme_release(context);

    return 0;
}