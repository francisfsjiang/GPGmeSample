#include <stdio.h>
#include <stdlib.h>

#include <gpgme.h>

#include "common.h"

int main(const int argc, const char* argv[]) {

    if (argc < 4) {
        printf("Usage: decrypt_verify USER-ID cipher_file plain_file");
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

    //read cipher text
    gpgme_data_t cipher_data = get_gpgme_data_from_file(
            argv[2],
            "r"
    );

    //write plain text
    gpgme_data_t plain_data = get_gpgme_data_from_file(
            argv[3],
            "w+"
    );

    //decrypt
    err = gpgme_op_decrypt_verify(context, cipher_data, plain_data);
    if (gpg_err_code (err) != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "GPGme decrypt failed. %s", gpgme_strerror(err));
        exit(-1);
    }

    gpgme_decrypt_result_t decrypt_result = gpgme_op_decrypt_result(context);
    if (decrypt_result) {
        printf("Key-id: %s\n", decrypt_result->recipients->keyid);
    }

    gpgme_verify_result_t  verify_result = gpgme_op_verify_result(context);
    if (verify_result) {
        printf("Status: %s\n", gpgme_strerror(
                verify_result->signatures->status
        ));
    }

    gpgme_data_release(plain_data);
    gpgme_data_release(cipher_data);

    gpgme_key_release(key);
    gpgme_release(context);

    return 0;
}