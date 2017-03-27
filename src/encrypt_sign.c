#include <stdio.h>
#include <stdlib.h>

#include <gpgme.h>

#include "common.h"

int main(const int argc, const char* argv[]) {

    if (argc < 4) {
        printf("Usage: encrypt_sign USER-ID plain_file cipher_file\n");
        exit(1);
    }

    gpgme_error_t err;

    gpgme_ctx_t context = init_context();
    if (!context) {
        fprintf(stderr, "gpgme context init failed.\n");
        exit(-1);
    }

    gpgme_key_t key = get_key(context, argv[1]);
    if (!key) {
        fprintf(stderr, "get key failed.\n");
        exit(-1);
    }

    //read plain text
    FILE* plain_file;
    gpgme_data_t plain_data = get_gpgme_data_from_file(
            &plain_file,
            argv[2],
            "r"
    );

    //write cipher text
    FILE* cipher_file;
    gpgme_data_t cipher_data = get_gpgme_data_from_file(
            &cipher_file,
            argv[3],
            "w+"
    );

    //encrypt
    gpgme_key_t recp[] = {key, NULL};
    err = gpgme_op_encrypt_sign(context, recp, 0, plain_data, cipher_data);
    if (gpg_err_code (err) != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "GPGme encrypt_sign failed. %s\n", gpgme_strerror(err));
    } else {
        gpgme_encrypt_result_t encrypt_result = gpgme_op_encrypt_result(context);
        if (encrypt_result) {
            printf("Encrypt succeed.\n");
        } else {
            printf("Encrypt failed.\n");
        }

        gpgme_sign_result_t sign_result = gpgme_op_sign_result(context);
        if (sign_result) {
            printf("Sign succeed.\n");
        } else {
            printf("Sign failed.\n");
        }
    }

    gpgme_data_release(plain_data);
    fclose(plain_file);
    gpgme_data_release(cipher_data);
    fclose(cipher_file);

    gpgme_key_release(key);
    gpgme_release(context);

    return 0;
}