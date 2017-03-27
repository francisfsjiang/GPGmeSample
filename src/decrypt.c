#include <stdio.h>
#include <stdlib.h>

#include <gpgme.h>

#include "common.h"

int main(const int argc, const char* argv[]) {

    if (argc < 4) {
        printf("Usage: decrypt USER-ID cipher_file plain_file\n");
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

    //read cipher text
    FILE* cipher_file;
    gpgme_data_t cipher_data = get_gpgme_data_from_file(
            &cipher_file,
            argv[2],
            "r"
    );

    //write plain text
    FILE* plain_file;
    gpgme_data_t plain_data = get_gpgme_data_from_file(
            &plain_file,
            argv[3],
            "w+"
    );

    //decrypt
    err = gpgme_op_decrypt(context, cipher_data, plain_data);
    if (gpg_err_code (err) != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "GPGme decrypt failed. %s\n", gpgme_strerror(err));
    } else {
        gpgme_decrypt_result_t decrypt_result = gpgme_op_decrypt_result(context);
        if (decrypt_result) {
            printf("Decrypt succeed.\n");
        } else {
            printf("Decrypt failed.\n");
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