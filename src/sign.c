#include <stdio.h>
#include <stdlib.h>

#include <gpgme.h>

#include "common.h"

int main(const int argc, const char* argv[]) {

    if (argc < 4) {
        printf("Usage: sign USER-ID plain_file signature_file");
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

    //write sign text
    gpgme_data_t sig_data = get_gpgme_data_from_file(
            argv[3],
            "w+"
    );

    //decrypt
    err = gpgme_op_sign(context, plain_data, sig_data, GPGME_SIG_MODE_DETACH);

    if (gpg_err_code (err) != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "GPGme sign failed. %s", gpgme_strerror(err));
    }

    gpgme_sign_result_t sign_result = gpgme_op_sign_result(context);
    if (sign_result) {
        printf("Finger print: %s\n", sign_result->signatures->fpr);
    }

    gpgme_data_release(plain_data);
    gpgme_data_release(sig_data);

    gpgme_key_release(key);
    gpgme_release(context);

    return 0;
}
