#include <stdio.h>
#include <stdlib.h>

#include <gpgme.h>

#include "common.h"

int main(const int argc, const char* argv[]) {

    if (argc < 3) {
        printf("Usage: verify plain_file signature_file");
        exit(1);
    }

    gpgme_error_t err;

    gpgme_ctx_t context = init_context();
    if (!context) {
        fprintf(stderr, "gpgme context init failed.");
        exit(-1);
    }

    //read cipher text
    gpgme_data_t plain_data = get_gpgme_data_from_file(
            argv[1],
            "r"
    );

    //write plain text
    gpgme_data_t sig_data = get_gpgme_data_from_file(
            argv[2],
            "r"
    );

    //verify
    err = gpgme_op_verify(context, sig_data, plain_data, 0);
    if (gpg_err_code (err) != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "GPGme decrypt failed. %s", gpgme_strerror(err));
    }

    gpgme_verify_result_t  verify_result = gpgme_op_verify_result(context);
    if (verify_result) {
        printf("Status: %s\n", gpgme_strerror(
                verify_result->signatures->status
        ));
    }

    gpgme_data_release(plain_data);
    gpgme_data_release(sig_data);

    gpgme_release(context);

    return 0;
}

