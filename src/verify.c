#include <stdio.h>
#include <stdlib.h>

#include <gpgme.h>

#include "common.h"

int main(const int argc, const char* argv[]) {

    if (argc < 3) {
        printf("Usage: verify plain_file signature_file\n");
        exit(1);
    }

    gpgme_error_t err;

    gpgme_ctx_t context = init_context();
    if (!context) {
        fprintf(stderr, "gpgme context init failed.\n");
        exit(-1);
    }

    //read cipher text
    FILE* plain_file;
    gpgme_data_t plain_data = get_gpgme_data_from_file(
            &plain_file,
            argv[2],
            "r"
    );

    //write plain text
    FILE* sig_file;
    gpgme_data_t sig_data = get_gpgme_data_from_file(
            &sig_file,
            argv[3],
            "r"
    );

    //verify
    err = gpgme_op_verify(context, sig_data, plain_data, 0);
    if (gpg_err_code (err) != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "GPGme verify failed. %s\n", gpgme_strerror(err));
    } else {
        gpgme_verify_result_t verify_result = gpgme_op_verify_result(context);
        if (verify_result) {
            printf("Verify succeed.\n");
        } else {
            printf("Verify failed.\n");
        }
    }

    gpgme_data_release(plain_data);
    fclose(plain_file);
    gpgme_data_release(sig_data);
    fclose(sig_file);

    gpgme_release(context);

    return 0;
}

