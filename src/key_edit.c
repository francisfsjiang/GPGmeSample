#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <errno.h>

#include <gpgme.h>

#include "common.h"


static void
flush_data (gpgme_data_t dh) {
    char buf[100];
    gpgme_error_t err;

    off_t ret= gpgme_data_seek(dh, 0, SEEK_SET);
    if (ret) {
        err = gpgme_error_from_errno(errno);
        if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
            fprintf (stderr, "GPGME data seek failed: %s\n", gpgme_strerror (err));
        }

    }

    while (1) {
        ssize_t size = gpgme_data_read(dh, buf, 100);
        if (size <= 0) {
            break;
        }
        fwrite(buf, (size_t)size, 1, stdout);
    }
    if (ret < 0) {
        err = gpgme_error_from_errno(errno);
        if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
            fprintf (stderr, "GPGME data seek failed: %s\n", gpgme_strerror (err));
        }
    }
}


gpgme_error_t
interact_fnc (void *opaque, const char *status, const char *args, int fd) {
    const char *result = NULL;

    fprintf(stdout, "[-- Code: %s, %s --]\n", status, args);

    if (fd >= 0) {
        if (!strcmp(args, "keyedit.prompt")) {
            static int step = 0;

            switch (step) {
                case 0:
                    result = "addphoto";
//                    result = "fpr";
                    break;
                case 1:
                    result = "quit";
                    break;
                case 2:
                    result = "Y";
                    break;

                default:
                    result = "quit";
                    break;
            }
            step++;
        }
        else if (!strcmp (args, "keyedit.save.okay")){
            result = "Y";
        }
        else if (!strcmp(args, "photoid.jpeg.add")) {
            result = (char*) opaque;
        }
        else if (!strcmp(args, "photoid.jpeg.size")) {
            result = "Y";
        }
    }
    printf("result: %s\n", result);
    if (result) {
        gpgme_io_writen(fd, result, strlen(result));
        gpgme_io_writen(fd, "\n", 1);
    }
    return 0;
}


int main(const int argc, const char* argv[]) {

    if (argc < 3) {
        printf("Usage: key_edit USER-ID new_photo_path \n");
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

    gpgme_data_t data;
    gpgme_data_new(&data);

    err = gpgme_op_interact(
            context,
            key,
            0,
            interact_fnc,
            (void*)argv[2],
            data
    );



    gpgme_key_release(key);
    gpgme_release(context);

    return 0;
}
