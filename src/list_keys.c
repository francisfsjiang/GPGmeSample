#include <stdio.h>
#include <stdlib.h>

#include <gpgme.h>

#include "common.h"

int main(const int argc, const char* argv[]) {

    if (argc < 2) {
        printf("Usage: list_keys USER-ID");
        exit(1);
    }

    gpgme_error_t err = 0;

    gpgme_ctx_t context = init_context();

    gpgme_key_t key;
    if (!err)
    {
        err = gpgme_op_keylist_start (context, argv[1], 0);
        while (!err)
        {
            err = gpgme_op_keylist_next (context, &key);
            if (err)
                break;
            printf ("%s:", key->subkeys->keyid);
            if (key->uids && key->uids->name)
                printf (" %s", key->uids->name);
            if (key->uids && key->uids->email)
                printf (" <%s>", key->uids->email);
            putchar ('\n');
            gpgme_subkey_t subkey_ptr = key->subkeys;
            while (subkey_ptr != NULL) {
                printf("Subkey: %s\n", subkey_ptr->keyid);
                printf("Can encrypt: %d\n", subkey_ptr->can_encrypt);
                printf("Can certify: %d\n", subkey_ptr->can_certify);
                printf("Can sign: %d\n", subkey_ptr->can_sign);
                subkey_ptr = subkey_ptr->next;
            }
            printf("\n");
            gpgme_key_release (key);
        }
        gpgme_release (context);
    }
    if (gpg_err_code (err) != GPG_ERR_EOF)
    {
        fprintf (stderr, "can not list keys: %s\n", gpgme_strerror (err));
        exit (1);
    }

    return 0;
}