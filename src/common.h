#ifndef GPGME_TEST_COMMON_H
#define GPGME_TEST_COMMON_H

#include <gpgme.h>


gpgme_key_t get_key(gpgme_ctx_t context, const char* user_id);

gpgme_ctx_t init_context();

gpgme_data_t get_gpgme_data_from_file(FILE** file, const char* path, const char* mode);


#endif //GPGME_TEST_COMMON_H
