#include "engine_prefix_abi.h"

static void ApplyDefaultBlobs(struct blob_collection_head *blobs)
{
    if (!zapret_engine_default_blobs(blobs, fake_tls_clienthello_default, sizeof(fake_tls_clienthello_default),
        &fake_http_request_default, native_publish_const_blob))
        exit_clean(1);
}
