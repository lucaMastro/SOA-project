#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>

#include "./hash_helper.h"

int compute_hash(char *input_string, int input_size, char *output_buffer) {
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int ret;

    tfm = crypto_alloc_shash(HASH_FUNC, 0, 0);
    if (IS_ERR(tfm)) {
        printk("compute_hash: error initializing transform\n");
        return PTR_ERR(tfm);
    }

    desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (desc == NULL) {
        printk("compute_hash: error initializing hash description\n");
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    desc->tfm = tfm;

    ret = crypto_shash_digest(desc, input_string, input_size, output_buffer);
    if (ret < 0) {
        printk("compute_hash: error initializing hash computation\n");
        kfree(desc);
        crypto_free_shash(tfm);
        return ret;
    }

    kfree(desc);
    crypto_free_shash(tfm);

    return 0;
}


