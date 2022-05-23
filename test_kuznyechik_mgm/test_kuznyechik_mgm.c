
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/err.h>
#include <linux/fips.h>
#include <linux/init.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/moduleparam.h>
#include <linux/jiffies.h>
#include <linux/timex.h>
#include <linux/interrupt.h>

// * return a string with the driver name

#define get_driver_name(tfm_type, tfm) crypto_tfm_alg_driver_name(tfm_type ## _tfm(tfm))



// * Used by test_cipher_speed()

#define ENCRYPT 1
#define DECRYPT 0



#define XBUFSIZE 8
#define MAX_IVLEN 32

static void hexdump(const char * prefix,  unsigned char *buf, unsigned int len)
{
    print_hex_dump(KERN_CONT, prefix, DUMP_PREFIX_OFFSET,
            16, 1,
            buf, len, false);
}


static int testmgr_alloc_buf(char *buf[XBUFSIZE])
{
	int i;

	for (i = 0; i < XBUFSIZE; i++) {
		buf[i] = (void *)__get_free_page(GFP_KERNEL);
		if (!buf[i])
			goto err_free_buf;
	}

	return 0;

err_free_buf:
	while (i-- > 0)
		free_page((unsigned long)buf[i]);

	return -ENOMEM;
}

static void testmgr_free_buf(char *buf[XBUFSIZE])
{
	int i;

	for (i = 0; i < XBUFSIZE; i++)
		free_page((unsigned long)buf[i]);
}

static void sg_init_aead(struct scatterlist *sg, char *xbuf[XBUFSIZE],
			 unsigned int buflen, const void *assoc,
			 unsigned int aad_size)
{
    int np = (buflen + PAGE_SIZE - 1)/PAGE_SIZE;  // numberPage = (buflen + 4095) / 4096  (1)
	int k, rem;

    if (np > XBUFSIZE) {  // 1 > 8
		rem = PAGE_SIZE;
		np = XBUFSIZE;
	} else {
        rem = buflen % PAGE_SIZE;  // rem = buflen
	}

    sg_init_table(sg, np + 1);  // 2

    sg_set_buf(&sg[0], assoc, aad_size);  // sg[0] -> assoc

	if (rem)
        np--;  // 0

    for (k = 0; k < np; k++) // not called
        sg_set_buf(&sg[k + 1], xbuf[k], PAGE_SIZE); // sg[1] - xbuf

    if (rem)
        sg_set_buf(&sg[k + 1], xbuf[k], rem);   // sg[1] - xbuf[0]
}

static inline int do_one_aead_op(struct aead_request *req, int ret)
{
	struct crypto_wait *wait = req->base.data;

	return crypto_wait_req(ret, wait);
}

// test vectors for rfc4106(gcm(aes128))
//static const char skey[20] =  "\x4C\x80\xCD\xEF\xBB\x5D\x10\xDA"
//                              "\x90\x6A\xC7\x3C\x36\x13\xA6\x34"
//                              "\x2E\x44\x3B\x68";

//static const char siv[8] = "\x49\x56\xED\x7E\x3B\x24\x4C\xFE";

//static const char splaintext[72] = "\x45\x00\x00\x48\x69\x9A\x00\x00"
//                                  "\x80\x11\x4D\xB7\xC0\xA8\x01\x02"
//                                  "\xC0\xA8\x01\x01\x0A\x9B\xF1\x56"
//                                  "\x38\xD3\x01\x00\x00\x01\x00\x00"
//                                  "\x00\x00\x00\x00\x04\x5F\x73\x69"
//                                  "\x70\x04\x5F\x75\x64\x70\x03\x73"
//                                  "\x69\x70\x09\x63\x79\x62\x65\x72"
//                                  "\x63\x69\x74\x79\x02\x64\x6B\x00"
//                                  "\x00\x21\x00\x01\x01\x02\x02\x01";

//static const char sassoc[20] =    "\x00\x00\x43\x21\x87\x65\x43\x21"
//                                  "\x00\x00\x00\x00\x49\x56\xED\x7E"
//                                  "\x3B\x24\x4C\xFE";

//static const char sciphertext[88] = "\xFE\xCF\x53\x7E\x72\x9D\x5B\x07"
//                                    "\xDC\x30\xDF\x52\x8D\xD2\x2B\x76"
//                                    "\x8D\x1B\x98\x73\x66\x96\xA6\xFD"
//                                    "\x34\x85\x09\xFA\x13\xCE\xAC\x34"
//                                    "\xCF\xA2\x43\x6F\x14\xA3\xF3\xCF"
//                                    "\x65\x92\x5B\xF1\xF4\xA1\x3C\x5D"
//                                    "\x15\xB2\x1E\x18\x84\xF5\xFF\x62"
//                                    "\x47\xAE\xAB\xB7\x86\xB9\x3B\xCE"
//                                    "\x61\xBC\x17\xD7\x68\xFD\x97\x32"
//                                    "\x45\x90\x18\x14\x8F\x6C\xBE\x72"
//                                    "\x2F\xD0\x47\x96\x56\x2D\xFD\xB4";

// skey - concatenated key (32 byte) & nonce 12 bytes
static const char skey[44] = "\xb6\x18\x0c\x14\x5c\x51\x2d\xbd\x69\xd9\xce\xa9\x2c\xac\x1b\x5c"
                             "\xe1\xbc\xfa\x73\x79\x2d\x61\xaf\x0b\x44\x0d\x84\xb5\x22\xcc\x38"
                             "\x7b\x67\xe6\xf2\x44\xf9\x7f\x06\x78\x95\x2e\x45";

static const char siv[8] =    "\x00\x00\x00\x00\x00\x00\x00\x00";

/*!
 * \brief sassoc
 *  real assoc is first 8 bytes. But in ase of using seqiv it has add another 8 bytes (iv xored with salt)
 *
 */
static const char sassoc[16] = "\x51\x46\x53\x6b\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00";


static const char splaintext[64] = "\x45\x00\x00\x3c\x23\x35\x00\x00\x7f\x01\xee\xcc\x0a\x6f\x0a\xc5"
                                   "\x0a\x6f\x0a\x1d\x08\x00\xf3\x5b\x02\x00\x58\x00\x61\x62\x63\x64"
                                   "\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74"
                                   "\x75\x76\x77\x61\x62\x63\x64\x65\x66\x67\x68\x69\x01\x02\x02\x04";

static const char sciphertext[76] = "\x18\x9d\x12\x88\xb7\x18\xf9\xea\xbe\x55\x4b\x23\x9b\xee\x65\x96"
                                    "\xc6\xd4\xea\xfd\x31\x64\x96\xef\x90\x1c\xac\x31\x60\x05\xaa\x07"
                                    "\x62\x97\xb2\x24\xbf\x6d\x2b\xe3\x5f\xd6\xf6\x7e\x7b\x9d\xeb\x31"
                                    "\x85\xff\xe9\x17\x9c\xa9\xbf\x0b\xdb\xaf\xc2\x3e\xae\x4d\xa5\x6f"
                                    "\x50\xb0\x70\xa1\x5a\x2b\xd9\x73\x86\x89\xf8\xed";

static void test_aead(const char *algo, int enc,
                            u8 authsize,             // 12
                            unsigned int aad_size)   // 16
{
	struct crypto_aead *tfm;
	int ret = -ENOMEM;
	const char *key;
	struct aead_request *req;
	struct scatterlist *sg;
	struct scatterlist *sgout;
	const char *e;
	void *assoc;
	char *iv;
	char *xbuf[XBUFSIZE];
	char *xoutbuf[XBUFSIZE];
	char *axbuf[XBUFSIZE];
	unsigned int iv_len;
	struct crypto_wait wait;

	iv = kzalloc(MAX_IVLEN, GFP_KERNEL);
	if (!iv)
		return;

	if (enc == ENCRYPT)
		e = "encryption";
	else
		e = "decryption";

	if (testmgr_alloc_buf(xbuf))
		goto out_noxbuf;
	if (testmgr_alloc_buf(axbuf))
		goto out_noaxbuf;
	if (testmgr_alloc_buf(xoutbuf))
		goto out_nooutbuf;

	sg = kmalloc(sizeof(*sg) * 9 * 2, GFP_KERNEL);
	if (!sg)
		goto out_nosg;
	sgout = &sg[9];


	tfm = crypto_alloc_aead(algo, 0, 0);

	if (IS_ERR(tfm)) {
        pr_err("alg: aead: Failed to load transform for %s: %ld\n", algo, PTR_ERR(tfm));
		goto out_notfm;
	}

	crypto_init_wait(&wait);
    printk(KERN_INFO "\ntesting of %s (%s) %s\n", algo,
			get_driver_name(crypto_aead, tfm), e);

	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
        pr_err("alg: aead: Failed to allocate request for %s\n", algo);
		goto out_noreq;
	}

	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);

    assoc = axbuf[0];
    memcpy(assoc, sassoc, aad_size);

    key =  kmalloc(44, GFP_KERNEL);
    memcpy((void*)key, skey, 44);

    if (enc) {
        memcpy(xbuf[0], splaintext, 64 );
    } else {
        memcpy(xbuf[0], sciphertext, 76 ); // 64 + 12
    }


    ret = crypto_aead_setkey(tfm, key, 44 );
    ret = crypto_aead_setauthsize(tfm, authsize);

    printk(KERN_INFO "authsize: %d", authsize);

    iv_len = crypto_aead_ivsize(tfm);
    if (iv_len)
        memcpy(iv, siv, iv_len);

    printk(KERN_INFO "iv len returned: %d", iv_len);

    crypto_aead_clear_flags(tfm, ~0);

    if (ret) {
        pr_err("setkey() failed flags=%x\n", crypto_aead_get_flags(tfm));
        goto out;
    }

    sg_init_aead(sg, xbuf,
                 64 + (enc ? 0 : authsize),
                 assoc, aad_size);

    sg_init_aead(sgout, xoutbuf,
                 64 + (enc ? authsize : 0),
                 assoc, aad_size);

    aead_request_set_ad(req, aad_size);

    aead_request_set_crypt(req, sg, sgout,
                           64 + (enc ? 0 : authsize),
                           iv);


    if (enc)
        ret = do_one_aead_op(req, crypto_aead_encrypt(req));
    else
        ret = do_one_aead_op(req, crypto_aead_decrypt(req));

    if (ret) {
        pr_err("%s() failed return code=%d\n", e, ret);
        goto out;
    } else {
        if (enc) {
            printk(KERN_INFO "test 1 enc Finished\n");
            hexdump("in:", xbuf[0], 64 );
            hexdump("assoc", axbuf[0], 8);
            hexdump("out:", xoutbuf[0], 76 );
        } else {
            printk(KERN_INFO "test 1 dec Finished\n");
            hexdump("in:", xbuf[0], 76 );
            hexdump("assoc", axbuf[0], 8);
            hexdump("out:", xoutbuf[0], 64 );
        }
    }


out:
	aead_request_free(req);
out_noreq:
	crypto_free_aead(tfm);
out_notfm:
	kfree(sg);
out_nosg:
	testmgr_free_buf(xoutbuf);
out_nooutbuf:
	testmgr_free_buf(axbuf);
out_noaxbuf:
	testmgr_free_buf(xbuf);
out_noxbuf:
	kfree(iv);
}



static int __init tcrypt_mod_init(void)
{
    int err = -ENOMEM;

    err = 0;
    test_aead("gost_esp(mgm(kuznyechik))", ENCRYPT, 12, 16);

    test_aead("gost_esp(mgm(kuznyechik))", DECRYPT, 12, 16);

	return err;
}


static void __exit tcrypt_mod_fini(void) { }

module_init(tcrypt_mod_init);
module_exit(tcrypt_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Quick & dirty crypto testing module");
MODULE_AUTHOR("Vit Kanevsky <cryptiaproject@gmail.com>");
