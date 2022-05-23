/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Quick & dirty crypto testing module.
 *
 * This will only exist until we have a better testing mechanism
 * (e.g. a char device).
 *
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 * Copyright (c) 2002 Jean-Francois Dive <jef@linuxbe.org>
 * Copyright (c) 2007 Nokia Siemens Networks
 */
#ifndef _CRYPTO_TCRYPT_H
#define _CRYPTO_TCRYPT_H



struct aead_speed_template {
	const char *key;
	unsigned int klen;
};


/*
 * Cipher speed tests
 */
static u8 speed_template_8[] = {8, 0};
static u8 speed_template_16[] = {16, 0};
static u8 speed_template_24[] = {24, 0};
static u8 speed_template_8_16[] = {8, 16, 0};
static u8 speed_template_8_32[] = {8, 32, 0};
static u8 speed_template_16_32[] = {16, 32, 0};
static u8 speed_template_16_24_32[] = {16, 24, 32, 0};
static u8 speed_template_20_28_36[] = {20, 28, 36, 0};
static u8 speed_template_32_40_48[] = {32, 40, 48, 0};
static u8 speed_template_32_48[] = {32, 48, 0};
static u8 speed_template_32_48_64[] = {32, 48, 64, 0};
static u8 speed_template_32_64[] = {32, 64, 0};
static u8 speed_template_32[] = {32, 0};

/*
 * AEAD speed tests
 */
static u8 aead_speed_template_19[] = {19, 0};
static u8 aead_speed_template_20[] = {20, 0};
static u8 aead_speed_template_36[] = {36, 0};


#endif	/* _CRYPTO_TCRYPT_H */
