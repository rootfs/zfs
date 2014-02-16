/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_ZIO_CHECKSUM_H
#define	_SYS_ZIO_CHECKSUM_H

#include <sys/zio.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Signature for checksum functions.
 */
typedef void zio_checksum_t(abd_t *data, uint64_t size, zio_cksum_t *zcp);

/*
 * Information about each checksum function.
 */
typedef const struct zio_checksum_info {
	zio_checksum_t	*ci_func[2]; /* checksum function for each byteorder */
	int		ci_correctable;	/* number of correctable bits	*/
	int		ci_eck;		/* uses zio embedded checksum? */
	int		ci_dedup;	/* strong enough for dedup? */
	char		*ci_name;	/* descriptive name */
} zio_checksum_info_t;

typedef struct zio_bad_cksum {
	zio_cksum_t		zbc_expected;
	zio_cksum_t		zbc_actual;
	const char		*zbc_checksum_name;
	uint8_t			zbc_byteswapped;
	uint8_t			zbc_injected;
	uint8_t			zbc_has_cksum;	/* expected/actual valid */
} zio_bad_cksum_t;

extern zio_checksum_info_t zio_checksum_table[ZIO_CHECKSUM_FUNCTIONS];

/*
 * Checksum routines.
 */
extern void abd_checksum_SHA256(abd_t *, uint64_t, zio_cksum_t *);
extern void abd_fletcher_2_native(abd_t *, uint64_t, zio_cksum_t *);
extern void abd_fletcher_2_byteswap(abd_t *, uint64_t, zio_cksum_t *);
extern void abd_fletcher_4_native(abd_t *, uint64_t, zio_cksum_t *);
extern void abd_fletcher_4_byteswap(abd_t *, uint64_t, zio_cksum_t *);

static inline void
zio_checksum_SHA256_init(zio_cksum_t *zcp)
{
	uint32_t H[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

	ZIO_SET_CHECKSUM(zcp,
	    (uint64_t)H[0] << 32 | H[1],
	    (uint64_t)H[2] << 32 | H[3],
	    (uint64_t)H[4] << 32 | H[5],
	    (uint64_t)H[6] << 32 | H[7]);
}

extern int zio_checksum_SHA256_incremental(const void *, uint64_t, void *);
extern void zio_checksum_SHA256(const void *, uint64_t, zio_cksum_t *);

extern void zio_checksum_compute(zio_t *zio, enum zio_checksum checksum,
    abd_t *data, uint64_t size);
extern int zio_checksum_error(zio_t *zio, zio_bad_cksum_t *out);
extern enum zio_checksum spa_dedup_checksum(spa_t *spa);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZIO_CHECKSUM_H */
