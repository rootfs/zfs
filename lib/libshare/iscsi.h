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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011 Gunnar Beutner
 */

#include <sys/list.h>

#define	SYSFS_SCST			"/sys/kernel/scst_tgt"
#define	PROC_IET_VOLUME			"/proc/net/iet/volume"
#define	PROC_IET_SESSION		"/proc/net/iet/session"
#define	IETM_CMD_PATH			"/usr/sbin/ietadm"
#define	STGT_CMD_PATH			"/usr/sbin/tgtadm"
#define	DOMAINNAME_FILE			"/etc/domainname"
#define	TARGET_NAME_FILE		"/etc/iscsi_target_id"
#define	EXTRA_ISCSI_SHARE_SCRIPT	"/sbin/zfs_share_iscsi"

/*
 * tid:1 name:iqn.2012-11.com.bayour:share.tests.iscsi1
 *	lun:0 state:0 iotype:fileio iomode:wt blocks:31457280 blocksize:512 \
 *	path:/dev/zvol/share/tests/iscsi1
 */
typedef struct iscsi_shareopts_s {
	char	name[255];	/* Target IQN name */
	int	lun;		/* LUN number */
	char	type[10];	/* disk or tape */
	char	iomode[5];	/* wb, ro or wt */
	int	blocksize;	/* 512, 1024, 2048 or 4096 */
} iscsi_shareopts_t;

/*
 * When the share is active
 *   debianzfs:~# cat /proc/net/iet/session
 *   tid:1 name:iqn.2012-11.com.bayour:share.tests.iscsi1
 *   	sid:281475651797504 initiator:iqn.1993-08.org.debian:01:e19b61b8377
 *   		cid:0 ip:192.168.69.3 state:active hd:none dd:none
 *
 * When the share is inactive
 *   debianzfs:~# cat /proc/net/iet/session
 *   tid:1 name:iqn.2012-11.com.bayour:share.tests.iscsi1
 */
typedef struct iscsi_session_s {
	int	tid;		/* Target ID */
	char	name[255];	/* Target Name */

	int	sid;		/* SID */
	char	initiator[255];	/* Initiator Name */
	int	cid;		/* CID */
	char	ip[255];	/* IP to Initiator */
	int	state;		/* State (active=1, inactive=0) */

	char	hd[255];	/* ?? => hd:none */
	char	dd[255];	/* ?? => dd:none */

	list_node_t next;
} iscsi_session_t;

/*
 * tid:1 name:iqn.2012-11.com.bayour:share.tests.iscsi1
 * 	lun:0 state:0 iotype:fileio iomode:wt blocks:31457280 \
 * 	blocksize:512 path:/dev/zvol/share/tests/iscsi1
 */
typedef struct iscsi_target_s {
	int	tid;		/* Target ID */
	char	name[255];	/* Target Name */
	int	lun;		/* Target LUN */
	int	state;		/* Target State */
	char	iotype[8];	/* Target IO Type - fileio, */
				/* blockio, nullio, disk, tape */
	char	iomode[5];	/* Target IO Mode - wb, wt, ro */
	int	blocks;		/* Target Size (blocks) */
	int	blocksize;	/* Target Block Size (bytes) */
	char	path[PATH_MAX];	/* Target Path */
	char	device[16];	/* For SCST: The iSCSI device */

	struct iscsi_session_s *session;

	list_node_t next;
} iscsi_target_t;

void libshare_iscsi_init(void);
