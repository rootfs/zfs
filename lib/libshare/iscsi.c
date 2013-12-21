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
 * Copyright (c) 2011-2014 Turbo Fredriksson <turbo@bayour.com>, loosely
 * based on nfs.c by Gunnar Beutner.
 *
 * This is an addition to the zfs device driver to retrieve, add and remove
 * iSCSI targets using either the 'ietadm' or 'tgtadm' command to add, remove
 * and modify targets.
 *
 * If SCST is the iSCSI target of choise, ZoL will read and modify appropriate
 * files below /sys/kernel/scst_tgt. See iscsi_retrieve_targets_scst() for
 * details.
 *
 * It (the driver) will automatically calculate the TID and IQN and use only
 * the ZVOL (in this case 'tank/test') in the command lines. Unless the optional
 * file '/etc/iscsi_target_id' exists, in which case the content of that will
 * be used instead for the system part of the IQN.
 */

#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <libzfs.h>
#include <libshare.h>
#include <sys/fs/zfs.h>
#include "libshare_impl.h"
#include "iscsi.h"

#if !defined(offsetof)
#define	offsetof(s, m)  ((size_t)(&(((s *)0)->m)))
#endif

static boolean_t iscsi_available(void);
static boolean_t iscsi_is_share_active(sa_share_impl_t);

static sa_fstype_t *iscsi_fstype;
static list_t all_iscsi_targets_list;

enum {
	ISCSI_IMPL_NONE,
	ISCSI_IMPL_IET,
	ISCSI_IMPL_SCST,
	ISCSI_IMPL_STGT
};

/*
 * What iSCSI implementation found
 *  0: none
 *  1: IET found
 *  2: SCST found
 *  3: STGT found
 */
static int iscsi_implementation;

typedef struct iscsi_dirs_s {
	char		path[PATH_MAX];
	char		entry[PATH_MAX];
	struct stat	stats;

	list_node_t next;
} iscsi_dirs_t;

static iscsi_dirs_t *
iscsi_dirs_list_alloc(void)
{
	iscsi_dirs_t *entries;

	entries = (iscsi_dirs_t *) malloc(sizeof (iscsi_dirs_t));
	if (entries == NULL)
		return (NULL);

	list_link_init(&entries->next);

	return (entries);
}

static iscsi_session_t *
iscsi_session_list_alloc(void)
{
	iscsi_session_t *session;

	session = (iscsi_session_t *) malloc(sizeof (iscsi_session_t));
	if (session == NULL)
		return (NULL);

	list_link_init(&session->next);

	return (session);
}

static list_t *
iscsi_look_for_stuff(char *path, const char *needle, boolean_t check_dir,
		int check_len)
{
	int ret;
	char path2[PATH_MAX], *path3;
	DIR *dir;
	struct dirent *directory;
	struct stat eStat;
	iscsi_dirs_t *entry;
	list_t *entries = malloc(sizeof (list_t));

#if DEBUG >= 2
	fprintf(stderr, "iscsi_look_for_stuff: '%s' (needle=%s) - %d/%d\n",
		path, needle ? needle : "null", check_dir, check_len);
#endif

	/* Make sure that path is set */
	assert(path != NULL);

	list_create(entries, sizeof (iscsi_dirs_t),
		    offsetof(iscsi_dirs_t, next));

	if ((dir = opendir(path))) {
		while ((directory = readdir(dir))) {
			if (directory->d_name[0] == '.')
				continue;

			path3 = NULL;
			ret = snprintf(path2, sizeof (path2),
					"%s/%s", path, directory->d_name);
			if (ret < 0 || ret >= sizeof (path2))
				/* Error or not enough space in string */
				/* TODO: Decide to continue or break */
				continue;

			if (stat(path2, &eStat) == -1)
				goto look_out;

			if (check_dir && !S_ISDIR(eStat.st_mode))
				continue;

			if (needle != NULL) {
				if (check_len) {
					if (strncmp(directory->d_name,
						    needle, check_len) == 0)
						path3 = path2;
				} else {
					if (strcmp(directory->d_name, needle)
					    == 0)
						path3 = path2;
				}
			} else {
				if (strcmp(directory->d_name, "mgmt") == 0)
					continue;

				path3 = path2;
			}

			entry = iscsi_dirs_list_alloc();
			if (entry == NULL)
				goto look_out;

			if (path3)
				strncpy(entry->path, path3,
					sizeof (entry->path));
			strncpy(entry->entry, directory->d_name,
				sizeof (entry->entry));
			entry->stats = eStat;

#if DEBUG >= 2
			fprintf(stderr, "  iscsi_look_for_stuff: %s\n",
				entry->path);
#endif
			list_insert_tail(entries, entry);
		}

look_out:
		closedir(dir);
	}

	return (entries);
}

static int
iscsi_read_sysfs_value(char *path, char **value)
{
	int rc = SA_SYSTEM_ERR, buffer_len;
	char buffer[255];
	FILE *scst_sysfs_file_fp = NULL;

	/* Make sure that path and value is set */
	assert(path != NULL);
	if (!value)
		return (rc);

	/*
	 * TODO:
	 * If *value is not NULL we might be dropping allocated memory, assert?
	 */
	*value = NULL;

#if DEBUG >= 2
	fprintf(stderr, "iscsi_read_sysfs_value: path=%s", path);
#endif

	scst_sysfs_file_fp = fopen(path, "r");
	if (scst_sysfs_file_fp != NULL) {
		if (fgets(buffer, sizeof (buffer), scst_sysfs_file_fp)
		    != NULL) {
			/* Trim trailing new-line character(s). */
			buffer_len = strlen(buffer);
			while (buffer_len > 0) {
			    buffer_len--;
			    if (buffer[buffer_len] == '\r' ||
				buffer[buffer_len] == '\n') {
				buffer[buffer_len] = 0;
			    } else
				break;
			}

			*value = strdup(buffer);

#if DEBUG >= 2
			fprintf(stderr, ", value=%s", *value);
#endif

			/* Check that strdup() was successful */
			if (*value)
				rc = SA_OK;
		}

		fclose(scst_sysfs_file_fp);
	}

#if DEBUG >= 2
	fprintf(stderr, "\n");
#endif
	return (rc);
}

static int
iscsi_write_sysfs_value(char *path, char *value)
{
	char full_path[PATH_MAX];
	int rc = SA_SYSTEM_ERR;
	FILE *scst_sysfs_file_fp = NULL;
	int ret;

	/* Make sure that path and value is set */
	assert(path != NULL);
	assert(value != NULL);

	ret = snprintf(full_path, sizeof (full_path), "%s/%s", SYSFS_SCST,
			path);
	if (ret < 0 || ret >= sizeof (full_path))
		return (rc);

#if DEBUG >= 2
	fprintf(stderr, "iscsi_write_sysfs_value: '%s' => '%s'\n",
		full_path, value);
#endif

	scst_sysfs_file_fp = fopen(full_path, "w");
	if (scst_sysfs_file_fp != NULL) {
		if (fputs(value, scst_sysfs_file_fp) != EOF)
			rc = SA_OK;

		fclose(scst_sysfs_file_fp);
	} else
		rc = SA_SYSTEM_ERR;

	return (rc);
}

/*
 * Generate a target name using the current year and month,
 * the domain name and the path.
 *
 * OR: Use information from /etc/iscsi_target_id:
 *     Example: iqn.2012-11.com.bayour
 *
 * => iqn.yyyy-mm.tld.domain:dataset (with . instead of /)
 */
static int
iscsi_generate_target(const char *dataset, char *iqn, size_t iqn_len)
{
	char tsbuf[8]; /* YYYY-MM */
	char domain[256], revname[256], name[256],
		tmpdom[256], *p, tmp[20][256], *pos,
		buffer[256], file_iqn[255];
	time_t now;
	struct tm *now_local;
	int i, ret;
	FILE *domainname_fp = NULL, *iscsi_target_name_fp = NULL;

	if (dataset == NULL)
		return (SA_SYSTEM_ERR);

	/*
	 * Make sure file_iqn buffer contain zero byte or else strlen() later
	 * can fail.
	 */
	file_iqn[0] = 0;

	iscsi_target_name_fp = fopen(TARGET_NAME_FILE, "r");
	if (iscsi_target_name_fp == NULL) {
		/* Generate a name using domain name and date etc */

		/* Get current time in EPOCH */
		now = time(NULL);
		now_local = localtime(&now);
		if (now_local == NULL)
			return (SA_SYSTEM_ERR);

		/* Parse EPOCH and get YYY-MM */
		if (strftime(tsbuf, sizeof (tsbuf), "%Y-%m", now_local) == 0)
			return (SA_SYSTEM_ERR);

		/*
		 * Make sure domain buffer contain zero byte or else strlen()
		 * later can fail.
		 */
		domain[0] = 0;

#ifdef HAVE_GETDOMAINNAME
		/* Retrieve the domain */
		if (getdomainname(domain, sizeof (domain)) < 0) {
			/* Could not get domain via getdomainname() */
#endif
			domainname_fp = fopen(DOMAINNAME_FILE, "r");
			if (domainname_fp == NULL) {
				fprintf(stderr, "ERROR: Can't open %s: %s\n",
					DOMAINNAME_FILE, strerror(errno));
				return (SA_SYSTEM_ERR);
			}

			if (fgets(buffer, sizeof (buffer), domainname_fp)
			    != NULL) {
				strncpy(domain, buffer, sizeof (domain)-1);
				if (domain[strlen(domain)-1] == '\n')
					domain[strlen(domain)-1] = '\0';
			} else
				return (SA_SYSTEM_ERR);

			fclose(domainname_fp);
#ifdef HAVE_GETDOMAINNAME
		}
#endif

		/* Tripple check that we really have a domainname! */
		if ((strlen(domain) == 0) || (strcmp(domain, "(none)") == 0)) {
			fprintf(stderr, "ERROR: Can't retreive domainname!\n");
			return (SA_SYSTEM_ERR);
		}

		/* Reverse the domainname ('bayour.com' => 'com.bayour') */
		strncpy(tmpdom, domain, sizeof (tmpdom));

		i = 0;
		p = strtok(tmpdom, ".");
		while (p != NULL) {
			if (i == 20) {
				/* Reached end of tmp[] */
				/* XXX: print error? */
				return (SA_SYSTEM_ERR);
			}

			strncpy(tmp[i], p, sizeof (tmp[i]));
			p = strtok(NULL, ".");

			i++;
		}
		i--;
		memset(&revname[0], 0, sizeof (revname));
		for (; i >= 0; i--) {
			if (strlen(revname)) {
				ret = snprintf(tmpdom, sizeof (tmpdom),
						"%s.%s", revname, tmp[i]);
				if (ret < 0 || ret >= sizeof (tmpdom)) {
					/* XXX: print error? */
					return (SA_SYSTEM_ERR);
				}

				ret = snprintf(revname, sizeof (revname), "%s",
						tmpdom);
				if (ret < 0 || ret >= sizeof (revname)) {
					/* XXX: print error? */
					return (SA_SYSTEM_ERR);
				}
			} else {
				strncpy(revname, tmp[i], sizeof (revname));
				revname [sizeof (revname)-1] = '\0';
			}
		}
	} else {
		/*
		 * Use the content of file as the IQN
		 *  => "iqn.2012-11.com.bayour"
		 */
		if (fgets(buffer, sizeof (buffer), iscsi_target_name_fp)
		    != NULL) {
			strncpy(file_iqn, buffer, sizeof (file_iqn)-1);
			file_iqn[strlen(file_iqn)-1] = '\0';
		} else
			return (SA_SYSTEM_ERR);

		fclose(iscsi_target_name_fp);
	}

	/* Take the dataset name, replace / with . */
	strncpy(name, dataset, sizeof (name));
	pos = name;
	while (*pos != '\0') {
		switch (*pos) {
		case '/':
		case '-':
		case ':':
		case ' ':
			*pos = '.';
		}
		++pos;
	}

	/*
	 * Put the whole thing togheter
	 *  => "iqn.2012-11.com.bayour:share.VirtualMachines.Astrix"
	 */
	if (file_iqn[0]) {
		ret = snprintf(iqn, iqn_len, "%s:%s", file_iqn, name);
		if (ret < 0 || ret >= iqn_len) {
			/* XXX: print error? */
			return (SA_SYSTEM_ERR);
		}
	} else {
		ret = snprintf(iqn, iqn_len, "iqn.%s.%s:%s", tsbuf, revname,
				name);
		if (ret < 0 || ret >= iqn_len) {
			/* XXX: print error? */
			return (SA_SYSTEM_ERR);
		}
	}

	return (SA_OK);
}

/*
 * Preferably we should use the dataset name here, but there's a limit
 * of 16 characters...
 */
static void
iscsi_generate_scst_device_name(char **device)
{
	char string[17];
	static const char valid_salts[] =
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"0123456789";
	unsigned long i;
	struct timeval tv;

	/* Mske sure that device is set */
	assert(device != NULL);

	/* Seed number for rand() */
	gettimeofday(&tv, NULL);
	srand((tv.tv_sec ^ tv.tv_usec) + getpid());

	/* ASCII characters only */
	for (i = 0; i < sizeof (string) - 1; i++)
		string[i] = valid_salts[rand() % (sizeof (valid_salts) - 1)];
	string[ i ] = '\0';

	*device = strdup(string);
}

/*
 * Reads the proc file and register if a tid have a sid. Save the value in
 * all_iscsi_targets_list->state
 */
static list_t *
iscsi_retrieve_sessions_iet(void)
{
	FILE *iscsi_volumes_fp = NULL;
	char *line, *token, *key, *value, *colon, *dup_value, buffer[512];
	int buffer_len;
	iscsi_session_t *session = NULL;
	list_t *target_sessions = malloc(sizeof (list_t));
	enum { ISCSI_SESSION, ISCSI_SID, ISCSI_CID } type;

	/* For storing the share info */
	char *tid = NULL, *name = NULL, *sid = NULL, *initiator = NULL,
		*cid = NULL, *ip = NULL, *state = NULL, *hd = NULL,
		*dd = NULL;

	list_create(target_sessions, sizeof (iscsi_session_t),
		    offsetof(iscsi_session_t, next));

	/* Open file with targets */
	iscsi_volumes_fp = fopen(PROC_IET_SESSION, "r");
	if (iscsi_volumes_fp == NULL)
		exit(SA_SYSTEM_ERR);

	/* Load the file... */
	while (fgets(buffer, sizeof (buffer), iscsi_volumes_fp) != NULL) {
		/* Trim trailing new-line character(s). */
		buffer_len = strlen(buffer);
		while (buffer_len > 0) {
			buffer_len--;
			if (buffer[buffer_len] == '\r' ||
			    buffer[buffer_len] == '\n') {
				buffer[buffer_len] = 0;
			} else
				break;
		}

		if (buffer[0] != '\t') {
			/*
			 * Line doesn't start with a TAB which means this is a
			 * session definition
			 */
			line = buffer;
			type = ISCSI_SESSION;

			free(name);
			free(tid);
			free(sid);
			free(cid);
			free(ip);
			free(initiator);
			free(state);
			free(hd);
			free(dd);

			name = tid = sid = cid = ip = NULL;
			initiator = state = hd = dd = NULL;
		} else if (buffer[0] == '\t' && buffer[1] == '\t') {
			/* Start with two tabs - CID definition */
			line = buffer + 2;
			type = ISCSI_CID;
		} else if (buffer[0] == '\t') {
			/* Start with one tab - SID definition */
			line = buffer + 1;
			type = ISCSI_SID;
		} else {
			/* Unknown line - skip it. */
			continue;
		}

		/* Get each option, which is separated by space */
		/* token='tid:18' */
		token = strtok(line, " ");
		while (token != NULL) {
			colon = strchr(token, ':');

			if (colon == NULL)
				goto next_sessions;

			key = token;
			value = colon + 1;
			*colon = '\0';

			dup_value = strdup(value);
			if (dup_value == NULL)
				exit(SA_NO_MEMORY);

			if (type == ISCSI_SESSION) {
				if (strcmp(key, "tid") == 0)
					tid = dup_value;
				else if (strcmp(key, "name") == 0)
					name = dup_value;
				else
					free(dup_value);
			} else if (type == ISCSI_SID) {
				if (strcmp(key, "sid") == 0)
					sid = dup_value;
				else if (strcmp(key, "initiator") == 0)
					initiator = dup_value;
				else
					free(dup_value);
			} else {
				if (strcmp(key, "cid") == 0)
					cid = dup_value;
				else if (strcmp(key, "ip") == 0)
					ip = dup_value;
				else if (strcmp(key, "state") == 0)
					state = dup_value;
				else if (strcmp(key, "hd") == 0)
					hd = dup_value;
				else if (strcmp(key, "dd") == 0)
					dd = dup_value;
				else
					free(dup_value);
			}

next_sessions:
			token = strtok(NULL, " ");
		}

		if (tid == NULL || sid == NULL || cid == NULL ||
		    name == NULL || initiator == NULL || ip == NULL ||
		    state == NULL || dd == NULL || hd == NULL)
			continue; /* Incomplete session definition */

		session = iscsi_session_list_alloc();
		if (session == NULL)
			exit(SA_NO_MEMORY);

		/* Save the values in the struct */
		session->tid = atoi(tid);
		session->sid = atoi(sid);
		session->cid = atoi(cid);

		strncpy(session->name, name, sizeof (session->name));
		strncpy(session->initiator, initiator,
			sizeof (session->initiator));
		strncpy(session->ip, ip, sizeof (session->ip));
		strncpy(session->hd, hd, sizeof (session->hd));
		strncpy(session->dd, dd, sizeof (session->dd));

		if (strcmp(state, "active") == 0)
			session->state = 1;
		else
			session->state = 0;

#ifdef DEBUG
		fprintf(stderr, "iscsi_retrieve_sessions: target=%s, tid=%d, "
			"sid=%d, cid=%d, initiator=%s, ip=%s, state=%d\n",
			session->name, session->tid, session->sid, session->cid,
			session->initiator, session->ip, session->state);
#endif

		/* Append the sessions to the list of new sessions */
		list_insert_tail(target_sessions, session);
	}

	if (iscsi_volumes_fp != NULL)
		fclose(iscsi_volumes_fp);

	free(name);
	free(tid);
	free(sid);
	free(cid);
	free(ip);
	free(initiator);
	free(state);
	free(hd);
	free(dd);

	return (target_sessions);
}

// name: 	$SYSFS/targets/iscsi/$name
// tid:		$SYSFS/targets/iscsi/$name/tid
// initiator:	$SYSFS/targets/iscsi/$name/sessions/$initiator/
// sid:		$SYSFS/targets/iscsi/$name/sessions/$initiator/sid
// cid:		$SYSFS/targets/iscsi/$name/sessions/$initiator/$ip/cid
// ip:		$SYSFS/targets/iscsi/$name/sessions/$initiator/$ip/ip
// state:	$SYSFS/targets/iscsi/$name/sessions/$initiator/$ip/state
static list_t *
iscsi_retrieve_sessions_scst(void)
{
	int ret;
	char path[PATH_MAX], tmp_path[PATH_MAX], *buffer = NULL;
	struct stat eStat;
	iscsi_dirs_t *entry1, *entry2, *entry3;
	iscsi_session_t *session = NULL;
	list_t *entries1, *entries2, *entries3;
	list_t *target_sessions = malloc(sizeof (list_t));

	/* For storing the share info */
	char *tid = NULL, *sid = NULL, *cid = NULL, *name = NULL,
		*initiator = NULL, *ip = NULL, *state = NULL;

	list_create(target_sessions, sizeof (iscsi_session_t),
		    offsetof(iscsi_session_t, next));

	/* DIR: $SYSFS/targets/iscsi/$name */
	ret = snprintf(path, sizeof (path), "%s/targets/iscsi", SYSFS_SCST);
	if (ret < 0 || ret >= sizeof (path))
		return (target_sessions);

	entries1 = iscsi_look_for_stuff(path, "iqn.", B_TRUE, 4);
	if (!list_is_empty(entries1))
		return (target_sessions);
	for (entry1 = list_head(entries1);
	     entry1 != NULL;
	     entry1 = list_next(entries1, entry1)) {
		/* DIR: $SYSFS/targets/iscsi/$name */

		/* RETRIEVE name */
		name = entry1->entry;

		/* RETRIEVE tid */
		ret = snprintf(tmp_path, sizeof (tmp_path), "%s/tid",
			    entry1->path);
		if (ret < 0 || ret >= sizeof (tmp_path))
			goto iscsi_retrieve_sessions_scst_error;
		if (iscsi_read_sysfs_value(tmp_path, &buffer) != SA_OK)
			goto iscsi_retrieve_sessions_scst_error;
		if (tid)
			free(tid);
		tid = buffer;
		buffer = NULL;

		ret = snprintf(path, sizeof (path), "%s/sessions",
			    entry1->path);
		if (ret < 0 || ret >= sizeof (path))
			goto iscsi_retrieve_sessions_scst_error;

		entries2 = iscsi_look_for_stuff(path, "iqn.", B_TRUE, 4);
		if (!list_is_empty(entries2))
			goto iscsi_retrieve_sessions_scst_error;
		for (entry2 = list_head(entries2);
		     entry2 != NULL;
		     entry2 = list_next(entries2, entry2)) {
			/* DIR: $SYSFS/targets/iscsi/$name/sessions/$initiator */

			/* RETRIEVE initiator */
			initiator = entry2->entry;

			/* RETRIEVE sid */
			ret = snprintf(tmp_path, sizeof (tmp_path), "%s/sid",
				    entry2->path);
			if (ret < 0 || ret >= sizeof (tmp_path))
				goto iscsi_retrieve_sessions_scst_error;
			if (iscsi_read_sysfs_value(tmp_path, &buffer) != SA_OK)
				goto iscsi_retrieve_sessions_scst_error;
			if (sid)
				free(sid);
			sid = buffer;
			buffer = NULL;

			entries3 = iscsi_look_for_stuff(entry2->path, NULL,
							B_TRUE, 4);
			if (!list_is_empty(entries3))
				goto iscsi_retrieve_sessions_scst_error;
			for (entry3 = list_head(entries3);
			     entry3 != NULL;
			     entry3 = list_next(entries3, entry3)) {
				/* DIR: $SYSFS/targets/iscsi/$name/sessions/$initiator/$ip */
				ret = snprintf(path, sizeof (path), "%s/cid",
					    entry3->path);
				if (ret < 0 || ret >= sizeof (path))
					goto iscsi_retrieve_sessions_scst_error;
				if (stat(path, &eStat) == -1)
					/* Not a IP directory */
					break;

				/* RETRIEVE ip */
				ip = entry3->entry;

				/* RETRIEVE cid */
				ret = snprintf(tmp_path, sizeof (tmp_path),
					    "%s/cid", entry3->path);
				if (ret < 0 || ret >= sizeof (tmp_path))
					goto iscsi_retrieve_sessions_scst_error;
				if (iscsi_read_sysfs_value(tmp_path, &buffer)
				    != SA_OK)
					goto iscsi_retrieve_sessions_scst_error;
				if (cid)
					free(cid);
				cid = buffer;
				buffer = NULL;

				/* RETRIEVE state */
				ret = snprintf(tmp_path, sizeof (tmp_path),
					    "%s/state", entry3->path);
				if (ret < 0 || ret >= sizeof (tmp_path))
					goto iscsi_retrieve_sessions_scst_error;
				if (iscsi_read_sysfs_value(tmp_path, &buffer)
				    != SA_OK)
					goto iscsi_retrieve_sessions_scst_error;
				if (state)
					free(state);
				state = buffer;
				buffer = NULL;

				/* SAVE values */
				if (tid == NULL || sid == NULL || cid == NULL ||
				    name == NULL || initiator == NULL ||
				    ip == NULL || state == NULL)
					continue; /* Incomplete session def */

				session = iscsi_session_list_alloc();
				if (session == NULL)
					exit(SA_NO_MEMORY);

				session->tid = atoi(tid);
				session->sid = atoi(sid);
				session->cid = atoi(cid);

				strncpy(session->name, name,
					sizeof (session->name));
				strncpy(session->initiator, initiator,
					sizeof (session->initiator));
				strncpy(session->ip, ip,
					sizeof (session->ip));

				session->hd[0] = '\0';
				session->dd[0] = '\0';

				if (strncmp(state, "established", 11) == 0)
					session->state = 1;
				else
					session->state = 0;

#ifdef DEBUG
				fprintf(stderr, "iscsi_retrieve_sessions: "
					"target=%s, tid=%d, sid=%d, cid=%d, "
					"initiator=%s, ip=%s, state=%d\n",
					session->name, session->tid,
					session->sid, session->cid,
					session->initiator, session->ip,
					session->state);
#endif

				/* Append the sessions to the list of new */
				list_insert_tail(target_sessions, session);

				/* Clear variables */
				free(tid);
				free(sid);
				free(cid);
				free(state);
				name = tid = sid = cid = ip = NULL;
				initiator = state = NULL;
			}
		}
	}

iscsi_retrieve_sessions_scst_error:
	free(tid);
	free(sid);
	free(cid);
	free(state);

	return (target_sessions);
}

/* Can only retreive the sessions/connections for one TID,
 * so this one accepts the parameter TID.
 */
static list_t *
iscsi_retrieve_sessions_stgt(int tid)
{
	int rc = SA_OK, buffer_len;
	char buffer[512], cmd[PATH_MAX];
	char *token, *dup_value;
	FILE *shareiscsi_temp_fp;
	iscsi_session_t *session = NULL;
	list_t *target_sessions = malloc(sizeof (list_t));

	/* For storing the share info */
	char *initiator = NULL, *address = NULL;

	list_create(target_sessions, sizeof (iscsi_session_t),
		    offsetof(iscsi_session_t, next));

	/* CMD: tgtadm --lld iscsi --op show --mode conn --tid TID */
	rc = snprintf(cmd, sizeof (cmd), "%s --lld iscsi --op show "
		      "--mode conn --tid %d", STGT_CMD_PATH, tid);

	if (rc < 0 || rc >= sizeof (cmd))
		return (NULL);

#ifdef DEBUG
	fprintf(stderr, "CMD: %s\n", cmd);
#endif

	shareiscsi_temp_fp = popen(cmd, "r");
	if (shareiscsi_temp_fp == NULL)
		return (NULL);

	while (fgets(buffer, sizeof (buffer), shareiscsi_temp_fp) != 0) {
		/* Trim trailing new-line character(s). */
		buffer_len = strlen(buffer);
		while (buffer_len > 0) {
			buffer_len--;
			if (buffer[buffer_len] == '\r' ||
			    buffer[buffer_len] == '\n') {
				buffer[buffer_len] = 0;
			} else
				break;
		}

		token = strchr(buffer, ':');
		dup_value = strdup(token + 2);

		if(strncmp(buffer, "        Initiator: ", 19) == 0) {
			initiator = dup_value;
		} else if(strncmp(buffer, "        IP Address: ", 20) == 0) {
			address = dup_value;
		}

		if (initiator == NULL || address == NULL)
			continue; /* Incomplete session definition */

		session = iscsi_session_list_alloc();
		if (session == NULL)
			exit(SA_NO_MEMORY);

		strncpy(session->name, "", sizeof (session->name));
		session->tid = tid;
		strncpy(session->initiator, initiator,
			sizeof (session->initiator));
		strncpy(session->ip, address, sizeof (session->ip));
		session->state = 1;

#ifdef DEBUG
		fprintf(stderr, "iscsi_retrieve_sessions: target=%s, tid=%d, "
			"initiator=%s, ip=%s, state=%d\n",
			session->name, session->tid, session->initiator,
			session->ip, session->state);
#endif

		/* Append the sessions to the list of new sessions */
		list_insert_tail(target_sessions, session);
	}

	if (pclose(shareiscsi_temp_fp) != 0)
		fprintf(stderr, "Failed to pclose stream\n");

	return (target_sessions);
}

/* iscsi_retrieve_targets_iet() retrieves list of iSCSI targets - IET version */
static int
iscsi_retrieve_targets_iet(void)
{
	FILE *iscsi_volumes_fp = NULL;
	char buffer[512];
	char *line, *token, *key, *value, *colon, *dup_value;
	int rc = SA_OK, buffer_len;
	iscsi_session_t *session;
	list_t *sessions;
	enum { ISCSI_TARGET, ISCSI_LUN } type;

	/* For soring the targets */
	char *tid = NULL, *name = NULL, *lun = NULL, *state = NULL;
	char *iotype = NULL, *iomode = NULL, *blocks = NULL;
	char *blocksize = NULL, *path = NULL;
	iscsi_target_t *target;

	/* Get all sessions */
	sessions = iscsi_retrieve_sessions_iet();

	/* Open file with targets */
	iscsi_volumes_fp = fopen(PROC_IET_VOLUME, "r");
	if (iscsi_volumes_fp == NULL)
		return (SA_SYSTEM_ERR);

	/* Load the file... */
	while (fgets(buffer, sizeof (buffer), iscsi_volumes_fp) != NULL) {
		/* Trim trailing new-line character(s). */
		buffer_len = strlen(buffer);
		while (buffer_len > 0) {
			buffer_len--;
			if (buffer[buffer_len] == '\r' ||
			    buffer[buffer_len] == '\n') {
				buffer[buffer_len] = 0;
			} else
				break;
		}

		if (buffer[0] != '\t') {
			/*
			 * Line doesn't start with a TAB which
			 * means this is a target definition
			 */
			line = buffer;
			type = ISCSI_TARGET;

			free(tid);
			free(name);
			free(lun);
			free(state);
			free(iotype);
			free(iomode);
			free(blocks);
			free(blocksize);
			free(path);

			tid = name = NULL;
			lun = state = iotype = iomode = NULL;
			blocks = blocksize = path = NULL;
		} else {
			/* LUN definition */
			line = buffer + 1;
			type = ISCSI_LUN;
		}

		/* Get each option, which is separated by space */
		/* token='tid:18' */
		token = strtok(line, " ");
		while (token != NULL) {
			colon = strchr(token, ':');

			if (colon == NULL)
				goto next_targets;

			key = token;
			value = colon + 1;
			*colon = '\0';

			dup_value = strdup(value);

			if (dup_value == NULL)
				exit(SA_NO_MEMORY);

			if (type == ISCSI_TARGET) {
				if (strcmp(key, "tid") == 0)
					tid = dup_value;
				else if (strcmp(key, "name") == 0)
					name = dup_value;
				else
					free(dup_value);
			} else {
				if (strcmp(key, "lun") == 0)
					lun = dup_value;
				else if (strcmp(key, "state") == 0)
					state = dup_value;
				else if (strcmp(key, "iotype") == 0)
					iotype = dup_value;
				else if (strcmp(key, "iomode") == 0)
					iomode = dup_value;
				else if (strcmp(key, "blocks") == 0)
					blocks = dup_value;
				else if (strcmp(key, "blocksize") == 0)
					blocksize = dup_value;
				else if (strcmp(key, "path") == 0)
					path = dup_value;
				else
					free(dup_value);
			}

next_targets:
			token = strtok(NULL, " ");
		}

		if (type != ISCSI_LUN)
			continue;

		if (tid == NULL || name == NULL || lun == NULL ||
		    state == NULL || iotype == NULL || iomode == NULL ||
		    blocks == NULL || blocksize == NULL || path == NULL)
			continue; /* Incomplete target definition */

		target = (iscsi_target_t *) malloc(sizeof (iscsi_target_t));
		if (target == NULL) {
			rc = SA_NO_MEMORY;
			goto retrieve_targets_iet_out;
		}

		/* Save the values in the struct */
		target->tid = atoi(tid);
		target->lun = atoi(lun);
		target->state = atoi(state);
		target->blocks = atoi(blocks);
		target->blocksize = atoi(blocksize);

		strncpy(target->name,	name,	sizeof (target->name));
		strncpy(target->path,	path,	sizeof (target->path));
		strncpy(target->iotype,	iotype,	sizeof (target->iotype));
		strncpy(target->iomode,	iomode,	sizeof (target->iomode));

		/* Link the session here */
		target->session = NULL;
		for (session = list_head(sessions);
		     session != NULL;
		     session = list_next(sessions, session)) {
			if (session->tid == target->tid) {
				target->session = session;
				list_link_init(&target->session->next);

				break;
			}
		}

#ifdef DEBUG
		fprintf(stderr, "iscsi_retrieve_targets_iet: target=%s, "
			"tid=%d, lun=%d, path=%s, active=%d\n", target->name,
			target->tid, target->lun, target->path,
			target->session ? target->session->state : -1);
#endif

		/* Append the target to the list of new targets */
		list_insert_tail(&all_iscsi_targets_list, target);
	}

retrieve_targets_iet_out:
	if (iscsi_volumes_fp != NULL)
		fclose(iscsi_volumes_fp);

	free(tid);
	free(name);
	free(lun);
	free(state);
	free(iotype);
	free(iomode);
	free(blocks);
	free(blocksize);
	free(path);

	return (rc);
}

/* iscsi_retrieve_targets_scst() retrieves list of iSCSI targets - SCST */
static int
iscsi_retrieve_targets_scst(void)
{
	char path[PATH_MAX], tmp_path[PATH_MAX], *buffer, *link = NULL;
	int rc = SA_SYSTEM_ERR, ret;
	iscsi_dirs_t *entry1, *entry2, *entry3;
	list_t *entries1, *entries2, *entries3;
	iscsi_target_t *target;
	iscsi_session_t *session;
	list_t *sessions;

	/* For storing the share info */
	char *tid = NULL, *lun = NULL, *state = NULL, *blocksize = NULL;
	char *name = NULL, *iotype = NULL, *dev_path = NULL, *device = NULL;

	/* Get all sessions */
	sessions = iscsi_retrieve_sessions_scst();

	/* DIR: /sys/kernel/scst_tgt/targets */
	ret = snprintf(path, sizeof (path), "%s/targets", SYSFS_SCST);
	if (ret < 0 || ret >= sizeof (path))
		return (SA_SYSTEM_ERR);

	entries1 = iscsi_look_for_stuff(path, "iscsi", B_TRUE, 0);
	for (entry1 = list_head(entries1);
	     entry1 != NULL;
	     entry1 = list_next(entries1, entry1)) {
		entries2 = iscsi_look_for_stuff(entry1->path, "iqn.",
						B_TRUE, 4);
		for (entry2 = list_head(entries2);
		     entry2 != NULL;
		     entry2 = list_next(entries2, entry2)) {
			/* DIR: /sys/kernel/scst_tgt/targets/iscsi/iqn.* */

			/* Save the share name */
			name = entry2->entry;

			/* RETRIEVE state */
			ret = snprintf(tmp_path, sizeof (tmp_path),
					"%s/enabled", entry2->path);
			if (ret < 0 || ret >= sizeof (tmp_path))
				goto retrieve_targets_scst_out;
			if (iscsi_read_sysfs_value(tmp_path, &buffer) != SA_OK)
				goto retrieve_targets_scst_out;
			state = buffer;
			buffer = NULL;

			/* RETRIEVE tid */
			ret = snprintf(tmp_path, sizeof (tmp_path), "%s/tid",
					entry2->path);
			if (ret < 0 || ret >= sizeof (tmp_path))
				goto retrieve_targets_scst_out;
			if (iscsi_read_sysfs_value(tmp_path, &buffer) != SA_OK)
				goto retrieve_targets_scst_out;
			tid = buffer;
			buffer = NULL;

			/* RETRIEVE lun(s) */
			ret = snprintf(tmp_path, sizeof (tmp_path),
					"%s/luns", entry2->path);
			if (ret < 0 || ret >= sizeof (tmp_path))
				goto retrieve_targets_scst_out;

			entries3 = iscsi_look_for_stuff(tmp_path, NULL,
							B_TRUE, 0);
			for (entry3 = list_head(entries3);
			     entry3 != NULL;
			     entry3 = list_next(entries3, entry3)) {
				lun = entry3->entry;

				/* RETRIEVE blocksize */
				ret = snprintf(tmp_path, sizeof (tmp_path),
						"%s/luns/%s/device/blocksize",
						entry2->path, lun);
				if (ret < 0 || ret >= sizeof (tmp_path))
					goto retrieve_targets_scst_out;
				if (iscsi_read_sysfs_value(tmp_path, &buffer)
				    != SA_OK)
					goto retrieve_targets_scst_out;
				blocksize = buffer;
				buffer = NULL;

				/* RETRIEVE block device path */
				ret = snprintf(tmp_path, sizeof (tmp_path),
						"%s/luns/%s/device/filename",
						entry2->path, lun);
				if (ret < 0 || ret >= sizeof (tmp_path))
					goto retrieve_targets_scst_out;
				if (iscsi_read_sysfs_value(tmp_path, &buffer)
				    != SA_OK)
					goto retrieve_targets_scst_out;
				dev_path = buffer;
				buffer = NULL;

				/*
				 * RETRIEVE scst device name
				 * trickier: '6550a239-iscsi1' (s/.*-//)
				 */
				ret = snprintf(tmp_path, sizeof (tmp_path),
					    "%s/luns/%s/device/t10_dev_id",
					    entry2->path, lun);
				if (ret < 0 || ret >= sizeof (tmp_path))
					goto retrieve_targets_scst_out;
				if (iscsi_read_sysfs_value(tmp_path, &buffer)
				    != SA_OK)
					goto retrieve_targets_scst_out;
				device = strstr(buffer, "-") + 1;
				buffer = NULL;

				/*
				 * RETRIEVE iotype
				 * tricker: it's only availible in the
				 * link.
				 */
				// $SYSFS/targets/iscsi/$name/luns/0/device/handler
				// => /sys/kernel/scst_tgt/handlers/vdisk_blockio
				ret = snprintf(tmp_path, sizeof (tmp_path),
						"%s/luns/%s/device/handler",
						entry2->path, lun);
				if (ret < 0 || ret >= sizeof (tmp_path))
					goto retrieve_targets_scst_out;

				link = (char *) calloc(PATH_MAX, 1);
				if (link == NULL) {
					rc = SA_NO_MEMORY;
					goto retrieve_targets_scst_out;
				}

				if(readlink(tmp_path, link, PATH_MAX) == -1) {
					rc = errno;
					goto retrieve_targets_scst_out;
				}
				link[strlen(link)] = '\0';
				iotype = strstr(link, "_") + 1;

				/* TODO: Retrieve iomode */

				target = (iscsi_target_t *)
					malloc(sizeof (iscsi_target_t));
				if (target == NULL) {
					rc = SA_NO_MEMORY;
					goto retrieve_targets_scst_out;
				}

				target->tid = atoi(tid);
				target->lun = atoi(lun);
				target->state = atoi(state);
				target->blocksize = atoi(blocksize);

				strncpy(target->name,	name,
					sizeof (target->name));
				strncpy(target->path,	dev_path,
					sizeof (target->path));
				strncpy(target->device,	device,
					sizeof (target->device));
				strncpy(target->iotype,	iotype,
					sizeof (target->iotype));
				/*
				 * TODO
				 * strncpy(target->iomode,	iomode,
				 *	sizeof (target->iomode));
				 */

				/* Link the session here */
				target->session = NULL;
				for (session = list_head(sessions);
				     session != NULL;
				     session = list_next(sessions, session)){
					if (session->tid == target->tid) {
						target->session = session;
						list_link_init(
						    &target->session->next);

						break;
					}
				}

#ifdef DEBUG
				fprintf(stderr,"iscsi_retrieve_targets_scst: "
					"target=%s, tid=%d, lun=%d, path=%s\n",
					target->name, target->tid, target->lun,
					target->path);
#endif

				/* Append the target to the list of new trgs */
				list_insert_tail(&all_iscsi_targets_list, target);
			}
		}
	}

	free(link);

	return (SA_OK);

retrieve_targets_scst_out:
	free(link);

	return (rc);
}

/* iscsi_retrieve_targets_stgt() retrieves list if iSCSI targets - STGT */
static int
iscsi_retrieve_targets_stgt(void)
{
	int rc = SA_OK, buffer_len;
	char buffer[512], cmd[PATH_MAX];
	char *value, *token, *key, *colon;
	FILE *shareiscsi_temp_fp;
	iscsi_session_t *session;
	list_t *sessions;

	/* For soring the targets */
	char *tid = NULL, *name = NULL, *lun = NULL, *state = NULL;
	char *iotype = NULL, *iomode = NULL, *blocks = NULL;
	char *blocksize = NULL, *path = NULL;
	iscsi_target_t *target;

	/* CMD: tgtadm --lld iscsi --op show --mode target */
	rc = snprintf(cmd, sizeof (cmd), "%s --lld iscsi --op show "
		      "--mode target", STGT_CMD_PATH);

	if (rc < 0 || rc >= sizeof (cmd))
		return (SA_SYSTEM_ERR);

#ifdef DEBUG
	fprintf(stderr, "CMD: %s\n", cmd);
#endif

	shareiscsi_temp_fp = popen(cmd, "r");
	if (shareiscsi_temp_fp == NULL)
		return (SA_SYSTEM_ERR);

	while (fgets(buffer, sizeof (buffer), shareiscsi_temp_fp) != 0) {
		/* Trim trailing new-line character(s). */
		buffer_len = strlen(buffer);
		while (buffer_len > 0) {
			buffer_len--;
			if (buffer[buffer_len] == '\r' ||
			    buffer[buffer_len] == '\n') {
				buffer[buffer_len] = 0;
			} else
				break;
		}

		if (strncmp(buffer, "Target ", 7) == 0) {
			/* Target definition */
			/* => Target 1: iqn.2012-11.com.bayour:test */

			/* Split the line in three, separated by space */
			token = strchr(buffer, ' ');
			while (token != NULL) {
				colon = strchr(token, ':');

				if (colon == NULL)
					goto next_token;

				key = token + 1;
				value = colon + 2;
				*colon = '\0';

				tid = strdup(key);
				if (tid == NULL)
					exit(SA_NO_MEMORY);

				name = strdup(value);
				if (name == NULL)
					exit(SA_NO_MEMORY);
next_token:
				token = strtok(NULL, " ");
			}
		} else if(strncmp(buffer, "        LUN: ", 13) == 0) {
			/* LUN */
			token = strchr(buffer, ':');
			lun = strdup(token + 2);
		} else if(strncmp(buffer, "            Online: ",
				  20) == 0) {
			/* STATUS */
			token = strchr(buffer, ':');
			state = strdup(token + 2);
		} else if(strncmp(buffer, "            Backing store path: ",
				  32) == 0) {
			/* PATH */
			token = strchr(buffer, ':');
			path = strdup(token + 2);

			if (strncmp(path, "None", 4) == 0) {
				/*
				 * For some reason it isn't possible to 
				 * add a path to the first LUN, so it's
				 * done in the second...
				 * Reset the variables and try again in
				 * the next loop round.
				 */
				lun = NULL;
				path = NULL;
			}
		}

		if (tid == NULL || name == NULL || lun == NULL ||
		    state == NULL || path == NULL)
			continue; /* Incomplete target definition */

		target = (iscsi_target_t *) malloc(sizeof (iscsi_target_t));
		if (target == NULL) {
			rc = SA_NO_MEMORY;
			goto retrieve_targets_stgt_out;
		}

		/* Save the values in the struct */
		target->tid = atoi(tid);
		target->lun = atoi(lun);
		if (strncmp(state, "Yes", 3))
			target->state = 1;
		else
			target->state = 0;
		strncpy(target->name, name, sizeof (target->name));
		strncpy(target->path, path, sizeof (target->path));

		/* Get all sessions for this TID */
		sessions = iscsi_retrieve_sessions_stgt(target->tid);

		/* Link the session here */
		target->session = NULL;
		for (session = list_head(sessions);
		     session != NULL;
		     session = list_next(sessions, session)) {
			if (session->tid == target->tid) {
				target->session = session;
				list_link_init(&target->session->next);

				break;
			}
		}

#ifdef DEBUG
		fprintf(stderr, "iscsi_retrieve_targets_stgt: "
			"target=%s, tid=%d, lun=%d, path=%s, active=%d\n",
			target->name, target->tid, target->lun, target->path,
			target->session ? target->session->state : -1);
#endif

		/* Append the target to the list of new targets */
		list_insert_tail(&all_iscsi_targets_list, target);

		tid = name = NULL;
		lun = state = iotype = iomode = NULL;
		blocks = blocksize = path = NULL;
	}

retrieve_targets_stgt_out:
	if (pclose(shareiscsi_temp_fp) != 0)
		fprintf(stderr, "Failed to pclose stream\n");

	free(tid);
	free(name);
	free(lun);
	free(state);
	free(iotype);
	free(iomode);
	free(blocks);
	free(blocksize);
	free(path);

	return (rc);
}

/*
 * WRAPPER: Depending on iSCSI implementation, call the
 * relevant function but only if we haven't already.
 * TODO: That doesn't work exactly as intended. Threading?
 */
static int
iscsi_retrieve_targets(void)
{
//	if (!list_is_empty(&all_iscsi_targets_list)) {
//		/* Try to limit the number of times we do this */
//fprintf(stderr, "iscsi_retrieve_targets: !list_is_empty()\n");
//		return (SA_OK);
//	}

	/* Create the global share list  */
	list_create(&all_iscsi_targets_list, sizeof (iscsi_target_t),
		    offsetof(iscsi_target_t, next));

	if (iscsi_implementation == ISCSI_IMPL_IET)
		return (iscsi_retrieve_targets_iet());
	else if (iscsi_implementation == ISCSI_IMPL_SCST)
		return (iscsi_retrieve_targets_scst());
	else if (iscsi_implementation == ISCSI_IMPL_STGT)
		return (iscsi_retrieve_targets_stgt());
	else
		return (SA_SYSTEM_ERR);
}

/*
 * Validates share option(s).
 */
static int
iscsi_get_shareopts_cb(const char *key, const char *value, void *cookie)
{
	char *dup_value;
	int lun;
	iscsi_shareopts_t *opts = (iscsi_shareopts_t *)cookie;

	if (strcmp(key, "on") == 0)
		return (SA_OK);

	/* iqn is an alias to name */
	if (strcmp(key, "iqn") == 0)
		key = "name";

	/*
	 * iotype is what's used in PROC_IET_VOLUME, but Type
	 * in ietadm and 'type' in shareiscsi option...
	 */
	if (strcmp(key, "iotype") == 0 ||
	    strcmp(key, "Type") == 0)
		key = "type";

	/* STGT calls it 'bstype' */
	if (strcmp(key, "bstype") == 0)
		key = "iomode";

	/* Just for completeness */
	if (strcmp(key, "BlockSize") == 0)
		key = "blocksize";

	/* Verify all options */
	if (strcmp(key, "name") != 0 &&
	    strcmp(key, "lun") != 0 &&
	    strcmp(key, "type") != 0 &&
	    strcmp(key, "iomode") != 0 &&
	    strcmp(key, "blocksize") != 0)
		return (SA_SYNTAX_ERR);


	dup_value = strdup(value);
	if (dup_value == NULL)
		return (SA_NO_MEMORY);

	/* Get share option values */
	if (strcmp(key, "name") == 0) {
		strncpy(opts->name, dup_value, sizeof (opts->name));
		opts->name [sizeof (opts->name)-1] = '\0';
	}

	if (strcmp(key, "type") == 0) {
		/* Make sure it's a valid type value */
		if (strcmp(dup_value, "fileio") != 0 &&
		    strcmp(dup_value, "blockio") != 0 &&
		    strcmp(dup_value, "nullio") != 0 &&
		    strcmp(dup_value, "disk") != 0 &&
		    strcmp(dup_value, "tape") != 0 &&
		    strcmp(dup_value, "ssc") != 0 &&
		    strcmp(dup_value, "pt") != 0)
			return (SA_SYNTAX_ERR);

		/*
		 * The *Solaris options 'disk' (and future 'tape')
		 * isn't availible in ietadm. It _seems_ that 'fileio'
		 * is the Linux version.
		 *
		 * NOTE: Only for IET
		 */
		if (iscsi_implementation == ISCSI_IMPL_IET &&
		    (strcmp(dup_value, "disk") == 0 ||
		    strcmp(dup_value, "tape") == 0))
			strncpy(dup_value, "fileio", 7);

		/*
		 * The STGT option ssc = tape
		 */
		if (iscsi_implementation == ISCSI_IMPL_STGT &&
		    strcmp(dup_value, "ssc") == 0)
			strncpy(dup_value, "tape", 5);

		strncpy(opts->type, dup_value, sizeof (opts->type));
		opts->type [sizeof (opts->type)-1] = '\0';
	}

	if (strcmp(key, "iomode") == 0) {
		/* Make sure it's a valid iomode */
		if (strcmp(dup_value, "wb") != 0 &&
		    strcmp(dup_value, "ro") != 0 &&
		    strcmp(dup_value, "wt") != 0 &&
		    strcmp(dup_value, "rdwr") != 0 &&	/* STGT */
		    strcmp(dup_value, "aio") != 0 &&	/* STGT */
		    strcmp(dup_value, "mmap") != 0 &&	/* STGT */
		    strcmp(dup_value, "sg") != 0 &&	/* STGT */
		    strcmp(dup_value, "ssc") != 0)	/* STGT */
			return (SA_SYNTAX_ERR);

		if (strcmp(opts->type, "blockio") == 0 &&
		    strcmp(dup_value, "wb") == 0)
			/* Can't do write-back cache with blockio */
			strncpy(dup_value, "wt", 3);

		strncpy(opts->iomode, dup_value, sizeof (opts->iomode));
		opts->iomode [sizeof (opts->iomode)-1] = '\0';
	}

	if (strcmp(key, "lun") == 0) {
		lun = atoi(dup_value);
		if (iscsi_implementation == ISCSI_IMPL_STGT &&
		    lun == 0)
			/*
			 * LUN0 is reserved and it isn't possible
			 * to add a device 'backing store' to it).
			 */
			lun = 1;
		else {
			if (lun >= 0 && lun <= 16384)
				opts->lun = lun;
			else
				return (SA_SYNTAX_ERR);
		}
	}

	if (strcmp(key, "blocksize") == 0) {
		/* Make sure it's a valid blocksize */
		if (strcmp(dup_value, "512")  != 0 &&
		    strcmp(dup_value, "1024") != 0 &&
		    strcmp(dup_value, "2048") != 0 &&
		    strcmp(dup_value, "4096") != 0)
			return (SA_SYNTAX_ERR);

		opts->blocksize = atoi(dup_value);
	}

	return (SA_OK);
}

/*
 * Takes a string containing share options (e.g. "name=Whatever,lun=3")
 * and converts them to a NULL-terminated array of options.
 */
static int
iscsi_get_shareopts(sa_share_impl_t impl_share, const char *shareopts,
		    iscsi_shareopts_t **opts)
{
	char iqn[255];
	int rc;
	iscsi_shareopts_t *new_opts;
	uint64_t blocksize;
	zfs_handle_t *zhp;

	assert(opts != NULL);
	*opts = NULL;

	new_opts = (iscsi_shareopts_t *) calloc(sizeof (iscsi_shareopts_t), 1);
	if (new_opts == NULL)
		return (SA_NO_MEMORY);

	/* Set defaults */
	if (impl_share && impl_share->dataset) {
		if ((rc = iscsi_generate_target(impl_share->dataset, iqn,
						sizeof (iqn))) != 0)
			return (rc);

		strncpy(new_opts->name, iqn, strlen(iqn));
		new_opts->name [strlen(iqn)+1] = '\0';
	} else
		new_opts->name[0] = '\0';

	if (impl_share && impl_share->handle &&
	    impl_share->handle->zfs_libhandle) {
		/* Get the volume blocksize */
		zhp = zfs_open(impl_share->handle->zfs_libhandle,
				impl_share->dataset,
				ZFS_TYPE_FILESYSTEM|ZFS_TYPE_VOLUME);

		if (zhp == NULL)
			return (SA_SYSTEM_ERR);

		blocksize = zfs_prop_get_int(zhp, ZFS_PROP_VOLBLOCKSIZE);

		zfs_close(zhp);

		if (blocksize == 512 || blocksize == 1024 ||
		    blocksize == 2048 || blocksize == 4096)
			new_opts->blocksize = blocksize;
		else
			new_opts->blocksize = 4096;
	} else
		new_opts->blocksize = 4096;

	if (iscsi_implementation == ISCSI_IMPL_STGT) {
		strncpy(new_opts->iomode, "rdwr", 5);
		strncpy(new_opts->type, "disk", 6);

		/*
		 * LUN0 is reserved and it isn't possible
		 * to add a device 'backing store' to it).
		 */
		new_opts->lun = 1;
	} else {
		strncpy(new_opts->iomode, "wt", 3);
		strncpy(new_opts->type, "blockio", 7);
		new_opts->lun = 0;
	}
	*opts = new_opts;

	rc = foreach_shareopt(shareopts, iscsi_get_shareopts_cb, *opts);
	if (rc != SA_OK) {
		free(*opts);
		*opts = NULL;
	}

	return (rc);
}

static int
iscsi_enable_share_one_iet(sa_share_impl_t impl_share, int tid)
{
	char *argv[10], params_name[255], params[255], tid_s[11];
	char *shareopts;
	iscsi_shareopts_t *opts;
	int rc, ret;

	opts = (iscsi_shareopts_t *) malloc(sizeof (iscsi_shareopts_t));
	if (opts == NULL)
		return (SA_NO_MEMORY);

	/* Get any share options */
	shareopts = FSINFO(impl_share, iscsi_fstype)->shareopts;
	rc = iscsi_get_shareopts(impl_share, shareopts, &opts);
	if (rc < 0) {
		free(opts);
		return (SA_SYSTEM_ERR);
	}

#ifdef DEBUG
	fprintf(stderr, "iscsi_enable_share_one_iet: name=%s, tid=%d, "
		"sharepath=%s, iomode=%s, type=%s, lun=%d, blocksize=%d\n",
		opts->name, tid, impl_share->sharepath, opts->iomode,
		opts->type, opts->lun, opts->blocksize);
#endif

	/*
	 * ietadm --op new --tid $next --params Name=$iqn
	 * ietadm --op new --tid $next --lun=0 --params \
	 *   Path=/dev/zvol/$sharepath,Type=<fileio|blockio|nullio>
	 */

	/*
	 * ======
	 * PART 1 - do the (inital) share. No path etc...
	 * CMD: ietadm --op new --tid <TID> --params <PARAMS>
	 */
	ret = snprintf(params_name, sizeof (params_name), "Name=%s",
			opts->name);
	if (ret < 0 || ret >= sizeof (params_name)) {
		free(opts);
		return (SA_SYSTEM_ERR);
	}

	/* int: between -2,147,483,648 and 2,147,483,647 => 10 chars + NUL */
	ret = snprintf(tid_s, sizeof (tid_s), "%d", tid);
	if (ret < 0 || ret >= sizeof (tid_s)) {
		free(opts);
		return (SA_SYSTEM_ERR);
	}

	argv[0] = IETM_CMD_PATH;
	argv[1] = (char *)"--op";
	argv[2] = (char *)"new";
	argv[3] = (char *)"--tid";
	argv[4] = tid_s;
	argv[5] = (char *)"--params";
	argv[6] = params_name;
	argv[7] = NULL;

#ifdef DEBUG
	int i;
	fprintf(stderr, "CMD: ");
	for (i = 0; i < 7; i++)
		fprintf(stderr, "%s ", argv[i]);
	fprintf(stderr, "\n");
#endif

	rc = libzfs_run_process(argv[0], argv, STDERR_VERBOSE);
	if (rc != 0) {
		free(opts);
		return (SA_SYSTEM_ERR);
	}

	/*
	 * ======
	 * PART 2 - Set share path and lun.
	 */
	ret = snprintf(params, sizeof (params),
			"Path=%s,Type=%s,iomode=%s,BlockSize=%d",
			impl_share->sharepath, opts->type, opts->iomode,
			opts->blocksize);
	if (ret < 0 || ret >= sizeof (params)) {
		free(opts);
		return (SA_SYSTEM_ERR);
	}

	/* CMD: ietadm --op new --tid <TID> --lun <LUN> --params <PARAMS> */
	argv[5] = (char *)"--lun";
	ret = snprintf(argv[6], sizeof (*argv[6]), "%d", opts->lun);
	if (ret < 0 || ret >= sizeof (argv[6])) {
		free(opts);
		return (SA_SYSTEM_ERR);
	}
	argv[7] = (char *)"--params";
	argv[8] = params;
	argv[9] = NULL;

#ifdef DEBUG
	fprintf(stderr, "CMD: ");
	for (i = 0; i < 9; i++)
		fprintf(stderr, "%s ", argv[i]);
	fprintf(stderr, "\n");
#endif

	rc = libzfs_run_process(argv[0], argv, STDERR_VERBOSE);
	if (rc != 0) {
		free(opts);
		return (SA_SYSTEM_ERR);
	}

	/*
	 * ======
	 * PART 3 - Run local update script.
	 */
	if (access(EXTRA_ISCSI_SHARE_SCRIPT, X_OK) == 0) {
		/* CMD: /sbin/zfs_share_iscsi <TID> */
		argv[0] = (char *)EXTRA_ISCSI_SHARE_SCRIPT;
		argv[1] = tid_s;
		argv[2] = NULL;

#ifdef DEBUG
		int i;
		fprintf(stderr, "CMD: ");
		for (i = 0; i < 2; i++)
			fprintf(stderr, "%s ", argv[i]);
		fprintf(stderr, "\n");
#endif

		rc = libzfs_run_process(argv[0], argv, STDERR_VERBOSE);
		if (rc != 0) {
			free(opts);
			return (SA_SYSTEM_ERR);
		}
	}

	free(opts);
	return (SA_OK);
}

/* NOTE: TID is not use with SCST - it's autogenerated at create time. */
static int
iscsi_enable_share_one_scst(sa_share_impl_t impl_share, int tid)
{
	char *argv[3], *shareopts, *device, buffer[255], path[PATH_MAX];
	iscsi_shareopts_t *opts;
	int rc, ret;

#ifdef DEBUG
	fprintf(stderr, "iscsi_enable_share_one_scst: tid=%d, sharepath=%s\n",
		tid, impl_share->sharepath);
#endif

	opts = (iscsi_shareopts_t *) malloc(sizeof (iscsi_shareopts_t));
	if (opts == NULL)
		return (SA_NO_MEMORY);

	/* Get any share options */
	shareopts = FSINFO(impl_share, iscsi_fstype)->shareopts;
	rc = iscsi_get_shareopts(impl_share, shareopts, &opts);
	if (rc < 0) {
		free(opts);
		return (SA_SYSTEM_ERR);
	}

	/* Generate a scst device name from the dataset name */
	iscsi_generate_scst_device_name(&device);

#ifdef DEBUG
	fprintf(stderr, "iscsi_enable_share_one_scst: name=%s, iomode=%s, type=%s, "
		"lun=%d, blocksize=%d\n", opts->name, opts->iomode, opts->type,
		opts->lun, opts->blocksize);
#endif

	/*
	 * ======
	 * PART 1 - Add target
	 * CMD: echo "add_target $name" > $SYSFS/targets/iscsi/mgmt
	 */
	strcpy(path, "targets/iscsi/mgmt");
	ret = snprintf(buffer, sizeof (buffer), "add_target %s", opts->name);
	if (ret < 0 || ret >= sizeof (buffer)) {
		free(opts);
		return (SA_NO_MEMORY);
	}
	if (iscsi_write_sysfs_value(path, buffer) != SA_OK) {
		free(opts);
		return (SA_NO_MEMORY);
	}

	/*
	 * ======
	 * PART 2 - Add device
	 * CMD: echo "add_device $dev filename=/dev/zvol/$vol;blocksize=512" \
	 *	> $SYSFS/handlers/vdisk_blockio/mgmt
	 */
	ret = snprintf(path, sizeof (buffer), "handlers/vdisk_%s/mgmt",
			opts->type);
	if (ret < 0 || ret >= sizeof (path)) {
		free(opts);
		return (SA_NO_MEMORY);
	}
	ret = snprintf(buffer, sizeof (buffer), "add_device %s filename=%s; "
			"blocksize=%d", device, impl_share->sharepath,
			opts->blocksize);
	if (ret < 0 || ret >= sizeof (buffer)) {
		free(opts);
		return (SA_NO_MEMORY);
	}
	if (iscsi_write_sysfs_value(path, buffer) != SA_OK) {
		free(opts);
		return (SA_NO_MEMORY);
	}

	/*
	 * ======
	 * PART 3 - Add lun
	 * CMD: echo "add $dev 0" > $SYSFS/targets/iscsi/$name/luns/mgmt
	 */
	ret = snprintf(path, sizeof (path), "targets/iscsi/%s/luns/mgmt",
			opts->name);
	if (ret < 0 || ret >= sizeof (path)) {
		free(opts);
		return (SA_NO_MEMORY);
	}
	ret = snprintf(buffer, sizeof (buffer), "add %s %d", device,
			opts->lun);
	if (ret < 0 || ret >= sizeof (buffer)) {
		free(opts);
		return (SA_NO_MEMORY);
	}
	if (iscsi_write_sysfs_value(path, buffer) != SA_OK) {
		free(opts);
		return (SA_NO_MEMORY);
	}

	/*
	 * ======
	 * PART 4 - Enable target
	 * CMD: echo 1 > $SYSFS/targets/iscsi/$name/enabled
	 */
	ret = snprintf(path, sizeof (path), "targets/iscsi/%s/enabled",
			opts->name);
	if (ret < 0 || ret >= sizeof (path)) {
		free(opts);
		return (SA_NO_MEMORY);
	}
	strcpy(buffer, "1");
	if (iscsi_write_sysfs_value(path, buffer) != SA_OK) {
		free(opts);
		return (SA_NO_MEMORY);
	}

	/*
	 * ======
	 * PART 5 - Run local update script.
	 */
	if (access(EXTRA_ISCSI_SHARE_SCRIPT, X_OK) == 0) {
		/* CMD: /sbin/zfs_share_iscsi <TID> */
		argv[0] = (char *)EXTRA_ISCSI_SHARE_SCRIPT;
		argv[1] = opts->name;
		argv[2] = NULL;

#ifdef DEBUG
		int i;
		fprintf(stderr, "CMD: ");
		for (i = 0; i < 2; i++)
			fprintf(stderr, "%s ", argv[i]);
		fprintf(stderr, "\n");
#endif

		rc = libzfs_run_process(argv[0], argv, STDERR_VERBOSE);
		if (rc != 0) {
			free(opts);
			return (SA_SYSTEM_ERR);
		}
	}

	free(opts);

	return (SA_OK);
}

static int
iscsi_enable_share_one_stgt(sa_share_impl_t impl_share, int tid)
{
	int rc = SA_OK, ret;
	char *argv[18], tid_s[11], iqn[255], *shareopts;
	iscsi_shareopts_t *opts;

#ifdef DEBUG
	fprintf(stderr, "iscsi_enable_share_one_stgt: tid=%d, sharepath=%s\n",
		tid, impl_share->sharepath);
#endif

	opts = (iscsi_shareopts_t *) malloc(sizeof (iscsi_shareopts_t));
	if (opts == NULL)
		return (SA_NO_MEMORY);

	/* Get any share options */
	shareopts = FSINFO(impl_share, iscsi_fstype)->shareopts;
	rc = iscsi_get_shareopts(impl_share, shareopts, &opts);
	if (rc < 0) {
		free(opts);
		return (SA_SYSTEM_ERR);
	}

	/* int: between -2,147,483,648 and 2,147,483,647 => 10 chars + NUL */
	ret = snprintf(tid_s, sizeof (tid_s), "%d", tid);
	if (ret < 0 || ret >= sizeof (tid_s)) {
		free(opts);
		return (SA_SYSTEM_ERR);
	}

	/* Generate an IQN */
	if (!opts->name) {
		if (iscsi_generate_target(impl_share->dataset, iqn,
					  sizeof (iqn)) != SA_OK)
			return (SA_SYSTEM_ERR);
	} else
		strcpy(iqn, opts->name);

	/* TODO: set 'iomode' and 'blocksize' */

	/* 
	 * ======
	 * PART 1 - do the (initial) share. No path etc...
	 * CMD: tgtadm --lld iscsi --op new --mode target --tid TID	\
	 *        --targetname `cat /etc/iscsi_target_id`:test
	 */
	argv[0]  = STGT_CMD_PATH;
	argv[1]  = (char *)"--lld";
	argv[2]  = (char *)"iscsi";
	argv[3]  = (char *)"--op";
	argv[4]  = (char *)"new";
	argv[5]  = (char *)"--mode";
	argv[6]  = (char *)"target";
	argv[7]  = (char *)"--tid";
	argv[8]  = tid_s;
	argv[9]  = (char *)"--targetname";
	argv[10] = iqn;
	argv[11] = NULL;

#ifdef DEBUG
	int i;
	fprintf(stderr, "CMD: ");
	for (i = 0; i < 11; i++)
		fprintf(stderr, "%s ", argv[i]);
	fprintf(stderr, "\n");
#endif

	rc = libzfs_run_process(argv[0], argv, STDERR_VERBOSE);
	if (rc != 0) {
		free(opts);
		return (SA_SYSTEM_ERR);
	}

	/*
	 * ======
	 * PART 2 - Set share path and lun.
	 * CMD: tgtadm --lld iscsi --op new --mode logicalunit --tid 1 \
	 *      --lun 1 -b /dev/zvol/mypool/tests/iscsi/tst001
	 */
	argv[6]  = (char *)"logicalunit";
	argv[7]  = (char *)"--tid";
	argv[8]  = tid_s;
	argv[9]  = (char *)"--lun";
	argv[10] = (char *)"1";
	argv[11] = (char *)"--backing-store";
	argv[12] = impl_share->sharepath;
	argv[13] = (char *)"--device-type";
	argv[14] = opts->type;
	argv[15] = (char *)"--bstype";
	argv[16] = opts->iomode;
	argv[17] = NULL;
	
#ifdef DEBUG
	fprintf(stderr, "CMD: ");
	for (i = 0; i < 17; i++)
		fprintf(stderr, "%s ", argv[i]);
	fprintf(stderr, "\n");
#endif

	rc = libzfs_run_process(argv[0], argv, STDERR_VERBOSE);
	if (rc != 0) {
		free(opts);
		return (SA_SYSTEM_ERR);
	}

	/*
	 * ======
	 * PART 3 - Bind the target to all portals
	 * CMD: tgtadm --lld iscsi --op bind --mode target --tid 1 \
	 *      --initiator-address ALL
	 */
	argv[4]  = (char *)"bind";
	argv[6]  = (char *)"target";
	argv[9]  = (char *)"--initiator-address";
	argv[10] = (char *)"ALL";
	argv[11] = NULL;

#ifdef DEBUG
	fprintf(stderr, "CMD: ");
	for (i = 0; i < 11; i++)
		fprintf(stderr, "%s ", argv[i]);
	fprintf(stderr, "\n");
#endif

	rc = libzfs_run_process(argv[0], argv, STDERR_VERBOSE);
	if (rc != 0) {
		free(opts);
		return (SA_SYSTEM_ERR);
	}

	/*
	 * ======
	 * PART 4 - Run local update script.
	 */
	if (access(EXTRA_ISCSI_SHARE_SCRIPT, X_OK) == 0) {
		/* CMD: /sbin/zfs_share_iscsi <TID> */
		argv[0] = (char *)EXTRA_ISCSI_SHARE_SCRIPT;
		argv[1] = tid_s;
		argv[2] = NULL;

#ifdef DEBUG
		int i;
		fprintf(stderr, "CMD: ");
		for (i = 0; i < 2; i++)
			fprintf(stderr, "%s ", argv[i]);
		fprintf(stderr, "\n");
#endif

		rc = libzfs_run_process(argv[0], argv, STDERR_VERBOSE);
		if (rc != 0) {
			free(opts);
			return (SA_SYSTEM_ERR);
		}
	}

	return (SA_OK);
}

/* WRAPPER: Depending on iSCSI implementation, call the relevant function */
static int
iscsi_enable_share_one(sa_share_impl_t impl_share, int tid)
{
	if (iscsi_implementation == ISCSI_IMPL_IET)
		return (iscsi_enable_share_one_iet(impl_share, tid));
	else if (iscsi_implementation == ISCSI_IMPL_SCST)
		return (iscsi_enable_share_one_scst(impl_share, tid));
	else if (iscsi_implementation == ISCSI_IMPL_STGT)
		return (iscsi_enable_share_one_stgt(impl_share, tid));
	else
		return (SA_SYSTEM_ERR);
}

static int
iscsi_enable_share(sa_share_impl_t impl_share)
{
	int tid = 0, prev_tid = 0;
	char *shareopts;
	iscsi_target_t *target;

	shareopts = FSINFO(impl_share, iscsi_fstype)->shareopts;
	if (shareopts == NULL) /* on/off */
		return (SA_SYSTEM_ERR);

	if (strcmp(shareopts, "off") == 0)
		return (SA_OK);

	for (target = list_head(&all_iscsi_targets_list);
	     target != NULL;
	     target = list_next(&all_iscsi_targets_list, target)) {
		/* Catch the fact that IET adds the target in reverse
		 * order (lower TID at the bottom). */
		if (target->tid > prev_tid)
			tid = target->tid;

		prev_tid = tid;
	}
	tid = prev_tid + 1; /* Next TID is/should be availible */

	/* Magic: Enable (i.e., 'create new') share */
	return (iscsi_enable_share_one(impl_share, tid));
}

static int
iscsi_disable_share_one_iet(int tid)
{
	char *argv[6];
	char tid_s[11];
	int rc, ret;

	/* int: between -2,147,483,648 and 2,147,483,647 => 10 chars + NUL */
	ret = snprintf(tid_s, sizeof (tid_s), "%d", tid);
	if (ret < 0 || ret >= sizeof (tid_s))
		return (SA_SYSTEM_ERR);

	/* CMD: ietadm --op delete --tid <TID> */
	argv[0] = IETM_CMD_PATH;
	argv[1] = (char *)"--op";
	argv[2] = (char *)"delete";
	argv[3] = (char *)"--tid";
	argv[4] = tid_s;
	argv[5] = NULL;

#ifdef DEBUG
	int i;
	fprintf(stderr, "CMD: ");
	for (i = 0; i < 5; i++)
		fprintf(stderr, "%s ", argv[i]);
	fprintf(stderr, "\n");
#endif

	rc = libzfs_run_process(argv[0], argv, STDERR_VERBOSE);
	if (rc != 0)
		return (SA_SYSTEM_ERR);
	else
		return (SA_OK);
}

static int
iscsi_disable_share_one_scst(int tid)
{
	int ret;
	char path[PATH_MAX], buffer[255];
	iscsi_target_t *target;

	for (target = list_head(&all_iscsi_targets_list);
	     target != NULL;
	     target = list_next(&all_iscsi_targets_list, target)) {
		if (target->tid == tid) {
#ifdef DEBUG
			fprintf(stderr, "iscsi_disable_share_one_scst: "
				"target=%s, tid=%d, path=%s, device=%s\n",
				target->name, target->tid,
				target->path, target->iotype);
#endif

			break;
		}
	}

	/*
	 * ======
	 * PART 1 - Disable target
	 * CMD: echo 0 > $SYSFS/targets/iscsi/$name/enabled
	 */
	ret = snprintf(path, sizeof (path), "targets/iscsi/%s/enabled",
		       target->name);
	if (ret < 0 || ret >= sizeof (path))
		return (SA_SYSTEM_ERR);
	strcpy(buffer, "0");
	if (iscsi_write_sysfs_value(path, buffer) != SA_OK)
		return (SA_NO_MEMORY);

	/*
	 * ======
	 * PART 2 - Delete device
	 */
	// dev=`/bin/ls -l $SYSFS/targets/iscsi/$name/luns/0/device | sed 's@.*/@@'`
	// echo "del_device $dev" > $SYSFS/handlers/vdisk_blockio/mgmt
	ret = snprintf(path, sizeof (path), "handlers/vdisk_%s/mgmt",
		       target->iotype);
	if (ret < 0 || ret >= sizeof (path))
		return (SA_SYSTEM_ERR);
	ret = snprintf(buffer, sizeof (buffer), "del_device %s",
		       target->device);
	if (ret < 0 || ret >= sizeof (buffer))
		return (SA_SYSTEM_ERR);
	if (iscsi_write_sysfs_value(path, buffer) != SA_OK)
		return (SA_NO_MEMORY);

	/*
	 * ======
	 * PART 3 - Delete target
	 * CMD: echo "del_target $name" > $SYSFS/targets/iscsi/mgmt
	 */
	strcpy(path, "targets/iscsi/mgmt");
	ret = snprintf(buffer, sizeof (buffer), "del_target %s",
		       target->name);
	if (ret < 0 || ret >= sizeof (buffer))
		return (SA_SYSTEM_ERR);
	if (iscsi_write_sysfs_value(path, buffer) != SA_OK)
		return (SA_NO_MEMORY);

	return (SA_OK);
}

static int
iscsi_disable_share_one_stgt(int tid)
{
	int rc = SA_OK, ret;
	char *argv[10], tid_s[11];

	/* int: between -2,147,483,648 and 2,147,483,647 => 10 chars + NUL */
	ret = snprintf(tid_s, sizeof (tid_s), "%d", tid);
	if (ret < 0 || ret >= sizeof (tid_s))
		return (SA_SYSTEM_ERR);

	/* CMD: tgtadm --lld iscsi --op delete --mode target --tid TID */
	argv[0] = STGT_CMD_PATH;
	argv[1] = (char *)"--lld";
	argv[2] = (char *)"iscsi";
	argv[3] = (char *)"--op";
	argv[4] = (char *)"delete";
	argv[5] = (char *)"--mode";
	argv[6] = (char *)"target";
	argv[7] = (char *)"--tid";
	argv[8] = tid_s;
	argv[9] = NULL;

#ifdef DEBUG
	int i;
	fprintf(stderr, "CMD: ");
	for (i = 0; i < 9; i++)
		fprintf(stderr, "%s ", argv[i]);
	fprintf(stderr, "\n");
#endif

	rc = libzfs_run_process(argv[0], argv, STDERR_VERBOSE);
	if (rc != 0)
		return (SA_SYSTEM_ERR);
	else
		return (SA_OK);
}

/* WRAPPER: Depending on iSCSI implementation, call the relevant function */
static int
iscsi_disable_share_one(int tid)
{
	if (iscsi_implementation == ISCSI_IMPL_IET)
		return (iscsi_disable_share_one_iet(tid));
	else if (iscsi_implementation == ISCSI_IMPL_SCST)
		return (iscsi_disable_share_one_scst(tid));
	else if (iscsi_implementation == ISCSI_IMPL_STGT)
		return (iscsi_disable_share_one_stgt(tid));
	else
		return (SA_SYSTEM_ERR);
}

static int
iscsi_disable_share(sa_share_impl_t impl_share)
{
	int ret;
	iscsi_target_t *target;

	if (!iscsi_available())
		return (B_FALSE);

	/* Does this target have active sessions? */
	iscsi_retrieve_targets();
	for (target = list_head(&all_iscsi_targets_list);
	     target != NULL;
	     target = list_next(&all_iscsi_targets_list, target)) {
		if (strcmp(impl_share->sharepath, target->path) == 0) {
#ifdef DEBUG
			fprintf(stderr, "iscsi_disable_share: target=%s, "
				"tid=%d, path=%s\n", target->name,
				target->tid, target->path);
#endif

			if (target->session &&
			    target->session->state) {
				/*
				 * XXX: This will wail twice because
				 *      sa_disable_share is called
				 *      twice - once with correct protocol
				 *      (iscsi) and once with  protocol=NULL
				 */
				fprintf(stderr, "Can't unshare - have active"
					" shares\n");
				return (SA_OK);
			}

			if ((ret = iscsi_disable_share_one(target->tid))
			    == SA_OK)
				list_remove(&all_iscsi_targets_list, target);
			return (ret);
		}
	}

	return (SA_OK);
}

static boolean_t
iscsi_is_share_active(sa_share_impl_t impl_share)
{
	iscsi_target_t *target;

	if (!iscsi_available())
		return (B_FALSE);

	/* Does this target have active sessions? */
	iscsi_retrieve_targets();
	for (target = list_head(&all_iscsi_targets_list);
	     target != NULL;
	     target = list_next(&all_iscsi_targets_list, target)) {
#ifdef DEBUG
		fprintf(stderr, "iscsi_is_share_active: %s ?? %s\n",
			target->path, impl_share->sharepath);
#endif

		if (strcmp(target->path, impl_share->sharepath) == 0) {
#ifdef DEBUG
			fprintf(stderr, "=> %s is active\n", target->name);
#endif
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

static int
iscsi_validate_shareopts(const char *shareopts)
{
	iscsi_shareopts_t *opts;
	int rc = SA_OK;

	rc = iscsi_get_shareopts(NULL, shareopts, &opts);

	free(opts);
	return (rc);
}

static int
iscsi_update_shareopts(sa_share_impl_t impl_share, const char *resource,
    const char *shareopts)
{
	int ret;
	char *shareopts_dup, *old_shareopts, tmp_opts[255], iqn[255];
	boolean_t needs_reshare = B_FALSE, have_active_sessions = B_FALSE;
	iscsi_target_t *target;
	iscsi_shareopts_t *opts;

	if (impl_share->dataset == NULL)
		return (B_FALSE);

	for (target = list_head(&all_iscsi_targets_list);
	     target != NULL;
	     target = list_next(&all_iscsi_targets_list, target)) {
		if ((strcmp(impl_share->sharepath, target->path) == 0) &&
		    target->session && target->session->state) {
			have_active_sessions = B_TRUE;

			break;
		}
	}

	/* Is the share active (i.e., shared */
	FSINFO(impl_share, iscsi_fstype)->active =
		iscsi_is_share_active(impl_share);

	/* Get old share opts */
	old_shareopts = FSINFO(impl_share, iscsi_fstype)->shareopts;

	if (strcmp(shareopts, "on") == 0 || 
	    (strncmp(shareopts, "name=", 5) != 0 &&
	     strncmp(shareopts, "iqn=",  4) != 0)) {
		/*
		 * Force a IQN value. This so that the iqn doesn't change
		 * 'next month' (when it's regenerated again) .
		 * NOTE: Does not change shareiscsi option, only sharetab!
		 */
		opts = (iscsi_shareopts_t *) malloc(sizeof (iscsi_shareopts_t));
		if (opts == NULL)
			return (SA_NO_MEMORY);

		ret = iscsi_get_shareopts(impl_share, old_shareopts, &opts);
		if (ret < 0) {
			free(opts);
			return (SA_SYSTEM_ERR);
		}

		if (!opts->name) {
			if (iscsi_generate_target(impl_share->dataset, iqn,
						  sizeof (iqn)) == SA_OK) {
				ret = snprintf(tmp_opts, sizeof (tmp_opts),
					       "name=%s,%s", iqn, shareopts);
				if (ret < 0 || ret >= sizeof (tmp_opts))
					return (SA_SYSTEM_ERR);
			}
		} else {
			ret = snprintf(tmp_opts, sizeof (tmp_opts),
				       "name=%s,%s", opts->name, shareopts);
			if (ret < 0 || ret >= sizeof (tmp_opts))
				return (SA_SYSTEM_ERR);
		}

		shareopts = tmp_opts;
	}

#ifdef DEBUG
	fprintf(stderr, "iscsi_update_shareopts: share=%s;%s,"
		" active=%d, have_active_sessions=%d, new_shareopts=%s, "
		"old_shareopts=%s\n",
		impl_share->dataset, impl_share->sharepath,
		FSINFO(impl_share, iscsi_fstype)->active, have_active_sessions,
		shareopts,
		FSINFO(impl_share, iscsi_fstype)->shareopts ?
		FSINFO(impl_share, iscsi_fstype)->shareopts : "null");
#endif

	/*
	 * RESHARE if:
	 *  is active
	 *  have old shareopts
	 *  old shareopts != shareopts
	 *  no active sessions
	 */
	if (FSINFO(impl_share, iscsi_fstype)->active && old_shareopts != NULL &&
	    strcmp(old_shareopts, shareopts) != 0 && !have_active_sessions) {
		needs_reshare = B_TRUE;
		iscsi_disable_share(impl_share);
	}

	shareopts_dup = strdup(shareopts);

	if (shareopts_dup == NULL)
		return (SA_NO_MEMORY);

	if (old_shareopts != NULL)
		free(old_shareopts);

	FSINFO(impl_share, iscsi_fstype)->shareopts = shareopts_dup;

	if (needs_reshare)
		iscsi_enable_share(impl_share);

	return (SA_OK);
}

static void
iscsi_clear_shareopts(sa_share_impl_t impl_share)
{
	free(FSINFO(impl_share, iscsi_fstype)->shareopts);
	FSINFO(impl_share, iscsi_fstype)->shareopts = NULL;
}

static const sa_share_ops_t iscsi_shareops = {
	.enable_share = iscsi_enable_share,
	.disable_share = iscsi_disable_share,

	.validate_shareopts = iscsi_validate_shareopts,
	.update_shareopts = iscsi_update_shareopts,
	.clear_shareopts = iscsi_clear_shareopts,
};

/*
 * Provides a convenient wrapper for determing iscsi availability
 */
static boolean_t
iscsi_available(void)
{
	struct stat eStat;

	iscsi_implementation = ISCSI_IMPL_NONE;

	if (access(PROC_IET_VOLUME, F_OK) == 0 &&
	    access(IETM_CMD_PATH, X_OK) == 0) {
		iscsi_implementation = ISCSI_IMPL_IET;
		return (B_TRUE);
	} else if (access(STGT_CMD_PATH, X_OK) == 0) {
		iscsi_implementation = ISCSI_IMPL_STGT;
		return (B_TRUE);
	} else if (stat(SYSFS_SCST, &eStat) == 0 &&
		   S_ISDIR(eStat.st_mode)) {
		iscsi_implementation = ISCSI_IMPL_SCST;
		return (B_TRUE);
	}

	return (B_FALSE);
}

void
libshare_iscsi_init(void)
{
	if (iscsi_available())
		iscsi_fstype = register_fstype("iscsi", &iscsi_shareops);
}
