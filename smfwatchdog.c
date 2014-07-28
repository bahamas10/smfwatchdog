/**
 * SMF Watchdog
 *
 * A health checking daemon to be used with an
 * SMF service.
 *
 * Author: Dave Eddy <dave@daveeddy.com>
 * Date: 5/19/2013
 * License: MIT
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libcontract.h>
#include <libgen.h>
#include <netdb.h>
#include <procfs.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PROGNAME           "smfwatchdog"
#define VERSION            "0.0.8"

#define DATEFMT            "%Y-%m-%dT%H:%M:%S"
#define DEFAULT_MAIL_PROG  "mailx -t"
#define MAX_FMRI_LEN       scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH)
#define WATCHDOG_DIR       "/opt/local/share/smf/smfwatchdog"
#define DISABLE_FILE       "DISABLE"

/* Action to take on failure, set by SMFWATCHDOG_ACTION */
#define ACT_RAISE_SIGABRT  0   /* kill ourself with SIGABRT */
#define ACT_RESTART_SVC    1   /* restart our own service (requires priv) */
#define ACT_EXIT           2   /* exit with a failure error code */
#define ACT_NOTHING        3   /* do nothing */

/* LOG() if SMFWATCHDOG_DEBUG is set */
#define DEBUG(...) \
	do { \
		if (options.debug) LOG(__VA_ARGS__); \
	} while (0)
/* Shortcut to die */
#define DIE(code, ...) \
	do { \
		LOG(__VA_ARGS__); \
		exit(code); \
	} while (0)

/* Environmental Options */
struct {
	int debug;       /* SMFWATCHDOG_DEBUG
	                    whether debug output is enabled */
	int sleep;       /* SMFWATCHDOG_SLEEP
	                    time to sleep between looping all the checks */
	int action;      /* SMFWATCHDOG_ACTION
			    the action to take when there is a failure */
	int no_contract; /* SMFWATCHDOG_IGNORE_CONTRACT
			    if set, the contract will not be looked up */
	int uid;         /* SMFWATCHDOG_UID
			    uid used to drop privileges before looping */
	int gid;         /* SMFWATCHDOG_GID
			    gid used to drop privileges before looping */
	char *command;   /* SMFWATCHDOG_COMMAND
			    a command to run before any action is taken */
	char *mail_to;   /* SMFWATCHDOG_EMAIL
			    an email address to alert when a health check
			    fails */
	char *mail_from; /* SMFWATCHDOG_EMAIL_FROM
			    who the email originates from, defaults to
			    noreply@<hostname> */
	char *mail_prog; /* SMFWATCHDOG_MAIL_PROG
			    a program that accepts mail data over stdin
			    to send an email, defaults to "mailx -t" */
} options;

/* Function Prototypes */
void LOG(const char *fmt, ...);
void loadenvironment();
int execute(const char *cmd, char **output);
int process();
int strreplace(char *s, char f, char r);
int sendmail(const char *check, const char *body);
int contract_id_by_pid(pid_t pid);
int num_pids_in_contract(int contractid);

int main(int argc, char **argv) {
	setbuf(stdout, NULL);

	/* print the version string if run with any arguments */
	if (argc > 1) {
		printf("%s@%s (compiled %s %s)\n",
		    PROGNAME, VERSION, __DATE__, __TIME__);
		return 0;
	}

	/* get the SMF FMRI */
	char *FMRI = getenv("SMF_FMRI");
	if (FMRI == NULL || FMRI[0] == '\0') {
		printf("%s is not meant to be run interatively\n",
		    PROGNAME);
		return 1;
	}

	/* check if we are disabled */
	char *disabled = getenv("SMFWATCHDOG_DISABLED");
	if (disabled != NULL && disabled[0] != '\0')
		DIE(0, "SMFWATCHDOG_DISABLED is set\n");

	LOG("SMF_FMRI=%s\n", FMRI);

	/* create the SMF watchdog dir if it doesn't exist */
	mkdir(WATCHDOG_DIR, 0755);

	int FMRI_LEN = strlen(FMRI);
	char _name[FMRI_LEN + 1];
	char *name = _name;

	/* copy the FMRI and remove the svc:/ prefix */
	strcpy(name, FMRI);
	if (strncmp(name, "svc:/", 5) == 0)
		name += 5;

	/* replace / with - */
	strreplace(name, '/', '-');

	/* plugins directory */
	/* <base> + '/' + <name> + '\0' */
	char dir[strlen(WATCHDOG_DIR) + 1 + strlen(name) + 1];
	sprintf(dir, "%s/%s", WATCHDOG_DIR, name);

	LOG("plugins directory: %s\n", dir);
	mkdir(dir, 0755);

	/* test dir existence by moving into it */
	if (chdir(dir) != 0)
		DIE(2, "chdir(%s): %s\n", dir, strerror(errno));

	/* load env options */
	loadenvironment();

	/* create the restart cmd */
	char restartcmd[15 + FMRI_LEN + 1];
	sprintf(restartcmd, "svcadm restart %s", FMRI);

	/* drop privileges */
	if (options.gid && setgid(options.gid) < 0)
		DIE(3, "setgid to %d failed: %s\n",
		    options.gid, strerror(errno));

	if (options.uid && setuid(options.uid) < 0)
		DIE(4, "setuid to %d failed: %s\n",
		    options.uid, strerror(errno));

	/* get the contract id of this process */
	int contractid = contract_id_by_pid(getpid());
	if (contractid < 0) {
		LOG("failed to get contract id: %s\n", strerror(errno));
		if (!options.no_contract)
			exit(5);
	}
	LOG("contract id: %d\n", contractid);

	/* start the loop */
	int ret = 0;
	int loop = 1;
	int numpids = 0;
	while (loop) {
		DEBUG("sleeping for %d seconds\n", options.sleep);
		sleep(options.sleep);

		DEBUG("waking up from sleep\n");

		/* check to make sure we aren't the only process in the contract */
		if (!options.no_contract) {
			numpids = num_pids_in_contract(contractid);
			DEBUG("pids found in this contract: %d\n", numpids);
			if (numpids == 1)
				DIE(6, "last process running in this contract, exiting\n");
		}

		/* check if the disable file exists */
		struct stat statbuf;
		if (stat(DISABLE_FILE, &statbuf) == 0) {
			LOG("file \"%s\" found, going back to sleep\n", DISABLE_FILE);
			continue;
		} else if (errno != ENOENT) {
			DIE(7, "error stat(2) \"%s\": %s\n", DISABLE_FILE, strerror(errno));
		}

		/* loop the directories */
		ret = process();
		if (ret == 0)
			continue;

		/* If we are here, something failed */
		if (options.command != NULL) {
			LOG("executing: %s\n", options.command);
			system(options.command);
		}
		switch (options.action) {
			default:
				LOG("unknown action\n");
			case ACT_RAISE_SIGABRT:
				LOG("raising SIGABRT\n");
				raise(SIGABRT);
				break;
			case ACT_RESTART_SVC:
				/* "svcadm restart " + FMRI + "\0" */
				LOG("executing: %s\n", restartcmd);
				system(restartcmd);
				break;
			case ACT_EXIT:
				loop = 0;
				break;
			case ACT_NOTHING:
				break;
		}
	}

	/* we have broken from the loop, exit */
	LOG("exiting\n");
	return ret;
}

/**
 * load environmental variables into the options struct
 */
void loadenvironment() {
	char *p = NULL;

	p = getenv("SMFWATCHDOG_DEBUG");
	options.debug = (p == NULL) ? 0 : atoi(p);
	DEBUG("option: {SMFWATCHDOG_DEBUG} debug output %s\n",
	    options.debug ? "enabled" : "disabled");

	p = getenv("SMFWATCHDOG_SLEEP");
	if (p != NULL) options.sleep = atoi(p);
	if (!options.sleep) options.sleep = 60;
	DEBUG("option: {SMFWATCHDOG_SLEEP} sleep %d seconds\n",
	    options.sleep);

	p = getenv("SMFWATCHDOG_ACTION");
	if (p != NULL) options.action = atoi(p);
	DEBUG("option: {SMFWATCHDOG_ACTION} on failure action %d\n",
	    options.action);

	p = getenv("SMFWATCHDOG_IGNORE_CONTRACT");
	if (p != NULL) options.no_contract = atoi(p);
	DEBUG("option: {SMFWATCHDOG_IGNORE_CONTRACT} ignore contract %d\n",
	    options.no_contract);

	p = getenv("SMFWATCHDOG_UID");
	if (p != NULL) options.uid = atoi(p);
	DEBUG("option: {SMFWATCHDOG_UID} uid for dropped privileges %d\n",
	    options.uid);

	p = getenv("SMFWATCHDOG_GID");
	if (p != NULL) options.gid = atoi(p);
	DEBUG("option: {SMFWATCHDOG_GID} gid for dropped privileges %d\n",
	    options.gid);

	options.command = getenv("SMFWATCHDOG_COMMAND");
	DEBUG("option: {SMFWATCHDOG_COMMAND} command to run \"%s\"\n",
	    options.command);

	options.mail_to = getenv("SMFWATCHDOG_EMAIL");
	DEBUG("option: {SMFWATCHDOG_EMAIL} email to \"%s\"\n",
	    options.mail_to);

	options.mail_from = getenv("SMFWATCHDOG_EMAIL_FROM");
	DEBUG("option: {SMFWATCHDOG_EMAIL_FROM} email from \"%s\"\n",
	    options.mail_from);

	p = getenv("SMFWATCHDOG_MAIL_PROG");
	options.mail_prog = (p != NULL && p[0] != '\0')
	    ? p : DEFAULT_MAIL_PROG;
	DEBUG("option: {SMFWATCHDOG_MAIL_PROG} mail prog \"%s\"\n",
	    options.mail_prog);
}

/**
 * loop over all files in the current directory and execute them
 */
int process() {
	struct dirent *dp; /* dir pointer */
	DIR *d = opendir(".");

	if (d == NULL) {
		LOG("opendir(): %s\n", strerror(errno));
		return 1;
	}

	/* loop over the dirent */
	int i = 0;
	int ret = 0;
	while ((dp = readdir(d)) != NULL) {
		/* skip hidden files */
		if (dp->d_name[0] == '.') continue;

		DEBUG("executing %s\n", dp->d_name);

		/* run the plugin */
		char *output = NULL;
		ret = execute(dp->d_name, &output);
		if (options.debug && output != NULL)
			printf("%s", output);

		/* something went wrong, ignore it */
		if (ret == -1) {
			LOG("error executing %s, moving on\n", dp->d_name);
			if (output != NULL) free(output);
			continue;
		}
		ret = WEXITSTATUS(ret);

		switch (ret) {
			case 0: /* success */
				DEBUG("%s executed succesfully\n",
				    dp->d_name);
				break;
			default: /* health check failed */
				LOG("%s failed (exit code %d)\n",
				    dp->d_name, ret);

				if (options.mail_to != NULL) {
					LOG("sending email to %s\n",
					    options.mail_to);
					sendmail(dp->d_name, output);
				}
				if (output != NULL) free(output);
				closedir(d);
				return ret;
		}
		if (output != NULL) free(output);
		i++;
	}
	closedir(d);

	DEBUG("%d scripts executed\n", i);

	return 0;
}

/**
 * execute the given script in the current directory
 */
int execute(const char *cmd, char **output) {
	/* "exec ./" + dp->d_name + " 2>&1\0" */
	char prog[7 + strlen(cmd) + 6];
	sprintf(prog, "exec ./%s 2>&1", cmd);

	FILE *fp = popen(prog, "r");
	if (fp == NULL) {
		LOG("popen: %s\n", strerror(errno));
		return -1;
	}

	char buf[BUFSIZ]; /* output buffer */
	int bytes = 0; /* bytes read */
	int outputsize = 1; /* output buffer size (+1 for nul byte) */
	char *out = malloc(sizeof(*out) * outputsize); /* all cmd output */
	if (out == NULL) {
		LOG("malloc: %s\n", strerror(errno));
		return -1;
	}
	out[0] = '\0';

	/* save all of the cmd output */
	while ((bytes = fread(buf, sizeof(*buf), sizeof(buf) / sizeof(*buf), fp)) > 0) {
		outputsize += bytes;
		char *tmp = realloc(out, outputsize);
		if (tmp == NULL) {
			LOG("realloc: %s\n", strerror(errno));
			free(out);
			out = NULL;
			return -1;
		}
		out = tmp;
		strncat(out, buf, bytes);
		out[outputsize - 1] = '\0';
	}
	if (!feof(fp)) {
		LOG("couldn't read until EOF: %s\n", strerror(errno));
		return -1;
	} else if (ferror(fp)) {
		LOG("ferror: %s\n", strerror(errno));
		return -1;
	}

	*output = out;
	return pclose(fp);
}

/**
 * print a timestamped log line
 *
 * usage is the same as printf()
 *
 * returns nothing
 */
void LOG(const char *fmt, ...) {
	char date[20];
	struct timeval tv;
	va_list args;

	/* print the progname, version, and timestamp */
	gettimeofday(&tv, NULL);
	strftime(date, sizeof(date) / sizeof(date[0]), DATEFMT, gmtime(&tv.tv_sec));
	printf("[%s@%s] [%s.%03ldZ] ", PROGNAME, VERSION, date, tv.tv_usec / 1000);

	/* printf like normal */
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

/**
 * replace characters in a string
 *
 * replace all occurences of char f with char r in char * s
 *
 * returns     number of replacements done
 */
int strreplace(char *s, char f, char r) {
	int i = 0;
	char *p = s;
	while (*p != '\0') {
		if (*p == f) {
			*p = r;
			i++;
		}
		p++;
	}
	return i;
}

/**
 * send an email message
 *
 * const char *check   the name of the check that failed
 * const char *body    the email body, rendered as HTML
 *
 * return         int pclose()
 */
int sendmail(const char *check, const char *body) {
	char *FMRI = getenv("SMF_FMRI");
	char *base = basename(FMRI);

	/* open the mail program for writing binary data */
	FILE *email = popen(options.mail_prog, "wb");
	if (email == NULL) {
		LOG("failed to email \"%s\" using program \"%s\": %s\n",
		    options.mail_to, options.mail_prog, strerror(errno));
		return -1;
	}

	/* get the hostname */
	char hostname[MAXHOSTNAMELEN + 1];
	hostname[MAXHOSTNAMELEN] = '\0';
	if (gethostname(hostname, MAXHOSTNAMELEN) == -1) {
		LOG("gethostname(): %s\n", strerror(errno));
		strcpy(hostname, "unknown");
	}

	/* noreply@ + '\0' + <hostname> + '\0' */
	char mail[8 + MAXHOSTNAMELEN + 1];
	mail[8 + MAXHOSTNAMELEN] = '\0';
	if (options.mail_from == NULL) {
		/* create a mail_from address */
		sprintf(mail, "noreply@%s", hostname);
	}

	char action[256];
	/* find out what action will be taken */
	switch (options.action) {
		default:
		case ACT_RAISE_SIGABRT:
			snprintf(action, sizeof(action) / sizeof(action[0]),
			    "raising SIGABRT");
			break;
		case ACT_RESTART_SVC:
			snprintf(action, sizeof(action) / sizeof(action[0]),
			    "restarting service with <code>svcadm restart %s</code>",
			    FMRI);
			break;
		case ACT_EXIT:
			snprintf(action, sizeof(action) / sizeof(action[0]),
			    "process exiting");
			break;
		case ACT_NOTHING:
			snprintf(action, sizeof(action) / sizeof(action[0]),
			    "no action taken");
			break;
	}

	/* get the timestamp */
	char date[20];
	struct timeval tv;
	gettimeofday(&tv, NULL);
	strftime(date, sizeof(date) / sizeof(date[0]), DATEFMT, gmtime(&tv.tv_sec));

	fprintf(email, "To: %s\n", options.mail_to);
	fprintf(email, "From: %s\n",
	    options.mail_from == NULL ?  mail : options.mail_from);
	fprintf(email, "Subject: [%s] %s failed health check on %s\n",
	    PROGNAME, base, hostname);
	fprintf(email, "Content-Type: text/html\n");
	fprintf(email, "\n");
	fprintf(email, "<code>%s</code> failed health check on <code>%s</code><br><br>\n\n",
	    base, hostname);
	fprintf(email, "<b>FMRI:</b> <code>%s</code><br>\n", FMRI);
	fprintf(email, "<b>Action:</b> <code>%s</code><br>\n", action);
	fprintf(email, "<b>Hostname:</b> <code>%s</code><br>\n", hostname);
	fprintf(email, "<b>Time (UTC):</b> <code>%s</code><br>\n", date);
	fprintf(email, "<b>Command:</b> <code>%s</code><br>\n", check);
	fprintf(email, "<b>Program:</b> <code>%s@%s (compiled %s %s)</code><br><br>\n\n",
	    PROGNAME, VERSION, __DATE__, __TIME__);

	fprintf(email, "<b>Command Output</b>\n");
	fprintf(email, "<pre>%s</pre>\n", body);

	return pclose(email);
}

/**
 * get the contract id of a given pid
 *
 * @param pid {pid_t} pid to check
 *
 * @returns the contract id, or a negative number
 * with errno set on failure
 */
int contract_id_by_pid(pid_t pid) {
	if (!pid) pid = getpid();

	struct psinfo info; /* psinfo struct for the process */
	char psinfo_file[256]; /* /proc/<pid>/psinfo */
	int fd; /* reusable fd */

	snprintf(psinfo_file,
		sizeof(psinfo_file) / sizeof(*psinfo_file),
		"/proc/%d/psinfo",
		(int)pid);

	/* read psinfo and load the struct*/
	fd = open(psinfo_file, O_RDONLY);
	if (fd < 0)
		return -1;
	if (read(fd, &info, sizeof(info)) != sizeof(info)) {
		close(fd);
		return -2;
	}
	close(fd);

	/* the processes contract id */
	return (int)info.pr_contract;
}

/**
 * Checks how many pid's exist in a given contract
 *
 * @param contractid {int} the contract ID to check
 *
 * @returns the number of pids in a contract, or a negative number
 * with errno set on failure
 */
int num_pids_in_contract(int contractid) {
	char contract_file[256]; /* /system/contract/all/<ctid>/status */
	int fd; /* reusable fd */

	/* a contract stat handle */
	ct_stathdl_t stathdl;

	snprintf(contract_file,
		sizeof(contract_file) / sizeof(*contract_file),
		"/system/contract/all/%d/status",
		contractid);
	fd = open(contract_file, O_RDONLY | O_LARGEFILE);
	if (fd < 0)
		return -3;
	if (ct_status_read(fd, CTD_ALL, &stathdl) != 0) {
		close(fd);
		return -4;
	}
	close(fd);

	pid_t *members;
	uint_t numpids;
	int err = 0;
	if ((err = ct_pr_status_get_members(stathdl, &members, &numpids)))
		return -5;
	ct_status_free(stathdl);

	return numpids;
}
