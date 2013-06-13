/**
 * SMF Watch Dog
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
#include <libgen.h>
#include <netdb.h>
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
#define VERSION            "0.0.3"

#define DATEFMT            "%Y-%m-%dT%H:%M:%S"
#define DEFAULT_MAIL_PROG  "mailx -t"
#define MAX_FMRI_LEN       scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH)
#define WATCHDOG_DIR       "/opt/local/share/smf/smfwatchdog"

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

/* Environmental Options */
struct {
	int sleep;       /* SMFWATCHDOG_SLEEP
	                    time to sleep between looping all the checks */
	int debug;       /* SMFWATCHDOG_DEBUG
	                    whether debug output is enabled */
	int action;      /* SMFWATCHDOG_ACTION
			    the action to take when there is a failure */
	int uid;         /* SMFWATCHDOG_UID
			    uid used to drop privileges before looping */
	int gid;         /* SMFWATCHDOG_GID
			    gid used to drop privileges before looping */
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
int done(int code);
int execute(const char *cmd, char **output);
int process();
int strreplace(char *s, char f, char r);
int sendmail(const char *check, const char *body);

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
		printf("%s is not meant to be run interatively\n\n",
		    PROGNAME);
		return 1;
	}

	/* check if we are disabled */
	char *disabled = getenv("SMFWATCHDOG_DISABLED");
	if (disabled != NULL && disabled[0] != '\0') {
		LOG("SMFWATCHDOG_DISABLED is set\n");
		return done(0);
	}

	LOG("SMF_FMRI=%s\n", FMRI);

	/* create the SMF watchdog dir if it doesn't exist */
	mkdir(WATCHDOG_DIR, 0755);

	int FMRI_LEN = strlen(FMRI);
	char _name[FMRI_LEN + 1];
	char *name = _name;

	/* copy the FMRI and remove the svc:/ prefix */
	strcpy(name, FMRI);
	if (strncmp(name, "svc:/", 5) == 0) {
		name += 5;
	}
	/* replace / with - */
	strreplace(name, '/', '-');

	/* plugins directory */
	/* <base> + '/' + <name> + '\0' */
	char dir[strlen(WATCHDOG_DIR) + 1 + strlen(name) + 1];
	sprintf(dir, "%s/%s", WATCHDOG_DIR, name);

	LOG("plugins directory: %s\n", dir);
	mkdir(dir, 0755);

	/* test dir existence by moving into it */
	if (chdir(dir) != 0) {
		LOG("chdir(%s): %s\n", dir, strerror(errno));
		return done(2);
	}

	/* load env options */
	loadenvironment();

	/* create the restart cmd */
	char restartcmd[15 + FMRI_LEN + 1];
	sprintf(restartcmd, "svcadm restart %s", FMRI);

	/* drop privileges */
	if (options.gid && setgid(options.gid) < 0) {
		LOG("setgid to %d failed: %s\n",
		    options.gid, strerror(errno));
		return done(3);
	}
	if (options.uid && setuid(options.uid) < 0) {
		LOG("setuid to %d failed: %s\n",
		    options.uid, strerror(errno));
		return done(4);
	}

	/* start the loop */
	int ret = 0;
	int loop = 1;
	while (loop) {
		DEBUG("sleeping for %d seconds\n", options.sleep);
		sleep(options.sleep);

		DEBUG("tick\n");

		ret = process();
		if (ret == 0) continue;

		/* If we are here, something failed */
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
	return done(ret);
}

/**
 * print "exiting." and return the code you give it
 */
int done(int code) {
	LOG("exiting.\n");
	return code;
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

	p = getenv("SMFWATCHDOG_UID");
	if (p != NULL) options.uid = atoi(p);
	DEBUG("option: {SMFWATCHDOG_UID} uid for dropped privileges %d\n",
	    options.uid);

	p = getenv("SMFWATCHDOG_GID");
	if (p != NULL) options.gid = atoi(p);
	DEBUG("option: {SMFWATCHDOG_GID} gid for dropped privileges %d\n",
	    options.gid);

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
			case 126: /* permission denied, consider this a success */
				break;
			default: /* health check failed */
				LOG("%s failed (exit code %d)\n",
				    dp->d_name, ret);

				if (options.mail_to != NULL) {
					LOG("sending email to %s\n",
					    options.mail_to);
					sendmail(dp->d_name, output);
				}
				/* TODO restart service */
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
	char *out = malloc(sizeof(char) * outputsize); /* all cmd output */
	if (out == NULL) {
		LOG("malloc: %s\n", strerror(errno));
		return -1;
	}
	*output = out;
	out[0] = '\0';

	/* save all of the cmd output */
	while ((bytes = fread(buf, sizeof(char), BUFSIZ, fp)) > 0) {
		outputsize += bytes;
		realloc(out, outputsize);
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
