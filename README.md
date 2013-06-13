smfwatchdog(1) - SMF Health Checking Daemon
===========================================

A health checking daemon to be used with SMF services.

- [Synopsis](#synopsis)
- [Installation](#installation)
- [Example](#example)
- [Options](#options)
- [Usage](#usage)
- [Notes](#notes)
- [License (MIT)](#license)

<a name="synopsis" />

Synopsis
--------

SMF manages services on [Illumos](http://illumos.org) based operating
systems. It ensures that services, which may consist of 0 to many
processes, are up and running, and handles any failures they may
encounter.

The one thing that SMF is lacking however, is the ability to do service level
health checks.  SMF bases your services health on process health, checking
things such as processes dying, or exiting abnormally, etc. However, it may be
the case that a process is up, has a pid and `/proc` structure, but has
locked up, or is not behaving how it should.  `smfwatchdog` is meant
to do health checks (in the form of scripts) on your services, and proactively
kill or restart the service under failure conditions.

The health check daemon is meant to run as a separate instance for each
service you would like to monitor.  For example, an instance of `smfwatchdog`
would be running under the `nginx` service, while a different instance of
`smfwatchdog` would be running under the `apache` service.  The watchdog
instance would only be responsible for checking the service under which it
is running.

You can learn more about SMF by reading [smf(5)](http://illumos.org/man/5/smf).

<a name="installation" />

Installation
------------

Clone this repo, compile the source code, and install

    git clone git://github.com/bahamas10/smfwatchdog.git
    cd smfwatchdog
    make
    [sudo] make install

This will install the `smfwatchdog` binary and the `smfwatchdog.1` manpage.

<a name="example" />

Example
-------

A service that is a single [Node.JS](http://nodejs.org) process acting
as a webserver with the given SMF manifest is running on a machine.

`daves-service.xml`

``` xml
<?xml version="1.0"?>
<!DOCTYPE service_bundle SYSTEM "/usr/share/lib/xml/dtd/service_bundle.dtd.1">
<!--
Manifest automatically generated by smfgen.
-->
<service_bundle type="manifest" name="application-daves-service" >
	<service name="application/daves-service" type="service" version="1" >
		<create_default_instance enabled="true" />
		<dependency name="dep1" grouping="require_all" restart_on="error" type="service" >
			<service_fmri value="svc:/milestone/multi-user:default" />
		</dependency>
		<method_context>
			<method_environment>
				<envvar name='PATH' value='/opt/local/bin:/opt/local/sbin:/bin:/usr/bin:/usr/sbin'/>
			</method_environment>
		</method_context>
		<exec_method type="method" name="start" exec="node /home/dave/daves-service/server.js &amp;" timeout_seconds="10" />
		<exec_method type="method" name="stop" exec=":kill" timeout_seconds="30" />
		<template >
			<common_name >
				<loctext xml:lang="C" >Dave's Service</loctext>
			</common_name>
		</template>
	</service>
</service_bundle>
```

This is a fairly standard manifest, generated with [smfgen](https://github.com/davepacheco/smfgen).
The server code written in Node looks like this:

`server.js`

``` js
var http = require('http');

var host = 'localhost';
var port = 8000;

http.createServer(onrequest).listen(port, host, listening);

function listening() {
  console.log('server started: http://%s:%d/', host, port);
}

var i = 0;
function onrequest(req, res) {
  console.log('new request');
  if (++i < 5) res.end();
}
```

This webserver has a bug however, on the 5th request and thereafter, all
requests will stall, and the server will lock up.  SMF by itself won't be able
to detect this problem, as the process is up and has a valid `/proc` structure.
This is where `smfwatchdog` can be used to detect and mitigate this issue.

Modify the `exec` line in the manifest to look like this:

``` diff
< <exec_method type="method" name="start" exec="node /home/dave/daves-service/server.js &amp;" timeout_seconds="10" />
---
> <exec_method type="method" name="start" exec="smfwatchdog &amp; node /home/dave/daves-service/server.js &amp;" timeout_seconds="10" />
```

This instructs the service to start an instance of `smfwatchdog` with the node
process.

Now, reimport the manifest, and restart the service.  The watchdog will be
running as part of the service, which you can verify with `svcs(1M)`

    $ svcs -p daves-service
    STATE          STIME    FMRI
    online         10:51:43 svc:/application/daves-service:default
                   10:51:43    32188 smfwatchdog
                   10:51:43    32189 node

The watchdog is running, however it has nothing to do, as it has no checks.
We now have to write a health check for the service, to ensure that the webserver is
reachable without timing out.

The daemon has created a unique directory for scripts to be placed in
`/opt/local/share/smf/smfwatchdog/application-daves-service:default`, you
can find that information by looking at the logs of the service. `smfwatchdog`
will log to the default log location as found in `svcs -L <fmri>`.

    $ grep 'plugins directory:' "$(svcs -L daves-service)" | tail -1
    [smfwatchdog@0.0.0] [2013-06-12T17:51:43.081Z] plugins directory: /opt/local/share/smf/smfwatchdog/application-daves-service:default

Any scripts in this directory will be executed every 60 seconds, and if any of
them return with a non-zero exit code, the service will be restarted, and
optionally an email will be sent out alerting of the failed health check and
the action taken (including the output generated by the script that failed).

Since checks are just scripts, we can use any language that we'd like, so let's
keep it simple and use bash.  We'll create a basic health check to ensure
the service is responsive over HTTP.

    vim /opt/local/share/smf/smfwatchdog/application-daves-service\:default/check.sh

``` bash
#!/usr/bin/env bash
CURLE_OPERATION_TIMEDOUT=28
timeout=20 # seconds

curl -sSk -m "$timeout" "http://localhost:8000"
if (( $? == $CURLE_OPERATION_TIMEDOUT )); then
        exit 1
else
        exit 0
fi
```

And ensure the file is executable with:

    chmod +x /opt/local/share/smf/smfwatchdog/application-daves-service\:default/check.sh

The watchdog daemon will scan the directory every 60 seconds, executing every
script it finds, in `readdir(3C)` order, and restart the service if any of the
scripts exit with a non-zero exit code.

If curl returns with code 28, that means it has timedout.  In the above script,
curl is set to timeout if 20 seconds have elapsed with no response from the
server, and then the script itself will return with exit code 1

When `smfwatchdog` sees that this health check has failed, it will send itself a
`SIGABRT` signal, which will trigger a core dump, and cause the entire service
to be restarted by SMF (under most circumstances), see [options](#options) below
for different actions to take upon failure.

We can see this happen in the logfile

    tail "$(svcs -L daves-service)"
    [ Jun 12 17:51:43 Executing start method ("smfwatchdog & node /home/dave/daves-service/server.js &"). ]
    [smfwatchdog@0.0.0] [2013-06-12T17:51:43.080Z] SMF_FMRI=svc:/application/daves-service:default
    [smfwatchdog@0.0.0] [2013-06-12T17:51:43.081Z] plugins directory: /opt/local/share/smf/smfwatchdog/application-daves-service:default
    [ Jun 12 17:51:43 Method "start" exited with status 0. ]
    server started: http://localhost:8000/
    new request
    new request
    new request
    new request
    new request
    [smfwatchdog@0.0.0] [2013-06-12T17:57:03.612Z] check.sh failed (exit code 1)
    [smfwatchdog@0.0.0] [2013-06-12T17:57:03.612Z] raising SIGABRT
    [ Jun 12 17:57:03 Stopping because process dumped core. ]
    [ Jun 12 17:57:03 Executing stop method (:kill). ]

Note that `new request` is printed 5 times, as on the 5th time the
server will become unresponsive, and the health check will fail.

Optionally, we can set an email address to alert any failures to by setting the
environmental variable `SMFWATCHDOG_EMAIL` in the manifest.

``` xml
<envvar name='SMFWATCHDOG_EMAIL' value='dave@daveeddy.com'/>
```

Now, when a health check fails it'll fire an informative email containing the
output from the health check script that failed, as well as some system information
that looks like:

    To: dave@daveeddy.com
    From: noreply@dave-01.local
    Subject: [smfwatchdog] daves-service:default failed health check on dave-01.local

    daves-service:default failed health check on dave-01.local

    FMRI: svc:/application/daves-service:default
    Action: raising SIGABRT
    Hostname: dave-01.local
    Time (UTC): 2013-06-12T04:38:13
    Command: check.sh
    Program: smfwatchdog@0.0.0 (compiled Jun 11 2013 21:32:47)

    Command Output
    curl: (28) Operation timed out after 20000 milliseconds with 0 bytes received

<a name="options" />

Options
-------

The following options can be passed in as environmental variables, most likely being
added to the SMF manifest.

- `SMFWATCHDOG_DEBUG`: (int) If this is non-zero, `smfwatchdog` will produce
    debug output to the service's log file (`svcs -L <fmri>`)
- `SMFWATCHDOG_SLEEP`: (int) The time, in seconds, to sleep between running
    health check scripts, defaults to 60
- `SMFWATCHDOG_ACTION`: (int) The action (see below) to take during a health
    check failure, defaults to 0 (raise `SIGABRT`)
- `SMFWATCHDOG_DISABLED`: If set, `smfwatchdog` will exit cleanly upon starting
- `SMFWATCHDOG_COMMAND`: A command to execute (parsed by a shell) after a failure
    case but before any action is taken, defaults to nothing
- `SMFWATCHDOG_UID`: (int) If this is non-zero, `setuid(2)` will be called with
    this variable before any plugins are run to drop privileges
- `SMFWATCHDOG_GID`: (int) If this is non-zero, `setgid(2)` will be called with
    this variable before any plugins are run to drop privileges
- `SMFWATCHDOG_EMAIL`: If set, this variable will be used as an email address
    to send alerts to when a service has failed a health check
- `SMFWATCHDOG_EMAIL_FROM`: This is the address from which the above email
    will be sent, defaults to `noreply@<hostname>`
- `SMFWATCHDOG_MAIL_PROG`: The mail program to use to send email on the system,
    it must accept binary email data over stdin, defaults to `mailx -t`
- `SMF_FMRI`: This shouldn't be manually set, it will be set automatically by
    SMF, and is used to tell the watchdog which service to monitor

### Actions

You can set the action to be taken during a health check failure by setting
`SMFWATCHDOG_ACTION` to a valid integer listed below.

``` c
#define ACT_RAISE_SIGABRT  0   /* kill ourself with SIGABRT */
#define ACT_RESTART_SVC    1   /* restart our own service (requires priv) */
#define ACT_EXIT           2   /* exit with a failure error code */
#define ACT_NOTHING        3   /* do nothing */
```

The default action is to raise a `SIGABRT` signal to trigger a core dump.
This will cause SMF to restart the entire service, without `smfwatchdog`
requiring escalated privileges.

Setting this variable to 1 will cause the command `svcadm restart <fmri>` to
be triggered after a failed health check.  Note that this will only work
if the effective UID of the `smfwatchdog` daemon has privileges to carry
out that command.

Setting this variable to 2 will cause `smfwatchdog` to exit with a failure
return code after a failed check.

Setting this variable to 3 will cause `smfwatchdog` to not take any action
except to log and optionally send an email in the event of a failed
health check, making it a good option for testing.

<a name="usage" />

Usage
-----

If you run `smfwatchdog` interactively (without `SMF_FMRI` set) you are greeted
with

    $ smfwatchdog
    smfwatchdog is not meant to be run interatively

as the daemon would have nothing to check.

If `smfwatchdog` is run with any number of arguments, the version string is printed
and the process exits cleanly.

    $ smfwatchdog -v
    smfwatchdog@0.0.2 (compiled Jun 13 2013 09:09:46)

The proper way to run `smfwatchdog` is to add it to the exec line of an SMF manifest,
and let SMF start and stop the daemon.

<a name="notes" />

Notes
-----

The watchdog isn't a solution to a problem; it doesn't fix bugs. The health
checks are meant to minimize the impact of bugs that exist that currently have
not been fixed in a service.

- This software hasn't been fully tested, and may contain bugs
- Scripts are executed with `popen(3C)`, and as such, have their names parsed by the shell.
Ensure that you don't name your scripts `$(rm -rf /)` or something
- Don't set `SMFWATCHDOG_UID` or `SMFWATCHDOG_GID` if the manifest itself
takes care of dropping privileges

<a name="license" />

License
-------

MIT License
