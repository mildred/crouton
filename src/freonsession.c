/*-
 * Copyright (c) 2002 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by ThinkSec AS and
 * Network Associates Laboratories, the Security Research Division of
 * Network Associates, Inc.  under DARPA/SPAWAR contract N66001-01-C-8035
 * ("CBOSS"), as part of the DARPA CHATS research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: head/fr_FR.ISO8859-1/articles/pam/converse.c 38826 2012-05-17 19:12:14Z hrs $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/pam_appl.h>

int
converse(int n, const struct pam_message **msg,
	struct pam_response **resp, void *data)
{
	struct pam_response *aresp;
	char buf[PAM_MAX_RESP_SIZE];
	int i;

	data = data;
	if (n <= 0 || n > PAM_MAX_NUM_MSG)
		return (PAM_CONV_ERR);
	if ((aresp = calloc(n, sizeof *aresp)) == NULL)
		return (PAM_BUF_ERR);
	for (i = 0; i < n; ++i) {
		aresp[i].resp_retcode = 0;
		aresp[i].resp = NULL;
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
			aresp[i].resp = strdup(getpass(msg[i]->msg));
			if (aresp[i].resp == NULL)
				goto fail;
			break;
		case PAM_PROMPT_ECHO_ON:
			fputs(msg[i]->msg, stderr);
			if (fgets(buf, sizeof buf, stdin) == NULL)
				goto fail;
			aresp[i].resp = strdup(buf);
			if (aresp[i].resp == NULL)
				goto fail;
			break;
		case PAM_ERROR_MSG:
			fputs(msg[i]->msg, stderr);
			if (strlen(msg[i]->msg) > 0 &&
			    msg[i]->msg[strlen(msg[i]->msg) - 1] != '\n')
				fputc('\n', stderr);
			break;
		case PAM_TEXT_INFO:
			fputs(msg[i]->msg, stdout);
			if (strlen(msg[i]->msg) > 0 &&
			    msg[i]->msg[strlen(msg[i]->msg) - 1] != '\n')
				fputc('\n', stdout);
			break;
		default:
			goto fail;
		}
	}
	*resp = aresp;
	return (PAM_SUCCESS);
 fail:
        for (i = 0; i < n; ++i) {
                if (aresp[i].resp != NULL) {
                        memset(aresp[i].resp, 0, strlen(aresp[i].resp));
                        free(aresp[i].resp);
                }
        }
        memset(aresp, 0, n * sizeof *aresp);
	*resp = NULL;
	return (PAM_CONV_ERR);
}

/*-
 * Copyright (c) 2002,2003 Networks Associates Technology, Inc.
 * Copyright (c) 2016 Mildred Ki'Lya <mildred.fr>
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by ThinkSec AS and
 * Network Associates Laboratories, the Security Research Division of
 * Network Associates, Inc.  under DARPA/SPAWAR contract N66001-01-C-8035
 * ("CBOSS"), as part of the DARPA CHATS research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $P4: //depot/projects/openpam/bin/su/su.c#10 $
 * $FreeBSD: head/fr_FR.ISO8859-1/articles/pam/su.c 38826 2012-05-17 19:12:14Z hrs $
 */

#include <sys/param.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <err.h>
#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <security/pam_appl.h>

#ifndef DRM_IOCTL_SET_MASTER
#  define DRM_IOCTL_SET_MASTER _IO('d', 0x1e)
#endif

#ifndef DRM_IOCTL_DROP_MASTER
#  define DRM_IOCTL_DROP_MASTER _IO('d', 0x1f)
#endif

extern char **environ;

static pam_handle_t *pamh;
static struct pam_conv pamc;

int child();

int main(int argc, char *argv[]) {
	const char *user;
	char **pam_envlist, **pam_env;
	struct passwd *pwd;
	int pam_err;

	user = "root";

	/* initialize PAM */
	//pamc.conv = &openpam_ttyconv;
	pamc.conv = converse;
	pam_start("freon", user, &pamc, &pamh);

	printf("Set XDG seat\n");
	if ((pam_err = pam_putenv(pamh, "XDG_SEAT=seat0")) != PAM_SUCCESS)
		goto pamerr;

	/* authentication succeeded; open a session */
	printf("Open Session\n");
	if ((pam_err = pam_open_session(pamh, 0)) != PAM_SUCCESS)
		goto pamerr;

	/* get mapped user name; PAM may have changed it */
	printf("Get PAM User\n");
	pam_err = pam_get_item(pamh, PAM_USER, (const void **)&user);
	if (pam_err != PAM_SUCCESS || (pwd = getpwnam(user)) == NULL)
		goto pamerr;

	fprintf(stderr, "PAM user: %s\n", user);

	/* export PAM environment */
	printf("Get PAM environment\n");
	if ((pam_envlist = pam_getenvlist(pamh)) != NULL) {
		for (pam_env = pam_envlist; *pam_env != NULL; ++pam_env) {
			char varname[strlen(*pam_env)];
			for(int i = 0; (*pam_env)[i]; ++i) {
				varname[i] = (*pam_env)[i];
				if (varname[i] == '=') {
					varname[i] = 0;
					fprintf(stderr, "PAM %s=%s\n", varname, &(*pam_env)[i+1]);
					setenv(varname, &(*pam_env)[i+1], 1);
					break;
				}
			}
			//putenv(*pam_env);
			free(*pam_env);
		}
		free(pam_envlist);
	}

	/*
	int child_res = child();
	pam_err = pam_close_session(pamh, 0);
	pam_end(pamh, pam_err);
	exit(child_res);
	*/

	int status;
	pid_t pid;

	switch ((pid = fork())) {
	case -1:
		warn("fork()");
		goto err;
	case 0:
		printf("Started session %s\n", getenv("XDG_SESSION_ID"));
		exit(child());
	default:
		/* parent: wait for child to exit */
		waitpid(pid, &status, 0);

		/* close the session and release PAM resources */
		pam_err = pam_close_session(pamh, 0);
		pam_end(pamh, pam_err);

		printf("Session terminated with status %d\n", WEXITSTATUS(status));
		exit(WEXITSTATUS(status));
	}

pamerr:
	fprintf(stderr, "PAM Error: %s\n", pam_strerror(pamh, pam_err));
	goto err;
err:
	pam_end(pamh, pam_err);
	exit(1);
}

#include <systemd/sd-bus.h>

int on_pause(sd_bus_message *m, void *userdata, sd_bus_error *ret_error);
int on_resume(sd_bus_message *m, void *userdata, sd_bus_error *ret_error);

#define HOST_DBUS_DIRECT 0

#if !HOST_DBUS_DIRECT
#define FREON_DBUS_METHOD_CALL(function) \
    system("host-dbus dbus-send --system --dest=org.chromium.LibCrosService " \
           "--type=method_call --print-reply /org/chromium/LibCrosService " \
           "org.chromium.LibCrosServiceInterface." #function)
#endif

struct state {
	sd_bus *host_bus;
	const char *session_path;
	int devfd;
};

int child() {
	sd_bus_error error = SD_BUS_ERROR_NULL;
	sd_bus_message *m1 = NULL, *m2 = NULL;
	sd_bus *bus = NULL;
	int r, inactive;
	struct state state;

	const char *script_template =
		"mkdir -p /run/freonsession;"
		"cd /run/freonsession;"
		"echo \"$XDG_SEAT\" >seat;"
		"echo \"$XDG_SESSION_ID\" >session_id;"
		"echo %d >pid;";
	char script[strlen(script_template)+64];
	snprintf(script, strlen(script_template)+64, script_template, getpid());
	system(script);

#if HOST_DBUS_DIRECT
	printf("Connect to the host system bus...\n");
	const char *old_bus_addr = getenv("DBUS_SYSTEM_BUS_ADDRESS");
	int len = strlen(old_bus_addr)+1024;
	char old_bus_env[len];
	snprintf(old_bus_env, len, "DBUS_SYSTEM_BUS_ADDRESS=%s", old_bus_addr);
	putenv("DBUS_SYSTEM_BUS_ADDRESS=unix:path=/var/host/dbus/system_bus_socket");
	r = sd_bus_open_system(&state.host_bus);
	putenv(old_bus_env);
	if (r < 0) {
		fprintf(stderr, "Failed to connect to host system bus: %s\n", strerror(-r));
		goto finish;
	}
#endif

	printf("Connect to system bus...\n");
	/* Connect to the system bus */
	r = sd_bus_open_system(&bus);
	if (r < 0) {
		fprintf(stderr, "Failed to connect to system bus: %s\n", strerror(-r));
		goto finish;
	}

	/* Issue the method call and store the respons message in m */
	r = sd_bus_call_method(bus,
		// service
		"org.freedesktop.login1",
		// object path
		"/org/freedesktop/login1",
		// interface and method name
		"org.freedesktop.login1.Manager", "GetSessionByPID",
		// object to return error in, return message on success
		&error, &m1,
		// input signature and arguments
		"u",
		getpid());
	if (r < 0) {
		fprintf(stderr, "Failed to issue method call: %s\n", error.message);
		goto finish;
	}

	/* Parse the response message */
	r = sd_bus_message_read(m1, "o", &state.session_path);
	if (r < 0) {
		fprintf(stderr, "Failed to parse response message: %s\n", strerror(-r));
		goto finish;
	}

	printf("Session path is %s\n", state.session_path);

	printf("Take Control (assume freon is currently running)\n");
	r = sd_bus_call_method(bus,
		"org.freedesktop.login1",
		state.session_path,
		"org.freedesktop.login1.Session", "TakeControl",
		&error, &m2,
		"b", 1);
	if (r < 0) {
		fprintf(stderr, "Failed to issue method call: %s\n", error.message);
		goto finish;
	}

	printf("Activate session\n");
	r = sd_bus_call_method(bus,
		"org.freedesktop.login1",
		state.session_path,
		"org.freedesktop.login1.Session", "Activate",
		&error, &m2,
		"");
	if (r < 0) {
		fprintf(stderr, "Failed to issue method call: %s\n", error.message);
		goto finish;
	}

	printf("Make CrOS release the video driver\n");
#if HOST_DBUS_DIRECT
	r = sd_bus_call_method(state.host_bus,
		"org.chromium.LibCrosService",
		"/org/chromium/LibCrosService",
		"org.chromium.LibCrosServiceInterface", "ReleaseDisplayOwnership",
		&error, &m2,
		"");
	sd_bus_message_unref(m2);
	if (r < 0) {
		fprintf(stderr, "Failed to pause freon: %s, %s\n", strerror(-r), error.message);
		return r;
	}
#else
	r = -FREON_DBUS_METHOD_CALL(ReleaseDisplayOwnership);
	if (r < 0) {
		fprintf(stderr, "Error: %d\n", r);
		return r;
	}
#endif

	printf("Take Device %d,%d (should be /dev/dri/card0)\n", 0xe2, 0x00);
	r = sd_bus_call_method(bus,
		"org.freedesktop.login1",
		state.session_path,
		"org.freedesktop.login1.Session", "TakeDevice",
		&error, &m2,
		"uu", 0xe2, 0x00);
	if (r < 0) {
		fprintf(stderr, "Failed to issue method call: %s\n", error.message);
		goto finish;
	}
	r = sd_bus_message_read(m2, "hb", &state.devfd, &inactive);
	if (r < 0) {
		fprintf(stderr, "Failed to parse response message: %s\n", strerror(-r));
		goto finish;
	}
	printf("TakeDevice -> %d (inactive: %d)\n", state.devfd, inactive);

	r = ioctl(state.devfd, DRM_IOCTL_DROP_MASTER, 0);
	if (r < 0) {
		fprintf(stderr, "Failed to drop master: %s\n", strerror(-r));
	}

	printf("Make CrOS take the video driver\n");
#if HOST_DBUS_DIRECT
	r = sd_bus_call_method(state.host_bus,
		"org.chromium.LibCrosService",
		"/org/chromium/LibCrosService",
		"org.chromium.LibCrosServiceInterface", "TakeDisplayOwnership",
		&error, &m2,
		"");
	sd_bus_message_unref(m2);
	if (r < 0) {
		fprintf(stderr, "Failed to resume: %s, %s\n", strerror(-r), error.message);
		return r;
	}
#else
	r = -FREON_DBUS_METHOD_CALL(TakeDisplayOwnership);
	if (r < 0) {
		fprintf(stderr, "Error: %d\n", r);
		return r;
	}
#endif

	printf("Register PauseDevice and ResumeDevice events\n");
	{
		size_t len = strlen(state.session_path)+1024;
		char match_pause[len], match_resume[len];
		snprintf(match_pause, len,
			"type='signal',"
			"sender='org.freedesktop.login1',"
			"path='%s',"
			"interface='org.freedesktop.login1.Session',"
			"member='PauseDevice'", state.session_path);
		snprintf(match_resume, len,
			"type='signal',"
			"sender='org.freedesktop.login1',"
			"path='%s',"
			"interface='org.freedesktop.login1.Session',"
			"member='ResumeDevice'", state.session_path);

		r = sd_bus_add_match(bus, NULL, match_pause, on_pause, &state);
		if (r < 0) {
			fprintf(stderr, "Failed to listen to pause signal: %s (%s) for match %s\n", strerror(-r), error.message, match_pause);
			goto finish;
		}
		r = sd_bus_add_match(bus, NULL, match_resume, on_resume, &state);
		if (r < 0) {
			fprintf(stderr, "Failed to listen to resume signal: %s (%s) for match %s\n", strerror(-r), error.message, match_resume);
			goto finish;
		}
	}

	printf("Loop...\n");
        for (;;) {
                /* Process requests */
                r = sd_bus_process(bus, NULL);
                if (r < 0) {
                        fprintf(stderr, "Failed to process bus: %s\n", strerror(-r));
                        goto finish;
                }
                if (r > 0) /* we processed a request, try to process another one, right-away */
                        continue;

                /* Wait for the next request to process */
                r = sd_bus_wait(bus, (uint64_t) -1);
                if (r < 0) {
                        fprintf(stderr, "Failed to wait on bus: %s\n", strerror(-r));
                        goto finish;
                }
        }

finish:
	system("loginctl");
	sd_bus_message_unref(m1);
	sd_bus_message_unref(m2);
	sd_bus_error_free(&error);
	sd_bus_unref(bus);

	return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

int on_pause(sd_bus_message *m, void *userdata, sd_bus_error *ret_error){
	struct state *state = userdata;
	unsigned int major = 0, minor = 0;
	const char *type;
	int r = sd_bus_message_read(m, "uus", &major, &minor, &type);
	sd_bus_message *m2 = NULL;
	printf("\nPause %s fd:%d %d,%d\n", type, state->devfd, major, minor);
	if (r < 0) {
		fprintf(stderr, "Failed to parse signal: %s\n", strerror(-r));
		return r;
	}
#if HOST_DBUS_DIRECT
	r = sd_bus_call_method(state->host_bus,
		"org.chromium.LibCrosService",
		"/org/chromium/LibCrosService",
		"org.chromium.LibCrosServiceInterface", "ReleaseDisplayOwnership",
		ret_error, &m2,
		"");
	sd_bus_message_unref(m2);
	if (r < 0) {
		fprintf(stderr, "Failed to pause: %s\n", strerror(-r));
		return r;
	}
#else
	r = -FREON_DBUS_METHOD_CALL(ReleaseDisplayOwnership);
	if (r < 0) {
		fprintf(stderr, "Failed to pause freon: %d\n", -r);
		return r;
	}
#endif
#if 0
	r = ioctl(state->devfd, DRM_IOCTL_SET_MASTER, 0);
	if (r < 0) {
		fprintf(stderr, "Failed to set master: %s\n", strerror(-r));
	}
#endif

	sd_bus *bus = sd_bus_message_get_bus(m);
	if (strcmp("pause", type) != 0) {
		printf("Paused freon, hope none one needed the device %d,%d\n", major, minor);
		return r;
	}

	//usleep(1e5);
	printf("Paused freon, notify logind (%d,%d)...\n", major, minor);
	r = sd_bus_call_method(bus,
		"org.freedesktop.login1",
		state->session_path,
		"org.freedesktop.login1.Session", "PauseDeviceComplete",
		ret_error, &m2,
		"uu", major, minor);
	sd_bus_message_unref(m2);
	if (r < 0) {
		fprintf(stderr, "Failed to notify pause complete: %s, %s\n", strerror(-r), ret_error->message);
		int r2 = ioctl(state->devfd, DRM_IOCTL_DROP_MASTER, 0);
		if (r2 < 0) {
			fprintf(stderr, "Failed to drop master: %s\n", strerror(-r2));
		}
#if HOST_DBUS_DIRECT
		r2 = sd_bus_call_method(state->host_bus,
			"org.chromium.LibCrosService",
			"/org/chromium/LibCrosService",
			"org.chromium.LibCrosServiceInterface", "TakeDisplayOwnership",
			ret_error, &m2,
			"");
		sd_bus_message_unref(m2);
		if (r2 < 0) {
			fprintf(stderr, "Failed to resume: %s, %s\n", strerror(-r2), ret_error->message);
		}
#else
		r2 = -FREON_DBUS_METHOD_CALL(TakeDisplayOwnership);
		if (r2 < 0) {
			fprintf(stderr, "Failed to give freon ownership: %s\n", strerror(-r2));
		}
#endif
	} else {
		printf("Ok\n");
	}
	return r;
}

int on_resume(sd_bus_message *m, void *userdata, sd_bus_error *ret_error){
	struct state *state = userdata;
	int major, minor, r;
	//if(state->devfd) close(state->devfd);
	//state->devfd = 0;
	r = sd_bus_message_read(m, "uuh", &major, &minor, &state->devfd);
	if (r < 0) {
		fprintf(stderr, "Failed to parse signal: %s\n", strerror(-r));
		return r;
	}
	printf("\nResume fd:%d %d,%d\n", state->devfd, major, minor);
	r = ioctl(state->devfd, DRM_IOCTL_DROP_MASTER, 0);
	if (r < 0) {
		fprintf(stderr, "Failed to drop master: %s\n", strerror(-r));
	}
#if HOST_DBUS_DIRECT
	sd_bus_message *m2 = NULL;
	r = sd_bus_call_method(state->host_bus,
		"org.chromium.LibCrosService",
		"/org/chromium/LibCrosService",
		"org.chromium.LibCrosServiceInterface", "TakeDisplayOwnership",
		ret_error, &m2,
		"");
	sd_bus_message_unref(m2);
	if (r < 0) {
		fprintf(stderr, "Failed to resume freon: %s\n", strerror(-r));
	}
#else
	r = -FREON_DBUS_METHOD_CALL(TakeDisplayOwnership);
	if (r < 0) {
		fprintf(stderr, "Failed to resume freon: %d\n", -r);
	}
#endif
	return r;
}
