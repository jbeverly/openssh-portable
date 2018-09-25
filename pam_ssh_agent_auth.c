/*
 * Copyright (c) 2008, Jamie Beverly. 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 * 
 *    1. Redistributions of source code must retain the above copyright notice, this list of
 *       conditions and the following disclaimer.
 * 
 *    2. Redistributions in binary form must reproduce the above copyright notice, this list
 *       of conditions and the following disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY Jamie Beverly ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL Jamie Beverly OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * The views and conclusions contained in the software and documentation are those of the
 * authors and should not be interpreted as representing official policies, either expressed
 * or implied, of Jamie Beverly.
 */

#include "config.h"
#include <syslog.h>

#ifdef HAVE_SECURITY_PAM_APPL_H

#include <security/pam_appl.h>
#define PAM_SM_AUTH
#include <security/pam_modules.h>

#elif HAVE_PAM_PAM_APPL_H

#include <pam/pam_appl.h>
#define PAM_SM_AUTH
#include <pam/pam_modules.h>

#endif

#include <stdarg.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include "iterate_ssh_agent_keys.h"
#include "includes.h"
#include "log.h"
#include "ssh.h"
#include "servconf.h"
#include "pam_static_macros.h"

#define strncasecmp_literal(A,B) strncasecmp( A, B, sizeof(B) - 1)
#define UNUSED(expr) do { (void)(expr); } while (0)


ServerOptions   options;
uint8_t         allow_user_owned_authorized_keys_file = 0;

#if ! HAVE___PROGNAME || HAVE_BUNDLE
char           *__progname;
#else
extern char    *__progname;
#endif

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
    char          **argv_ptr;
    char           *p = NULL;
    const char     *user = NULL;
    char           *ruser_ptr = NULL;
    char           *servicename = NULL;
    char            ruser[128] = "";
    uint8_t         stderr_output = 0;

    int             i = 0;
    int             retval = PAM_AUTH_ERR;

    LogLevel        log_lvl = SYSLOG_LEVEL_INFO;
    SyslogFacility  facility = SYSLOG_FACILITY_AUTH;

#ifdef LOG_AUTHPRIV 
    facility = SYSLOG_FACILITY_AUTHPRIV;
#endif

    UNUSED(flags);
    pam_get_item(pamh, PAM_SERVICE, (void *) &servicename);
/*
 * XXX: 
 * When testing on MacOS (and I presume them same would be true on other a.out systems)
 * I tried '-undefined supress -flat_namespace', but then rather than compilation errors, I
 * received dl_open errors about the unresolvable symbol. So I just made my own symbol, and it 
 * works quite nicely... if you know of a better way than this kludge, I'd be most appreciative for 
 * a patch 8-)
 */
#if ! HAVE___PROGNAME || HAVE_BUNDLE
    __progname = xstrdup(servicename);
#endif

    for(i = argc, argv_ptr = (char **) argv; i > 0; ++argv_ptr, i--) {
        if(strncasecmp_literal(*argv_ptr, "debug") == 0) { 
            log_lvl = SYSLOG_LEVEL_DEBUG3;
        }
        if(strncasecmp_literal(*argv_ptr, "stderr_output") == 0 ) {
            stderr_output = 1;
        }
    }

    log_init(__progname, log_lvl, facility, stderr_output);
    pam_get_item(pamh, PAM_USER, (void *) &user);
    pam_get_item(pamh, PAM_RUSER, (void *) &ruser_ptr);

    verbose("Beginning pam_ssh_agent_auth for user %s", user);

    if(ruser_ptr) {
        strncpy(ruser, ruser_ptr, sizeof(ruser) - 1);
    } else {
        if( ! getpwuid(getuid()) ) {
            verbose("Unable to getpwuid(getuid())");
            goto cleanexit;
        }
        strncpy(ruser, getpwuid(getuid())->pw_name, sizeof(ruser) - 1);
    }

    /* Might as well explicitely confirm the user(s) exists here */
    if(! getpwnam(ruser) ) {
        verbose("getpwnam(%s) failed, bailing out", ruser);
        goto cleanexit;
    }
    if( ! getpwnam(user) ) {
        verbose("getpwnam(%s) failed, bailing out", user);
        goto cleanexit;
    }

    for(i = argc, argv_ptr = (char **) argv; i > 0; ++argv_ptr, i--) {
        if(strncasecmp_literal(*argv_ptr, "allow_user_owned_authorized_keys_file")  == 0) {
            allow_user_owned_authorized_keys_file = 1;
        }
        if(strncasecmp_literal(*argv_ptr, "file=") == 0 ) { 
            if (options->num_authkeys_files >= MAX_AUTHKEYS_FILES) {
                fatal("%s line %d: too many authorized keys files.", filename, linenum);
            }
            options->authorized_keys_files[options->num_authkeys_files++] 
              = tilde_expand_filename(*argv_ptr + sizeof("file=") - 1, ruser)
        }
        if(options->authorized_keys_command == NULL 
                && strncasecmp_literal(*argv_ptr, "authorized_keys_command=") == 0 ) { 
            p = *argv_ptr + sizeof("authorized_keys_command=") - 1;
            if (*p != '/' && strncasecmp_literal(c, "none") != 0) {
                fatal("authorized_keys_command must be an absolute path");
            }
            options->authorized_keys_command = xstrdup(p);
        }
        if(options->authorized_keys_command_user == NULL 
               && strncasecmp_literal(*argv_ptr, "authorized_keys_command_user=") == 0 ) { 
            options->authorized_keys_command_user = xstrdup(*argv_ptr + sizeof("authorized_keys_command_user=") - 1);
        }
        if(options->trusted_user_ca_keys == NULL 
                && strncasecmp_literal(*argv_ptr, "trusted_user_ca_keys_file=") == 0) {
            options->trusted_user_ca_keys = xstrdup(*argv_ptr + sizeof("trusted_user_ca_keys_file=") - 1);
        }
    }

    if(options->num_authkeys_files == 0 && options->trusted_user_ca_keys == NULL) {
        verbose("Using default file=/etc/security/authorized_keys");
        options->authorized_keys_files[options->num_authkeys_files++] 
            = xstrdup("/etc/security/authorized_keys");
    }

    /* 
     * PAM_USER and PAM_RUSER do not necessarily have to get set by the calling application, and we may be unable to divine the latter.
     * In those cases we should fail
     */

    if(user && strlen(ruser) > 0) {
        verbose("Attempting authentication: `%s' as `%s' using %s", ruser, user, authorized_keys_file);
        if(find_authorized_keys(user, ruser, servicename)) { 
            logit("Authenticated: `%s' as `%s' using %s", ruser, user, authorized_keys_file);
            retval = PAM_SUCCESS;
        } else {
            logit("Failed Authentication: `%s' as `%s' using %s", ruser, user, authorized_keys_file);
        }
    } else {
        logit("No %s specified, cannot continue with this form of authentication", (user) ? "ruser" : "user" );
    }

cleanexit:

#if ! HAVE___PROGNAME || HAVE_BUNDLE
    free(__progname);
#endif

    free(authorized_keys_file);

    return retval;
}


PAM_EXTERN int
pam_sm_setcred(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
    UNUSED(pamh);
    UNUSED(flags);
    UNUSED(argc);
    UNUSED(argv);
    return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_ssh_agent_auth_modstruct = {
    "pam_ssh_agent_auth",
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    NULL,
    NULL,
    NULL,
};
#endif
