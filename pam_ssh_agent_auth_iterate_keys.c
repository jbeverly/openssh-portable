#include <string.h>

#include "includes.h"
#include "config.h"

#include "openbsd-compat/sys-queue.h"

#include "xmalloc.h"
#include "log.h"
#include "buffer.h"
#include "key.h"
#include "authfd.h"
#include <stdio.h>
#include <openssl/evp.h>
#include "ssh2.h"
#include "misc.h"

#include "log.h"
#include "authfd.h"
#include "identity.h"
#include "userauth_pubkey_from_id.h"

#include "get_command_line.h"
extern char **environ;

static char *
psaa_log_action(char ** action, size_t count)
{
    size_t i;
    char *buf = NULL;

    if (count == 0)
        return NULL;

    buf = xcalloc((count * MAX_LEN_PER_CMDLINE_ARG) + (count * 3), sizeof(*buf));
    for (i = 0; i < count; i++) {
        strcat(buf, (i > 0) ? " '" : "'");
        strncat(buf, action[i], MAX_LEN_PER_CMDLINE_ARG);
        strcat(buf, "'");
    }
    return buf;
}

void
static psaa_agent_action(Buffer *buf, char ** action, size_t count)
{
    size_t i;
    buffer_init(buf);

    buffer_put_int(buf, count);

    for (i = 0; i < count; i++) {
        buffer_put_cstring(buf, action[i]);
    }
}


void
pamsshagentauth_session_gen(Buffer * session, const char * user,
                                const char * ruser, const char * servicename)
{
    char *cookie = NULL;
    uint8_t i = 0;
    uint32_t rnd = 0;
    uint8_t cookie_len;
    char hostname[256] = { 0 };
    char pwd[1024] = { 0 };
    time_t ts;
    char ** reported_argv = NULL;
    size_t count = 0;
    char * action_logbuf = NULL;
    Buffer action_agentbuf;
    uint8_t free_logbuf = 0;
    char * retc;
    int32_t reti;

    rnd = arc4random_uniform(239);
    cookie_len = ((uint8_t) rnd) + 16;

    cookie = xcalloc(1,cookie_len);

    for (i = 0; i < cookie_len; i++) {
        if (i % 4 == 0) {
            rnd = arc4random();
        }
        cookie[i] = (char) rnd;
        rnd >>= 8;
    }

    count = get_command_line(&reported_argv);
    if (count > 0) {
        free_logbuf = 1;
        psaa_action_logbuf = log_action(reported_argv, count);
        psaa_agent_action(&action_agentbuf, reported_argv, count);
        free_command_line(reported_argv, count);
    }
    else {
        action_logbuf = "unknown on this platform";
        buffer_init(&action_agentbuf); /* stays empty, means unavailable */
    }

    reti = gethostname(hostname, sizeof(hostname) - 1);
    retc = getcwd(pwd, sizeof(pwd) - 1);
    time(&ts);

    buffer_init(session);

    buffer_put_int(session, PAM_SSH_AGENT_AUTH_REQUESTv1);
    buffer_put_string(session, cookie, cookie_len);
    buffer_put_cstring(session, user);
    buffer_put_cstring(session, ruser);
    buffer_put_cstring(session, servicename);
    if(retc) {
        buffer_put_cstring(session, pwd);
    } else {
        buffer_put_cstring(session, "");
    }
    buffer_put_string(session, action_agentbuf.buf + action_agentbuf.offset, action_agentbuf.end - action_agentbuf.offset);
    if (free_logbuf) {
        xfree(action_logbuf);
        buffer_free(&action_agentbuf);
    }
    if(reti >= 0) {
        buffer_put_cstring(session, hostname);
    } else {
        buffer_put_cstring(session, "");
    }
    buffer_put_int64(session, (uint64_t) ts);

    free(cookie);
    return;
}

int
pamsshagentauth_find_authorized_keys(const char * user, const char * ruser, const char * servicename)
{
    Buffer session = { 0 };
    Identity *id;
    Key *key;
    AuthenticationConnection *ac;
    char *comment;
    uint8_t retval = 0;
    uid_t uid = getpwnam(ruser)->pw_uid;

    if ((ac = ssh_get_authentication_connection(uid))) {
        pamsshagentauth_verbose("Contacted ssh-agent of user %s (%u)", ruser, uid);
        for (key = ssh_get_first_identity(ac, &comment, 2); key != NULL; key = ssh_get_next_identity(ac, &comment, 2))
        {
            if(key != NULL) {
                id = pamsshagentauth_xcalloc(1, sizeof(*id));
                id->key = key;
                id->filename = comment;
                id->ac = ac;
                if(userauth_pubkey_from_id(ruser, id, &session)) {
                    retval = 1;
                }
                pamsshagentauth_xfree(id->filename);
                pamsshagentauth_key_free(id->key);
                pamsshagentauth_xfree(id);
                if(retval == 1)
                    break;
            }
        }
        pamsshagentauth_buffer_free(&session);
        ssh_close_authentication_connection(ac);
    }
    else {
        pamsshagentauth_verbose("No ssh-agent could be contacted");
    }
    /* pamsshagentauth_xfree(session); */
    EVP_cleanup();
    return retval;
}


static int
psaa_get_identity_list(const char *user, const char *ruser, int *sock, struct ssh_identitylist **idlp) {
    int err = 0;
    if(ssh_get_authentication_socket(sock) != 0) {
        logit("No ssh-agent could be contactedi for `%s' as `%s'", ruser, user);
        return 0;
    }
    verbose("Contacted ssh-agent of user %s", ruser);

    *idlp = xcalloc(1, sizeof(*idlp)); 
    if((err = ssh_fetch_identitylist(*sock, 2, idlp)) != 0) {
        debug3("Unable to retrieve identitylist from agent: %d", err);
        return 0;
    }
    return 1;
}

int
find_authorized_keys(const char *user, const char *ruser, const char *servicename) {
    Buffer session = { 0 };
    int sock = -1;
    size_t i = 0;
    struct ssh_identitylist *idlp;
    Key *key = NULL;
    Identity *id;
    struct passwd *pw;
    uid_t uid;

    pw = getpwnam(ruser);
    if(pw == NULL) {
        logit("invalid user: `%s'", ruser);
        return 0;
    }

#ifdef WITH_OPENSSL
    OpenSSL_add_all_digests();
#endif
    pamsshagentauth_session_gen(&session, user, ruser, servicename);

    if(!psaa_get_identity_list(user, ruser, &sock, &idlp) || sock < 0) {
        return 0;
    }

    uid = pw->pw_uid;
    for(i = 0; i < idlp->nkeys; i++) {
        key = *(idlp->keys+i);
        if(key == NULL) continue;
        id = xcalloc(1, sizeof(*id));
        id->key = key;
        id->filename = *(idlp->comments+i);
        id->agent_fd = sock;
        if(userauth_pubkey_from_id(ruser, id, &session)) {
            retval = 1;
        }
    }
#ifdef WITH_OPENSSL
    EVP_cleanup();
#endif
    ssh_free_identitylist(&idlp);
    return retval;
}
