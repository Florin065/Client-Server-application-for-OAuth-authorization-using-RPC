/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include "oauth.h"
#include <stdio.h>
#include <stdlib.h>
#include <rpc/pmap_clnt.h>
#include <string.h>
#include <memory.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "oauth_server.h"

#ifndef SIG_PF
#define SIG_PF void(*)(int)
#endif

static AuthResponse *
_requestauthorization_1 (AuthRequest  *argp, struct svc_req *rqstp)
{
	return (requestauthorization_1_svc(*argp, rqstp));
}

static AccessTokenResponse *
_requestaccesstoken_1 (AccessTokenRequest  *argp, struct svc_req *rqstp)
{
	return (requestaccesstoken_1_svc(*argp, rqstp));
}

static AccessTokenResponse *
_refreshaccesstoken_1 (RefreshTokenRequest  *argp, struct svc_req *rqstp)
{
	return (refreshaccesstoken_1_svc(*argp, rqstp));
}

static ValidateActionResponse *
_validateaction_1 (ValidateActionRequest  *argp, struct svc_req *rqstp)
{
	return (validateaction_1_svc(*argp, rqstp));
}

static void *
_approverequest_1 (ApproveRequestToken  *argp, struct svc_req *rqstp)
{
	return (approverequest_1_svc(*argp, rqstp));
}

static void
oauth_prog_1(struct svc_req *rqstp, register SVCXPRT *transp)
{
	union {
		AuthRequest requestauthorization_1_arg;
		AccessTokenRequest requestaccesstoken_1_arg;
		RefreshTokenRequest refreshaccesstoken_1_arg;
		ValidateActionRequest validateaction_1_arg;
		ApproveRequestToken approverequest_1_arg;
	} argument;
	char *result;
	xdrproc_t _xdr_argument, _xdr_result;
	char *(*local)(char *, struct svc_req *);

	switch (rqstp->rq_proc) {
	case NULLPROC:
		(void) svc_sendreply (transp, (xdrproc_t) xdr_void, (char *)NULL);
		return;

	case RequestAuthorization:
		_xdr_argument = (xdrproc_t) xdr_AuthRequest;
		_xdr_result = (xdrproc_t) xdr_AuthResponse;
		local = (char *(*)(char *, struct svc_req *)) _requestauthorization_1;
		break;

	case RequestAccessToken:
		_xdr_argument = (xdrproc_t) xdr_AccessTokenRequest;
		_xdr_result = (xdrproc_t) xdr_AccessTokenResponse;
		local = (char *(*)(char *, struct svc_req *)) _requestaccesstoken_1;
		break;

	case RefreshAccessToken:
		_xdr_argument = (xdrproc_t) xdr_RefreshTokenRequest;
		_xdr_result = (xdrproc_t) xdr_AccessTokenResponse;
		local = (char *(*)(char *, struct svc_req *)) _refreshaccesstoken_1;
		break;

	case ValidateAction:
		_xdr_argument = (xdrproc_t) xdr_ValidateActionRequest;
		_xdr_result = (xdrproc_t) xdr_ValidateActionResponse;
		local = (char *(*)(char *, struct svc_req *)) _validateaction_1;
		break;

	case ApproveRequest:
		_xdr_argument = (xdrproc_t) xdr_ApproveRequestToken;
		_xdr_result = (xdrproc_t) xdr_void;
		local = (char *(*)(char *, struct svc_req *)) _approverequest_1;
		break;

	default:
		svcerr_noproc (transp);
		return;
	}
	memset ((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
		svcerr_decode (transp);
		return;
	}
	result = (*local)((char *)&argument, rqstp);
	if (result != NULL && !svc_sendreply(transp, (xdrproc_t) _xdr_result, result)) {
		svcerr_systemerr (transp);
	}
	if (!svc_freeargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
		fprintf (stderr, "%s", "unable to free arguments");
		exit (1);
	}
	return;
}

int
main (int argc, char **argv)
{
	register SVCXPRT *transp;

	pmap_unset (OAUTH_PROG, OAUTH_VERS);

	transp = svcudp_create(RPC_ANYSOCK);
	if (transp == NULL) {
		fprintf (stderr, "%s", "cannot create udp service.");
		exit(1);
	}
	if (!svc_register(transp, OAUTH_PROG, OAUTH_VERS, oauth_prog_1, IPPROTO_UDP)) {
		fprintf (stderr, "%s", "unable to register (OAUTH_PROG, OAUTH_VERS, udp).");
		exit(1);
	}

	transp = svctcp_create(RPC_ANYSOCK, 0, 0);
	if (transp == NULL) {
		fprintf (stderr, "%s", "cannot create tcp service.");
		exit(1);
	}
	if (!svc_register(transp, OAUTH_PROG, OAUTH_VERS, oauth_prog_1, IPPROTO_TCP)) {
		fprintf (stderr, "%s", "unable to register (OAUTH_PROG, OAUTH_VERS, tcp).");
		exit(1);
	}

	OAuthServer::getInstance().initServer(argc, argv);

	svc_run ();
	fprintf (stderr, "%s", "svc_run returned");
	exit (1);
	/* NOTREACHED */
}
