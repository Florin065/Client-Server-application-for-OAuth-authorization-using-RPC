/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include "oauth.h"

bool_t
xdr_AuthRequest (XDR *xdrs, AuthRequest *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->user_id, 15))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_AuthResponse (XDR *xdrs, AuthResponse *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->request_token, 15))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_AccessTokenRequest (XDR *xdrs, AccessTokenRequest *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->user_id, 15))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->request_token, 15))
		 return FALSE;
	 if (!xdr_bool (xdrs, &objp->refresh))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_RefreshTokenRequest (XDR *xdrs, RefreshTokenRequest *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->access_token, 15))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->refresh_token, 15))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_AccessTokenResponse (XDR *xdrs, AccessTokenResponse *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->access_token, 15))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->refresh_token, 15))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->ttl))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_ValidateActionRequest (XDR *xdrs, ValidateActionRequest *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->operation, ~0))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->resource, ~0))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->access_token, 15))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_ValidateActionResponse (XDR *xdrs, ValidateActionResponse *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->response, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_ApproveRequestToken (XDR *xdrs, ApproveRequestToken *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->user_id, 15))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->request_token, 15))
		 return FALSE;
	return TRUE;
}
