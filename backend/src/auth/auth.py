import json
from flask import request, abort
from functools import wraps
from jose import jwt
from urllib.request import urlopen


AUTH0_DOMAIN = "https://mwiru.auth0.com/"
ALGORITHMS = ["RS256"]
API_AUDIENCE = "coffeeshop"

# AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


# Auth Header
def get_token_auth_header():
    if "Authorization" not in request.headers:
        abort(401, "No Auth headers found.")
    headers = request.headers["Authorization"].split(' ')
    if len(headers) != 2:
        abort(401, "Invalid auth headers.")
    elif headers[0].lower() != "bearer":
        abort(401, "Invalid auth headers prefix.")
    return headers[1]


def check_permissions(permission, payload):
    if "permissions" not in payload:
        raise AuthError({
            "code": "invalid_header",
            "description": "Permissions not included in payload."
        }, 400)
    if permission not in payload["permissions"]:
        raise AuthError({
            "code": "unauthorized",
            "description": "Permission not found."
        }, 403)
    return True


'''
    !!NOTE urlopen has a common certificate error described here:
    https://stackoverflow.com/questions/50236117/scraping-ssl-certificate\
        -verify-failed-error-for-http-en-wikipedia-org
'''


def verify_decode_jwt(token):
    # get public key from Auth0
    json_url = urlopen(f'{AUTH0_DOMAIN}.well-known/jwks.json')
    jwks = json.loads(json_url.read())

    # get data from headers
    unverified_headers = jwt.get_unverified_header(token)

    # choose the key
    rsa_key = {}
    if "kid" not in unverified_headers:
        raise AuthError({
            "code": "invalid_header",
            "description": "Authorization malformed."
        })
    for key in jwks["keys"]:
        if key["kid"] == unverified_headers["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["n"]
            }

    # verify claims
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer=AUTH0_DOMAIN
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise AuthError({
                "code": "token_expired",
                "description": "Token expired."
            }, 401)
        except jwt.JWTClaimsError:
            raise AuthError({
                "code": "invalid_claims",
                "description": "Incorrect claims. Please check the audience and issuer."
            }, 401)
        except Exception:
            raise AuthError({
                "code": "invalid_header",
                "description": "Unable to parse authentication token."
            }, 400)
    raise AuthError({
        "code": "invalid_header",
        "description": "Unable to find the appropriate key."
    })


def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator
