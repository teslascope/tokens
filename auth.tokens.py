# Tesla SSO OAuth Token Generation
# Allows for the generation of a refresh token required by third-party Tesla services.
# Original Repository: https://github.com/enode-engineering/tesla-oauth2
# Credit: Enode (https://www.enode.io/)

# This modified version has been distributed with permission.
# For more information on the process, please review the comments below.

import base64
import hashlib
import os
import re
import random
import time
import argparse
import json
from urllib.parse import parse_qs
import requests

# Defining some variables we'll use later on.
# The CLIENT ID provided is utilized by the mobile app and third-party services to ensure tokens are refreshable.
MAX_ATTEMPTS = 3
CLIENT_ID = "81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384"
UA = "SSO Token Generation"
X_TESLA_USER_AGENT = "SSO Token Generation"

# Setting up the ability to receive parameters via command line.
parser = argparse.ArgumentParser(description='Provide credentials for Tesla authentication.')
parser.add_argument('-u')
parser.add_argument('-p')
parser.add_argument('-c')
args = parser.parse_args()

# Generates random strings used for validation purposes and is standard with OAuth2.
def gen_params():
    verifier_bytes = os.urandom(86)
    code_verifier = base64.urlsafe_b64encode(verifier_bytes).rstrip(b"=")
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier).digest()).rstrip(b"=")
    state = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode("utf-8")
    return code_verifier, code_challenge, state

# This removes single quotes around the provided parameters to prevent some Python errors.
def remove_quotes(string):
    if string.startswith("'") and string.endswith("'"):
        string = string[1:-1]
        return string
    else:
        return string

# The main process of authenticating a Tesla account.
# For the sake of simplicity, a email, password, and passcode is always required.
def login(email, password, passcode):

    headers = {
        "User-Agent": UA,
        "x-tesla-user-agent": X_TESLA_USER_AGENT,
        "X-Requested-With": "com.teslamotors.tesla",
    }

    # [1] The first process of authenticating is to request the Login form on Tesla.com and receive some
    # variables to send with a subsequent request. This is essential for our login attempt to succeed.
    for attempt in range(MAX_ATTEMPTS):
        code_verifier, code_challenge, state = gen_params()

        # GET parameters that are required for the login request to continue are prepared.
        params = (
            ("client_id", "ownerapi"),
            ("code_challenge", code_challenge),
            ("code_challenge_method", "S256"),
            ("redirect_uri", "https://auth.tesla.com/void/callback"),
            ("response_type", "code"),
            ("scope", "openid email offline_access"),
            ("state", state),
        )

        # A new session is started; this will carry over the cookie from this request to use with subsequent requests.
        session = requests.Session()
        resp = session.get("https://auth.tesla.com/oauth2/v3/authorize", headers=headers, params=params)
        if resp.ok and "<title>" in resp.text:
            break
        time.sleep(3)
    else:
        return print(f"An error occurred when making a request to Tesla.")

    # [2] Everything is clear, so lets get those variables we mentioned above.
    # Once we've extracted them, we'll insert them into the data object below including the provided credentials.
    csrf = re.search(r'name="_csrf".+value="([^"]+)"', resp.text).group(1)
    transaction_id = re.search(r'name="transaction_id".+value="([^"]+)"', resp.text).group(1)

    data = {
        "_csrf": csrf,
        "_phase": "authenticate",
        "_process": "1",
        "transaction_id": transaction_id,
        "cancel": "",
        "identity": email,
        "credential": password,
    }

    for attempt in range(MAX_ATTEMPTS):
        resp = session.post(
            "https://auth.tesla.com/oauth2/v3/authorize", headers=headers, params=params, data=data, allow_redirects=False
        )
        if resp.ok and (resp.status_code == 302 or "<title>" in resp.text):
            if not "Your account has been locked" in resp.text:
                break
            else:
                return print(f"Your Tesla Account is locked and requires its password to be reset on Tesla.com.")
        time.sleep(1)
    else:
        return print(f"The credentials you provided were not valid.")

    # Determine if user has MFA enabled
    # In that case there is no redirect to `https://auth.tesla.com/void/callback` and app shows new form with Passcode / Backup Passcode field
    is_mfa = True if resp.status_code == 200 and "/mfa/verify" in resp.text else False

    # [3a] If the account has MFA enabled, we'll have to make an additional request and utilize the provided passcode.
    if is_mfa:
        resp = session.get(
            f"https://auth.tesla.com/oauth2/v3/authorize/mfa/factors?transaction_id={transaction_id}", headers=headers,
        )
        factor_id = resp.json()["data"][0]["id"]

        # Can use Passcode
        data = {"transaction_id": transaction_id, "factor_id": factor_id, "passcode": passcode}
        resp = session.post("https://auth.tesla.com/oauth2/v3/authorize/mfa/verify", headers=headers, json=data)
        if "error" in resp.text or not resp.json()["data"]["approved"] or not resp.json()["data"]["valid"]:
            return print(f"The passcode you provided was invalid.")

        data = {"transaction_id": transaction_id}

        for attempt in range(MAX_ATTEMPTS):
            resp = session.post(
                "https://auth.tesla.com/oauth2/v3/authorize",
                headers=headers,
                params=params,
                data=data,
                allow_redirects=False,
            )
            if resp.headers.get("location"):
                break
        else:
            return print(f"Something went wrong with the authentication process. Please try again.")

    code = parse_qs(resp.headers["location"])["https://auth.tesla.com/void/callback?code"]

    headers = {"user-agent": UA, "x-tesla-user-agent": X_TESLA_USER_AGENT}
    payload = {
        "grant_type": "authorization_code",
        "client_id": "ownerapi",
        "code_verifier": code_verifier.decode("utf-8"),
        "code": code,
        "redirect_uri": "https://auth.tesla.com/void/callback",
    }

    # [4] Lastly, we'll take the authorization code that we parsed above and send it and our previously
    # generated code verifier to its final destination to generate our SSO refresh token.
    resp = session.post("https://auth.tesla.com/oauth2/v3/token", headers=headers, json=payload)
    refresh_token = resp.json()["refresh_token"]
    print(f'Provide the following refresh token to the third-party service or app: {refresh_token}')

if __name__ == "__main__":
    login(remove_quotes(args.u), remove_quotes(args.p), remove_quotes(args.c or '111111'))
