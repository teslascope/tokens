# Tesla SSO OAuth Token Generation
# Allows for the generation of a refresh token required by third-party Tesla services.
# Original Repository: https://github.com/enode-engineering/tesla-oauth2
# Credit: Enode (https://www.enode.io/)

# This modified version has been distributed with permission.
# For more information on the process, please review the comments below.

import argparse
import base64
import hashlib
import os
import re
import time
import json
from urllib.parse import parse_qs

import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

MAX_ATTEMPTS = 30
CLIENT_ID = "81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384"
USER_AGENT = "Mozilla/5.0 (Linux; Android 10; Pixel 3 Build/QQ2A.200305.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/85.0.4183.81 Mobile Safari/537.36"

def gen_params():
    verifier_bytes = os.urandom(86)
    code_verifier = base64.urlsafe_b64encode(verifier_bytes).rstrip(b"=")
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier).digest()).rstrip(b"=")
    state = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode("utf-8")
    return code_verifier, code_challenge, state

def remove_quotes(string):
    if string.startswith("'") and string.endswith("'"):
        string = string[1:-1]
        return string
    else:
        return string

def create_driver():
    options = webdriver.ChromeOptions()
    options.headless = True
    driver = webdriver.Chrome(options=options)
    driver.execute_cdp_cmd("Network.setUserAgentOverride", {"userAgent": USER_AGENT})
    return driver

def login(args):
    # Set up some random parameters we'll use later.
    email, password = remove_quotes(args.email), remove_quotes(args.password)
    vprint = print if args.v else lambda _: None
    session, resp, params, code_verifier = (None,) * 4
    code_verifier, code_challenge, state = gen_params()

    # Set the default headers that we'll reuse a few times.
    default_headers = {}

    # Set the default params; many endpoints will require this to avoid a 400 error (Bad Request)
    params = (
        ("audience", ""),
        ("client_id", "ownerapi"),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256"),
        ("locale", "en"),
        ("prompt", "login"),
        ("redirect_uri", "https://auth.tesla.com/void/callback"),
        ("response_type", "code"),
        ("scope", "openid email offline_access"),
        ("state", state),
    )

    # [1] Login Form
    session = requests.Session()
    driver = create_driver()
    driver.get(f"https://auth.tesla.com/oauth2/v3/authorize?audience=&state={state}&code_challenge={code_challenge}&prompt=login&code_challenge_method=S256&client_id=ownerapi&redirect_uri=https%3A%2F%2Fauth.tesla.com%2Fvoid%2Fcallback&locale=en-US&scope=openid+email+offline_access&audience=owenerapi&response_type=code")
    WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.CSS_SELECTOR, "input[name=identity]")))

    # inject browser cookies to requests.Session
    for cookie in driver.get_cookies():
        session.cookies.set(cookie["name"], cookie["value"])

    csrf = driver.find_element_by_css_selector("input[name=_csrf]").get_attribute("value")
    transaction_id = driver.find_element_by_css_selector("input[name=transaction_id]").get_attribute("value")
    driver.quit()

    # Now that we've extracted the CRSF and transaction_id, lets build our form data.
    data = {
        "_csrf": csrf,
        "_phase": "authenticate",
        "_process": "1",
        "transaction_id": transaction_id,
        "cancel": "",
        "identity": email,
        "credential": password,
    }

    # [2] Attempt to login.
    # We can experience a handful of possible outcomes here as discussed below.
    for attempt in range(MAX_ATTEMPTS):
        try:
            resp = session.post("https://auth.tesla.com/oauth2/v3/authorize", headers=default_headers, params=params, data=data, allow_redirects=False, timeout=1)

            # We triggered Tesla's WAF (Web Application Firewall), so lets try again.
            if resp.ok and "support ID" in resp.text:
                vprint(f"Got bot detection. Will try again.")

            # We were redirected somewhere, so lets determine where that will take us.
            if resp.ok and (resp.status_code == 302 or "<title>" in resp.text):

                # We were successful at logging in, so lets move to the next step.
                if not "Your account has been locked" in resp.text:
                    vprint(f"Post auth form success - {attempt + 1} attempt(s).")
                    break
                else:
                    raise print(json.dumps({"code": 420, "response": "Your Tesla Account is locked and requires its password to be reset on Tesla.com. This may have occurred due to repeatedly providing the wrong credentials or another third-party service you use not being updated to the latest authentication system."}))

            # Credentials are incorrect.
            if "We could not sign you in" in resp.text and resp.status_code == 401:
                raise print(json.dumps({"code": 401, "response": "The credentials you provided were not valid."}))

        except requests.exceptions.Timeout as e:
            vprint('Request timed out. Trying again.')
        time.sleep(1)
    else:
        raise print(json.dumps({"code": 500, "response": "An error occurred when making a request to Tesla. Please try again or let our team know."}))

    # Determine if user has MFA enabled
    is_mfa = True if resp.status_code == 200 and "/mfa/verify" in resp.text else False

    if is_mfa:
        # [3] If the account has MFA enabled, we'll attempt to get the device/app they set up.
        # We will need this for the following steps.
        for attempt in range(MAX_ATTEMPTS):
            try:
                resp = session.get(f"https://auth.tesla.com/oauth2/v3/authorize/mfa/factors?transaction_id={transaction_id}", headers=default_headers, timeout=1)

                # We triggered Tesla's WAF (Web Application Firewall), so lets try again.
                if resp.ok and "support ID" in resp.text:
                    vprint(f"Got bot detection. Will try again.")

                # We successfully got the MFA device, so we'll set its value and continue onward.
                if resp.ok and resp.json()["data"][0]["id"] is not None:

                    factor_id = resp.json()["data"][0]["id"]

                    vprint(f"Got MFA factors, continuing onward. - {attempt + 1} attempt(s).")
                    break
            except requests.exceptions.Timeout as e:
                vprint('Request timed out. Trying again.')
            time.sleep(1)
        else:
            raise print(json.dumps({"code": 500, "response": "An error occurred when making a request to Tesla to obtain MFA devices. If this continues, please let our team know."}))

        # Let's set up some special headers to prepare for our actual MFA verification request below.
        headers = {}

        # Set up our data that we've extracted in previous requests + the passcode.
        data = {"transaction_id": transaction_id, "factor_id": factor_id, "passcode": remove_quotes(args.c)}

        # [4] Let's attempt to verify the MFA passcode. Fingers crossed by the time we get here it hasn't expired.
        for attempt in range(MAX_ATTEMPTS):
            try:
                resp = session.post("https://auth.tesla.com/oauth2/v3/authorize/mfa/verify", headers=headers, json=data, timeout=1)

                # We successfully verified the passcode so let's continue on!
                if(resp.json()["data"]["valid"]):
                    vprint(f"MFA was valid, continuing onward. - {attempt + 1} attempt(s).")
                    break

                # The passcode was incorrect or invalid (expired).
                if "error" in resp.text or not resp.json()["data"]["approved"] or not resp.json()["data"]["valid"]:
                    vprint(resp.json())
                    raise print(json.dumps({"code": "401", "response": "The passcode you provided was invalid."}))
            except requests.exceptions.Timeout as e:
                vprint('Request timed out. Trying again.')
        else:
            raise print(json.dumps({"code": 500, "response": "An error occurred when making a request to Tesla with your MFA. If this continues, please let our team know."}))

        # Set up the data and headers for our following step.
        data = {"transaction_id": transaction_id}

        headers = {}

        # [5] Now that we've successfully authenticated and verified our MFA (if needed), lets get an auth code.
        for attempt in range(MAX_ATTEMPTS):
            try:
                resp = session.post("https://auth.tesla.com/oauth2/v3/authorize", headers=headers, params=params, data=data, allow_redirects=False, timeout=1)
                # We succeeded and got a "location", so lets grab that authorization code and continue onward.
                if resp.headers.get("location"):
                    vprint(f"Got authorization code in {attempt + 1} attempt(s).")
                    break
            except requests.exceptions.Timeout as e:
                vprint('Request timed out. Trying again.')
        else:
            raise print(json.dumps({"code": 500, "response": "Something went wrong with the authentication process. Please try again."}))

    code = parse_qs(resp.headers["location"])["https://auth.tesla.com/void/callback?code"]

    # We're almost there. Let's set up one of our final payloads.
    payload = {
        "grant_type": "authorization_code",
        "client_id": "ownerapi",
        "code_verifier": code_verifier.decode("utf-8"),
        "code": code,
        "redirect_uri": "https://auth.tesla.com/void/callback",
    }

    # [6] Lets take that authorization code and generate our SSO tokens! FINALLY.
    for attempt in range(MAX_ATTEMPTS):
        try:
            resp = session.post("https://auth.tesla.com/oauth2/v3/token", headers=default_headers, json=payload, timeout=1)

            # We got our SSO tokens. Let's grab the tokens that we'll use later.
            if resp.ok and resp.json()["access_token"]:

                sso_access_token = resp.json()["access_token"]
                sso_refresh_token = resp.json()["refresh_token"]

                vprint(f"Got SSO tokens in {attempt + 1} attempt(s).")
                break
        except requests.exceptions.Timeout as e:
            vprint('Request timed out. Trying again.')
        time.sleep(3)
    else:
        raise print(json.dumps({"code": 500, "response": "Something went wrong getting account tokens. Please try again."}))

    # Set up the headers and payload for our final step.
    default_headers["authorization"] = "bearer " + sso_access_token
    payload = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "client_id": CLIENT_ID,
    }

    # [7] We got a SSO token so we can do things on the account's behalf now.
    # Let's use this to generate an owners API token which allows us to access vehicle data.
    for attempt in range(MAX_ATTEMPTS):
        try:
            resp = session.post("https://owner-api.teslamotors.com/oauth/token", headers=default_headers, json=payload)

            # If the response contains an access token, then we're done!
            if resp.json()["access_token"] is not None:
                vprint(f"Got access token in {attempt + 1} attempt(s).")
                break
        except requests.exceptions.Timeout as e:
            vprint('Request timed out. Trying again.')
        time.sleep(3)
    else:
        raise print(json.dumps({"code": 500, "response": "Something went wrong getting SSO tokens. Please try again."}))

    # Let's display their tokens.
    print(json.dumps({"code": 200, "tokens": {"owner_access_token": resp.json()["access_token"], "sso_refresh_token": sso_refresh_token}}))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--email", required=True, help="Tesla account email")
    parser.add_argument("-p", "--password", required=True, help="Tesla account password")
    parser.add_argument("-v", required=False, action="store_true", help="Be verbose")

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("-c", help="Passcode generated by your authenticator app")

    args = parser.parse_args()
    login(args)
