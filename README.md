## Tesla SSO OAuth Token Generation
This script allows for the generation of a refresh token required by third-party Tesla services.

### Setup
This method requires the following to be prepared and installed.
1. Install the latest version of ``Python 3``.
2. Install the ``Requests`` Python 3 package (to install: ``pip3 install requests``)
3. Install the ``Selenium`` Python 3 package (to install: ``pip3 install selenium``)
4. Download and set up chromedriver ([download link here](https://sites.google.com/a/chromium.org/chromedriver/downloads)) that matches your version of Google Chrome and add it to the same directory as the python script (or to your system path).
5. Download the file ``auth.tokens.py`` located in this repository.

### Generating Tokens
To utilize this script, simply navigate to the directory where this file exists and then run the following command in your preferred command-line interface (CLI).

If your Tesla account has MFA enabled:
```
python3 ./auth.tokens.py -u 'email' -p 'password' -c 'passcode'
```

If your Tesla account does **not** have MFA enabled:
```
python3 ./auth.tokens.py -u 'email' -p 'password'
```

If successful, you will be given a response that contains your refresh token. You will need to copy the entirety of this large string to the third-party service/app of your choice.

### Errors / Unsuccessful Token Generation
When attempting to generate your own tokens, you may get a response back that something went wrong. While most are
self-explanatory, we'll break down each error below.

> **An error occurred when making a request to Tesla.**

If this occurs, a general error occurred, and the script was unable to make the initial request to Tesla. This can happen at random
and is usually recommended to just try again a few seconds later.

> **The credentials you provided were not valid.**

The credentials that you provided to the script were not correct and we could not log you in correctly. Please double-check your email and password and try again.

> **Your Tesla Account is locked and requires its password to be reset on Tesla.com.**

If this occurs, you unsuccessfully attempted to authenticate your Tesla Account too many times and was temporarily locked.
You will unfortunately need to reset your password.

> **The passcode you provided was invalid.**

You successfully authenticated your account, but the MFA/2FA passcode provided was invalid or expired. Please double-check
that the code you provided is six-digits and numerical.

> **Something went wrong with the authentication process. Please try again.**

A general error occurred when trying to authenticate via MFA. There is usually no explanation for this and very rarely happens.
Simply try authenticating again (but don't forget to use a new passcode).

### Credits
This modified script is based off [this repository](https://github.com/enode-engineering/tesla-oauth2) and has been redistributed with permission by [Enode](https://www.enode.io/).



