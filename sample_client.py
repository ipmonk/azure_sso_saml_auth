#!/usr/bin/env python3

# stdlib imports
from http.client import HTTPConnection
import logging

# 3rd party imports
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# local imports
from azure_sso_saml_auth import AzureSsoSamlAuth

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logger = logging.getLogger(__name__)

def main():

    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)
    requests_log = logging.getLogger("urllib3")
    requests_log.setLevel(logging.INFO)
    requests_log.propagate = True

    # change to 1 to see debugs
    HTTPConnection.debuglevel = 0 

    user = "foo"
    password = "bar"
    host = "https://webpage.net"
    url = f"{host}/test.html"

    with requests.session() as sess:
        kwargs = {
            "user": user,
            "password": password,
            "sess": sess,
            "host": host,
            "url": url,
        }
        samlauth = AzureSsoSamlAuth(**kwargs)
        samlauth.main()

if __name__ == "__main__":
    main()
