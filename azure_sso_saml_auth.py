""" class to authenticate to a webpage served on Apache with auth_mellon module
    that uses Azure AD SSO
"""

# stdlib imports
import json
import logging
import re
import sys
import traceback

# 3rd party imports
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class AzureSsoSamlAuth:
    """ authenticates via SAML to MS Azure SSO
    """

    def __init__(self, **kwargs):
        self.user = kwargs.get("user")
        self.password = kwargs.get("password")
        self.sess = kwargs.get("sess")
        self.api_host = kwargs.get("api_host")
        self.api_url = kwargs.get("api_url")
        self.tenent_guid = ""
        self.esctx = ""
        self.referer = ""
        self.externalidpstatehash = ""
        self.buid = ""
        self.fpc = ""
        self.stsservicecookie = ""
        self.x_ms_gateway_slice = ""
        self.x_ms_request_id = ""
        self.canary = ""
        self.apicanary = ""
        self.sft = ""
        self.hpgid = ""
        self.hpgact = ""
        self.sctx = ""
        self.correlationid = ""
        self.token = ""

    def main(self):
        """
        calls functions in sequence
        """
        self.saml_request()
        self.get_credential_type()
        self.saml_response()
        self.post_mellon()

    def saml_request(self):
        """sends GET to webpage
        redirects via 303 to /mellon/login on host
        redirects via 303 https://login.microsoftonline.com/
        URI path = <tenent_guid>/saml2/
        URI parameter = SAMLRequest
        URI parameter = RelayState
        """
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

        logger.info(f"headers sent: {headers}")
        logger.info(f"sending GET to {self.api_url}")

        response = self.sess.get(
            self.api_url, headers=headers, verify=False, cookies=self.sess.cookies
        )
        response.raise_for_status()

        logger.info(f"headers received: {dict(response.headers)}")

        self.esctx = response.cookies["esctx"]
        self.referer = response.url

        try:
            self.tenent_guid = response.url.split("/")[3]
        except IndexError:
            trace = "".join(traceback.format_exception(*sys.exc_info()))
            raise SystemExit(
                f"unable to obtain tenent guid from url in response\n{trace}"
            )

        self.buid = response.cookies["buid"]
        self.fpc = response.cookies["fpc"]
        self.stsservicecookie = response.cookies["stsservicecookie"]
        self.x_ms_gateway_slice = response.cookies["x-ms-gateway-slice"]
        self.x_ms_request_id = response.headers["x-ms-request-id"]

        config = re.findall(b"Config=([^;]*)", response.content)[0]
        config = json.loads(config)
        logger.info(f"content received: {config}")

        self.canary = config["canary"]
        self.apicanary = config["apiCanary"]
        self.sft = config["sFT"]
        self.hpgid = str(config["hpgid"])
        self.hpgact = str(config["hpgact"])
        self.sctx = config["sCtx"]
        self.correlationid = config["correlationId"]

    def get_credential_type(self):
        """sends POST to https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US"""

        url = "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US"
        headers = {
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Referer": self.referer,
            "hpgid": self.hpgid,
            "hpgact": self.hpgact,
            "canary": self.apicanary,
            "client-request-id": self.correlationid,
            "hpgrequestid": self.x_ms_request_id,
            "Content-Type": "application/json; charset=utf-8",
            "Origin": "https://login.microsoftonline.com",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        logger.info(f"headers sent: {headers}")

        cookies_out = {
            "buid": self.buid,
            "fpc": self.fpc,
            "esctx": self.esctx,
            "x_ms_gateway_slice": self.x_ms_gateway_slice,
            "stsservicecookie": self.stsservicecookie,
            "brcap": "0",
        }

        data_payload = {
            "username": self.user,
            "isOtherIdpSupported": True,
            "checkPhones": False,
            "isRemoteNGCSupported": True,
            "isCookieBannerShown": False,
            "isFidoSupported": False,
            "originalRequest": self.sctx,
            "country": "US",
            "forceotclogin": False,
            "isExternalFederationDisallowed": False,
            "isRemoteConnectSupported": False,
            "federationFlags": 0,
            "isSignup": False,
            "flowToken": self.sft,
            "isAccessPassSupported": True,
        }
        logger.info(f"payload sent: {data_payload}")

        logger.info(
            "sending POST to https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US"
        )
        response = self.sess.post(
            url,
            headers=headers,
            cookies=cookies_out,
            json=data_payload,
            verify=False,
        )
        response.raise_for_status()

        data = json.loads(response.content)
        logger.info(f"content received: {data}")

    def saml_response(self):
        """sends POST to https://login.microsoftonline.com/{self.tenent_guid}/login
        gets a SAML Response
        """

        url = f"https://login.microsoftonline.com/{self.tenent_guid}/login"
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Referer": self.referer,
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://login.microsoftonline.com",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        logger.info(f"headers sent: {headers}")

        cookies_out = {
            "buid": self.buid,
            "fpc": self.fpc,
            "esctx": self.esctx,
            "x_ms_gateway_slice": self.x_ms_gateway_slice,
            "stsservicecookie": self.stsservicecookie,
            "brcap": "0",
        }

        data_payload = {
            "i13": "0",
            "login": self.user,
            "loginfmt": self.user,
            "type": "11",
            "LoginOptions": "3",
            "lrt": "",
            "lrtPartition": "",
            "hisRegion": "",
            "hisScaleUnit": "",
            "passwd": self.password,
            "ps": "2",
            "psRNGCDefaultType": "",
            "psRNGCEntropy": "",
            "psRNGCSLK": "",
            "canary": self.canary,
            "ctx": self.sctx,
            "hpgrequestid": self.x_ms_request_id,
            "flowToken": self.sft,
            "PPSX": "",
            "NewUser": "1",
            "FoundMSAs": "",
            "fspost": "0",
            "i21": "0",
            "CookieDisclosure": "0",
            "IsFidoSupported": "0",
            "isSignupPost": "0",
            "i2": "1",
            "i17": "",
            "i18": "",
            "i19": "0",
        }
        logger.info("payload sent: {data_payload}")

        logger.info(
            f"sending POST to https://login.microsoftonline.com/{self.tenent_guid}/login"
        )
        response = self.sess.post(
            url,
            headers=headers,
            cookies=cookies_out,
            data=data_payload,
            verify=False,
        )
        response.raise_for_status()
        soup = BeautifulSoup(response.text, features="html.parser")
        tag = soup.find(attrs={"name": "SAMLResponse"})
        if not tag:
            config = re.findall(b"Config=([^;]*)", response.content)[0]
            config = json.loads(config)
            logger.info(f"content received: {config}")
            logger.info(f"error received: {config['arrValErrs']}")
            if "50126" in config["arrValErrs"]:
                raise SystemExit("invalid username or password")
            err_string = "SSO returned error(s), details can be found here:\n"
            for code in config["arrValErrs"]:
                err_string += f"https://login.microsoftonline.com/error?code={code}\n"
            raise SystemExit(err_string)
        self.token = tag["value"]

    def post_mellon(self):
        """sends POST to mellon containing the SAMLResponse"""
        url = f"{self.api_host}/mellon/postResponse"
        payload = {"RelayState": self.api_url, "SAMLResponse": self.token}
        response = self.sess.post(url, data=payload, verify=False)
        response.raise_for_status()
        print(response.text)
