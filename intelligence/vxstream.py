from re import match

from fame.core.module import ThreatIntelligenceModule
from fame.common.exceptions import ModuleInitializationError, \
    ModuleExecutionError

try:
    import requests

    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

RESPONSE_OK = 0
RESPONSE_ERROR = -1


class HTTP:
    OK = 200
    TooManyRequests = 429
    json = "application/json"


class VxStreamAPIDataFormatError(ModuleExecutionError):
    err = "API response data format differs for "

    def __init__(self, msg):
        super(VxStreamAPIDataFormatError, self).__init__(self.err + msg)


class VxStreamIntelligence(ThreatIntelligenceModule):
    name = "VxStream"
    description = "VxStream Sandbox features in-depth static and dynamic " \
                  "analysis techniques within sandboxed environments and is a " \
                  "malware repository created by Payload Security."

    config = [
        {
            "name": "url",
            "type": "str",
            "default": "https://www.vxstream-sandbox.com/",
            "description": "Base URL of the online service."
        },
        {
            "name": "api",
            "type": "str",
            "default": "https://www.vxstream-sandbox.com/api/",
            "description": "URL of the API endpoint."
        },
        {
            "name": "apikey",
            "type": "str",
            "default": "",
            "description": "API key of the service account."
        },
        {
            "name": "secret",
            "type": "str",
            "default": "",
            "description": "API key secret of the service account."
        }
    ]

    def initialize(self):
        # check dependencies
        if not HAVE_REQUESTS:
            raise ModuleInitializationError(self,
                                            "Missing dependency: requests")
        return True

    def ioc_lookup(self, ioc):
        url = self.api + "search"
        param = {
            "params": {
                "apikey": self.apikey,
                "secret": self.secret,
                "query": operator(ioc) + ":" + ioc
            },
            "headers": {
                "User-agent": "FAME (https://github.com/certsocietegenerale/fame) "
                              "VxStream Sandbox Intelligence Module"
            }
        }
        msg = "unsuccessful IOC search"

        self.ioc = ioc
        tags = []
        indicators = []

        data = self.query(url, param, msg)
        if data:
            try:
                data = data[0]
            except IndexError:
                raise VxStreamAPIDataFormatError(url)
            tags = [i.get("vxfamily") for i in data if i.get("vxfamily") != ""]
            indicators = [(i.get("submitname"), i.get("sha256")) for i in data
                          if i.get("verdict") in ["suspicious", "malicious"]]

        return tags, indicators

    def query(self, url, param, msg):
        res = requests.get(url, **param)

        msg = msg + " - "

        if res.status_code == HTTP.OK:
            if res.headers["Content-Type"] == HTTP.json:
                null = None  # to account for potential JSON null values
                data = res.json()
                if data["response_code"] == RESPONSE_ERROR:
                    self.warn(msg + data["response"]["error"])
                elif data["response_code"] == RESPONSE_OK:
                    return data["response"]
                else:
                    self.warn(msg + "unexpected JSON response code " +
                              data["response_code"])
            else:
                self.warn(msg + "unexpected response content type " +
                          res.headers["Content-Type"])
        else:
            msg += "%s (HTTP" + res.status_code + " " + res.reason + ")"
            if res.status_code == HTTP.TooManyRequests:
                raise ModuleExecutionError(
                    msg % "API key quota has been reached")
            else:
                self.error(msg % "unspecified error")
        return None

    def info(self, msg):
        self.log("info", self.ioc + ": " + msg)

    def warn(self, msg):
        self.log("warning", self.ioc + ": " + msg)

    def error(self, msg, ):
        self.log("error", self.ioc + ": " + msg)


def operator(string):
    if ishash(string):
        return "similar-to"
    elif isipaddr(string):
        return "host"
    elif isport(string):
        return "port"
    elif isdomain(string):
        return "domain"
    else:
        # default fallback case
        return "url"


def ishash(string):
    # md5, sha-1, sha-256, sha-512
    return ishex(string) and len(string) / 2 * 8 in [128, 160, 256, 512]


def ishex(string):
    pat = r"\A" \
          r"[0-9a-fA-F]+" \
          r"\Z"
    return False if not string else \
        True if match(pat, string) else False


def isipaddr(string):
    pat = r"\A" \
          r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}" \
          r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" \
          r"\Z"
    return True if match(pat, string) else False


def isport(string):
    try:
        n = int(string)
        return n >= 0 and n < 2 ** 16
    except ValueError:
        return False


def isdomain(string):
    pat = r"\A" \
          r"([0-9a-zA-Z-]+.)+[0-9a-zA-Z-]+" \
          r"\Z"
    return False if not string else \
        True if match(pat, string) else False
