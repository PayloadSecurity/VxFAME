from os import path, remove
from time import sleep
from gzip import open as gzopen
from zipfile import ZipFile
from requests.auth import HTTPBasicAuth

from fame.core.module import ProcessingModule
from fame.common.utils import tempdir
from fame.common.exceptions import ModuleInitializationError, \
    ModuleExecutionError

try:
    import requests

    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

RESPONSE_OK = 0
RESPONSE_ERROR = -1

GZIP = ".gz"
ZIP = ".zip"


class HTTP:
    OK = 200
    BadRequest = 400
    TooManyRequests = 429
    json = "application/json"
    octetstream = "application/octet-stream"


class Environment:
    apk = "ANDROID"
    nix = "LINUX"
    win = "WINDOWS"


class VxStreamAPIDataFormatError(ModuleExecutionError):
    err = "API response data format differs for "

    def __init__(self, msg):
        super(VxStreamAPIDataFormatError, self).__init__(self.err + msg)


class VxStream(ProcessingModule):
    name = "vxstream"
    description = "VxStream Sandbox features in-depth static and dynamic " \
                  "analysis techniques within sandboxed environments and is a " \
                  "malware repository created by Payload Security."

    acts_on = ["apk", "eml", "excel", "executable", "html", "jar",
               "javascript", "msg", "pdf", "powerpoint", "word", "zip"]
    acts_on += [
        "application/arj",  # arj
        "application/octet-stream",  # wim
        "application/vnd.ms-htmlhelp",  # chm
        "application/x-7z-compressed",  # 7z
        "application/x-ace-compressed",  # ace
        "application/x-bzip2",  # bzip2
        "application/x-executable",  # elf
        "application/x-gzip",  # gzip2
        "application/x-iso9660-image",  # iso
        "application/x-ms-shortcut",  # lnk
        "application/x-mspublisher",  # pub
        "application/x-perl",  # pl
        "application/x-rar-compressed",  # rar, rev
        "application/x-shockwave-flash",  # swf
        "application/x-tar",  # tar
        "application/x-xz"  # xz
        "application/xml",  # sct, wsf
        "image/svg+xml",  # svg
        "text/html",  # hta
        "text/plain",  # ps1, psd1, psm1, vbe, vbs
        "text/x-python"  # py
    ]

    generates = ["memory_dump", "pcap"]

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
        },
        {
            "name": "environmentId",
            "type": "integer",
            "default": 100,
            "description": "Environment setting where analyses are run.",
            "option": True
        },
        {
            "name": "extractfiles",
            "type": "bool",
            "default": True,
            "description": "Downloads files extracted from an analysis upon "
                           "retrieval of the report.",
            "option": True
        },
        {
            "name": "graceperiod",
            "type": "integer",
            "default": 300,
            "description": "Grace period value in seconds of the analysis "
                           "startup window.",
        },
        {
            "name": "html",
            "type": "bool",
            "default": True,
            "description": "Downloads a HTML page of an analysis upon "
                           "retrieval of the report.",
            "option": True
        },
        {
            "name": "hybridanalysis",
            "type": "bool",
            "default": True,
            "description": "Enables memory dump and its automated analysis for "
                           "file submissions.",
            "option": True
        },
        {
            "name": "interval",
            "type": "integer",
            "default": 30,
            "description": "Interval in seconds of the heartbeat check for an "
                           "analysis report."
        },
        {
            "name": "memory",
            "type": "bool",
            "default": False,
            "description": "Downloads a memory dump of an analysis upon "
                           "retrieval of the report.",
            "option": True
        },
        {
            "name": "nosharevt",
            "type": "bool",
            "default": False,
            "description": "Disallow third-party downloads of the sample "
                           "submitted for analysis."
        },
        {
            "name": "pcap",
            "type": "bool",
            "default": False,
            "description": "Downloads a network traffic capture of an analysis "
                           "upon retrieval of the report.",
            "option": True
        },
        {
            "name": "timeout",
            "type": "integer",
            "default": 600,
            "description": "Timeout value in seconds of the wait time for the "
                           "end of an analysis after the grace period."
        },
        {
            "name": "torenabledanalysis",
            "type": "bool",
            "default": False,
            "description": "Network traffic generated during analysis is routed "
                           "through The Onion Router (TOR) network for file "
                           "submissions.",
            "option": True
        }
    ]

    permissions = {
        "vxstream_access": "For users that have access to the VxStream Sandbox "
                           "instance. It displays a URL to the analysis on "
                           "VxStream Sandbox."
    }

    def initialize(self):
        # check dependencies
        if not HAVE_REQUESTS:
            raise ModuleInitializationError(self,
                                            "Missing dependency: requests")

    def each_with_type(self, target, type):
        self.headers = {
            "User-agent": "FAME (https://github.com/certsocietegenerale/fame) "
                          "VxStream Sandbox Processing Module"
        }
        self.results = {}
        self.state = "module"

        url = self.url + "system/state"
        param = {
            "params": {
                "apikey": self.apikey,
                "secret": self.secret
            },
            "headers": self.headers
        }
        msg = "unsuccessful system state query"

        data = self.query(url, param, msg, json=True)

        if data:
            try:
                data = data["backend"]["nodes"][0]["environment"]
            except (KeyError, IndexError):
                raise VxStreamAPIDataFormatError(url)
            msg = "invalid or unavailable analysis environment(s)"

            if type == "apk":
                env = Environment.apk
            elif type == "application/x-executable":
                env = Environment.nix
            else:  # url, windows
                env = Environment.win

            tmp = [i.get("ID") for i in data if i.get("architecture") == env]
            if not self.environmentId in tmp or not tmp:
                raise ModuleExecutionError(msg)
        else:
            self.warn("using configured analysis environment")

        # submit file or url for analysis
        self.submit(target, type)
        # wait for the analysis to be over
        self.heartbeat()
        # retrieve the report and populate results
        self.report()

        return True

    def submit(self, target, type):
        url = self.api + "submit"
        param = {
            "auth": HTTPBasicAuth(self.apikey, self.secret),
            "data": {
                "environmentId": self.environmentId,
                "hybridanalysis": ("false", "true")[self.hybridanalysis],
                "nosharevt": ("false", "true")[self.nosharevt],
                "torenabledanalysis": ("false", "true")[self.torenabledanalysis]
            },
            "headers": self.headers,
            "verify": False
        }
        msg = "unsuccessful file submission"

        if type == "url":
            url += "url"
            param["data"]["analyzeurl"] = target
            # elif type == "apk":
            # nothing changes
        #    pass
        else:  # apk, windows
            param["files"] = {"file": open(target, 'rb')}

        data = self.post(url, param, msg, json=True)

        if data:
            try:
                self.state = data["sha256"]
            except KeyError:
                raise VxStreamAPIDataFormatError(url)
            self.inf("successful file submission")
        else:
            raise ModuleExecutionError(msg + ", exiting")

    def heartbeat(self):
        url = self.api + "state/" + self.state
        param = {
            "params": {
                "apikey": self.apikey,
                "secret": self.secret,
                "environmentId": self.environmentId
            },
            "headers": self.headers
        }
        msg = "unsuccessful heartbeat check"

        try:
            self.timeout = int(self.timeout)
            if self.timeout < 0:
                raise ValueError
        except ValueError:
            self.warn("invalid timeout (%s) value, "
                      "using default value of 600 seconds" % self.timeout)
            self.timeout = 600
        try:
            self.graceperiod = int(self.graceperiod)
            if self.graceperiod < 0:
                raise ValueError
        except ValueError:
            self.warn("invalid grace period (%s) value, "
                      "using default value of 300 seconds" % self.graceperiod)
            self.graceperiod = 300

        self.inf("waiting %s seconds before checking the analysis status"
                 % self.graceperiod)
        sleep(self.graceperiod)

        stopwatch = 0
        while stopwatch < self.timeout:
            data = self.query(url, param, msg, json=True)
            try:
                if data and data["state"] == "SUCCESS":
                    break
            except KeyError:
                raise VxStreamAPIDataFormatError(url)

            if stopwatch + self.interval <= self.timeout:
                tmp = self.interval
            else:
                tmp = self.timeout - stopwatch

            self.inf("analysis has not finished yet, waiting " +
                     str(self.timeout - stopwatch) + " more seconds")

            sleep(tmp)
            stopwatch += tmp

        if stopwatch >= self.timeout:
            raise ModuleExecutionError("report retrieval timed out")

        self.inf("analysis finished, retrieving report")

    def report(self):
        url = self.api + "scan/" + self.state
        param = {
            "params": {
                "apikey": self.apikey,
                "secret": self.secret,
                "environmentId": self.environmentId,
                "type": "json"
            },
            "headers": self.headers
        }
        msg = "unsuccessful report retrieval"

        data = self.query(url, param, msg, json=True)

        if data:
            try:
                data = data[0]
            except IndexError:
                raise VxStreamAPIDataFormatError(url)

            # signature
            self.add_probable_name(data.get("vxfamily"))
            self.results["signatures"] = data.get("vxfamily")
            # tags
            for t in data.get("classification_tags"):
                self.add_tag(t)
            # iocs
            ioc = set()
            if data.get("compromised_hosts"):
                ioc |= set(data["compromised_hosts"])
            if data.get("domains"):
                ioc |= set(data["domains"])
            if data.get("hosts"):
                ioc |= set(data["hosts"])
            for i in ioc:
                self.add_ioc(i)
            # extracted files
            if self.extractfiles:
                self.dropped(param, "dropped.zip", "Dropped Files", ZIP)
            # html
            if self.html:
                param["params"]["type"] = "html"
                self.result(param, "html", "Full Report", GZIP)
            # memory
            if self.memory:
                param["params"]["type"] = "memory"
                self.result(param, "raw", "Memory Dump", ZIP,
                            register="memory_dump")
            # pcap
            if self.pcap:
                param["params"]["type"] = "pcap"
                self.result(param, "pcap", "PCAP", GZIP,
                            register="pcap")
            # results
            self.results["analysis_start_time"] = data.get(
                "analysis_start_time")
            self.results["avdetect"] = data.get("avdetect")
            self.results["environmentDescription"] = data.get(
                "environmentDescription")
            self.results["environmentId"] = data.get("environmentId")
            self.results["isinteresting"] = data.get("isinteresting")
            self.results["size"] = data.get("size")
            self.results["submitname"] = data.get("submitname")
            self.results["threatlevel"] = data.get("threatlevel")
            self.results["threatscore"] = data.get("threatscore")
            self.results["total_network_connections"] = data.get(
                "total_network_connections")
            self.results["total_processes"] = data.get("total_processes")
            self.results["total_signatures"] = data.get("total_signatures")
            self.results["type"] = data.get("type")
            self.results["URL"] = self.url + "sample/" + self.state + \
                                  "?environmentId=" + str(self.environmentId)
            self.results["verdict"] = data.get("verdict")
        else:
            self.error("report response data invalid: " + str(data))

    def result(self, *arg, **kwarg):
        url = self.api + "result/" + self.state
        files = self.download(url, *arg)
        for i in files:
            self.add_support_file(arg[2], i)
        if files and kwarg.get("register"):
            self.register_files(kwarg["register"], files)

    def dropped(self, *arg):
        url = self.api + "sample-dropped-files/" + self.state
        files = self.download(url, *arg)
        # self.add_extraction(label, extraction)
        if files:
            for i in files:
                self.add_extracted_file(i)

    def download(self, url, param, ext, name, compression):
        files, tmp = [], []
        msg = "unsuccessful download of the " + name
        data = self.query(url, param, msg, bin=True)
        if data:
            ext = "." + ext
            tmpdir = tempdir()
            file = path.join(tmpdir, self.state + ext)
            decompressed = file

            if compression == GZIP:
                file += GZIP
            elif compression == ZIP:
                file += ZIP

            with open(file, 'wb') as fd:
                fd.write(data)

            if compression == GZIP:
                with gzopen(file, 'rb') as gz:
                    with open(decompressed, 'wb') as fd:
                        fd.write(gz.read())
                remove(file)
                tmp += [decompressed]
            elif compression == ZIP:
                zip = ZipFile(file, 'r')
                for i in zip.namelist():
                    tmp += [zip.extract(i, tmpdir)]
                zip.close()
                remove(file)

            files = [i for i in tmp if not i.endswith(GZIP)]
            for i in [i for i in tmp if i.endswith(GZIP)]:
                file = i[:-len(GZIP)]
                with gzopen(i, 'rb') as gz:
                    with open(file, 'wb') as fd:
                        fd.write(gz.read())
                remove(i)
                files += [file]

        return files

    def post(self, url, param, msg, json=False, bin=False):
        return self.query(url, param, msg, post=True, json=json, bin=bin)

    def query(self, url, param, msg, post=False, json=False, bin=False):
        if not post:
            res = requests.get(url, **param)
        else:
            res = requests.post(url, **param)

        msg = msg + " - "

        if res.status_code == HTTP.OK:
            if res.headers["Content-Type"] == HTTP.json:
                null = None  # to account for potential JSON null values
                data = res.json()
                if data["response_code"] == RESPONSE_ERROR:
                    self.warn(msg + data["response"]["error"])
                elif data["response_code"] == RESPONSE_OK and json:
                    return data["response"]
                else:
                    self.warn(msg + "unexpected JSON response code " +
                              data["response_code"])
            elif res.headers["Content-Type"] == HTTP.octetstream and bin:
                return res.content
            else:
                self.warn(msg + "unexpected response content type " +
                          res.headers["Content-Type"])
        else:
            msg += "%s (HTTP" + res.status_code + " " + res.reason + ")"
            if res.status_code == HTTP.BadRequest:
                self.error(msg % "file submission error")
            elif res.status_code == HTTP.TooManyRequests:
                raise ModuleExecutionError(
                    msg % "API key quota has been reached")
            else:
                self.error(msg % "unspecified error")
        return None

    def debug(self, msg):
        self.log("debug", self.state + ": " + msg)

    def inf(self, msg):
        self.log("info", self.state + ": " + msg)

    def warn(self, msg):
        self.log("warning", self.state + ": " + msg)

    def error(self, msg, ):
        self.log("error", self.state + ": " + msg)
