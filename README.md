# VxFame
*VxFame* is the name given to the project that integrates [FAME](https://certsocietegenerale.github.io/fame/), an open-source malware analysis framework written in Python 2.7.x, with the RESTful Application Programming Interface (API) of [VxStream Sandbox](https://www.vxstream-sandbox.com/), an online sandbox for malware analysis belonging to Payload Security. The project relates to **two FAME modules** that integrate with the API of VxStream Sandbox, one being a **processing module** and the other a **threat intelligence module**. The processing module is under `vxstream` while the threat intelligence module is under `intelligence`. The structure of the modules are valid with the [FAME development instructions](https://fame.readthedocs.io/en/latest/modules.html) and are as follows:
* `vxstream/__init__.py`: empty file that identifies `vxstream` as a valid Python package to be recognized by FAME;
* `vxstream/details.html`: HTML and Jinja2 template code for displaying results graphically in the web interface;
* `vxstream/requirements.txt`: list of Python dependencies that the module uses, depicting only [`requests`](https://github.com/requests/requests) for HTTP interaction;
* `vxstream/vxstream.py`: the Python entry point of the **processing module** that integrates with the API of VxStream Sandbox;
* `intelligence/vxstream.py`: the Python entry point of the **threat intelligence module** that integrates with the API of VxStream Sandbox.

Both modules were developed while considering both the usefulness and completeness of their functionality with the VxStream Sandbox API in relation to the FAME framework. These considerations are realized in the modules as features of analysis of malware and URLs and of retrieval of reports and data, which constitute the purpose of the modules as set by FAME. FAME is licensed under GNU GPLv3 and its source code is available at its [main GitHub repository](https://github.com/certsocietegenerale/fame). Most modules developed for FAME are also licensed under GNU GPLv3 and are available at a [second GitHub repository](https://github.com/certsocietegenerale/fame_modules). FAME is documented at [Read the Docs](https://fame.readthedocs.io/en/latest/).

The `vxstream/vxstream.py` and `vxstream/details.html` files are described in detail in the next two sections, respectively. The sections that follow describe `vxstream.py` and list all the API resources used by the module. The next to last section overviews the usage of the module, while the very last one lists resources consulted throughout development.

# `vxstream/vxstream.py`
Most modules developed for FAME are subclasses of `ProcessingModule`, which is meant to be the base class for modules that perform some automated analysis of files or URLs. The purpose of `vxstream` fits the role of `ProcessingModule` and is therefore a subclass of it called `VxStream`. The next subsections compartmentalize the description of the module in terms of methods, variables and general workflow of its execution.

## Methods
The **methods** of the module can be described as follows, in the same order as they appear in the source code:
* `initialize`: checks for the presence of `requests` during module initialization;
* `each_with_type`: defines the workflow of an analysis for each file or URL;
* `submit`: submits a file or URL for analysis to `/api/submit` or `/api/submiturl`, respectively;
* `heartbeat`: checks the status of an analysis on `/api/state` according to a timeout value;
* `report`: retrieves the report of an analysis from `/api/scan`, downloads additional data from `/api/result` and populates `self.results`;
* `result`: wraps `download` to target `/api/result/` and to register downloaded files;
* `dropped`: wraps `download` to target `/api/sample-dropped-files` and to mark extracted files;
* `download`: handles downloaded files according to a certain compression algorithm and marks decompressed files as support files;
* `post`: wraps `query` to change the type of HTTP request to `POST`;
* `query`: conducts HTTP `GET` (default) or `POST` requests to the VxStream Sandbox API and handles predefined response errors;
* `debug`, `inf`, `warn` and `error`: logs debug, informational, warning and error messages, respectively.

## Variables
The module is developed with consistency in terms of nomenclature and purpose, particularly in **variables** used in different methods that have the same purpose. Some of those are described as follows:
* `data`: `dict` with parsed JSON data or `str` with binary response data from a HTTP request;
* `msg`: `str` holding an error message to be logged;
* `param`: `dict` with `requests` fields for HTTP requests with `requests.get` or `requests.post`;
* `url`: `str` with the full URL of the API resource to be queried, excluding HTTP `GET` parameters.

Another set of **instance variables** have a module-wide scope. Of note are all module configurations that are set as instance variables by FAME, as well as the following:
* `self.headers`: `dict` with the HTTP header field for HTTP queries;
* `self.results`: `dict` with summary results of an analysis to be presented in the web interface as required by FAME;
* `self.state`: `str` holding a symbolic identifier of the current state of the module (*i.e.*, `module` or a hash value of a submission).

## Execution Workflow
A **general workflow** of the execution of `VxStream` is as follows:
1. retrieve available analysis environments and check if the one specified in the module configuration is valid;
2. submit a file or a URL for analysis;
3. wait for an analysis to finish or timeout;
4. retrieve an analysis report;
5. populate the malware signature, sample tags and Indicators of Compromise (IOCs);
6. download all files dropped during an analysis, the full HTML report, and potentially a memory dump and a network traffic capture;
7. finally populate `self.results` with an analysis summary.

# `vxstream/details.html`
Some FAME modules can present results graphically to the user via the web interface. This is the case of `VxStream` where summary results of an analysis are retrieved from the `/api/scan` API resource and then shown in the analysis page of a certain submission. This Python and HTML integration is achieved via the Jinja2 templating language that, in the case of FAME modules, pertains mainly to the `self.results` instance variable. The `vxstream` module shows all data points that populate this variable, as well as download URLs for the full HTML report and support files of an analysis, namely a memory dump and a network traffic capture.

# `intelligence/vxstream.py`
The threat intelligence module is called `VxStreamIntelligence` and is a subclass of `ThreatIntelligenceModule`, which is a class meant to enrich analyses by adding information on Indicators of Compromised (IOC) retrieved during analyzes. Threat intelligence modules share some variables and methods from the base module class of FAME and are simpler than processing modules because their goal is only to query for additional data that characterizes IOC. Some methods and variables of `VxStreamIntelligence` are the same as in `VxStream`.

One the one hand, distinct **methods** of `VxStreamIntelligence` are described as follows:
* `ioc_lookup`: retrieves information on passed IOC on `/api/search` and populates `tags` and `indicators` with the results;
* `operator`: determines which IOC type (*i.e.*, hash value, IP address, port number or domain) is passed through the use o regular expressions.

On the other hand, noteworthy **variables** are described as follows:
* `tags`: `list` of `str` with tags characterizing an indicator;
* `indicators`: `list` of `dict` with a name and a description of the indicator.

# VxStream Sandbox API List
The `VxStream` and `VxStreamIntelligence` modules consume a selected few API resources from VxStream Sandbox to achieve their integration with FAME and thereby fulfill their purpose of malware analysis and reporting. The **full list** and description of API resources used by the modules is, in alphabetical order, the following:
* `/api/result`: used to retrieve particular result data of an analysis, namely full HTML reports, memory dumps and network traffic captures;
* `/api/sample-dropped-files/`: used to download potentially malicious files dropped during an analysis;
* `/api/scan`: used to retrieve summary information of an analysis;
* `/api/search`: used to search for data characterizing indicators;
* `/api/submit`: used to submit a file for analysis;
* `/api/submiturl`: used to submit a URL for analysis;
* `/api/state`: used to retrieve status information of an analysis;
* `/system/state`: used to determine the available analysis environments.

# Usage
The installation of FAME is not complicated and can be accomplished by following the instructions at [Read the Docs](https://fame.readthedocs.io/en/latest/). As a modular framework, it provides means to support the development of additional modules in two manners:
* fully integrated into the framework by utilizing the Flask web interface to create new analyzes and to visualize results that are saved onto its MongoDB database using a Celery task queue; or
* offline testing without resorting to any of its main components by resorting to a helper Python script suitable for repeated usage.

Once FAME is installed and properly configured, running the framework from within its main folder `fame` is attainable by first instantiating the webserver, as such:
```
$ ./utils/run.sh webserver.py
```
The web interface is then available at http://127.0.0.1:4200/, if FAME is configured to run on the local system. Analysis submissions require one or more separate workers to be launched. FAME workers handle task queues and make sure that module dependencies are met before actually launching modules. One worker is launched with the following command:
```
$ ./utils/run.sh worker.py
```
Modules need to be placed at `modules/community/` in order to be recognized by FAME and subsequently be listed on the web interface as working modules, provided that they pass syntax and validation checks. The framework detects changes to modules if it is already running. In the case of `vxstream`, its location within the module folder tree is `modules/community/processing/vxstream`. The threat intelligence module `VxStreamIntelligence` is placed under `modules/community/threat_intelligence/vxstream.py`.

The second, offline testing option is more convenient to run modules under development or to check their output structure. The helper utility allows to specify only one module for testing against one file alone. In this case, module checks are performed every time the helper utility is run, which is accomplished for `vxstream` as follows:
```
$ ./utils/run.sh utils/single_module.py -t vxstream <file>
```

Unfortunately, FAME does not provide a way to test threat intelligence modules, and so the usage explained above applies only to processing module.

# Resources
https://certsocietegenerale.github.io/fame/<br />
https://github.com/certsocietegenerale/fame<br />
https://github.com/certsocietegenerale/fame_modules<br />
https://fame.readthedocs.io/en/latest/
