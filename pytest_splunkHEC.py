import pytest
import json
import requests
import time
import os
import datetime
import logging
import configparser


class PyHEC:

    def __init__(self, token, uri, port='8088'):
        if 'http' not in uri:
            raise ValueError("no http or https found in hostname")
        self.token = token
        self.uri = uri + ":" + port + "/services/collector/event"
        self.port = port
        self.payload = {"time": 0.0, "event": None}

    def send(self, metadata=None, **kwargs):
        headers = {'Authorization': 'Splunk ' + self.token}
        self.payload['source'] = 'utaf:'+kwargs.get('source')
        if metadata:
            self.payload.update(metadata)
        r = requests.post(self.uri, data=json.dumps(self.payload), headers=headers)
        return r.status_code, r.text

    def update_payload(self, pld):
        """
        Update payload with mandatory fields
        """
        self.payload['event'] = pld
        self.payload['time'] = time.time() - pld['execution_time']
        interval = self.get_execution_time_interval()
        pld.update(tc_start=interval[0], tc_stop=interval[1])

    def get_execution_time_interval(self):
        """
        Calculating interval of this event
        @return: interval
        @rtype: tuple
        """
        start = str(datetime.datetime.fromtimestamp(self.payload['time']))
        stop = str(
            datetime.datetime.fromtimestamp(self.payload['time'] + self.payload['event']['execution_time']))
        return start, stop


logger = logging.getLogger('SplunkHecHandler')

hec = None


def pytest_addoption(parser):
    """
    To switch on data collection and sending to splunk
    add -- splunk followed by token and uri
    """
    parser.addoption("--splunk", action='store_true',
                     help="Splunk token and uri")
    parser.addoption("--splunk_cfg", dest="filename", help='Path to splunk config')


def generate_splunk_report(report, pld):
    """
    Gen payload with mandatory fields, from report obj
    and cli args
    @param report: pytest report object
    @param options: dictionary with cli args
    """

    tc_module = report.nodeid.split('::')
    pld.update(TC_Module=tc_module[1], TC_Name=tc_module[2])
    pld.update(failed=report.failed, passed=report.passed, skipped=report.skipped)
    add_info = report.longreprtext[:2000] + " TRUNCATED " + report.longreprtext[-3000:] \
        if len(report.longreprtext) > 5000 else report.longreprtext
    pld.update(additional_info=add_info)
    pld.update(JENKINS_URL=os.environ.get("BUILD_URL"))
    pld.update(execution_time=report.duration)
    pld.update(extract_marks(report))
    return pld


def merge_cli_and_ini_args(cfg):
    """
    Merge command line arguments with ini, cli in priority
    @param cfg: pytest cfg file
    @return: dict of merged attr
    @rtype: dict
    """
    options = vars(cfg.option)
    mandatory_fields = ['platform', 'tsn', 'test_environment', 'manage_id', 'branch', 'device_ip', 'mso', 'build',
                        'morpheus_rls', "hsn", "os_version", "device_model", "ca_device_id"]
    pld = {}
    for i in mandatory_fields:
        try:
            if options.get(i):
                opt = options.get(i)
            else:
                opt = cfg.getini(i)
            pld[i] = opt
        except Exception:
            logger.error("Couldn't find cfg {}".format(i))

    pld.update(suite=options['markexpr'])
    return pld


def get_path(opt=None):
    """
    Build path to splunk.cfg file from DIR var
    @return: path to .cfg
    @rtype: str
    """
    dir = os.environ.get("DIR")
    pth = os.path.join(dir, 'splunk.cfg') if dir else 'splunk.cfg'
    if os.path.exists(pth):
        return pth
    else:
        try:
            return os.path.expandvars(opt.get('filename'))
        except Exception:
            logger.info("Couldn't find splunk cfg")


def read_cfg(pth):
    """
    Seeking for token and host in .cfg file
    @param pth: path to file
    @type pth: basestring
    @return: token and URI
    @rtype: tuple
    """
    global token, uri, source
    if not (token and uri and source):
        cfg = configparser.ConfigParser()
        cfg.read(pth)
        default = cfg['DEFAULT']
        return default['Token'], default['Host'], default['Source']
    return token, uri, source


def extract_marks(report):
    """
    Extracting marks which was used when tc executed
    @param report: pytest object
    @return: dict with list of markers
    @rtype: dict
    """
    markers = pytest.mark._markers
    payload = {"markers": [], "misc": []}
    misc = ['timeout', 'skip', 'skipif', 'usefixtures',  'repeat', 'testrail', 'BAT_1', 'BAT_2', 'devhost', 'e2e',
            'not_devhost', 'notapplicable', 'p1_regression', 'parametrize', 'sanity', 'test_stabilization', 'testrail',
            'xfail', 'flaky']
    for i, _ in report.keywords.items():
        try:
            if i in misc:
                payload['misc'].append(i)
            elif i in markers:
                payload['markers'].append(i)
        except Exception:
            pass
    return payload


token = None
uri = None
source = None


def pytest_report_teststatus(report, config):
    """
    Send splunk report after each tc execution
    @param report: pytest report object
    @param config: pytest config object
    """
    global hec, token, uri, source
    opt = vars(config.option)
    try:
        if opt['splunk']:
            pth = get_path(opt)
            if pth:
                token, uri, source = read_cfg(pth)
                if report.when == 'setup':
                    hec = PyHEC(token, uri)
                elif report.when == 'call' and hec is not None:
                    try:
                        hec.update_payload(generate_splunk_report(report, merge_cli_and_ini_args(config)))
                        status, answer = hec.send(source=source)
                        logger.info("Answer from splunk backend: {}".format(answer))
                    except Exception as e:
                        logger.info("Posting splunk report failed, pld was: {}, exception {}".format(hec.payload, e))
                    finally:
                        hec = None
        else:
            logger.info("To post reports to splunk define --splunk_cfg and --splunk cli")
    except Exception:
        pass
