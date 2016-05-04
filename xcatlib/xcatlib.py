import contextlib
import functools
from six.moves import http_client as httplib
import socket

from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils

# from xcatlib.i18n import _
# from xcatlib.i18n import _LE
# from xcatlib.i18n import _LI
# from xcatlib import exception
# from xcatlib import exception
import exceptions as exception

LOG = logging.getLogger(__name__)

CONF = cfg.CONF


XCAT_RINV_HOST_KEYWORDS = {
    "zvm_host": "z/VM Host:",
    "zhcp": "zHCP:",
    "cec_vendor": "CEC Vendor:",
    "cec_model": "CEC Model:",
    "hypervisor_os": "Hypervisor OS:",
    "hypervisor_name": "Hypervisor Name:",
    "architecture": "Architecture:",
    "lpar_cpu_total": "LPAR CPU Total:",
    "lpar_cpu_used": "LPAR CPU Used:",
    "lpar_memory_total": "LPAR Memory Total:",
    "lpar_memory_used": "LPAR Memory Used:",
    "lpar_memory_offline": "LPAR Memory Offline:",
    "ipl_time": "IPL Time:",
    }


XCAT_RESPONSE_KEYS = ('info', 'data', 'node', 'errorcode', 'error')


class XCATUrl(object):
    """To return xCAT url for invoking xCAT REST API."""

    def __init__(self, username, password):
        """Set constant that used to form xCAT url."""
        self.PREFIX = '/xcatws'
        # username is from CONF.zvm_xcat_username and
        # password from CONF.zvm_xcat_password
        self.SUFFIX = ('?userName=' + username +
                      '&password=' + password +
                      '&format=json')

        self.NODES = '/nodes'
        self.VMS = '/vms'
        self.IMAGES = '/images'
        self.OBJECTS = '/objects/osimage'
        self.OS = '/OS'
        self.TABLES = '/tables'
        self.HV = '/hypervisor'
        self.NETWORK = '/networks'

        self.POWER = '/power'
        self.INVENTORY = '/inventory'
        self.STATUS = '/status'
        self.MIGRATE = '/migrate'
        self.CAPTURE = '/capture'
        self.EXPORT = '/export'
        self.IMGIMPORT = '/import'
        self.BOOTSTAT = '/bootstate'
        self.XDSH = '/dsh'
        self.VERSION = '/version'

    def _nodes(self, arg=''):
        return self.PREFIX + self.NODES + arg + self.SUFFIX

    def _vms(self, arg=''):
        return self.PREFIX + self.VMS + arg + self.SUFFIX

    def _hv(self, arg=''):
        return self.PREFIX + self.HV + arg + self.SUFFIX

    def rpower(self, arg=''):
        return self.PREFIX + self.NODES + arg + self.POWER + self.SUFFIX

    def nodels(self, arg=''):
        return self._nodes(arg)

    def rinv(self, arg='', addp=None):
        rurl = self.PREFIX + self.NODES + arg + self.INVENTORY + self.SUFFIX
        return self._append_addp(rurl, addp)

    def mkdef(self, arg=''):
        return self._nodes(arg)

    def rmdef(self, arg=''):
        return self._nodes(arg)

    def nodestat(self, arg=''):
        return self.PREFIX + self.NODES + arg + self.STATUS + self.SUFFIX

    def chvm(self, arg=''):
        return self._vms(arg)

    def lsvm(self, arg=''):
        return self._vms(arg)

    def chhv(self, arg=''):
        return self._hv(arg)

    def mkvm(self, arg=''):
        return self._vms(arg)

    def rmvm(self, arg=''):
        return self._vms(arg)

    def tabdump(self, arg='', addp=None):
        rurl = self.PREFIX + self.TABLES + arg + self.SUFFIX
        return self._append_addp(rurl, addp)

    def _append_addp(self, rurl, addp=None):
        if addp is not None:
            return rurl + addp
        else:
            return rurl

    def imgcapture(self, arg=''):
        return self.PREFIX + self.IMAGES + arg + self.CAPTURE + self.SUFFIX

    def imgexport(self, arg=''):
        return self.PREFIX + self.IMAGES + arg + self.EXPORT + self.SUFFIX

    def rmimage(self, arg=''):
        return self.PREFIX + self.IMAGES + arg + self.SUFFIX

    def rmobject(self, arg=''):
        return self.PREFIX + self.OBJECTS + arg + self.SUFFIX

    def lsdef_node(self, arg='', addp=None):
        rurl = self.PREFIX + self.NODES + arg + self.SUFFIX
        return self._append_addp(rurl, addp)

    def lsdef_image(self, arg='', addp=None):
        rurl = self.PREFIX + self.IMAGES + arg + self.SUFFIX
        return self._append_addp(rurl, addp)

    def imgimport(self, arg=''):
        return self.PREFIX + self.IMAGES + self.IMGIMPORT + arg + self.SUFFIX

    def chtab(self, arg=''):
        return self.PREFIX + self.NODES + arg + self.SUFFIX

    def nodeset(self, arg=''):
        return self.PREFIX + self.NODES + arg + self.BOOTSTAT + self.SUFFIX

    def rmigrate(self, arg=''):
        return self.PREFIX + self.NODES + arg + self.MIGRATE + self.SUFFIX

    def gettab(self, arg='', addp=None):
        rurl = self.PREFIX + self.TABLES + arg + self.SUFFIX
        return self._append_addp(rurl, addp)

    def tabch(self, arg='', addp=None):
        """Add/update/delete row(s) in table arg, with attribute addp."""
        rurl = self.PREFIX + self.TABLES + arg + self.SUFFIX
        return self._append_addp(rurl, addp)

    def xdsh(self, arg=''):
        """Run shell command."""
        return self.PREFIX + self.NODES + arg + self.XDSH + self.SUFFIX

    def network(self, arg='', addp=None):
        rurl = self.PREFIX + self.NETWORK + arg + self.SUFFIX
        if addp is not None:
            return rurl + addp
        else:
            return rurl

    def version(self):
        return self.PREFIX + self.VERSION + self.SUFFIX


class XCATConnection(object):
    """Https requests to xCAT web service."""

    def __init__(self):
        """Initialize https connection to xCAT service."""
        self.host = CONF.zvm_xcat_server
        self.conn = httplib.HTTPSConnection(self.host,
                        timeout=CONF.zvm_xcat_connection_timeout)

    def request(self, method, url, body=None, headers=None):
        """Send https request to xCAT server.

        Will return a python dictionary including:
        {'status': http return code,
         'reason': http reason,
         'message': response message}

        """
        headers = headers or {}
        if body is not None:
            body = jsonutils.dumps(body)
            headers = {'content-type': 'text/plain',
                       'content-length': len(body)}

        _rep_ptn = ''.join(('&password=', CONF.zvm_xcat_password))
        LOG.debug("Sending request to xCAT. xCAT-Server:%(xcat_server)s "
                  "Request-method:%(method)s "
                  "URL:%(url)s "
                  "Headers:%(headers)s "
                  "Body:%(body)s" %
                  {'xcat_server': CONF.zvm_xcat_server,
                   'method': method,
                   'url': url.replace(_rep_ptn, ''),  # hide password in log
                   'headers': str(headers),
                   'body': body})

        try:
            self.conn.request(method, url, body, headers)
        except socket.gaierror as err:
            msg = ("Failed to find address: %s") % err
            raise exception.XCATRequestFailed(xcatserver=self.host, msg=msg)
        except (socket.error, socket.timeout) as err:
            msg = ("Communication error: %s") % err
            raise exception.XCATRequestFailed(xcatserver=self.host, msg=msg)

        try:
            res = self.conn.getresponse()
        except Exception as err:
            msg = ("Failed to get response from xCAT: %s") % err
            raise exception.CATRequestFailed(xcatserver=self.host, msg=msg)

        msg = res.read()
        resp = {
            'status': res.status,
            'reason': res.reason,
            'message': msg}

        LOG.debug("xCAT response: %s" % str(resp))

        # Only "200" or "201" returned from xCAT can be considered
        # as good status
        err = None
        if method == "POST":
            if res.status != 201:
                err = str(resp)
        else:
            if res.status != 200:
                err = str(resp)

        if err is not None:
            raise exception.XCATRequestFailed(xcatserver=self.host,
                                                 msg=err)

        return resp


def xcat_request(method, url, body=None, headers=None):
    headers = headers or {}
    conn = XCATConnection()
    resp = conn.request(method, url, body, headers)
    return load_xcat_resp(resp['message'])


def jsonloads(jsonstr):
    try:
        return jsonutils.loads(jsonstr)
    except ValueError:
        errmsg = ("xCAT response data is not in JSON format")
        LOG.error(errmsg)
        raise exception.XCATInvalidResponseDataError(msg=errmsg)


@contextlib.contextmanager
def expect_invalid_xcat_resp_data():
    """Catch exceptions when using xCAT response data."""
    try:
        yield
    except (ValueError, TypeError, IndexError, AttributeError,
            KeyError) as err:
        raise exception.XCATInvalidResponseDataError(msg=err)


def wrap_invalid_xcat_resp_data_error(function):
    """Catch exceptions when using xCAT response data."""

    @functools.wraps(function)
    def decorated_function(*arg, **kwargs):
        try:
            return function(*arg, **kwargs)
        except (ValueError, TypeError, IndexError, AttributeError,
                KeyError) as err:
            raise exception.XCATInvalidResponseDataError(msg=err)

    return decorated_function


def xcat_cmd_gettab(xcaturl, table, col, col_value, attr):
    addp = ("&col=%(col)s=%(col_value)s&attribute=%(attr)s" %
            {'col': col, 'col_value': col_value, 'attr': attr})
    url = xcaturl.gettab('/%s' % table, addp)
    res_info = xcat_request("GET", url)
    with expect_invalid_xcat_resp_data():
        return res_info['data'][0][0]


def xcat_cmd_gettab_multi_attr(xcaturl, table, col, col_value, attr_list):
    attr_str = ''.join(["&attribute=%s" % attr for attr in attr_list])
    addp = ("&col=%(col)s=%(col_value)s&%(attr)s" %
            {'col': col, 'col_value': col_value, 'attr': attr_str})
    url = xcaturl.gettab('/%s' % table, addp)
    res_data = xcat_request("GET", url)['data']

    outp = {}
    with expect_invalid_xcat_resp_data():
        for attr in attr_list:
            for data in res_data:
                if attr in data[0]:
                    outp[attr] = data[0].rpartition(':')[2].strip()
                    res_data.remove(data)
                    break

    return outp


def format_exception_msg(exc_obj):
    return str(exc_obj)


@contextlib.contextmanager
def ignore_errors():
    """Only execute the clauses and ignore the results."""

    try:
        yield
    except Exception as err:
        emsg = format_exception_msg(err)
        LOG.debug("Ignore an error: %s" % emsg)
        pass


@contextlib.contextmanager
def except_xcat_call_failed_and_reraise(exc, **kwargs):
    """Catch all kinds of xCAT call failure and reraise.

    exc: the exception that would be raised.
    """
    try:
        yield
    except (exception.XCATRequestFailed,
            exception.XCATInvalidResponseDataError,
            exception.XCATInternalError) as err:
        msg = err.format_message()
        kwargs['msg'] = msg
        LOG.error(('XCAT response return error: %s'), msg)
        raise exc(**kwargs)


@wrap_invalid_xcat_resp_data_error
def translate_xcat_resp(rawdata, dirt):
    """Translate xCAT response JSON stream to a python dictionary.

    xCAT response example:
    node: keyword1: value1\n
    node: keyword2: value2\n
    ...
    node: keywordn: valuen\n

    Will return a python dictionary:
    {keyword1: value1,
     keyword2: value2,
     ...
     keywordn: valuen,}

    """
    data_list = rawdata.split("\n")

    data = {}

    for ls in data_list:
        for k in dirt.keys():
            if ls.__contains__(dirt[k]):
                data[k] = ls[(ls.find(dirt[k]) + len(dirt[k])):].strip()
                break

    if data == {}:
        msg = ("No value matched with keywords. Raw Data: %(raw)s; "
                "Keywords: %(kws)s") % {'raw': rawdata, 'kws': str(dirt)}
        raise exception.XCATInvalidResponseDataError(msg=msg)

    return data


@wrap_invalid_xcat_resp_data_error
def load_xcat_resp(message):
    """Abstract information from xCAT REST response body.

    As default, xCAT response will in format of JSON and can be
    converted to Python dictionary, would looks like:
    {"data": [{"info": [info,]}, {"data": [data,]}, ..., {"error": [error,]}]}

    Returns a Python dictionary, looks like:
    {'info': [info,],
     'data': [data,],
     ...
     'error': [error,]}

    """
    resp_list = jsonloads(message)['data']
    keys = XCAT_RESPONSE_KEYS

    resp = {}

    for k in keys:
        resp[k] = []

    for d in resp_list:
        for k in keys:
            if d.get(k) is not None:
                resp[k].append(d.get(k))

    err = resp.get('error')
    if err != []:
        for e in err:
            if _is_warning_or_recoverable_issue(str(e)):
                # ignore known warnings or errors:
                continue
            else:
                raise exception.XCATInternalError(msg=message)

    _log_warnings(resp)
    return resp


def _log_warnings(resp):
    for msg in (resp['info'], resp['node'], resp['data']):
        msgstr = str(msg)
        if 'warn' in msgstr.lower():
            LOG.info(("Warning from xCAT: %s") % msgstr)


def _is_warning_or_recoverable_issue(err_str):
    return _is_warning(err_str) or _is_recoverable_issue(err_str)


def _is_recoverable_issue(err_str):
    dirmaint_request_counter_save = ['Return Code: 596', 'Reason Code: 1185']
    recoverable_issues = [dirmaint_request_counter_save]
    for issue in recoverable_issues:
        # Search all matchs in the return value
        # any mismatch leads to recoverable not empty
        recoverable = [t for t in issue if t not in err_str]
        if recoverable == []:
            return True

    return False


def _is_warning(err_str):
    ignore_list = (
        'Warning: the RSA host key for',
        'Warning: Permanently added',
        'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED',
    )

    for im in ignore_list:
        if im in err_str:
            return True

    return False


def get_userid(xcaturl, node_name):
    """Returns z/VM userid for the xCAT node."""
    url = xcaturl.lsdef_node(''.join(['/', node_name]))
    info = xcat_request('GET', url)['info']

    with expect_invalid_xcat_resp_data():
        for s in info[0]:
            if s.__contains__('userid='):
                return s.strip().rpartition('=')[2]


def xdsh(xcaturl, node, commands):
    """"Run command on xCAT node."""
    LOG.debug('Run command %(cmd)s on xCAT node %(node)s' %
              {'cmd': commands, 'node': node})

    def xdsh_execute(node, commands):
        """Invoke xCAT REST API to execute command on node."""
        xdsh_commands = 'command=%s' % commands
        body = [xdsh_commands]
        url = xcaturl.xdsh('/' + node)
        return xcat_request("PUT", url, body)

    with except_xcat_call_failed_and_reraise(
            exception.XCATXdshFailed):
        res_dict = xdsh_execute(node, commands)

    return res_dict
