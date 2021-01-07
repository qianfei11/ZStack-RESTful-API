import re
import sys

try:
    import urllib3
except ImportError:
    print 'urlib3 is not installed, run "pip install urlib3"'
    sys.exit(1)

import string
import json
from uuid import uuid4
import time
import threading
import functools
import traceback
import base64
import hmac
import sha
from hashlib import sha1
import datetime
import time

CONFIG_HOSTNAME = 'hostname'
CONFIG_PORT = 'port'
CONFIG_POLLING_TIMEOUT = 'default_polling_timeout'
CONFIG_POLLING_INTERVAL = 'default_polling_interval'
CONFIG_WEBHOOK = 'webhook'
CONFIG_READ_TIMEOUT = 'read_timeout'
CONFIG_WRITE_TIMEOUT = 'write_timeout'
CONFIG_CONTEXT_PATH = 'context_path'

HEADER_JOB_UUID = "X-Job-UUID"
HEADER_WEBHOOK = "X-Web-Hook"
HEADER_JOB_SUCCESS = "X-Job-Success"
HEADER_AUTHORIZATION = "Authorization"
HEADER_REQUEST_IP = "X-Request-Ip";
OAUTH = "OAuth"
LOCATION = "location"

HTTP_ERROR = "sdk.1000"
POLLING_TIMEOUT_ERROR = "sdk.1001"
INTERNAL_ERROR = "sdk.1002"

__config__ = {}


class SdkError(Exception):
    pass


def _exception_safe(func):
    @functools.wraps(func)
    def wrap(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except:
            print traceback.format_exc()

    return wrap


def _error_if_not_configured():
    if not __config__:
        raise SdkError('call configure() before using any APIs')


def _http_error(status, body=None):
    err = ErrorCode()
    err.code = HTTP_ERROR
    err.description = 'the http status code[%s] indicates a failure happened' % status
    err.details = body
    return {'error': err}


def _error(code, desc, details):
    err = ErrorCode()
    err.code = code
    err.desc = desc
    err.details = details
    return {'error': err}


def configure(
        hostname='127.0.0.1',
        context_path=None,
        port=8080,
        polling_timeout=3600*3,
        polling_interval=1,
        read_timeout=15,
        write_timeout=15,
        web_hook=None
):
    __config__[CONFIG_HOSTNAME] = hostname
    __config__[CONFIG_PORT] = port
    __config__[CONFIG_POLLING_TIMEOUT] = polling_timeout
    __config__[CONFIG_POLLING_INTERVAL] = polling_interval
    __config__[CONFIG_WEBHOOK] = web_hook
    __config__[CONFIG_READ_TIMEOUT] = read_timeout
    __config__[CONFIG_WRITE_TIMEOUT] = write_timeout
    __config__[CONFIG_CONTEXT_PATH] = context_path


class ParamAnnotation(object):
    def __init__(
            self,
            required=False,
            valid_values=None,
            valid_regex_values=None,
            max_length=None,
            min_length=None,
            non_empty=None,
            null_elements=None,
            empty_string=None,
            number_range=None,
            no_trim=False
    ):
        self.required = required
        self.valid_values = valid_values
        self.valid_regex_values = valid_regex_values
        self.max_length = max_length
        self.min_length = min_length
        self.non_empty = non_empty
        self.null_elements = null_elements
        self.empty_string = empty_string
        self.number_range = number_range
        self.no_trim = no_trim


class ErrorCode(object):
    def __init__(self):
        self.code = None
        self.description = None
        self.details = None
        self.cause = None


class Obj(object):
    def __init__(self, d):
        for a, b in d.items():
            if isinstance(b, (list, tuple)):
                setattr(self, a, [Obj(x) if isinstance(x, dict) else x for x in b])
            else:
                setattr(self, a, Obj(b) if isinstance(b, dict) else b)

    def __getattr__(self, item):
        return None


class AbstractAction(object):
    def __init__(self):
        self.apiId = None
        self.sessionId = None
        self.requestIp = None
        self.systemTags = None
        self.userTags = None
        self.timeout = None
        self.pollingInterval = None

        self._param_descriptors = {
            'systemTags': ParamAnnotation(),
            'userTags': ParamAnnotation()
        }

        self._param_descriptors.update(self.PARAMS)

    def _check_params(self):
        for param_name, annotation in self._param_descriptors.items():
            value = getattr(self, param_name, None)

            if value is None and annotation.required:
                raise SdkError('missing a mandatory parameter[%s]' % param_name)

            if value is not None and annotation.valid_values and value not in annotation.valid_values:
                raise SdkError('invalid parameter[%s], the value[%s] is not in the valid options%s' % (param_name, value, annotation.valid_values))

            if value is not None and isinstance(value, str) and annotation.max_length and len(value) > annotation.max_length:
                raise SdkError('invalid length[%s] of the parameter[%s], the max allowed length is %s' % (len(value), param_name, annotation.max_length))

            if value is not None and isinstance(value, str) and annotation.min_length and len(value) > annotation.min_length:
                raise SdkError('invalid length[%s] of the parameter[%s], the minimal allowed length is %s' % (len(value), param_name, annotation.min_length))

            if value is not None and isinstance(value, list) and annotation.non_empty is True and len(value) == 0:
                raise SdkError('invalid parameter[%s], it cannot be an empty list' % param_name)

            if value is not None and isinstance(value, list) and annotation.null_elements is True and None in value:
                raise SdkError('invalid parameter[%s], the list cannot contain a null element' % param_name)

            if value is not None and isinstance(value, str) and annotation.empty_string is False and len(value) == 0:
                raise SdkError('invalid parameter[%s], it cannot be an empty string' % param_name)

            if value is not None and (isinstance(value, int) or isinstance(value, long)) \
                    and annotation.number_range is not None and len(annotation.number_range) == 2:
                low = annotation.number_range[0]
                high = annotation.number_range[1]
                if value < low or value > high:
                    raise SdkError('invalid parameter[%s], its value is not in the valid range' % annotation.number_range)

            if value is not None and isinstance(value, str) and annotation.no_trim is False:
                value = str(value).strip()
                setattr(self, param_name, value)

        if self.NEED_SESSION:
            if self.sessionId is None and (self.accessKeyId is None or self.accessKeySecret is None):
                raise SdkError('sessionId or accessKey must be provided')

    def _params(self):
        ret = {}
        for k, _ in self._param_descriptors.items():
            val = getattr(self, k, None)
            if val is not None:
                ret[k] = val

        return ret

    def _query_string(self, params):
        queryParams = {}
        for k, v in params.items():
            if k == "accessKeySecret":
                continue
            if k == "accessKeyId":
                continue
            queryParams[k] = v
        return '&'.join(['%s=%s' % (k, v) for k, v in queryParams.items()])

    def _url(self):
        elements = ['http://', __config__[CONFIG_HOSTNAME], ':', str(__config__[CONFIG_PORT])]
        context_path = __config__.get(CONFIG_CONTEXT_PATH, None)
        if context_path is not None:
            elements.append(context_path)
        elements.append('/v1')

        path = self.PATH.replace('{', '${')
        unresolved = re.findall('${(.+?)}', path)
        params = self._params()
        if unresolved:
            for u in unresolved:
                if u in params:
                    raise SdkError('missing a mandatory parameter[%s]' % u)

        path = string.Template(path).substitute(params)
        elements.append(path)

        if self.HTTP_METHOD == 'GET' or self.HTTP_METHOD == 'DELETE':
            elements.append('?')
            elements.append(self._query_string(params))

        return ''.join(elements), unresolved

    def calculateAccessKey(self, url, date):
        # url example:  http://127.0.0.1:8080/zstack/v1/vminstances/uuid?xx
        elements = url.split(":")
        path = elements[2].split("/", 2)
        path = path[2].split("?")

        h = hmac.new(self.accessKeySecret, self.HTTP_METHOD + "\n"
            + date + "\n"
            + "/" + path[0], sha1)
        Signature = base64.b64encode(h.digest())
        return "ZStack %s:%s" % (self.accessKeyId, Signature)

    def call(self, cb=None):

        def _return(result):
            if cb:
                cb(result)
            else:
                return result

        _error_if_not_configured()

        self._check_params()
        url, params_in_url = self._url()

        headers = {}
        if self.apiId is not None:
            headers[HEADER_JOB_UUID] = self.apiId
        else:
            headers[HEADER_JOB_UUID] = _uuid()

        date = time.time()
        datestr = datetime.datetime.fromtimestamp(date).strftime('%a, %d %b %Y %H:%M:%S CST')

        if self.requestIp is not None:
            headers[HEADER_REQUEST_IP] = self.requestIp

        if self.NEED_SESSION:
            if self.sessionId is not None:
                headers[HEADER_AUTHORIZATION] = "%s %s" % (OAUTH, self.sessionId)
            else :
                headers["Date"] = datestr
                headers[HEADER_AUTHORIZATION] = self.calculateAccessKey(url, datestr)

        web_hook = __config__.get(CONFIG_WEBHOOK, None)
        if web_hook is not None:
            headers[CONFIG_WEBHOOK] = web_hook

        params = self._params()
        body = None
        if self.HTTP_METHOD == 'POST' or self.HTTP_METHOD == 'PUT':
            m = {}
            for k, v in params.items():
                if v is None:
                    continue

                if k == 'sessionId':
                    continue

                if k == 'accessKeyId':
                    continue

                if k == 'accessKeySecret':
                    continue

                if k in params_in_url:
                    continue

                m[k] = v

            body = {self.PARAM_NAME: m}

        if not self.timeout:
            self.timeout = __config__[CONFIG_READ_TIMEOUT]

        rsp = _json_http(uri=url, body=body, headers=headers, method=self.HTTP_METHOD, timeout=self.timeout)

        if rsp.status < 200 or rsp.status >= 300:
            return _return(Obj(_http_error(rsp.status, rsp.data)))
        elif rsp.status == 200 or rsp.status == 204:
            # the API completes
            return _return(Obj(self._write_result(rsp)))
        elif rsp.status == 202:
            # the API needs polling
            return self._poll_result(rsp, cb)
        else:
            raise SdkError('[Internal Error] the server returns an unknown status code[%s], body[%s]' % (rsp.status, rsp.data))

    def _write_result(self, rsp):
        data = rsp.data
        if not data:
            data = '{}'

        if rsp.status == 200:
            return {"value": json.loads(data)}
        elif rsp.status == 503:
            return json.loads(data)
        else:
            raise SdkError('unknown status code[%s]' % rsp.status)

    def _poll_result(self, rsp, cb):
        if not self.NEED_POLL:
            raise SdkError('[Internal Error] the api is not an async API but the server returns 202 status code')

        m = json.loads(rsp.data)
        location = m[LOCATION]
        if not location:
            raise SdkError("Internal Error] the api[%s] is an async API but the server doesn't return the polling location url")

        if cb:
            # async polling
            self._async_poll(location, cb)
        else:
            # sync polling
            return self._sync_polling(location)

    def _fill_timeout_parameters(self):
        if self.timeout is None:
            self.timeout = __config__.get(CONFIG_POLLING_TIMEOUT)

        if self.pollingInterval is None:
            self.pollingInterval = __config__.get(CONFIG_POLLING_INTERVAL)

    def _async_poll(self, location, cb):
        @_exception_safe
        def _polling():
            ret = self._sync_polling(location)
            cb(ret)

        threading.Thread(target=_polling).start()

    def _sync_polling(self, location):
        count = 0
        self._fill_timeout_parameters()

        while count < self.timeout:
            rsp = _json_http(
                uri=location,
                headers={HEADER_AUTHORIZATION: "%s %s" % (OAUTH, self.sessionId)},
                method='GET'
            )

            if rsp.status not in [200, 503, 202]:
                return Obj(_http_error(rsp.status, rsp.data))
            elif rsp.status in [200, 503]:
                return Obj(self._write_result(rsp))

            time.sleep(self.pollingInterval)
            count += self.pollingInterval

        return Obj(_error(POLLING_TIMEOUT_ERROR, 'polling an API result time out',
                          'failed to poll the result after %s seconds' % self.timeout))


class QueryAction(AbstractAction):
    PARAMS = {
        'conditions': ParamAnnotation(required=True),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(valid_values=['asc', 'desc']),
        'fields': ParamAnnotation(),
    }

    def __init__(self):
        super(QueryAction, self).__init__()
        self.conditions = []
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.sessionId = None

    def _query_string(self, params):
        m = []

        ps = {}
        for k, v in params.items():
            if k in self.PARAMS:
                ps[k] = v

        for k, v in ps.items():
            if v is None:
                continue

            if k == 'accessKeySecret':
                continue

            if k == 'accessKeyId':
                continue

            if k == 'sortBy' and v is not None:
                if self.sortDirection is None:
                    m.append('sort=%s' % v)
                else:
                    op = '+' if self.sortDirection == 'asc' else '-'
                    m.append('sort=%s%s' % (op, v))
            elif k == 'sortDirection':
                continue
            elif k == 'fields':
                m.append('fields=%s' % ','.join(v))
            elif k == 'conditions':
                m.extend(['q=%s' % q for q in v])
            else:
                m.append('%s=%s' % (k, v))

        return '&'.join(m)


def _uuid():
    return str(uuid4()).replace('-', '')


def _json_http(
        uri,
        body=None,
        headers={},
        method='POST',
        timeout=120.0
):
    pool = urllib3.PoolManager(timeout=timeout, retries=urllib3.util.retry.Retry(15))
    headers.update({'Content-Type': 'application/json', 'Connection': 'close'})

    if body is not None and not isinstance(body, str):
        body = json.dumps(body).encode('utf-8')

    print '[Request]: %s url=%s, headers=%s, body=%s' % (method, uri, headers, body)
    if body:
        headers['Content-Length'] = len(body)
        rsp = pool.request(method, uri, body=body, headers=headers)
    else:
        rsp = pool.request(method, uri, headers=headers)

    print '[Response to %s %s]: status: %s, body: %s' % (method, uri, rsp.status, rsp.data)
    return rsp




class CreateDataVolumeFromVolumeSnapshotAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/volumes/data/from/volume-snapshots/{volumeSnapshotUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'volumeSnapshotUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'primaryStorageUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateDataVolumeFromVolumeSnapshotAction, self).__init__()
        self.name = None
        self.description = None
        self.volumeSnapshotUuid = None
        self.primaryStorageUuid = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DetachBackupStorageFromZoneAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/zones/{zoneUuid}/backup-storage/{backupStorageUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'backupStorageUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'zoneUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DetachBackupStorageFromZoneAction, self).__init__()
        self.backupStorageUuid = None
        self.zoneUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryLdapServerAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/ldap/servers'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryLdapServerAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetResourceConfigAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/resource-configurations/{resourceUuid}/{category}/{name}'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'category': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetResourceConfigAction, self).__init__()
        self.category = None
        self.name = None
        self.resourceUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AttachVmNicToVmAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/vm-instances/{vmInstanceUuid}/nices/{vmNicUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'vmNicUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'vmInstanceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AttachVmNicToVmAction, self).__init__()
        self.vmNicUuid = None
        self.vmInstanceUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetResourceAccountAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/resources/accounts'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'resourceUuids': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetResourceAccountAction, self).__init__()
        self.resourceUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetVolumeCapabilitiesAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/volumes/{uuid}/capabilities'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetVolumeCapabilitiesAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetVmHostnameAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/vm-instances/{uuid}/hostnames'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetVmHostnameAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ShrinkVolumeSnapshotAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/volume-snapshots/shrink/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'shrinkVolumeSnapshot'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ShrinkVolumeSnapshotAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryGlobalConfigAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/global-configurations'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryGlobalConfigAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeletePolicyAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/accounts/policies/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeletePolicyAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateSystemTagAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/system-tags/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateSystemTag'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'tag': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateSystemTagAction, self).__init__()
        self.uuid = None
        self.tag = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateCephBackupStorageMonAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/backup-storage/ceph/mons/{monUuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateCephBackupStorageMon'

    PARAMS = {
        'monUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=False,no_trim=False),
        'hostname': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'sshUsername': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'sshPassword': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'sshPort': ParamAnnotation(required=False,number_range=[1, 65535],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'monPort': ParamAnnotation(required=False,number_range=[1, 65535],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateCephBackupStorageMonAction, self).__init__()
        self.monUuid = None
        self.hostname = None
        self.sshUsername = None
        self.sshPassword = None
        self.sshPort = None
        self.monPort = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateClusterAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/clusters/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateCluster'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateClusterAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetCandidatePrimaryStoragesForCreatingVmAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/vm-instances/candidate-storages'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'imageUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'l3NetworkUuids': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'rootDiskOfferingUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'dataDiskOfferingUuids': ParamAnnotation(required=False,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'zoneUuid': ParamAnnotation(),
        'clusterUuid': ParamAnnotation(),
        'defaultL3NetworkUuid': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetCandidatePrimaryStoragesForCreatingVmAction, self).__init__()
        self.imageUuid = None
        self.l3NetworkUuids = None
        self.rootDiskOfferingUuid = None
        self.dataDiskOfferingUuids = None
        self.zoneUuid = None
        self.clusterUuid = None
        self.defaultL3NetworkUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateRootVolumeTemplateFromVolumeSnapshotAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/images/root-volume-templates/from/volume-snapshots/{snapshotUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'snapshotUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'guestOsType': ParamAnnotation(),
        'backupStorageUuids': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'platform': ParamAnnotation(required=False,valid_values=['Linux','Windows','Other','Paravirtualization','WindowsVirtio'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'system': ParamAnnotation(),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateRootVolumeTemplateFromVolumeSnapshotAction, self).__init__()
        self.snapshotUuid = None
        self.name = None
        self.description = None
        self.guestOsType = None
        self.backupStorageUuids = None
        self.platform = None
        self.system = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ResumeVmInstanceAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'resumeVmInstance'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ResumeVmInstanceAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateKVMHostAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/hosts/kvm/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateKVMHost'

    PARAMS = {
        'username': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=False,no_trim=False),
        'password': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'sshPort': ParamAnnotation(required=False,number_range=[1, 65535],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'managementIp': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=False,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateKVMHostAction, self).__init__()
        self.username = None
        self.password = None
        self.sshPort = None
        self.uuid = None
        self.name = None
        self.description = None
        self.managementIp = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateVirtualRouterOfferingAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/instance-offerings/virtual-routers/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateVirtualRouterOffering'

    PARAMS = {
        'isDefault': ParamAnnotation(),
        'imageUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'allocatorStrategy': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateVirtualRouterOfferingAction, self).__init__()
        self.isDefault = None
        self.imageUuid = None
        self.uuid = None
        self.name = None
        self.description = None
        self.allocatorStrategy = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AttachDataVolumeToVmAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/volumes/{volumeUuid}/vm-instances/{vmInstanceUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'vmInstanceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'volumeUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AttachDataVolumeToVmAction, self).__init__()
        self.vmInstanceUuid = None
        self.volumeUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetVmAttachableL3NetworkAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/vm-instances/{vmInstanceUuid}/l3-networks-candidates'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'vmInstanceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetVmAttachableL3NetworkAction, self).__init__()
        self.vmInstanceUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class RemoveMonFromCephBackupStorageAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/backup-storage/ceph/{uuid}/mons'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'monHostnames': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(RemoveMonFromCephBackupStorageAction, self).__init__()
        self.uuid = None
        self.monHostnames = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class RemoveVmNicFromLoadBalancerAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/load-balancers/listeners/{listenerUuid}/vm-instances/nics'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'vmNicUuids': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'listenerUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(RemoveVmNicFromLoadBalancerAction, self).__init__()
        self.vmNicUuids = None
        self.listenerUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AttachL2NetworkToClusterAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/l2-networks/{l2NetworkUuid}/clusters/{clusterUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'null'

    PARAMS = {
        'l2NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'clusterUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AttachL2NetworkToClusterAction, self).__init__()
        self.l2NetworkUuid = None
        self.clusterUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateVolumeSnapshotAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/volumes/{volumeUuid}/volume-snapshots'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'volumeUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateVolumeSnapshotAction, self).__init__()
        self.volumeUuid = None
        self.name = None
        self.description = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateCephPrimaryStorageMonAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/primary-storage/ceph/mons/{monUuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateCephPrimaryStorageMon'

    PARAMS = {
        'monUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=False,no_trim=False),
        'hostname': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'sshUsername': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'sshPassword': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'sshPort': ParamAnnotation(required=False,number_range=[1, 65535],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'monPort': ParamAnnotation(required=False,number_range=[1, 65535],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateCephPrimaryStorageMonAction, self).__init__()
        self.monUuid = None
        self.hostname = None
        self.sshUsername = None
        self.sshPassword = None
        self.sshPort = None
        self.monPort = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryAccountResourceRefAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/accounts/resources/refs'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryAccountResourceRefAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddIpv6RangeAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/l3-networks/{l3NetworkUuid}/ipv6-ranges'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'startIp': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'endIp': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'gateway': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'prefixLen': ParamAnnotation(required=True,number_range=[8, 126],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'addressMode': ParamAnnotation(required=True,valid_values=['SLAAC','Stateful-DHCP','Stateless-DHCP'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'ipRangeType': ParamAnnotation(required=False,valid_values=['Normal','AddressPool'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddIpv6RangeAction, self).__init__()
        self.l3NetworkUuid = None
        self.name = None
        self.description = None
        self.startIp = None
        self.endIp = None
        self.gateway = None
        self.prefixLen = None
        self.addressMode = None
        self.ipRangeType = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DetachNetworkServiceFromL3NetworkAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/l3-networks/{l3NetworkUuid}/network-services'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'networkServices': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DetachNetworkServiceFromL3NetworkAction, self).__init__()
        self.l3NetworkUuid = None
        self.networkServices = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteVolumeSnapshotGroupAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/volume-snapshots/group/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteVolumeSnapshotGroupAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateAccessControlListAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/access-control-lists'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'ipVersion': ParamAnnotation(required=False,valid_values=['4','6'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateAccessControlListAction, self).__init__()
        self.name = None
        self.description = None
        self.ipVersion = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class RemoveAccessControlListEntryAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/access-control-lists/{aclUuid}/ipentries/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'aclUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(RemoveAccessControlListEntryAction, self).__init__()
        self.aclUuid = None
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ReconnectVirtualRouterAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/appliances/virtual-routers/{vmInstanceUuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'reconnectVirtualRouter'

    PARAMS = {
        'vmInstanceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ReconnectVirtualRouterAction, self).__init__()
        self.vmInstanceUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AttachSecurityGroupToL3NetworkAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/security-groups/{securityGroupUuid}/l3-networks/{l3NetworkUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'securityGroupUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AttachSecurityGroupToL3NetworkAction, self).__init__()
        self.securityGroupUuid = None
        self.l3NetworkUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeletePortForwardingRuleAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/port-forwarding/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeletePortForwardingRuleAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CheckIpAvailabilityAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/l3-networks/{l3NetworkUuid}/ip/{ip}/availability'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'ip': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CheckIpAvailabilityAction, self).__init__()
        self.l3NetworkUuid = None
        self.ip = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryClusterAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/clusters'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryClusterAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteLongJobAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/longjobs/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteLongJobAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateVolumeSnapshotGroupAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/volume-snapshots/group'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'rootVolumeUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'withMemory': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateVolumeSnapshotGroupAction, self).__init__()
        self.rootVolumeUuid = None
        self.name = None
        self.description = None
        self.withMemory = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetVersionAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/management-nodes/actions'
    NEED_SESSION = False
    NEED_POLL = False
    PARAM_NAME = 'getVersion'

    PARAMS = {
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetVersionAction, self).__init__()
        self.systemTags = None
        self.userTags = None
        self.requestIp = None


class AttachBackupStorageToZoneAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/zones/{zoneUuid}/backup-storage/{backupStorageUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'zoneUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'backupStorageUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AttachBackupStorageToZoneAction, self).__init__()
        self.zoneUuid = None
        self.backupStorageUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetCandidateVmNicsForLoadBalancerAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/load-balancers/listeners/{listenerUuid}/vm-instances/candidate-nics'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'listenerUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetCandidateVmNicsForLoadBalancerAction, self).__init__()
        self.listenerUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryVirtualRouterVmAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/vm-instances/appliances/virtual-routers'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryVirtualRouterVmAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AttachPolicyToUserAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/accounts/users/{userUuid}/policies'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'userUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'policyUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AttachPolicyToUserAction, self).__init__()
        self.userUuid = None
        self.policyUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteVmHostnameAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/vm-instances/{uuid}/hostnames'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteVmHostnameAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateVmCdRomAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/vm-instances/cdroms'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'vmInstanceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'isoUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateVmCdRomAction, self).__init__()
        self.name = None
        self.vmInstanceUuid = None
        self.isoUuid = None
        self.description = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetVipUsedPortsAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/vips/{uuid}/usedports'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'protocol': ParamAnnotation(required=True,valid_values=['TCP','UDP'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetVipUsedPortsAction, self).__init__()
        self.uuid = None
        self.protocol = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryVolumeSnapshotGroupAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/volume-snapshots/group'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryVolumeSnapshotGroupAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateInstanceOfferingAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/instance-offerings/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateInstanceOffering'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'allocatorStrategy': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateInstanceOfferingAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.allocatorStrategy = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class RemoveCertificateFromLoadBalancerListenerAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/load-balancers/listeners/{listenerUuid}/certificate'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'certificateUuid': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'listenerUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(RemoveCertificateFromLoadBalancerListenerAction, self).__init__()
        self.certificateUuid = None
        self.listenerUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AttachRoleToAccountAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/identities/accounts/{accountUuid}/roles/{roleUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'roleUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'accountUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AttachRoleToAccountAction, self).__init__()
        self.roleUuid = None
        self.accountUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryPolicyAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/accounts/policies'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryPolicyAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetElaborationCategoriesAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/errorcode/elaborations/categories'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetElaborationCategoriesAction, self).__init__()
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteVniRangeAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/l2-networks/vxlan-pool/vni-ranges/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteVniRangeAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteSecurityGroupAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/security-groups/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteSecurityGroupAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateInstanceOfferingAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/instance-offerings'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'cpuNum': ParamAnnotation(required=True,number_range=[1, 1024],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'memorySize': ParamAnnotation(required=True,number_range=[1, 9223372036854775807],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'allocatorStrategy': ParamAnnotation(),
        'sortKey': ParamAnnotation(),
        'type': ParamAnnotation(),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateInstanceOfferingAction, self).__init__()
        self.name = None
        self.description = None
        self.cpuNum = None
        self.memorySize = None
        self.allocatorStrategy = None
        self.sortKey = None
        self.type = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DetachEipAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/eips/{uuid}/vm-instances/nics'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DetachEipAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class LogOutAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/accounts/sessions/{sessionUuid}'
    NEED_SESSION = False
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'sessionUuid': ParamAnnotation(),
        'clientInfo': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(LogOutAction, self).__init__()
        self.sessionUuid = None
        self.clientInfo = None
        self.systemTags = None
        self.userTags = None
        self.requestIp = None


class AddPolicyStatementsToRoleAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/identities/roles/{uuid}/policy-statements'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'statements': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddPolicyStatementsToRoleAction, self).__init__()
        self.uuid = None
        self.statements = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ChangeBackupStorageStateAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/backup-storage/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'changeBackupStorageState'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'stateEvent': ParamAnnotation(required=True,valid_values=['enable','disable'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ChangeBackupStorageStateAction, self).__init__()
        self.uuid = None
        self.stateEvent = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class SetVmSshKeyAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'setVmSshKey'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'SshKey': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(SetVmSshKeyAction, self).__init__()
        self.uuid = None
        self.SshKey = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetL3NetworkRouterInterfaceIpAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/l3-networks/{l3NetworkUuid}/router-interface-ip'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetL3NetworkRouterInterfaceIpAction, self).__init__()
        self.l3NetworkUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteTagAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/tags/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteTagAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateLoadBalancerAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/load-balancers/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateLoadBalancer'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateLoadBalancerAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryBackupStorageAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/backup-storage'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryBackupStorageAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class SubmitLongJobAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/longjobs'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'jobName': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'jobData': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'targetResourceUuid': ParamAnnotation(required=False,max_length=32,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(SubmitLongJobAction, self).__init__()
        self.name = None
        self.description = None
        self.jobName = None
        self.jobData = None
        self.targetResourceUuid = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateVipAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/vips'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'allocatorStrategy': ParamAnnotation(),
        'ipRangeUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'requiredIp': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateVipAction, self).__init__()
        self.name = None
        self.description = None
        self.l3NetworkUuid = None
        self.allocatorStrategy = None
        self.ipRangeUuid = None
        self.requiredIp = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateVmInstanceAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateVmInstance'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'state': ParamAnnotation(required=False,valid_values=['Stopped','Running'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'defaultL3NetworkUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'platform': ParamAnnotation(required=False,valid_values=['Linux','Windows','Other','Paravirtualization','WindowsVirtio'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'cpuNum': ParamAnnotation(required=False,number_range=[1, 1024],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'memorySize': ParamAnnotation(required=False,number_range=[1, 9223372036854775807],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateVmInstanceAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.state = None
        self.defaultL3NetworkUuid = None
        self.platform = None
        self.cpuNum = None
        self.memorySize = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateCertificateAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/certificates'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'certificate': ParamAnnotation(required=True,max_length=60000,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateCertificateAction, self).__init__()
        self.name = None
        self.certificate = None
        self.description = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ChangeVipStateAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vips/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'changeVipState'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'stateEvent': ParamAnnotation(required=True,valid_values=['enable','disable'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ChangeVipStateAction, self).__init__()
        self.uuid = None
        self.stateEvent = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetCandidateLdapEntryForBindingAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/ldap/entries/candidates'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'ldapFilter': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(required=False,number_range=[1, 2147483647],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetCandidateLdapEntryForBindingAction, self).__init__()
        self.ldapFilter = None
        self.limit = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class LogInByUserAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/accounts/users/login'
    NEED_SESSION = False
    NEED_POLL = False
    PARAM_NAME = 'logInByUser'

    PARAMS = {
        'accountUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'accountName': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'userName': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'password': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'clientInfo': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(LogInByUserAction, self).__init__()
        self.accountUuid = None
        self.accountName = None
        self.userName = None
        self.password = None
        self.clientInfo = None
        self.systemTags = None
        self.userTags = None
        self.requestIp = None


class QueryApplianceVmAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/vm-instances/appliances'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryApplianceVmAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class PauseVmInstanceAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'pauseVmInstance'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(PauseVmInstanceAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateLoadBalancerListenerAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/load-balancers/listeners/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateLoadBalancerListener'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateLoadBalancerListenerAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class TriggerGCJobAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/gc-jobs/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'triggerGCJob'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(TriggerGCJobAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryVolumeSnapshotAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/volume-snapshots'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryVolumeSnapshotAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetVmConsolePasswordAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/vm-instances/{uuid}/console-passwords'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetVmConsolePasswordAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteL3NetworkAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/l3-networks/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteL3NetworkAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryInstanceOfferingAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/instance-offerings'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryInstanceOfferingAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddDnsToL3NetworkAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/l3-networks/{l3NetworkUuid}/dns'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'dns': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddDnsToL3NetworkAction, self).__init__()
        self.l3NetworkUuid = None
        self.dns = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryLdapBindingAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/ldap/bindings'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryLdapBindingAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateL2NetworkAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/l2-networks/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateL2Network'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateL2NetworkAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateRoleAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/identities/roles/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateRole'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'statements': ParamAnnotation(),
        'policyUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateRoleAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.statements = None
        self.policyUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AttachPolicyToRoleAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/identities/policies/{policyUuid}/roles/{roleUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'roleUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'policyUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AttachPolicyToRoleAction, self).__init__()
        self.roleUuid = None
        self.policyUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryVmPriorityConfigAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/vm-priority-config'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryVmPriorityConfigAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteClusterAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/clusters/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteClusterAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteVipAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/vips/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteVipAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryIpAddressAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/l3-networks/ip-address'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryIpAddressAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteVmNicAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/nics/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteVmNicAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class StopVmInstanceAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'stopVmInstance'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'type': ParamAnnotation(required=False,valid_values=['grace','cold'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'stopHA': ParamAnnotation(required=False,valid_values=['true'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(StopVmInstanceAction, self).__init__()
        self.uuid = None
        self.type = None
        self.stopHA = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryUserTagAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/user-tags'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryUserTagAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ChangeResourceOwnerAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/account/{accountUuid}/resources'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'accountUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ChangeResourceOwnerAction, self).__init__()
        self.accountUuid = None
        self.resourceUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryVirtualRouterOfferingAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/instance-offerings/virtual-routers'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryVirtualRouterOfferingAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DetachPolicyFromUserAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/accounts/users/{userUuid}/policies/{policyUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'policyUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'userUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DetachPolicyFromUserAction, self).__init__()
        self.policyUuid = None
        self.userUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryIpRangeAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/l3-networks/ip-ranges'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryIpRangeAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateVmNicAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/nics'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'ip': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateVmNicAction, self).__init__()
        self.l3NetworkUuid = None
        self.ip = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateL2VxlanNetworkAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/l2-networks/vxlan'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'vni': ParamAnnotation(required=False,number_range=[1, 16777214],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'poolUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'zoneUuid': ParamAnnotation(required=False,max_length=1024,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'physicalInterface': ParamAnnotation(required=False,max_length=1024,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'type': ParamAnnotation(),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateL2VxlanNetworkAction, self).__init__()
        self.vni = None
        self.poolUuid = None
        self.name = None
        self.description = None
        self.zoneUuid = None
        self.physicalInterface = None
        self.type = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class RevokeResourceSharingAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/accounts/resources/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'revokeResourceSharing'

    PARAMS = {
        'resourceUuids': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'toPublic': ParamAnnotation(),
        'accountUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'all': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(RevokeResourceSharingAction, self).__init__()
        self.resourceUuids = None
        self.toPublic = None
        self.accountUuids = None
        self.all = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DetachRoleFromAccountAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/identities/accounts/{accountUuid}/roles/{roleUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'roleUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'accountUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DetachRoleFromAccountAction, self).__init__()
        self.roleUuid = None
        self.accountUuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryVmNicAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/vm-instances/nics'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryVmNicAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetVolumeFormatAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/volumes/formats'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetVolumeFormatAction, self).__init__()
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddMonToCephBackupStorageAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/backup-storage/ceph/{uuid}/mons'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'monUrls': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddMonToCephBackupStorageAction, self).__init__()
        self.uuid = None
        self.monUrls = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdatePortForwardingRuleAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/port-forwarding/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updatePortForwardingRule'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdatePortForwardingRuleAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateL3NetworkAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/l3-networks/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateL3Network'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'dnsDomain': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'category': ParamAnnotation(required=False,valid_values=['Public','Private','System'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'system': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateL3NetworkAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.dnsDomain = None
        self.category = None
        self.system = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class RenewSessionAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/accounts/sessions/{sessionUuid}/renew'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'renewSession'

    PARAMS = {
        'sessionUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'duration': ParamAnnotation(required=False,number_range=[60, 31536000],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(RenewSessionAction, self).__init__()
        self.sessionUuid = None
        self.duration = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateL2NoVlanNetworkAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/l2-networks/no-vlan'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'zoneUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'physicalInterface': ParamAnnotation(required=True,max_length=1024,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'type': ParamAnnotation(),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateL2NoVlanNetworkAction, self).__init__()
        self.name = None
        self.description = None
        self.zoneUuid = None
        self.physicalInterface = None
        self.type = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateL2VlanNetworkAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/l2-networks/vlan'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'vlan': ParamAnnotation(required=True,number_range=[1, 4094],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'zoneUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'physicalInterface': ParamAnnotation(required=True,max_length=1024,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'type': ParamAnnotation(),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateL2VlanNetworkAction, self).__init__()
        self.vlan = None
        self.name = None
        self.description = None
        self.zoneUuid = None
        self.physicalInterface = None
        self.type = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QuerySftpBackupStorageAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/backup-storage/sftp'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QuerySftpBackupStorageAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryUserAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/accounts/users'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryUserAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteCertificateAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/certificates/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteCertificateAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QuerySecurityGroupAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/security-groups'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QuerySecurityGroupAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteLoadBalancerListenerAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/load-balancers/listeners/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteLoadBalancerListenerAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddCertificateToLoadBalancerListenerAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/load-balancers/listeners/{listenerUuid}/certificate'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'certificateUuid': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'listenerUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddCertificateToLoadBalancerListenerAction, self).__init__()
        self.certificateUuid = None
        self.listenerUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CheckResourcePermissionAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/accounts/resource/api-permissions'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'resourceType': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CheckResourcePermissionAction, self).__init__()
        self.resourceType = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetVolumeSnapshotSizeAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/volume-snapshots/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'getVolumeSnapshotSize'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetVolumeSnapshotSizeAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteCephPrimaryStoragePoolAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/primary-storage/ceph/pools/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteCephPrimaryStoragePoolAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryAccountAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/accounts'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryAccountAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetAttachablePublicL3ForVRouterAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/vm-instances/appliances/virtual-routers/{vmInstanceUuid}/attachable-public-l3s'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'vmInstanceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetAttachablePublicL3ForVRouterAction, self).__init__()
        self.vmInstanceUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddIpRangeAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/l3-networks/{l3NetworkUuid}/ip-ranges'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'startIp': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'endIp': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'netmask': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'gateway': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'ipRangeType': ParamAnnotation(required=False,valid_values=['Normal','AddressPool'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddIpRangeAction, self).__init__()
        self.l3NetworkUuid = None
        self.name = None
        self.description = None
        self.startIp = None
        self.endIp = None
        self.netmask = None
        self.gateway = None
        self.ipRangeType = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddIpv6RangeByNetworkCidrAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/l3-networks/{l3NetworkUuid}/ipv6-ranges/by-cidr'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'networkCidr': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'addressMode': ParamAnnotation(required=True,valid_values=['SLAAC','Stateful-DHCP','Stateless-DHCP'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'ipRangeType': ParamAnnotation(required=False,valid_values=['Normal','AddressPool'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddIpv6RangeByNetworkCidrAction, self).__init__()
        self.name = None
        self.description = None
        self.l3NetworkUuid = None
        self.networkCidr = None
        self.addressMode = None
        self.ipRangeType = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class RecoverVmInstanceAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'recoverVmInstance'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(RecoverVmInstanceAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryVtepAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/l2-networks/vteps'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryVtepAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class RemoveUserFromGroupAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/accounts/groups/{groupUuid}/users/{userUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'userUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'groupUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(RemoveUserFromGroupAction, self).__init__()
        self.userUuid = None
        self.groupUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ReconnectPrimaryStorageAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/primary-storage/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'reconnectPrimaryStorage'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ReconnectPrimaryStorageAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateSftpBackupStorageAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/backup-storage/sftp/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateSftpBackupStorage'

    PARAMS = {
        'username': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'password': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'hostname': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'sshPort': ParamAnnotation(required=False,number_range=[1, 65535],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateSftpBackupStorageAction, self).__init__()
        self.username = None
        self.password = None
        self.hostname = None
        self.sshPort = None
        self.uuid = None
        self.name = None
        self.description = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AttachL3NetworkToVmNicAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/nics/{vmNicUuid}/l3-networks/{l3NetworkUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'vmNicUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'staticIp': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AttachL3NetworkToVmNicAction, self).__init__()
        self.vmNicUuid = None
        self.l3NetworkUuid = None
        self.staticIp = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ChangeInstanceOfferingAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/{vmInstanceUuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'changeInstanceOffering'

    PARAMS = {
        'vmInstanceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'instanceOfferingUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ChangeInstanceOfferingAction, self).__init__()
        self.vmInstanceUuid = None
        self.instanceOfferingUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ChangeClusterStateAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/clusters/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'changeClusterState'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'stateEvent': ParamAnnotation(required=True,valid_values=['enable','disable'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ChangeClusterStateAction, self).__init__()
        self.uuid = None
        self.stateEvent = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ChangePortForwardingRuleStateAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/port-forwarding/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'changePortForwardingRuleState'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'stateEvent': ParamAnnotation(required=True,valid_values=['enable','disable'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ChangePortForwardingRuleStateAction, self).__init__()
        self.uuid = None
        self.stateEvent = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryVolumeSnapshotTreeAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/volume-snapshots/trees'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryVolumeSnapshotTreeAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AttachL3NetworkToVmAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/vm-instances/{vmInstanceUuid}/l3-networks/{l3NetworkUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'vmInstanceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'staticIp': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AttachL3NetworkToVmAction, self).__init__()
        self.vmInstanceUuid = None
        self.l3NetworkUuid = None
        self.staticIp = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddImageAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/images'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'url': ParamAnnotation(required=True,max_length=1024,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'mediaType': ParamAnnotation(required=False,valid_values=['RootVolumeTemplate','ISO','DataVolumeTemplate'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'guestOsType': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'system': ParamAnnotation(),
        'format': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'platform': ParamAnnotation(required=False,valid_values=['Linux','Windows','Other','Paravirtualization','WindowsVirtio'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'backupStorageUuids': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'type': ParamAnnotation(),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddImageAction, self).__init__()
        self.name = None
        self.description = None
        self.url = None
        self.mediaType = None
        self.guestOsType = None
        self.system = None
        self.format = None
        self.platform = None
        self.backupStorageUuids = None
        self.type = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddCephPrimaryStoragePoolAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/primary-storage/ceph/{primaryStorageUuid}/pools'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'primaryStorageUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'poolName': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'aliasName': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'type': ParamAnnotation(required=True,valid_values=['Root','Data'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'isCreate': ParamAnnotation(),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddCephPrimaryStoragePoolAction, self).__init__()
        self.primaryStorageUuid = None
        self.poolName = None
        self.aliasName = None
        self.description = None
        self.type = None
        self.isCreate = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QuerySecurityGroupRuleAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/security-groups/rules'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QuerySecurityGroupRuleAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryManagementNodeAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/management-nodes'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryManagementNodeAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateVolumeSnapshotGroupAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/volume-snapshots/group/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateVolumeSnapshotGroup'

    PARAMS = {
        'name': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateVolumeSnapshotGroupAction, self).__init__()
        self.name = None
        self.description = None
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateUserGroupAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/accounts/groups'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateUserGroupAction, self).__init__()
        self.name = None
        self.description = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateSecurityGroupAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/security-groups/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateSecurityGroup'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateSecurityGroupAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DetachPoliciesFromUserAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/accounts/users/{userUuid}/policies'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'policyUuids': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'userUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DetachPoliciesFromUserAction, self).__init__()
        self.policyUuids = None
        self.userUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ChangeImageStateAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/images/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'changeImageState'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'stateEvent': ParamAnnotation(required=True,valid_values=['enable','disable'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ChangeImageStateAction, self).__init__()
        self.uuid = None
        self.stateEvent = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddAccessControlListEntryAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/access-control-lists/{aclUuid}/ipentries'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'aclUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'entries': ParamAnnotation(required=True,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddAccessControlListEntryAction, self).__init__()
        self.aclUuid = None
        self.entries = None
        self.description = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateHostAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/hosts/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateHost'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'managementIp': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=False,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateHostAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.managementIp = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DetachPortForwardingRuleAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/port-forwarding/{uuid}/vm-instances/nics'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DetachPortForwardingRuleAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateVmCdRomAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/cdroms/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateVmCdRom'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateVmCdRomAction, self).__init__()
        self.uuid = None
        self.description = None
        self.name = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateResourceConfigAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/resource-configurations/{category}/{name}/{resourceUuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateResourceConfig'

    PARAMS = {
        'category': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'value': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateResourceConfigAction, self).__init__()
        self.category = None
        self.name = None
        self.resourceUuid = None
        self.value = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ValidateSessionAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/accounts/sessions/{sessionUuid}/valid'
    NEED_SESSION = False
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'sessionUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ValidateSessionAction, self).__init__()
        self.sessionUuid = None
        self.systemTags = None
        self.userTags = None
        self.requestIp = None


class GetLocalStorageHostDiskCapacityAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/primary-storage/local-storage/{primaryStorageUuid}/capacities'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'hostUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'primaryStorageUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetLocalStorageHostDiskCapacityAction, self).__init__()
        self.hostUuid = None
        self.primaryStorageUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteGCJobAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/gc-jobs/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteGCJobAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteWebhookAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/web-hooks/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteWebhookAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ZQLQueryAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/zql'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'zql': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ZQLQueryAction, self).__init__()
        self.zql = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetCandidateIsoForAttachingVmAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/vm-instances/{vmInstanceUuid}/iso-candidates'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'vmInstanceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetCandidateIsoForAttachingVmAction, self).__init__()
        self.vmInstanceUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DetachL2NetworkFromClusterAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/l2-networks/{l2NetworkUuid}/clusters/{clusterUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'l2NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'clusterUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DetachL2NetworkFromClusterAction, self).__init__()
        self.l2NetworkUuid = None
        self.clusterUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CancelLongJobAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/longjobs/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'cancelLongJob'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CancelLongJobAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetMissedElaborationAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/errorcode/elaborations/missed'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'repeats': ParamAnnotation(required=False,number_range=[1, 9223372036854775807],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'startTime': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetMissedElaborationAction, self).__init__()
        self.repeats = None
        self.startTime = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DebugSignalAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/debug'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'signals': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DebugSignalAction, self).__init__()
        self.signals = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddSimulatorHostAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/hosts/simulators'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'memoryCapacity': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'cpuCapacity': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'managementIp': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=False,no_trim=False),
        'clusterUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddSimulatorHostAction, self).__init__()
        self.memoryCapacity = None
        self.cpuCapacity = None
        self.name = None
        self.description = None
        self.managementIp = None
        self.clusterUuid = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetL3NetworkMtuAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/l3-networks/{l3NetworkUuid}/mtu'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetL3NetworkMtuAction, self).__init__()
        self.l3NetworkUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddSftpBackupStorageAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/backup-storage/sftp'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'hostname': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=False,no_trim=False),
        'username': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'password': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'sshPort': ParamAnnotation(required=False,number_range=[1, 65535],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'url': ParamAnnotation(required=True,max_length=2048,non_empty=False,null_elements=False,empty_string=False,no_trim=False),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'type': ParamAnnotation(),
        'importImages': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddSftpBackupStorageAction, self).__init__()
        self.hostname = None
        self.username = None
        self.password = None
        self.sshPort = None
        self.url = None
        self.name = None
        self.description = None
        self.type = None
        self.importImages = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetPrimaryStorageAllocatorStrategiesAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/primary-storage/allocators/strategies'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetPrimaryStorageAllocatorStrategiesAction, self).__init__()
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class LocalStorageGetVolumeMigratableHostsAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/volumes/{volumeUuid}/migration-target-hosts'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'volumeUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(LocalStorageGetVolumeMigratableHostsAction, self).__init__()
        self.volumeUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ResumeLongJobAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/longjobs/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'resumeLongJob'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ResumeLongJobAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateL2VxlanNetworkPoolAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/l2-networks/vxlan-pool'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'zoneUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'physicalInterface': ParamAnnotation(required=False,max_length=1024,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'type': ParamAnnotation(),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateL2VxlanNetworkPoolAction, self).__init__()
        self.name = None
        self.description = None
        self.zoneUuid = None
        self.physicalInterface = None
        self.type = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetZoneAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/zones/{uuid}/info'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetZoneAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryPortForwardingRuleAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/port-forwarding'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryPortForwardingRuleAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryVolumeAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/volumes'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryVolumeAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateVolumeAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/volumes/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateVolume'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateVolumeAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AttachPortForwardingRuleAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/port-forwarding/{ruleUuid}/vm-instances/nics/{vmNicUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'ruleUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'vmNicUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AttachPortForwardingRuleAction, self).__init__()
        self.ruleUuid = None
        self.vmNicUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ChangeVolumeStateAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/volumes/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'changeVolumeState'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'stateEvent': ParamAnnotation(required=True,valid_values=['enable','disable'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ChangeVolumeStateAction, self).__init__()
        self.uuid = None
        self.stateEvent = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteDataVolumeAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/volumes/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteDataVolumeAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ReconnectHostAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/hosts/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'reconnectHost'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ReconnectHostAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddSharedMountPointPrimaryStorageAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/primary-storage/smp'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'url': ParamAnnotation(required=True,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'type': ParamAnnotation(),
        'zoneUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddSharedMountPointPrimaryStorageAction, self).__init__()
        self.url = None
        self.name = None
        self.description = None
        self.type = None
        self.zoneUuid = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateAccountAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/accounts'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'password': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'type': ParamAnnotation(required=False,valid_values=['SystemAdmin','Normal'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateAccountAction, self).__init__()
        self.name = None
        self.password = None
        self.type = None
        self.description = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class RerunLongJobAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/longjobs/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'rerunLongJob'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(RerunLongJobAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateLdapServerAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/ldap/servers/{ldapServerUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateLdapServer'

    PARAMS = {
        'ldapServerUuid': ParamAnnotation(required=True,max_length=32,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'url': ParamAnnotation(required=False,max_length=1024,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'base': ParamAnnotation(required=False,max_length=1024,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'username': ParamAnnotation(required=False,max_length=1024,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'password': ParamAnnotation(required=False,max_length=1024,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'encryption': ParamAnnotation(required=False,valid_values=['None','TLS'],max_length=1024,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateLdapServerAction, self).__init__()
        self.ldapServerUuid = None
        self.name = None
        self.description = None
        self.url = None
        self.base = None
        self.username = None
        self.password = None
        self.encryption = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetVmMigrationCandidateHostsAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/vm-instances/{vmInstanceUuid}/migration-target-hosts'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'vmInstanceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetVmMigrationCandidateHostsAction, self).__init__()
        self.vmInstanceUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CheckVolumeSnapshotGroupAvailabilityAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/volume-snapshots/groups/availabilities'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'uuids': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CheckVolumeSnapshotGroupAvailabilityAction, self).__init__()
        self.uuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class MigrateVmAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/{vmInstanceUuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'migrateVm'

    PARAMS = {
        'vmInstanceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'hostUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'migrateFromDestination': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'allowUnknown': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'strategy': ParamAnnotation(required=False,valid_values=['auto-converge'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(MigrateVmAction, self).__init__()
        self.vmInstanceUuid = None
        self.hostUuid = None
        self.migrateFromDestination = None
        self.allowUnknown = None
        self.strategy = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateL3NetworkAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/l3-networks'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'type': ParamAnnotation(),
        'l2NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'category': ParamAnnotation(required=False,valid_values=['Public','Private','System'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'ipVersion': ParamAnnotation(required=False,valid_values=['4','6'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'system': ParamAnnotation(),
        'dnsDomain': ParamAnnotation(),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateL3NetworkAction, self).__init__()
        self.name = None
        self.description = None
        self.type = None
        self.l2NetworkUuid = None
        self.category = None
        self.ipVersion = None
        self.system = None
        self.dnsDomain = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateZoneAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/zones'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateZoneAction, self).__init__()
        self.name = None
        self.description = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddCephPrimaryStorageAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/primary-storage/ceph'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'monUrls': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=False,no_trim=False),
        'rootVolumePoolName': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'dataVolumePoolName': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'imageCachePoolName': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'url': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'type': ParamAnnotation(),
        'zoneUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddCephPrimaryStorageAction, self).__init__()
        self.monUrls = None
        self.rootVolumePoolName = None
        self.dataVolumePoolName = None
        self.imageCachePoolName = None
        self.url = None
        self.name = None
        self.description = None
        self.type = None
        self.zoneUuid = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class IsReadyToGoAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/management-nodes/ready'
    NEED_SESSION = False
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'managementNodeId': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(IsReadyToGoAction, self).__init__()
        self.managementNodeId = None
        self.systemTags = None
        self.userTags = None
        self.requestIp = None


class UpdatePriorityConfigAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-priority-config/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updatePriorityConfig'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'cpuShares': ParamAnnotation(required=False,number_range=[2, 262144],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'oomScoreAdj': ParamAnnotation(required=False,number_range=[-1000, 1000],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdatePriorityConfigAction, self).__init__()
        self.uuid = None
        self.cpuShares = None
        self.oomScoreAdj = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetL3NetworkIpStatisticAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/l3-networks/{l3NetworkUuid}/ip-statistic'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceType': ParamAnnotation(required=False,valid_values=['All','Vip','VM'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'ip': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'sortBy': ParamAnnotation(required=False,valid_values=['Ip','CreateDate'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'start': ParamAnnotation(required=False,number_range=[0, 2147483647],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(required=False,number_range=[0, 2147483647],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'replyWithCount': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetL3NetworkIpStatisticAction, self).__init__()
        self.l3NetworkUuid = None
        self.resourceType = None
        self.ip = None
        self.sortBy = None
        self.sortDirection = None
        self.start = None
        self.limit = None
        self.replyWithCount = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CleanUpImageCacheOnPrimaryStorageAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/primary-storage/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'cleanUpImageCacheOnPrimaryStorage'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CleanUpImageCacheOnPrimaryStorageAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetDebugSignalAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/debug'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetDebugSignalAction, self).__init__()
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateVmPriorityAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateVmPriority'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'priority': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateVmPriorityAction, self).__init__()
        self.uuid = None
        self.priority = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryL2VxlanNetworkAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/l2-networks/vxlan'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryL2VxlanNetworkAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetCpuMemoryCapacityAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/hosts/capacities/cpu-memory'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'zoneUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'clusterUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'hostUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'hypervisorType': ParamAnnotation(required=False,valid_values=['KVM','ESX'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'all': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetCpuMemoryCapacityAction, self).__init__()
        self.zoneUuids = None
        self.clusterUuids = None
        self.hostUuids = None
        self.hypervisorType = None
        self.all = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryRoleAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/identities/roles'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryRoleAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DetachDataVolumeFromVmAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/volumes/{uuid}/vm-instances'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'vmUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DetachDataVolumeFromVmAction, self).__init__()
        self.uuid = None
        self.vmUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddVmNicToSecurityGroupAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/security-groups/{securityGroupUuid}/vm-instances/nics'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'securityGroupUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'vmNicUuids': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddVmNicToSecurityGroupAction, self).__init__()
        self.securityGroupUuid = None
        self.vmNicUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DetachPrimaryStorageFromClusterAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/clusters/{clusterUuid}/primary-storage/{primaryStorageUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'primaryStorageUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'clusterUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DetachPrimaryStorageFromClusterAction, self).__init__()
        self.primaryStorageUuid = None
        self.clusterUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeletePrimaryStorageAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/primary-storage/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeletePrimaryStorageAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryL2VlanNetworkAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/l2-networks/vlan'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryL2VlanNetworkAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryLoadBalancerListenerAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/load-balancers/listeners'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryLoadBalancerListenerAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class SetL3NetworkMtuAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/l3-networks/{l3NetworkUuid}/mtu'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'mtu': ParamAnnotation(required=True,number_range=[68, 9216],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(SetL3NetworkMtuAction, self).__init__()
        self.l3NetworkUuid = None
        self.mtu = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AttachNetworkServiceToL3NetworkAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/l3-networks/{l3NetworkUuid}/network-services'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'networkServices': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AttachNetworkServiceToL3NetworkAction, self).__init__()
        self.l3NetworkUuid = None
        self.networkServices = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteVmConsolePasswordAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/vm-instances/{uuid}/console-password'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteVmConsolePasswordAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteLoadBalancerAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/load-balancers/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteLoadBalancerAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateWebhookAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/web-hooks'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'url': ParamAnnotation(required=True,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'type': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'opaque': ParamAnnotation(),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateWebhookAction, self).__init__()
        self.name = None
        self.description = None
        self.url = None
        self.type = None
        self.opaque = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ReconnectSftpBackupStorageAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/backup-storage/sftp/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'reconnectSftpBackupStorage'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ReconnectSftpBackupStorageAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryPrimaryStorageAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/primary-storage'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryPrimaryStorageAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryLocalStorageResourceRefAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/primary-storage/local-storage/resource-refs'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryLocalStorageResourceRefAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ChangePrimaryStorageStateAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/primary-storage/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'changePrimaryStorageState'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'stateEvent': ParamAnnotation(required=True,valid_values=['enable','disable','maintain','deleting'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ChangePrimaryStorageStateAction, self).__init__()
        self.uuid = None
        self.stateEvent = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateVirtualRouterAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/appliances/virtual-routers/{vmInstanceUuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateVirtualRouter'

    PARAMS = {
        'vmInstanceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'defaultRouteL3NetworkUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateVirtualRouterAction, self).__init__()
        self.vmInstanceUuid = None
        self.defaultRouteL3NetworkUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DetachPolicyFromRoleAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/identities/policies/{policyUuid}/roles/{roleUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'roleUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'policyUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DetachPolicyFromRoleAction, self).__init__()
        self.roleUuid = None
        self.policyUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ChangeHostStateAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/hosts/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'changeHostState'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'stateEvent': ParamAnnotation(required=True,valid_values=['enable','disable','maintain'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ChangeHostStateAction, self).__init__()
        self.uuid = None
        self.stateEvent = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetEipAttachableVmNicsAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/eips/{eipUuid}/vm-instances/candidate-nics'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'eipUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'vipUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'vmUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'vmName': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'networkServiceProvider': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'attachedToVm': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetEipAttachableVmNicsAction, self).__init__()
        self.eipUuid = None
        self.vipUuid = None
        self.vmUuid = None
        self.vmName = None
        self.networkServiceProvider = None
        self.attachedToVm = None
        self.limit = None
        self.start = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteLdapServerAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/ldap/servers/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteLdapServerAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetSpiceCertificatesAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/spice/certificates'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetSpiceCertificatesAction, self).__init__()
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ExpungeDataVolumeAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/volumes/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'expungeDataVolume'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ExpungeDataVolumeAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryCephPrimaryStorageAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/primary-storage/ceph'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryCephPrimaryStorageAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class RequestConsoleAccessAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/consoles'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'vmInstanceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(RequestConsoleAccessAction, self).__init__()
        self.vmInstanceUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ExpungeImageAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/images/{imageUuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'expungeImage'

    PARAMS = {
        'uuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'imageUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'backupStorageUuids': ParamAnnotation(required=False,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ExpungeImageAction, self).__init__()
        self.uuid = None
        self.imageUuid = None
        self.backupStorageUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetBackupStorageCapacityAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/backup-storage/capacities'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'zoneUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'backupStorageUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'all': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetBackupStorageCapacityAction, self).__init__()
        self.zoneUuids = None
        self.backupStorageUuids = None
        self.all = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class LogInByAccountAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/accounts/login'
    NEED_SESSION = False
    NEED_POLL = False
    PARAM_NAME = 'logInByAccount'

    PARAMS = {
        'accountName': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'password': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'accountType': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'captchaUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'verifyCode': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'clientInfo': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(LogInByAccountAction, self).__init__()
        self.accountName = None
        self.password = None
        self.accountType = None
        self.captchaUuid = None
        self.verifyCode = None
        self.clientInfo = None
        self.systemTags = None
        self.userTags = None
        self.requestIp = None


class GetPrimaryStorageLicenseInfoAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/primary-storage/{uuid}/license'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetPrimaryStorageLicenseInfoAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteExportedImageFromBackupStorageAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/backup-storage/{backupStorageUuid}/exported-images/{imageUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'backupStorageUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'imageUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteExportedImageFromBackupStorageAction, self).__init__()
        self.backupStorageUuid = None
        self.imageUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteVmBootModeAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/vm-instances/{uuid}/bootmode'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteVmBootModeAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AttachPoliciesToUserAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/accounts/users/{userUuid}/policy-collection'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'userUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'policyUuids': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AttachPoliciesToUserAction, self).__init__()
        self.userUuid = None
        self.policyUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class RevertVmFromSnapshotGroupAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/volume-snapshots/group/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'revertVmFromSnapshotGroup'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(RevertVmFromSnapshotGroupAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ReconnectConsoleProxyAgentAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/consoles/agents'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'reconnectConsoleProxyAgent'

    PARAMS = {
        'agentUuids': ParamAnnotation(required=False,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ReconnectConsoleProxyAgentAction, self).__init__()
        self.agentUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateCertificateAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/certificates/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateCertificate'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateCertificateAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryLongJobAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/longjobs'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryLongJobAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ChangeEipStateAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/eips/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'changeEipState'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'stateEvent': ParamAnnotation(required=True,valid_values=['enable','disable'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ChangeEipStateAction, self).__init__()
        self.uuid = None
        self.stateEvent = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetIpAddressCapacityAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/ip-capacity'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'zoneUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'l3NetworkUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'ipRangeUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'all': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetIpAddressCapacityAction, self).__init__()
        self.zoneUuids = None
        self.l3NetworkUuids = None
        self.ipRangeUuids = None
        self.all = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class RemovePolicyStatementsFromRoleAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/identities/roles/{uuid}/policy-statements'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'policyStatementUuids': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(RemovePolicyStatementsFromRoleAction, self).__init__()
        self.uuid = None
        self.policyStatementUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ResetGlobalConfigAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/global-configurations/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'resetGlobalConfig'

    PARAMS = {
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ResetGlobalConfigAction, self).__init__()
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetPrimaryStorageCapacityAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/primary-storage/capacities'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'zoneUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'clusterUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'primaryStorageUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'all': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetPrimaryStorageCapacityAction, self).__init__()
        self.zoneUuids = None
        self.clusterUuids = None
        self.primaryStorageUuids = None
        self.all = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreatePortForwardingRuleAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/port-forwarding'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'vipUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'vipPortStart': ParamAnnotation(required=True,number_range=[1, 65535],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'vipPortEnd': ParamAnnotation(required=False,number_range=[1, 65535],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'privatePortStart': ParamAnnotation(required=False,number_range=[1, 65535],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'privatePortEnd': ParamAnnotation(required=False,number_range=[1, 65535],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'protocolType': ParamAnnotation(required=True,valid_values=['TCP','UDP'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'vmNicUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'allowedCidr': ParamAnnotation(),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreatePortForwardingRuleAction, self).__init__()
        self.vipUuid = None
        self.vipPortStart = None
        self.vipPortEnd = None
        self.privatePortStart = None
        self.privatePortEnd = None
        self.protocolType = None
        self.vmNicUuid = None
        self.allowedCidr = None
        self.name = None
        self.description = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetTrashOnPrimaryStorageAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/primary-storage/trash'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceType': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'trashType': ParamAnnotation(required=False,valid_values=['MigrateVolume','MigrateVolumeSnapshot','RevertVolume','VolumeSnapshot'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetTrashOnPrimaryStorageAction, self).__init__()
        self.uuid = None
        self.resourceUuid = None
        self.resourceType = None
        self.trashType = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetCandidateBackupStorageForCreatingImageAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = 'null'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'volumeUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'volumeSnapshotUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetCandidateBackupStorageForCreatingImageAction, self).__init__()
        self.volumeUuid = None
        self.volumeSnapshotUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateUserGroupAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/accounts/groups/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateUserGroup'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateUserGroupAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class RefreshCaptchaAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/captcha/refresh'
    NEED_SESSION = False
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(RefreshCaptchaAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.requestIp = None


class QueryL2NetworkAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/l2-networks'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryL2NetworkAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateDataVolumeFromVolumeTemplateAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/volumes/data/from/data-volume-templates/{imageUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'imageUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'primaryStorageUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'hostUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateDataVolumeFromVolumeTemplateAction, self).__init__()
        self.imageUuid = None
        self.name = None
        self.description = None
        self.primaryStorageUuid = None
        self.hostUuid = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddHostRouteToL3NetworkAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/l3-networks/{l3NetworkUuid}/hostroute'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'prefix': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'nexthop': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddHostRouteToL3NetworkAction, self).__init__()
        self.l3NetworkUuid = None
        self.prefix = None
        self.nexthop = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateLdapBindingAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/ldap/bindings'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'ldapUid': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'accountUuid': ParamAnnotation(required=True,max_length=32,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateLdapBindingAction, self).__init__()
        self.ldapUid = None
        self.accountUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateQuotaAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/accounts/quotas/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateQuota'

    PARAMS = {
        'identityUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'value': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateQuotaAction, self).__init__()
        self.identityUuid = None
        self.name = None
        self.value = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateDataVolumeTemplateFromVolumeSnapshotAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/images/data-volume-templates/from/volume-snapshots/{snapshotUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'snapshotUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'backupStorageUuids': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateDataVolumeTemplateFromVolumeSnapshotAction, self).__init__()
        self.snapshotUuid = None
        self.name = None
        self.description = None
        self.backupStorageUuids = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryDiskOfferingAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/disk-offerings'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryDiskOfferingAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ShareResourceAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/accounts/resources/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'shareResource'

    PARAMS = {
        'resourceUuids': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'accountUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'toPublic': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ShareResourceAction, self).__init__()
        self.resourceUuids = None
        self.accountUuids = None
        self.toPublic = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateCephPrimaryStoragePoolAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/primary-storage/ceph/pools/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateCephPrimaryStoragePool'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'aliasName': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateCephPrimaryStoragePoolAction, self).__init__()
        self.uuid = None
        self.aliasName = None
        self.description = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddMonToCephPrimaryStorageAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/primary-storage/ceph/{uuid}/mons'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'monUrls': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddMonToCephPrimaryStorageAction, self).__init__()
        self.uuid = None
        self.monUrls = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class RefreshLoadBalancerAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/load-balancers/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'refreshLoadBalancer'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(RefreshLoadBalancerAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateRoleAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/identities/roles'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'statements': ParamAnnotation(),
        'policyUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'identity': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=False,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateRoleAction, self).__init__()
        self.name = None
        self.description = None
        self.statements = None
        self.policyUuids = None
        self.identity = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreatePolicyAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/accounts/policies'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'statements': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreatePolicyAction, self).__init__()
        self.name = None
        self.description = None
        self.statements = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CleanUpTrashOnBackupStorageAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/backup-storage/{uuid}/trash/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'cleanUpTrashOnBackupStorage'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'trashId': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CleanUpTrashOnBackupStorageAction, self).__init__()
        self.uuid = None
        self.trashId = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryVniRangeAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/l2-networks/vxlan-pool/vni-range'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryVniRangeAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ChangeL3NetworkStateAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/l3-networks/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'changeL3NetworkState'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'stateEvent': ParamAnnotation(required=True,valid_values=['enable','disable'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ChangeL3NetworkStateAction, self).__init__()
        self.uuid = None
        self.stateEvent = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateAccountAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/accounts/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateAccount'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'password': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'oldPassword': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateAccountAction, self).__init__()
        self.uuid = None
        self.password = None
        self.name = None
        self.description = None
        self.oldPassword = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetBackupStorageTypesAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/backup-storage/types'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetBackupStorageTypesAction, self).__init__()
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DestroyVmInstanceAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/vm-instances/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DestroyVmInstanceAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetCandidateZonesClustersHostsForCreatingVmAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/vm-instances/candidate-destinations'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'instanceOfferingUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'imageUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'l3NetworkUuids': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'rootDiskOfferingUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'dataDiskOfferingUuids': ParamAnnotation(required=False,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'cpuNum': ParamAnnotation(required=False,number_range=[1, 1024],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'memorySize': ParamAnnotation(required=False,number_range=[1, 9223372036854775807],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'zoneUuid': ParamAnnotation(),
        'clusterUuid': ParamAnnotation(),
        'defaultL3NetworkUuid': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetCandidateZonesClustersHostsForCreatingVmAction, self).__init__()
        self.instanceOfferingUuid = None
        self.imageUuid = None
        self.l3NetworkUuids = None
        self.rootDiskOfferingUuid = None
        self.dataDiskOfferingUuids = None
        self.cpuNum = None
        self.memorySize = None
        self.zoneUuid = None
        self.clusterUuid = None
        self.defaultL3NetworkUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryImageCacheAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/primary-storage/imagecache'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryImageCacheAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteHostAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/hosts/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteHostAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddCephBackupStorageAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/backup-storage/ceph'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'monUrls': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=False,no_trim=False),
        'poolName': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'url': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'type': ParamAnnotation(),
        'importImages': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddCephBackupStorageAction, self).__init__()
        self.monUrls = None
        self.poolName = None
        self.url = None
        self.name = None
        self.description = None
        self.type = None
        self.importImages = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetCandidateVmNicForSecurityGroupAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/security-groups/{securityGroupUuid}/vm-instances/candidate-nics'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'securityGroupUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetCandidateVmNicForSecurityGroupAction, self).__init__()
        self.securityGroupUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class SetVmInstanceDefaultCdRomAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/{vmInstanceUuid}/cdroms/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'setVmInstanceDefaultCdRom'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'vmInstanceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(SetVmInstanceDefaultCdRomAction, self).__init__()
        self.uuid = None
        self.vmInstanceUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetFreeIpAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = 'null'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'l3NetworkUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'ipRangeUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'start': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'ipRangeType': ParamAnnotation(required=False,valid_values=['Normal','AddressPool'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'ipVersion': ParamAnnotation(required=False,valid_values=['4','6'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetFreeIpAction, self).__init__()
        self.l3NetworkUuid = None
        self.ipRangeUuid = None
        self.start = None
        self.ipRangeType = None
        self.ipVersion = None
        self.limit = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class SetVmConsolePasswordAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'setVmConsolePassword'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'consolePassword': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(SetVmConsolePasswordAction, self).__init__()
        self.uuid = None
        self.consolePassword = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteIpRangeAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/l3-networks/ip-ranges/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteIpRangeAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddUserToGroupAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/accounts/groups/{groupUuid}/users'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'userUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'groupUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddUserToGroupAction, self).__init__()
        self.userUuid = None
        self.groupUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetVmAttachableDataVolumeAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/vm-instances/{vmInstanceUuid}/data-volume-candidates'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'vmInstanceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetVmAttachableDataVolumeAction, self).__init__()
        self.vmInstanceUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryL2VxlanNetworkPoolAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/l2-networks/vxlan-pool'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryL2VxlanNetworkPoolAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryAccessControlListAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/access-control-lists'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryAccessControlListAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetNetworkServiceTypesAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/network-services/types'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetNetworkServiceTypesAction, self).__init__()
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryGCJobAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/gc-jobs'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryGCJobAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ChangeInstanceOfferingStateAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/instance-offerings/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'changeInstanceOfferingState'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'stateEvent': ParamAnnotation(required=True,valid_values=['enable','disable'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ChangeInstanceOfferingStateAction, self).__init__()
        self.uuid = None
        self.stateEvent = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryWebhookAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/web-hooks'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryWebhookAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ReconnectBackupStorageAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/backup-storage/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'reconnectBackupStorage'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ReconnectBackupStorageAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ChangeRoleStateAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/identities/roles/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'changeRoleState'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'stateEvent': ParamAnnotation(required=True,valid_values=['enable','disable'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ChangeRoleStateAction, self).__init__()
        self.uuid = None
        self.stateEvent = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DetachIsoFromVmInstanceAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/vm-instances/{vmInstanceUuid}/iso'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'vmInstanceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'isoUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DetachIsoFromVmInstanceAction, self).__init__()
        self.vmInstanceUuid = None
        self.isoUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class RevertVolumeFromSnapshotAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/volume-snapshots/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'revertVolumeFromSnapshot'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(RevertVolumeFromSnapshotAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryHostAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/hosts'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryHostAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteVmSshKeyAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/vm-instances/{uuid}/ssh-keys'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteVmSshKeyAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteEipAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/eips/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteEipAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class RemoveHostRouteFromL3NetworkAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/l3-networks/{l3NetworkUuid}/hostroute'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'prefix': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(RemoveHostRouteFromL3NetworkAction, self).__init__()
        self.l3NetworkUuid = None
        self.prefix = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddNfsPrimaryStorageAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/primary-storage/nfs'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'url': ParamAnnotation(required=True,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'type': ParamAnnotation(),
        'zoneUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddNfsPrimaryStorageAction, self).__init__()
        self.url = None
        self.name = None
        self.description = None
        self.type = None
        self.zoneUuid = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CleanUpTrashOnPrimaryStorageAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/primary-storage/{uuid}/trash/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'cleanUpTrashOnPrimaryStorage'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'trashId': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CleanUpTrashOnPrimaryStorageAction, self).__init__()
        self.uuid = None
        self.trashId = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetInterdependentL3NetworksImagesAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/images-l3networks/dependencies'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'zoneUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'l3NetworkUuids': ParamAnnotation(required=False,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'imageUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetInterdependentL3NetworksImagesAction, self).__init__()
        self.zoneUuid = None
        self.l3NetworkUuids = None
        self.imageUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryEipAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/eips'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryEipAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateIpRangeAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/l3-networks/ip-ranges/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateIpRange'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateIpRangeAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class RemoveDnsFromL3NetworkAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/l3-networks/{l3NetworkUuid}/dns/{dns}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'dns': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(RemoveDnsFromL3NetworkAction, self).__init__()
        self.l3NetworkUuid = None
        self.dns = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetCandidateVmForAttachingIsoAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/images/iso/{isoUuid}/vm-candidates'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'isoUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetCandidateVmForAttachingIsoAction, self).__init__()
        self.isoUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryVipAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/vips'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryVipAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryImageAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/images'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryImageAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddAccessControlListToLoadBalancerAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/load-balancers/listeners/{listenerUuid}/access-control-lists'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'aclUuids': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'aclType': ParamAnnotation(required=True,valid_values=['white','black'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'listenerUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddAccessControlListToLoadBalancerAction, self).__init__()
        self.aclUuids = None
        self.aclType = None
        self.listenerUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddVmNicToLoadBalancerAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/load-balancers/listeners/{listenerUuid}/vm-instances/nics'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'vmNicUuids': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'listenerUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddVmNicToLoadBalancerAction, self).__init__()
        self.vmNicUuids = None
        self.listenerUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateVipAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vips/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateVip'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateVipAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteL2NetworkAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/l2-networks/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteL2NetworkAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AttachIsoToVmInstanceAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/vm-instances/{vmInstanceUuid}/iso/{isoUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'null'

    PARAMS = {
        'vmInstanceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'isoUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AttachIsoToVmInstanceAction, self).__init__()
        self.vmInstanceUuid = None
        self.isoUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetVmCapabilitiesAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/vm-instances/{uuid}/capabilities'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetVmCapabilitiesAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class RemoveAccessControlListFromLoadBalancerAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/load-balancers/listeners/{listenerUuid}/access-control-lists'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'aclUuids': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'listenerUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(RemoveAccessControlListFromLoadBalancerAction, self).__init__()
        self.aclUuids = None
        self.listenerUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ExpungeVmInstanceAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'expungeVmInstance'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ExpungeVmInstanceAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CheckElaborationContentAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/errorcode/elaborations/check'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = 'params'

    PARAMS = {
        'elaborateFile': ParamAnnotation(required=False,non_empty=True,null_elements=False,empty_string=False,no_trim=False),
        'elaborateContent': ParamAnnotation(required=False,non_empty=True,null_elements=False,empty_string=False,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CheckElaborationContentAction, self).__init__()
        self.elaborateFile = None
        self.elaborateContent = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ExportImageFromBackupStorageAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/backup-storage/{backupStorageUuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'exportImageFromBackupStorage'

    PARAMS = {
        'backupStorageUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'imageUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'exportFormat': ParamAnnotation(required=False,valid_values=['raw','qcow2'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ExportImageFromBackupStorageAction, self).__init__()
        self.backupStorageUuid = None
        self.imageUuid = None
        self.exportFormat = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class RecoverDataVolumeAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/volumes/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'recoverDataVolume'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(RecoverDataVolumeAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetAccountQuotaUsageAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/accounts/quota/{uuid}/usages'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetAccountQuotaUsageAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryAddressPoolAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/l3-networks/address-pools'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryAddressPoolAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class KvmRunShellAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/hosts/kvm/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'kvmRunShell'

    PARAMS = {
        'hostUuids': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'script': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(KvmRunShellAction, self).__init__()
        self.hostUuids = None
        self.script = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateSecurityGroupAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/security-groups'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'ipVersion': ParamAnnotation(required=False,valid_values=['4','6'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateSecurityGroupAction, self).__init__()
        self.name = None
        self.description = None
        self.ipVersion = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateWebhookAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/web-hooks/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateWebhook'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'url': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'type': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'opaque': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateWebhookAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.url = None
        self.type = None
        self.opaque = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetCandidateL3NetworksForLoadBalancerAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/load-balancers/listeners/{listenerUuid}/networks/candidates'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'listenerUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetCandidateL3NetworksForLoadBalancerAction, self).__init__()
        self.listenerUuid = None
        self.limit = None
        self.start = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetVmConsoleAddressAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/vm-instances/{uuid}/console-addresses'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetVmConsoleAddressAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QuerySharedResourceAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/accounts/resources'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QuerySharedResourceAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateLoadBalancerListenerAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/load-balancers/{loadBalancerUuid}/listeners'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'loadBalancerUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'instancePort': ParamAnnotation(required=False,number_range=[1, 65535],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'loadBalancerPort': ParamAnnotation(required=True,number_range=[1, 65535],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'protocol': ParamAnnotation(required=False,valid_values=['udp','tcp','http','https'],max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'certificateUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'healthCheckProtocol': ParamAnnotation(required=False,valid_values=['tcp','udp','http'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'healthCheckMethod': ParamAnnotation(required=False,valid_values=['GET','HEAD'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'healthCheckURI': ParamAnnotation(required=False,valid_regex_values=r'^/[A-Za-z0-9-/.%?#&]+',max_length=80,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'healthCheckHttpCode': ParamAnnotation(required=False,max_length=80,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'aclStatus': ParamAnnotation(required=False,valid_values=['enable','disable'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'aclUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'aclType': ParamAnnotation(required=False,valid_values=['white','black'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateLoadBalancerListenerAction, self).__init__()
        self.loadBalancerUuid = None
        self.name = None
        self.description = None
        self.instancePort = None
        self.loadBalancerPort = None
        self.protocol = None
        self.certificateUuid = None
        self.healthCheckProtocol = None
        self.healthCheckMethod = None
        self.healthCheckURI = None
        self.healthCheckHttpCode = None
        self.aclStatus = None
        self.aclUuids = None
        self.aclType = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateGlobalConfigAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/global-configurations/{category}/{name}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateGlobalConfig'

    PARAMS = {
        'category': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'value': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateGlobalConfigAction, self).__init__()
        self.category = None
        self.name = None
        self.value = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteRoleAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/identities/roles/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteRoleAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class SetVmQxlMemoryAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'setVmQxlMemory'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'ram': ParamAnnotation(required=False,number_range=[1024, 524288],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'vram': ParamAnnotation(required=False,number_range=[1024, 524288],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'vgamem': ParamAnnotation(required=False,number_range=[1024, 524288],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(SetVmQxlMemoryAction, self).__init__()
        self.uuid = None
        self.ram = None
        self.vram = None
        self.vgamem = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class LogInByLdapAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/ldap/login'
    NEED_SESSION = False
    NEED_POLL = False
    PARAM_NAME = 'logInByLdap'

    PARAMS = {
        'uid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'password': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'verifyCode': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'captchaUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'clientInfo': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(LogInByLdapAction, self).__init__()
        self.uid = None
        self.password = None
        self.verifyCode = None
        self.captchaUuid = None
        self.clientInfo = None
        self.systemTags = None
        self.userTags = None
        self.requestIp = None


class DeleteImageAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/images/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'backupStorageUuids': ParamAnnotation(required=False,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteImageAction, self).__init__()
        self.uuid = None
        self.backupStorageUuids = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetDataVolumeAttachableVmAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/volumes/{volumeUuid}/candidate-vm-instances'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'volumeUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetDataVolumeAttachableVmAction, self).__init__()
        self.volumeUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetVmSshKeyAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/vm-instances/{uuid}/ssh-keys'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetVmSshKeyAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryUserGroupAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/accounts/groups'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryUserGroupAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateUserTagAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/user-tags'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'resourceType': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'tag': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateUserTagAction, self).__init__()
        self.resourceType = None
        self.resourceUuid = None
        self.tag = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryL3NetworkAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/l3-networks'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryL3NetworkAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ReloadElaborationAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/errorcode/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'reloadElaboration'

    PARAMS = {
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ReloadElaborationAction, self).__init__()
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteZoneAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/zones/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteZoneAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryLoadBalancerAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/load-balancers'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryLoadBalancerAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryVmCdRomAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/vm-instances/cdroms'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryVmCdRomAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteResourceConfigAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/resource-configurations/{category}/{name}/{resourceUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'category': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteResourceConfigAction, self).__init__()
        self.category = None
        self.name = None
        self.resourceUuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class SyncPrimaryStorageCapacityAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/primary-storage/{primaryStorageUuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'syncPrimaryStorageCapacity'

    PARAMS = {
        'primaryStorageUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(SyncPrimaryStorageCapacityAction, self).__init__()
        self.primaryStorageUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetResourceBindableConfigAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/resource-configurations/bindable'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'category': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetResourceBindableConfigAction, self).__init__()
        self.category = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ChangeZoneStateAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/zones/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'changeZoneState'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'stateEvent': ParamAnnotation(required=True,valid_values=['enable','disable'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ChangeZoneStateAction, self).__init__()
        self.uuid = None
        self.stateEvent = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryNetworkServiceProviderAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/network-services/providers'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryNetworkServiceProviderAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteUserAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/accounts/users/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteUserAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetVmBootOrderAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/vm-instances/{uuid}/boot-orders'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetVmBootOrderAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateVolumeSnapshotAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/volume-snapshots/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateVolumeSnapshot'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateVolumeSnapshotAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetHostAllocatorStrategiesAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/hosts/allocators/strategies'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetHostAllocatorStrategiesAction, self).__init__()
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AttachPrimaryStorageToClusterAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/clusters/{clusterUuid}/primary-storage/{primaryStorageUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'clusterUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'primaryStorageUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AttachPrimaryStorageToClusterAction, self).__init__()
        self.clusterUuid = None
        self.primaryStorageUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddSimulatorBackupStorageAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/backup-storage/simulators'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'totalCapacity': ParamAnnotation(),
        'availableCapacity': ParamAnnotation(),
        'url': ParamAnnotation(required=True,max_length=2048,non_empty=False,null_elements=False,empty_string=False,no_trim=False),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'type': ParamAnnotation(),
        'importImages': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddSimulatorBackupStorageAction, self).__init__()
        self.totalCapacity = None
        self.availableCapacity = None
        self.url = None
        self.name = None
        self.description = None
        self.type = None
        self.importImages = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryVmInstanceAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/vm-instances'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryVmInstanceAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CheckApiPermissionAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/accounts/permissions/actions'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = 'checkApiPermission'

    PARAMS = {
        'userUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'apiNames': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CheckApiPermissionAction, self).__init__()
        self.userUuid = None
        self.apiNames = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateVmInstanceAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/vm-instances'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'instanceOfferingUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'cpuNum': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'memorySize': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'imageUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'l3NetworkUuids': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'type': ParamAnnotation(required=False,valid_values=['UserVm','ApplianceVm'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'rootDiskOfferingUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'rootDiskSize': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'dataDiskOfferingUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'zoneUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'clusterUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'hostUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'primaryStorageUuidForRootVolume': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'defaultL3NetworkUuid': ParamAnnotation(),
        'strategy': ParamAnnotation(required=False,valid_values=['InstantStart','JustCreate','CreateStopped'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'rootVolumeSystemTags': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'dataVolumeSystemTags': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateVmInstanceAction, self).__init__()
        self.name = None
        self.instanceOfferingUuid = None
        self.cpuNum = None
        self.memorySize = None
        self.imageUuid = None
        self.l3NetworkUuids = None
        self.type = None
        self.rootDiskOfferingUuid = None
        self.rootDiskSize = None
        self.dataDiskOfferingUuids = None
        self.zoneUuid = None
        self.clusterUuid = None
        self.hostUuid = None
        self.primaryStorageUuidForRootVolume = None
        self.description = None
        self.defaultL3NetworkUuid = None
        self.strategy = None
        self.rootVolumeSystemTags = None
        self.dataVolumeSystemTags = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class BatchDeleteVolumeSnapshotAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/volume-snapshots/batch-delete'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'batchDeleteVolumeSnapshot'

    PARAMS = {
        'uuids': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=False,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(BatchDeleteVolumeSnapshotAction, self).__init__()
        self.uuids = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class BatchQueryAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/batch-queries'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'script': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(BatchQueryAction, self).__init__()
        self.script = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetPrimaryStorageTypesAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/primary-storage/types'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetPrimaryStorageTypesAction, self).__init__()
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetVmDeviceAddressAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/vm-instances/devices'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceTypes': ParamAnnotation(required=True,valid_values=['VolumeVO'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetVmDeviceAddressAction, self).__init__()
        self.uuid = None
        self.resourceTypes = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryConsoleProxyAgentAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/consoles/agents'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryConsoleProxyAgentAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AttachPolicyToUserGroupAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/accounts/groups/{groupUuid}/policies'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'policyUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'groupUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AttachPolicyToUserGroupAction, self).__init__()
        self.policyUuid = None
        self.groupUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetHypervisorTypesAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/hosts/hypervisor-types'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetHypervisorTypesAction, self).__init__()
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DetachPolicyFromUserGroupAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/accounts/groups/{groupUuid}/policies/{policyUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'policyUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'groupUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DetachPolicyFromUserGroupAction, self).__init__()
        self.policyUuid = None
        self.groupUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class SyncImageSizeAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/images/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'syncImageSize'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(SyncImageSizeAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetTaskProgressAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/task-progresses/{apiId}'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'apiId': ParamAnnotation(),
        'all': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetTaskProgressAction, self).__init__()
        self.apiId = None
        self.all = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class LocalStorageMigrateVolumeAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/primary-storage/local-storage/volumes/{volumeUuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'localStorageMigrateVolume'

    PARAMS = {
        'volumeUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'destHostUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(LocalStorageMigrateVolumeAction, self).__init__()
        self.volumeUuid = None
        self.destHostUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class RemoveMonFromCephPrimaryStorageAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/primary-storage/ceph/{uuid}/mons'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'monHostnames': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(RemoveMonFromCephPrimaryStorageAction, self).__init__()
        self.uuid = None
        self.monHostnames = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdatePrimaryStorageAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/primary-storage/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updatePrimaryStorage'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'url': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdatePrimaryStorageAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.url = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateVniRangeAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/l2-networks/vxlan-pool/vni-ranges/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateVniRange'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateVniRangeAction, self).__init__()
        self.uuid = None
        self.name = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateClusterOSAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/clusters/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateClusterOS'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'excludePackages': ParamAnnotation(required=False,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'updatePackages': ParamAnnotation(required=False,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'releaseVersion': ParamAnnotation(required=False,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateClusterOSAction, self).__init__()
        self.uuid = None
        self.excludePackages = None
        self.updatePackages = None
        self.releaseVersion = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateUserAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/accounts/users'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'password': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateUserAction, self).__init__()
        self.name = None
        self.password = None
        self.description = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DetachSecurityGroupFromL3NetworkAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/security-groups/{securityGroupUuid}/l3-networks/{l3NetworkUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'securityGroupUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DetachSecurityGroupFromL3NetworkAction, self).__init__()
        self.securityGroupUuid = None
        self.l3NetworkUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetL3NetworkTypesAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/l3-networks/types'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetL3NetworkTypesAction, self).__init__()
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetResourceNamesAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/resources/names'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'uuids': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetResourceNamesAction, self).__init__()
        self.uuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class SetVmBootModeAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'setVmBootMode'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'bootMode': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(SetVmBootModeAction, self).__init__()
        self.uuid = None
        self.bootMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class SetVmHostnameAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'setVmHostname'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'hostname': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(SetVmHostnameAction, self).__init__()
        self.uuid = None
        self.hostname = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddLocalPrimaryStorageAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/primary-storage/local-storage'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'url': ParamAnnotation(required=True,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'type': ParamAnnotation(),
        'zoneUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddLocalPrimaryStorageAction, self).__init__()
        self.url = None
        self.name = None
        self.description = None
        self.type = None
        self.zoneUuid = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddSecurityGroupRuleAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/security-groups/{securityGroupUuid}/rules'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'securityGroupUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'rules': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'remoteSecurityGroupUuids': ParamAnnotation(required=False,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddSecurityGroupRuleAction, self).__init__()
        self.securityGroupUuid = None
        self.rules = None
        self.remoteSecurityGroupUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetL3NetworkDhcpIpAddressAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/l3-networks/{l3NetworkUuid}/dhcp-ip'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetL3NetworkDhcpIpAddressAction, self).__init__()
        self.l3NetworkUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateEipAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/eips'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'vipUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'vmNicUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'usedIpUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateEipAction, self).__init__()
        self.name = None
        self.description = None
        self.vipUuid = None
        self.vmNicUuid = None
        self.usedIpUuid = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class IsOpensourceVersionAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/meta-data/opensource'
    NEED_SESSION = False
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(IsOpensourceVersionAction, self).__init__()
        self.systemTags = None
        self.userTags = None
        self.requestIp = None


class QueryNetworkServiceL3NetworkRefAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/l3-networks/network-services/refs'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryNetworkServiceL3NetworkRefAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteUserGroupAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/accounts/groups/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteUserGroupAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryZoneAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/zones'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryZoneAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteDiskOfferingAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/disk-offerings/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteDiskOfferingAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateZoneAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/zones/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateZone'

    PARAMS = {
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateZoneAction, self).__init__()
        self.name = None
        self.description = None
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryCephPrimaryStoragePoolAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/primary-storage/ceph/pools'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryCephPrimaryStoragePoolAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class SetL3NetworkRouterInterfaceIpAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/l3-networks/{l3NetworkUuid}/router-interface-ip'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'routerInterfaceIp': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(SetL3NetworkRouterInterfaceIpAction, self).__init__()
        self.l3NetworkUuid = None
        self.routerInterfaceIp = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UngroupVolumeSnapshotGroupAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/volume-snapshots/ungroup/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UngroupVolumeSnapshotGroupAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryQuotaAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/accounts/quotas'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryQuotaAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateVxlanVtepAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/l2-networks/vxlan/vteps'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'hostUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'poolUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'vtepIp': ParamAnnotation(),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateVxlanVtepAction, self).__init__()
        self.hostUuid = None
        self.poolUuid = None
        self.vtepIp = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetPortForwardingAttachableVmNicsAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/port-forwarding/{ruleUuid}/vm-instances/candidate-nics'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'ruleUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetPortForwardingAttachableVmNicsAction, self).__init__()
        self.ruleUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateLoadBalancerAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/load-balancers'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'vipUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateLoadBalancerAction, self).__init__()
        self.name = None
        self.description = None
        self.vipUuid = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateDiskOfferingAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/disk-offerings'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'diskSize': ParamAnnotation(required=True,number_range=[1, 9223372036854775807],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'sortKey': ParamAnnotation(),
        'allocationStrategy': ParamAnnotation(),
        'type': ParamAnnotation(required=False,valid_values=['zstack'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateDiskOfferingAction, self).__init__()
        self.name = None
        self.description = None
        self.diskSize = None
        self.sortKey = None
        self.allocationStrategy = None
        self.type = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateDataVolumeAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/volumes/data'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'diskOfferingUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'diskSize': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'primaryStorageUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateDataVolumeAction, self).__init__()
        self.name = None
        self.description = None
        self.diskOfferingUuid = None
        self.diskSize = None
        self.primaryStorageUuid = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetElaborationsAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/errorcode/elaborations'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'category': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'code': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'regex': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetElaborationsAction, self).__init__()
        self.category = None
        self.code = None
        self.regex = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AttachEipAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/eips/{eipUuid}/vm-instances/nics/{vmNicUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'eipUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'vmNicUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'usedIpUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AttachEipAction, self).__init__()
        self.eipUuid = None
        self.vmNicUuid = None
        self.usedIpUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateVirtualRouterOfferingAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/instance-offerings/virtual-routers'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'zoneUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'managementNetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'imageUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'publicNetworkUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'isDefault': ParamAnnotation(),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'cpuNum': ParamAnnotation(required=True,number_range=[1, 1024],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'memorySize': ParamAnnotation(required=True,number_range=[1, 9223372036854775807],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'allocatorStrategy': ParamAnnotation(),
        'sortKey': ParamAnnotation(),
        'type': ParamAnnotation(),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateVirtualRouterOfferingAction, self).__init__()
        self.zoneUuid = None
        self.managementNetworkUuid = None
        self.imageUuid = None
        self.publicNetworkUuid = None
        self.isDefault = None
        self.name = None
        self.description = None
        self.cpuNum = None
        self.memorySize = None
        self.allocatorStrategy = None
        self.sortKey = None
        self.type = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ChangeSecurityGroupStateAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/security-groups/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'changeSecurityGroupState'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'stateEvent': ParamAnnotation(required=True,valid_values=['enable','disable'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ChangeSecurityGroupStateAction, self).__init__()
        self.uuid = None
        self.stateEvent = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddIpRangeByNetworkCidrAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/l3-networks/{l3NetworkUuid}/ip-ranges/by-cidr'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'networkCidr': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'gateway': ParamAnnotation(required=False,max_length=64,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'ipRangeType': ParamAnnotation(required=False,valid_values=['Normal','AddressPool'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddIpRangeByNetworkCidrAction, self).__init__()
        self.name = None
        self.description = None
        self.l3NetworkUuid = None
        self.networkCidr = None
        self.gateway = None
        self.ipRangeType = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddSimulatorPrimaryStorageAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/primary-storage/simulators'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'totalCapacity': ParamAnnotation(),
        'availableCapacity': ParamAnnotation(),
        'availablePhysicalCapacity': ParamAnnotation(),
        'totalPhysicalCapacity': ParamAnnotation(),
        'url': ParamAnnotation(required=True,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'type': ParamAnnotation(),
        'zoneUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddSimulatorPrimaryStorageAction, self).__init__()
        self.totalCapacity = None
        self.availableCapacity = None
        self.availablePhysicalCapacity = None
        self.totalPhysicalCapacity = None
        self.url = None
        self.name = None
        self.description = None
        self.type = None
        self.zoneUuid = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateEipAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/eips/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateEip'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateEipAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetVmStartingCandidateClustersHostsAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/vm-instances/{uuid}/starting-target-hosts'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetVmStartingCandidateClustersHostsAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateSystemTagAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/system-tags'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'resourceType': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'tag': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateSystemTagAction, self).__init__()
        self.resourceType = None
        self.resourceUuid = None
        self.tag = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class SetVmBootOrderAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'setVmBootOrder'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'bootOrder': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(SetVmBootOrderAction, self).__init__()
        self.uuid = None
        self.bootOrder = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddKVMHostAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/hosts/kvm'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'username': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'password': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'sshPort': ParamAnnotation(required=False,number_range=[1, 65535],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'managementIp': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=False,no_trim=False),
        'clusterUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddKVMHostAction, self).__init__()
        self.username = None
        self.password = None
        self.sshPort = None
        self.name = None
        self.description = None
        self.managementIp = None
        self.clusterUuid = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class StartVmInstanceAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'startVmInstance'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'clusterUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'hostUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(StartVmInstanceAction, self).__init__()
        self.uuid = None
        self.clusterUuid = None
        self.hostUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateUserAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/accounts/users/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateUser'

    PARAMS = {
        'uuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'password': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'oldPassword': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateUserAction, self).__init__()
        self.uuid = None
        self.password = None
        self.name = None
        self.description = None
        self.oldPassword = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteLdapBindingAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/ldap/bindings/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,max_length=32,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteLdapBindingAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetCurrentTimeAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/management-nodes/actions'
    NEED_SESSION = False
    NEED_POLL = False
    PARAM_NAME = 'getCurrentTime'

    PARAMS = {
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetCurrentTimeAction, self).__init__()
        self.systemTags = None
        self.userTags = None
        self.requestIp = None


class DeleteAccountAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/accounts/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteAccountAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ReimageVmInstanceAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/{vmInstanceUuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'reimageVmInstance'

    PARAMS = {
        'vmInstanceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ReimageVmInstanceAction, self).__init__()
        self.vmInstanceUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateClusterAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/clusters'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'zoneUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'hypervisorType': ParamAnnotation(required=True,valid_values=['KVM','Simulator','baremetal','xdragon'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'type': ParamAnnotation(required=False,valid_values=['zstack','baremetal'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateClusterAction, self).__init__()
        self.zoneUuid = None
        self.name = None
        self.description = None
        self.hypervisorType = None
        self.type = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateDiskOfferingAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/disk-offerings/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateDiskOffering'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateDiskOfferingAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateVmNicDriverAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/{vmInstanceUuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateVmNicDriver'

    PARAMS = {
        'vmInstanceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'vmNicUuid': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'driverType': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateVmNicDriverAction, self).__init__()
        self.vmInstanceUuid = None
        self.vmNicUuid = None
        self.driverType = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class AddLdapServerAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/ldap/servers'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'url': ParamAnnotation(required=True,max_length=1024,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'base': ParamAnnotation(required=True,max_length=1024,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'username': ParamAnnotation(required=True,max_length=1024,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'password': ParamAnnotation(required=True,max_length=1024,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'encryption': ParamAnnotation(required=True,valid_values=['None','TLS'],max_length=1024,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'scope': ParamAnnotation(required=True,valid_values=['account','IAM2'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(AddLdapServerAction, self).__init__()
        self.name = None
        self.description = None
        self.url = None
        self.base = None
        self.username = None
        self.password = None
        self.encryption = None
        self.scope = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class SetVmSoundTypeAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'setVmSoundType'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'soundType': ParamAnnotation(required=True,valid_values=['ac97','ich6'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(SetVmSoundTypeAction, self).__init__()
        self.uuid = None
        self.soundType = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteVmStaticIpAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/vm-instances/{vmInstanceUuid}/static-ips'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'vmInstanceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'staticIp': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteVmStaticIpAction, self).__init__()
        self.vmInstanceUuid = None
        self.l3NetworkUuid = None
        self.staticIp = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryResourceConfigAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/resource-configurations'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryResourceConfigAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetL2NetworkTypesAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/l2-networks/types'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetL2NetworkTypesAction, self).__init__()
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteBackupStorageAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/backup-storage/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteBackupStorageAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateVniRangeAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/l2-networks/vxlan-pool/{l2NetworkUuid}/vni-ranges'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'startVni': ParamAnnotation(required=True,number_range=[0, 16777214],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'endVni': ParamAnnotation(required=True,number_range=[0, 16777214],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'l2NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateVniRangeAction, self).__init__()
        self.name = None
        self.description = None
        self.startVni = None
        self.endVni = None
        self.l2NetworkUuid = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetSupportedIdentityModelsAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/identity-models'
    NEED_SESSION = False
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetSupportedIdentityModelsAction, self).__init__()
        self.systemTags = None
        self.userTags = None
        self.requestIp = None


class DeleteVolumeSnapshotAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/volume-snapshots/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteVolumeSnapshotAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class RebootVmInstanceAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'rebootVmInstance'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(RebootVmInstanceAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class RecoverImageAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/images/{imageUuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'recoverImage'

    PARAMS = {
        'imageUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'backupStorageUuids': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(RecoverImageAction, self).__init__()
        self.imageUuid = None
        self.backupStorageUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateDataVolumeTemplateFromVolumeAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/images/data-volume-templates/from/volumes/{volumeUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'volumeUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'backupStorageUuids': ParamAnnotation(required=False,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateDataVolumeTemplateFromVolumeAction, self).__init__()
        self.name = None
        self.description = None
        self.volumeUuid = None
        self.backupStorageUuids = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetHostTaskAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/hosts/task-details'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'hostUuids': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetHostTaskAction, self).__init__()
        self.hostUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateLongJobAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/longjobs/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateLongJob'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateLongJobAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CleanInvalidLdapBindingAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/ldap/bindings/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'cleanInvalidLdapBinding'

    PARAMS = {
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CleanInvalidLdapBindingAction, self).__init__()
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class SetVmStaticIpAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/vm-instances/{vmInstanceUuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'setVmStaticIp'

    PARAMS = {
        'vmInstanceUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'l3NetworkUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'ip': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'ip6': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(SetVmStaticIpAction, self).__init__()
        self.vmInstanceUuid = None
        self.l3NetworkUuid = None
        self.ip = None
        self.ip6 = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateBackupStorageAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/backup-storage/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateBackupStorage'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateBackupStorageAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteAccessControlListAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/access-control-lists/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteAccessControlListAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetLdapEntryAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/ldap/entry'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'ldapFilter': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(required=False,number_range=[1, 2147483647],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetLdapEntryAction, self).__init__()
        self.ldapFilter = None
        self.limit = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QuerySystemTagAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/system-tags'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QuerySystemTagAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateConsoleProxyAgentAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/consoles/agents/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateConsoleProxyAgent'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'consoleProxyOverriddenIp': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateConsoleProxyAgentAction, self).__init__()
        self.uuid = None
        self.consoleProxyOverriddenIp = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryCertificateAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/certificates'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryCertificateAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ChangeDiskOfferingStateAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/disk-offerings/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'changeDiskOfferingState'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'stateEvent': ParamAnnotation(required=True,valid_values=['enable','disable'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ChangeDiskOfferingStateAction, self).__init__()
        self.uuid = None
        self.stateEvent = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateVmInstanceFromVolumeAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/vm-instances/from/volume'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'instanceOfferingUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'cpuNum': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'memorySize': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'l3NetworkUuids': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'type': ParamAnnotation(required=False,valid_values=['UserVm','ApplianceVm'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'volumeUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'platform': ParamAnnotation(required=False,valid_values=['Linux','Windows','Other','Paravirtualization','WindowsVirtio'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'zoneUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'clusterUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'hostUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'primaryStorageUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'defaultL3NetworkUuid': ParamAnnotation(),
        'strategy': ParamAnnotation(required=False,valid_values=['InstantStart','CreateStopped'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateVmInstanceFromVolumeAction, self).__init__()
        self.name = None
        self.description = None
        self.instanceOfferingUuid = None
        self.cpuNum = None
        self.memorySize = None
        self.l3NetworkUuids = None
        self.type = None
        self.volumeUuid = None
        self.platform = None
        self.zoneUuid = None
        self.clusterUuid = None
        self.hostUuid = None
        self.primaryStorageUuid = None
        self.defaultL3NetworkUuid = None
        self.strategy = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class CreateRootVolumeTemplateFromRootVolumeAction(AbstractAction):
    HTTP_METHOD = 'POST'
    PATH = '/images/root-volume-templates/from/volumes/{rootVolumeUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'guestOsType': ParamAnnotation(),
        'backupStorageUuids': ParamAnnotation(required=False,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'rootVolumeUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'platform': ParamAnnotation(required=False,valid_values=['Linux','Windows','Other','Paravirtualization','WindowsVirtio'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'system': ParamAnnotation(),
        'resourceUuid': ParamAnnotation(),
        'tagUuids': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(CreateRootVolumeTemplateFromRootVolumeAction, self).__init__()
        self.name = None
        self.description = None
        self.guestOsType = None
        self.backupStorageUuids = None
        self.rootVolumeUuid = None
        self.platform = None
        self.system = None
        self.resourceUuid = None
        self.tagUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryCephBackupStorageAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/backup-storage/ceph'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryCephBackupStorageAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteVmCdRomAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/vm-instances/cdroms/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteVmCdRomAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class UpdateImageAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/images/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'updateImage'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'name': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'description': ParamAnnotation(required=False,max_length=2048,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'guestOsType': ParamAnnotation(required=False,max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'mediaType': ParamAnnotation(required=False,valid_values=['RootVolumeTemplate','DataVolumeTemplate','ISO'],max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'format': ParamAnnotation(required=False,valid_values=['raw','qcow2','iso'],max_length=255,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'system': ParamAnnotation(),
        'platform': ParamAnnotation(required=False,valid_values=['Linux','Windows','Other','Paravirtualization','WindowsVirtio'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(UpdateImageAction, self).__init__()
        self.uuid = None
        self.name = None
        self.description = None
        self.guestOsType = None
        self.mediaType = None
        self.format = None
        self.system = None
        self.platform = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteSecurityGroupRuleAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/security-groups/rules'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'ruleUuids': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteSecurityGroupRuleAction, self).__init__()
        self.ruleUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DetachL3NetworkFromVmAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/vm-instances/nics/{vmNicUuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'vmNicUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DetachL3NetworkFromVmAction, self).__init__()
        self.vmNicUuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class ChangeLoadBalancerListenerAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/load-balancers/listeners/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'changeLoadBalancerListener'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'connectionIdleTimeout': ParamAnnotation(required=False,number_range=[0, 2147483647],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'maxConnection': ParamAnnotation(required=False,number_range=[0, 100000],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'balancerAlgorithm': ParamAnnotation(required=False,valid_values=['weightroundrobin','roundrobin','leastconn','source'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'healthCheckTarget': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'healthyThreshold': ParamAnnotation(required=False,number_range=[1, 2147483647],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'unhealthyThreshold': ParamAnnotation(required=False,number_range=[1, 2147483647],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'healthCheckInterval': ParamAnnotation(required=False,number_range=[1, 2147483647],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'healthCheckProtocol': ParamAnnotation(required=False,valid_values=['tcp','udp','http'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'healthCheckMethod': ParamAnnotation(required=False,valid_values=['GET','HEAD'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'healthCheckURI': ParamAnnotation(required=False,valid_regex_values=r'^/[A-Za-z0-9-/.%?#&]+',max_length=80,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'healthCheckHttpCode': ParamAnnotation(required=False,max_length=80,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'aclStatus': ParamAnnotation(required=False,valid_values=['enable','disable'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(ChangeLoadBalancerListenerAction, self).__init__()
        self.uuid = None
        self.connectionIdleTimeout = None
        self.maxConnection = None
        self.balancerAlgorithm = None
        self.healthCheckTarget = None
        self.healthyThreshold = None
        self.unhealthyThreshold = None
        self.healthCheckInterval = None
        self.healthCheckProtocol = None
        self.healthCheckMethod = None
        self.healthCheckURI = None
        self.healthCheckHttpCode = None
        self.aclStatus = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class SetImageBootModeAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/images/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'setImageBootMode'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'bootMode': ParamAnnotation(required=True,valid_values=['Legacy','UEFI','UEFI_WITH_CSM'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(SetImageBootModeAction, self).__init__()
        self.uuid = None
        self.bootMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class GetTrashOnBackupStorageAction(AbstractAction):
    HTTP_METHOD = 'GET'
    PATH = '/backup-storage/trash'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceUuid': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'resourceType': ParamAnnotation(required=False,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'trashType': ParamAnnotation(required=False,valid_values=['MigrateImage'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(GetTrashOnBackupStorageAction, self).__init__()
        self.uuid = None
        self.resourceUuid = None
        self.resourceType = None
        self.trashType = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteInstanceOfferingAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/instance-offerings/{uuid}'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'deleteMode': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteInstanceOfferingAction, self).__init__()
        self.uuid = None
        self.deleteMode = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class QueryVmNicInSecurityGroupAction(QueryAction):
    HTTP_METHOD = 'GET'
    PATH = '/security-groups/vm-instances/nics'
    NEED_SESSION = True
    NEED_POLL = False
    PARAM_NAME = ''

    PARAMS = {
        'conditions': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'limit': ParamAnnotation(),
        'start': ParamAnnotation(),
        'count': ParamAnnotation(),
        'groupBy': ParamAnnotation(),
        'replyWithCount': ParamAnnotation(),
        'filterName': ParamAnnotation(),
        'sortBy': ParamAnnotation(),
        'sortDirection': ParamAnnotation(required=False,valid_values=['asc','desc'],non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'fields': ParamAnnotation(),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(QueryVmNicInSecurityGroupAction, self).__init__()
        self.conditions = None
        self.limit = None
        self.start = None
        self.count = None
        self.groupBy = None
        self.replyWithCount = None
        self.filterName = None
        self.sortBy = None
        self.sortDirection = None
        self.fields = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class DeleteVmNicFromSecurityGroupAction(AbstractAction):
    HTTP_METHOD = 'DELETE'
    PATH = '/security-groups/{securityGroupUuid}/vm-instances/nics'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = ''

    PARAMS = {
        'securityGroupUuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'vmNicUuids': ParamAnnotation(required=True,non_empty=True,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(DeleteVmNicFromSecurityGroupAction, self).__init__()
        self.securityGroupUuid = None
        self.vmNicUuids = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None


class SyncVolumeSizeAction(AbstractAction):
    HTTP_METHOD = 'PUT'
    PATH = '/volumes/{uuid}/actions'
    NEED_SESSION = True
    NEED_POLL = True
    PARAM_NAME = 'syncVolumeSize'

    PARAMS = {
        'uuid': ParamAnnotation(required=True,non_empty=False,null_elements=False,empty_string=True,no_trim=False),
        'systemTags': ParamAnnotation(),
        'userTags': ParamAnnotation(),
        'sessionId': ParamAnnotation(required=False),
        'accessKeyId': ParamAnnotation(required=False),
        'accessKeySecret': ParamAnnotation(required=False),
        'requestIp': ParamAnnotation(required=False)
    }

    def __init__(self):
        super(SyncVolumeSizeAction, self).__init__()
        self.uuid = None
        self.systemTags = None
        self.userTags = None
        self.sessionId = None
        self.accessKeyId = None
        self.accessKeySecret = None
        self.requestIp = None
