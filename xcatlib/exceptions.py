from oslo_log import log as logging
import six

LOG = logging.getLogger(__name__)


class XcatLibException(Exception):
    def __init__(self, message=None, **kwargs):
        if not message:
            try:
                message = self.msg_fmt % kwargs

            except Exception:
                # kwargs doesn't match a variable in the message
                # log the issue and the kwargs
                for name, value in six.iteritems(kwargs):
                    LOG.error("%s: %s" % (name, value))    # noqa

                message = self.msg_fmt

        self.message = message
        super(XcatLibException, self).__init__(message)

    def format_message(self):
        return self.args[0]


class XCATRequestFailed(XcatLibException):
    msg_fmt = ('Request to xCAT server %(xcatserver)s failed: %(msg)s')


class XCATInvalidResponseDataError(XcatLibException):
    msg_fmt = ('Invalid data returned from xCAT: %(msg)s')


class XCATInternalError(XcatLibException):
    msg_fmt = ('Error returned from xCAT: %(msg)s')


class XCATXdshFailed(XcatLibException):
    msg_fmt = ('Execute xCAT xdsh command failed: %(msg)s')
