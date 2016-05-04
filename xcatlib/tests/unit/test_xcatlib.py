import mock
import testtools

from xcatlib import exceptions as exception
from xcatlib import xcatlib as xcat


class XcatlibTestCase(testtools.TestCase):
    pass


class XcatconnTestCase(XcatlibTestCase):
    def setUp(self):
        super(XcatconnTestCase, self).setUp()
        self.xcaturl = xcat.XCATUrl('dummy', 'dummy')

    @mock.patch('xcatlib.xcatlib.xcat_request')
    def test_xcat_cmd_gettab(self, mock_request):
        fake_resp = {"data": [["/install"]]}
        mock_request.return_value = fake_resp

        outp = xcat.xcat_cmd_gettab(self.xcaturl, "site", "key", "installdir",
                                    "value")
        self.assertEqual(outp, "/install")

    @mock.patch('xcatlib.xcatlib.xcat_request')
    def test_xcat_cmd_gettab_multi_attr(self, mock_request):
        attr_list = ['name', 'type', 'version']
        res_data = {'data': [['table.name: fake'],
                             ['table.type: fake'],
                             ['table.version: fake']]}
        mock_request.return_value = res_data

        outp = xcat.xcat_cmd_gettab_multi_attr(self.xcaturl, 'table', 'id',
                                               'fake', attr_list)
        self.assertEqual(outp['name'], 'fake')
        self.assertEqual(outp['type'], 'fake')
        self.assertEqual(outp['version'], 'fake')

    def test_is_recoverable_issue(self):
        error = ['Return Code: 596', 'Reason Code: 1185']
        ret = xcat._is_recoverable_issue(error)
        self.assertTrue(ret)
        error = ['dummy']
        ret = xcat._is_recoverable_issue(error)
        self.assertFalse(ret)

    def test_translate_xcat_resp(self):
        rawindata = ("opnstk1: z/VM Host: OPNSTK1\n"
                    "opnstk1: zHCP: zhcp.ibm.com\n"
                    "opnstk1: Architecture: s390x\n"
                    "opnstk1: CEC Vendor: IBM\n"
                    "opnstk1: CEC Model: 2817\n"
                    "opnstk1: Hypervisor OS: z/VM 6.3.0\n"
                    "opnstk1: Hypervisor Name: OPNSTK1\n"
                    "opnstk1: LPAR CPU Total: 6\n"
                    "opnstk1: LPAR CPU Used: 6\n"
                    "opnstk1: LPAR Memory Total: 50G\n"
                    "opnstk1: LPAR Memory Used: 0M\n"
                    "opnstk1: LPAR Memory Offline: 0\n"
                    "opnstk1: IPL Time: IPL at 12/10/15 14:38:11 EST\n"
                    "opnstk1: xCAT Hypervisor Node: opnstk1\n")
        expect_data = {"zvm_host": "OPNSTK1",
                       "zhcp": "zhcp.ibm.com",
                       "cec_vendor": "IBM",
                       "cec_model": "2817",
                       "hypervisor_os": "z/VM 6.3.0",
                       "hypervisor_name": "OPNSTK1",
                       "architecture": "s390x",
                       "lpar_cpu_total": "6",
                       "lpar_cpu_used": "6",
                       "lpar_memory_total": "50G",
                       "lpar_memory_used": "0M",
                       "lpar_memory_offline": "0",
                       "ipl_time": "IPL at 12/10/15 14:38:11 EST"}

        rinv_keys = xcat.XCAT_RINV_HOST_KEYWORDS
        data = xcat.translate_xcat_resp(rawindata, rinv_keys)
        self.assertEqual(expect_data, data)

    def test_translate_xcat_resp_invalid(self):
        rawindata = "opnstk1: z/VM Host: OPNSTK1\n"
        key = {'host': 'dummy'}
        self.assertRaises(exception.XCATInvalidResponseDataError,
                          xcat.translate_xcat_resp, rawindata, key)

    def test_load_xcat_resp(self):
        msgs = '{"data": [{"info": ["i1", "i2", "i3"], "data": ["data"]}]}'
        expected = {
                        "info": [['i1', 'i2', 'i3']],
                        "data": [['data']],
                        'error': [],
                        'errorcode': [],
                        'node': []
                   }
        data = xcat.load_xcat_resp(msgs)
        self.assertEqual(expected, data)

    @mock.patch('xcatlib.xcatlib.xcat_request')
    def test_xdsh(self, mock_request):
        commands = 'dummy'
        node = 'node1'
        mock_request.return_value = 'ret'

        res = xcat.xdsh(self.xcaturl, node, commands)
        self.assertEqual('ret', res)

    @mock.patch('xcatlib.xcatlib.xcat_request')
    def test_get_userid_has_value(self, mock_request):
        node = 'node1'
        mock_request.return_value = {'info': [['userid=test1']]}

        res = xcat.get_userid(self.xcaturl, node)
        self.assertEqual('test1', res)

    @mock.patch('xcatlib.xcatlib.xcat_request')
    def test_get_userid_has_no_value(self, mock_request):
        node = 'node1'
        mock_request.return_value = {'info': [['']]}

        res = xcat.get_userid(self.xcaturl, node)
        self.assertIsNone(res)
