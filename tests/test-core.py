from unittest import TestCase, main
from unittest.mock import patch, Mock
from requests.auth import HTTPBasicAuth
import nutanix
from requests.models import Response


class TestNutanix(TestCase):
    def setUp(self):
        self.ntxclusters = nutanix.Ntxclusters(user='test', password='pass', initialrefresh=False)

    @patch.object(nutanix, 'post', autosoec=True)
    def test_cluster_refresh(self, mockresponse):
        getclusterjsonresp = {
            "api": "3.0",
            "entities": [

                {
                    "spec": {
                        "name": "NTXCHBIXXX",
                        "resources": {
                            "network": {
                                "external_ip": "10.236.36.84"
                            }
                        }
                    },

                    "metadata": {
                        "uuid": "00056aad-674c-94e6-0000-00000001a896"
                    },

                    "status": {
                        "resources": {
                            "nodes": {
                                "hypervisor_server_list": [
                                    {
                                        "ip": "10.236.36.76",
                                        "type": "VMWARE",
                                        "version": "6.0.0-5050593"
                                    }
                                ]
                            }
                        }
                    }

                }
            ]
        }

        nutaresponse = Mock(spec=Response)
        nutaresponse.json = Mock(return_value=getclusterjsonresp)
        nutaresponse.status = 200

        mockresponse.return_value = nutaresponse
        self.ntxclusters.refresh()

        self.assertIsInstance(self.ntxclusters.allclusters, list)
        self.assertEqual(len(self.ntxclusters.allclusters), 1)


if __name__ == '__main__':
    main()

'''
       urlrun = '{baseurl}/{api}'.format(baseurl='https://127.0.0.1/api/nutanix/v3/', api='clusters/list')
        data = {"kind": "cluster"}
        auth = HTTPBasicAuth('user', 'password')
'''
