import json
from unittest import TestCase, main
from unittest.mock import patch, Mock

from requests.models import Response

import nutanix


class TestNutanix(TestCase):
    def setUp(self):
        self.ntxclusters = nutanix.Ntxclusters(user='test', password='pass', initialrefresh=False)

    @patch.object(nutanix, 'post', autosoec=True)
    def test_cluster_refresh(self, mockresponse):
        with open('tests/cluster.json', 'r') as outfile:
            getclusterjsonresp = json.load(outfile)

        nutaresponse = Mock(spec=Response)
        nutaresponse.json = Mock(return_value=getclusterjsonresp)
        nutaresponse.status = 200

        mockresponse.return_value = nutaresponse
        self.ntxclusters.refresh()

        self.assertIsInstance(self.ntxclusters.clusters, list)
        self.assertAlmostEquals(len(self.ntxclusters.clusters), 13)


if __name__ == '__main__':
    main()

'''
       urlrun = '{baseurl}/{api}'.format(baseurl='https://127.0.0.1/api/nutanix/v3/', api='clusters/list')
        data = {"kind": "cluster"}
        auth = HTTPBasicAuth('user', 'password')
'''
