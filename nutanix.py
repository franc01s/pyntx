from requests import Session, Response, get
from requests.auth import HTTPBasicAuth
import json, os
from collections import namedtuple
from enum import Enum
from addict import Dict
import urllib3
import time

NTXPRISMCENTRAL = 'its-prism-central.swatchgroup.net:9440'
NTXBASEURL3 = 'https://{prismhost}/api/nutanix/{version}'.format(prismhost=NTXPRISMCENTRAL, version='v3')
NTXBASEURL2 = 'https://{prismhost}/api/nutanix/{version}'.format(prismhost=NTXPRISMCENTRAL, version='v2.0')
PROTECTIONDOMAIN = 'PD-NTXCHBI009-TO-NTXCHGR010-GOLD'

# Disable Insecure Rquests Warning globally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def checkpassword(user, password):
    urlrun = '{baseurl}/{api}'.format(baseurl=NTXBASEURL3,
                                      api='services/xfit/status')
    response = get(urlrun, auth=(user, password), verify=False)

    return response.ok


def getclusters(session, filters):
    urlrun = '{baseurl}/{api}'.format(baseurl=NTXBASEURL3,
                                      api='clusters/list')
    data = {"kind": "cluster"}
    response = session.post(urlrun, json=data)
    clusters = Dict(response.json())
    clusterlist = []
    for cluster in clusters.entities:
        clusterip = cluster.spec.resources.network.external_ip
        clustername = cluster.spec.name
        clusteruuid = cluster.metadata.uuid

        # Check for a valid cluster
        if clusterip != {}:
            # set location representing char 6 and 7 of the cluster name
            clusterloc = clustername[5:7]
            # Apply input filters
            if filters == None or clustername.lower() in [filter.lower() for filter in filters]:
                for clusternode in cluster.status.resources.nodes.hypervisor_server_list:
                    clustertype = clusternode.type
                    break
                clusterlist.append((clustername, clusteruuid, clusterip, clustertype, clusterloc))
    return clusterlist


class Ntxvms:

    def __init__(self, user=None, password=None, sslverify=False, filters=None):
        self.session = Session()
        self.session.auth = HTTPBasicAuth(user, password)
        self.session.headers.update({'content-type': 'application/json'})
        self.session.headers.update({'Accept': 'application/json'})
        self.session.verify = sslverify

        self.filters = filters
        # VMs as dictionary
        self.vms = {}

    def refresh(self):
        self.vms.clear()
        print('Start refresh VMs')
        self.clusters = getclusters(self.session, self.filters)

        for clustername, clusteruuid, clusterip, clustertype, clusterloc in self.clusters:
            print('get VMs on {}'.format(clustername))
            self.vms.update(self.getclustervms(clusterip, clustername, clusterloc))

    def gettask(self, vm):
        urlrun = 'https://{clusterip}:9440/api/nutanix/v2.0/tasks/{uuid}'.format(clusterip=vm.clusterip,
                                                                                 uuid=vm.taskuuid)

        response = self.session.get(urlrun)
        if response.status_code < 400:
            resp = response.json()

            timeout = 0
            taskstatus = resp.get('progress_status', None)
            while taskstatus == 'Running' and timeout < 10:
                time.sleep(10)
                response = self.session.get(urlrun)
                resp = response.json()
                taskstatus = resp.get('progress_status', None)
                timeout += 1
        vm.taskuuid = None
        return response.ok

    def gethosts(self, session):
        urlrun = '{baseurl}/{api}'.format(baseurl=NTXBASEURL3,
                                          api='hosts/list')
        data = {"kind": "host"}
        response = session.post(urlrun, json=data)
        hosts = Dict(response.json())
        HostCluster = namedtuple('HostCluster', 'clusteruuid hostname hostuuid')
        hostlist = []
        for host in hosts.entities:
            clusteruuid = host.status.cluster_reference.uuid
            hostname = host.spec.name
            hostuuid = host.metadata.uuid
            hostcluster = HostCluster(clusteruuid, hostname, hostuuid)
            hostlist.append(hostcluster)
        return hostlist

    def getclustervms(self, clusterip, clustername, clusterloc):
        payload = {'include_vm_disk_config': 'true'}
        urlbase = 'https://{}:9440/api/nutanix/v2.0/vms'.format(clusterip)
        vmsraw = self.session.get(urlbase, params=payload)
        vms = {}
        if vmsraw.ok == True:
            clustervms = Dict(vmsraw.json())
            for vm in clustervms.entities:
                vm['clusterip'] = clusterip
                vm['clustername'] = clustername
                vm['clusterloc'] = clusterloc
                vms[vm.uuid] = vm
            return vms
        return None

    def getvmsbyuuid(self, uuid):
        return self.vms.get(uuid, None)

    def getvmsbyname(self, vmnamepattern):
        vm = [vm for k, vm in self.vms.items() if vmnamepattern in vm.name]
        return vm

    def getdiskuuid(self, vm, index):
        disks = vm.vm_disk_info
        for disk in disks:
            if disk.disk_address.device_bus == 'scsi' and disk.disk_address.device_index == index:
                return (disk.disk_address.vmdisk_uuid, disk.storage_container_uuid)
        return None

    def getvmsnapsnots(self, vmnamepattern):
        vms = self.getvmsbyname(vmnamepattern)
        if len(vms) == 1:
            # First vm of the match
            vm = vms[0]
            payload = {'vm_uuid': vm.uuid}
            url = 'https://{}:9440/api/nutanix/v2.0/snapshots'.format(vm.clusterip)
            resp = self.session.get(url, verify=False, params=payload)
            if resp.ok:
                snapshots = Dict(resp.json())
                snapshots.clusterip = vm.clusterip
                snapshots.clustername = vm.clustername
                snapshots.clusterloc = vm.clusterloc
                return snapshots
        else:
            print('To much VMs match')

        return []

    def delsnapsnots(self, clusterip, uuid):
        # First vm of the match
        url = 'https://{clusterip}:9440/api/nutanix/v2.0/snapshots/{uuid}'.format(clusterip=clusterip, uuid=uuid)
        resp = self.session.delete(url, verify=False)
        return resp.ok

    def getsnapsnots(self, clusterip):
        url = 'https://{}:9440/api/nutanix/v2.0/snapshots'.format(clusterip)
        resp = self.session.get(url, verify=False)
        if resp.ok:
            return Dict(resp.json())
        else:
            return None

    def createsnapshot(self, vm, snapname):
        data = {
            "snapshot_specs": [
                {
                    "snapshot_name": snapname,
                    "vm_uuid": vm.uuid
                }
            ]
        }
        url = 'https://{}:9440/api/nutanix/v2.0/snapshots'.format(vm.clusterip)
        resp = self.session.post(url, verify=False, json=data)
        if resp.ok:
            vm.taskuuid = resp.json()['task_uuid']

        return resp.ok

    def updatevm(self, vm, data):
        url = 'https://{}:9440/api/nutanix/v2.0/vms/{}'.format(vm.clusterip, vm.uuid)
        resp = self.session.put(url, verify=False, json=data)
        if resp.ok:
            vm.taskuuid = resp.json()['task_uuid']

        return resp.ok

    def clonevm(self, vm, data):
        url = 'https://{}:9440/api/nutanix/v2.0/vms/{}/clone'.format(vm.clusterip, vm.uuid)
        resp = self.session.post(url, verify=False, json=data)
        if resp.ok:
            vm.taskuuid = resp.json()['task_uuid']

        return resp.ok

    def protectiondomainsaddvm(self, vm):
        data = {
            "uuids": [
                vm.uuid
            ]
        }

        url = 'https://{}:9440/api/nutanix/v2.0/protection_domains/{}/protect_vms'.format(vm.clusterip,
                                                                                          PROTECTIONDOMAIN)
        resp = self.session.post(url, verify=False, json=data)

        return resp.ok

    def createimage(self, vm, index):
        vmdisk_uuid, storage_container_uuid = self.getdiskuuid(vm, index)
        data = {
            "spec": {
                "name": vm.name,
                "resources": {
                    "image_type": "DISK_IMAGE",
                    "source_uri": "nfs://{clusterip}/{clustername}-SSD-1/.acropolis/vmdisk/{vmiskuuid}".format(
                        clusterip=vm.clusterip, clustername=vm.clustername, vmiskuuid=vmdisk_uuid)
                },
            },
            "api_version": "3.1",
            "metadata": {
                "kind": "image",
                "name": vm.name
            }
        }
        url = '{baseurl}/{api}'.format(baseurl=NTXBASEURL3, api='images')
        resp = self.session.post(url, verify=False, json=data)

        return resp.ok

    def createsnapident(self):
        urlrun = '{baseurl}/{api}'.format(baseurl=NTXBASEURL3, api='idempotence_identifiers')
        data = {
            "count": 1,
            "client_identifier": self.vmuuid
        }

        response = self.session.post(urlrun, data=json.dumps(data))
        if response.ok:
            snapuuid = response.json()
            # return the unique element
            self.identlist.extend(snapuuid.get('uuid_list', []))

    @property
    def getvmlist(self):
        return self.vms

    def getpdlist(self):
        urlrun = '{baseurl}/{api}'.format(baseurl=NTXBASEURL2,
                                          api='protection_domains/PD-NTXCHGR004-BACKUP/dr_snapshots')
        response = self.session.get(urlrun)
        print(json.dumps(response.json(), indent=4))

    def diskattach(self, ndfs_filepath):
        if ndfs_filepath != None:
            if self.clustertype != 'AHV':
                diskpath, diskext = os.path.splitext(ndfs_filepath)
                ndfs_filepath = '{diskpath}-flat{diskext}'.format(diskpath=diskpath, diskext=diskext)
            api = 'vms/{vmuuid}/disks/attach'.format(vmuuid=self.vm.uuid)
            urlrun = 'https://{baseurl}:9440/api/nutanix/v2.0/{api}'.format(baseurl=self.clusterip,
                                                                            api=api)
            data = {
                "uuid": self.vmuuid,
                "vm_disks": [
                    {
                        "vm_disk_clone": {
                            "disk_address": {
                                "device_bus": "SCSI",
                                "device_index": 0,
                                "ndfs_filepath": ndfs_filepath
                            }
                        }
                    }
                ]
            }
            resp = self.session.post(urlrun, data=json.dumps(data))
            if resp.ok:
                return resp.json()['task_uuid']
            else:
                return resp.json()
        else:
            resp = Response()
            resp.status_code = 500
            resp.json = {"status": "error", "message": "Disk index"}
            return resp

    def diskdetach(self, index):
        api = 'vms/{vmuuid}/disks/detach'.format(vmuuid=self.vm.uuid)
        urlrun = 'https://{baseurl}:9440/api/nutanix/v2.0/{api}'.format(baseurl=self.clusterip,
                                                                        api=api)
        diskuuid = self.getvmdiskuuid(index)
        if diskuuid != None:
            data = {
                "uuid": self.vm.uuid,
                "vm_disks": [
                    {
                        "disk_address": {
                            "device_bus": "SCSI",
                            "device_index": index,
                            "vmdisk_uuid": diskuuid,
                            "ndfs_filepath": self.getvmdiskpathbyindex(index)
                        }
                    }
                ]
            }
            response = self.session.post(urlrun, data=json.dumps(data))
            if response.ok:
                return response.json()['task_uuid']
            else:
                return None

    def getvmdiskpathbydiskuuid(self, diskuuid):
        diskpath = [disk.path for disk in self.vmdisks if diskuuid in disk.path]
        if len(diskpath) > 0:
            return diskpath[0]
        else:
            return None

    def getvmdiskpathbyindex(self, index):
        diskpath = [disk.path for disk in self.vmdisks if disk.index == index]
        if len(diskpath) > 0:
            return diskpath[0]
        else:
            return None

    def createsnapident(self):
        urlrun = '{baseurl}/{api}'.format(baseurl=NTXBASEURL3, api='idempotence_identifiers')
        data = {
            "count": 1,
            "client_identifier": self.vm.uuid
        }

        response = self.session.post(urlrun, json=data)
        if response.ok:
            snapuuid = response.json()
            # return the unique element
            self.identlist.extend(snapuuid.get('uuid_list', []))

    def createvmsnapshots(self, snapname):
        if self.identlist != []:
            urlrun = '{baseurl}/{api}'.format(baseurl=NTXBASEURL3, api='vm_snapshots')
            data = {
                "spec": {
                    "resources": {
                        "entity_uuid": self.vm.uuid
                    },
                    "snapshot_type": "CRASH_CONSISTENT",
                    "name": snapname
                },
                "api_version": "3.1",
                "metadata": {
                    "kind": "vm_snapshot",
                    "uuid": self.identlist[0]
                }
            }

            response = self.session.post(urlrun, json=data)
            return response.json()


class Ntxsnapshots:

    def __init__(self, user=None, password=None, sslverify=False, filters=None):
        self.session = Session()
        self.session.auth = HTTPBasicAuth(user, password)
        self.session.headers.update({'content-type': 'application/json'})
        self.session.headers.update({'Accept': 'application/json'})
        self.session.verify = sslverify
        # Snapshots as list
        self.snapshots = []
        self.filters = filters

    def refresh(self):
        self.snapshots.clear()
        print('Start refresh Snapshots')

        clusters = getclusters(self.session, self.filters)
        for clustername, clusteruuid, clusterip, clustertype, clusterloc in clusters:
            print('get VMs snapshots on {}'.format(clustername))
            self.snapshots.extend(self._getclustersnaphots(clusterip))

    def _getclustersnaphots(self, clusterip):
        urlbase = 'https://{}:9440/api/nutanix/v2.0/snapshots'.format(clusterip)
        snapshotsraw = self.session.get(urlbase)
        if snapshotsraw.ok == True:
            snapshots = Dict(snapshotsraw.json())
            return snapshots.entities
        return None

    @property
    def getsnapshots(self):
        return self.snapshots


class Ntxhosts:
    def __init__(self, user=None, password=None, sslverify=False, filters=None):
        self.session = Session()
        self.session.auth = HTTPBasicAuth(user, password)
        self.session.headers.update({'content-type': 'application/json'})
        self.session.headers.update({'Accept': 'application/json'})
        self.session.verify = sslverify
        # Hosts as dictionary
        self.hosts = {}
        self.filters = filters

    def refresh(self):
        self.hosts.clear()
        print('Start refresh Hosts')

        clusters = getclusters(self.session, self.filters)
        for clustername, clusteruuid, clusterip, clustertype, clusterloc in clusters:
            print('get Hosts on {}'.format(clustername))
            self.hosts.update(self._gethosts(clusterip, clusterloc))

    def _gethosts(self, clusterip, clusterloc):
        urlrun = 'https://{clusterip}:9440/api/nutanix/v2.0/{api}'.format(clusterip=clusterip,
                                                                          api='hosts')
        response = self.session.get(urlrun)
        hosts = Dict(response.json())
        Host = namedtuple('Host', 'hostname hostclusterip hostclusteruuid hostgpus hostloc')
        hostlist = {}
        for host in hosts.entities:
            hostlist[host.uuid] = Host(host.name, clusterip, host.uuid, host.host_gpus, clusterloc)
        return hostlist

    @property
    def gethosts(self):
        return self.hosts

    def gethostuuids(self, hostname):
        return [k for k, host in self.hosts.items() if hostname in host.hostname]

    def gethostsaffinity(self, gputype, loc):
        return [k for k, host in self.hosts.items() if
                host.hostgpus != None and gputype in host.hostgpus and host.hostloc == loc]

    def gethostgpus(self, uuid):
        host = self.hosts.get(uuid, None)
        if host != None and host.hostgpus:
            urlrun = 'https://{hostclusterip}:9440/api/nutanix/v2.0/hosts/{uuid}/host_gpus'.format(
                hostclusterip=host.hostclusterip, uuid=uuid)
            response = self.session.get(urlrun)
            hostgpus = Dict(response.json())

            vgpus = []
            for hostgpu in hostgpus.entities:
                if hostgpu.num_vgpus_allocated > 0:
                    vgpus.append(hostgpu)

            return vgpus
        else:
            return None
