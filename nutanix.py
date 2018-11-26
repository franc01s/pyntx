import json
import os
import time

import urllib3
from addict import Dict as Adict, Dict
from marshmallow import Schema, fields, post_load
from requests import Response, get, post, put, delete
from requests.auth import HTTPBasicAuth

NTXPRISMCENTRAL = 'its-prism-central.swatchgroup.net:9440'
NTXBASEURL3 = 'https://{prismhost}/api/nutanix/{version}'.format(prismhost=NTXPRISMCENTRAL, version='v3')
NTXBASEURL2 = 'https://{prismhost}/api/nutanix/{version}'.format(prismhost=NTXPRISMCENTRAL, version='v2.0')

# Disable Insecure Requests Warning globally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def ntxError(resp):
    if isinstance(resp, Response):
        code = resp.status_code
        status = resp.text
    elif isinstance(resp, str):
        code = 500
        status = {"exception": resp}

    return {"code": code, "status": status}


class VmSchema(Schema):
    name = fields.String()
    uuid = fields.String()


##########

class Cluster():
    def __init__(self, name, uuid, ip, type, loc):
        self.name = name
        self.ip = ip
        self.uuid = uuid
        self.type = type
        self.loc = loc

    def __repr__(self):
        return self.name


class Clusterchema(Schema):
    name = fields.String(required=True)
    ip = fields.String(required=True)
    uuid = fields.String(required=True)
    type = fields.String(required=True)
    loc = fields.String(required=True)

    @post_load
    def make_cluster(self, data):
        return Cluster(**data)


class Host():
    def __init__(self, name, uuid, gpus, cluster):
        self.name = name
        self.uid = uuid
        self.gpus = gpus
        self.cluster = cluster

    def __repr__(self):
        return self.name


def checkpassword(user, password):
    urlrun = '{baseurl}/{api}'.format(baseurl=NTXBASEURL3, api='services/xfit/status')
    response = get(urlrun, auth=(user, password), verify=False)
    return response.ok


class Ntxclusters:
    def __init__(self, user=None, password=None, sslverify=False, filters=None, initialrefresh=True):
        self.user = user
        self.password = password
        self.filters = filters
        self.sslverify = sslverify

        # All Clusters as list of Cluster class
        self.clusters = []

        self.auth = HTTPBasicAuth(user, password)
        if initialrefresh:
            self.refresh()

    def refresh(self):
        try:
            self.clusters.clear()

            urlrun = '{baseurl}/{api}'.format(baseurl=NTXBASEURL3, api='clusters/list')
            data = {"kind": "cluster"}
            resp = post(urlrun, json=data, auth=self.auth, verify=self.sslverify)
            if resp.ok:
                clustersdict = Adict(resp.json())
                for cluster in clustersdict.entities:
                    clusterip = cluster.spec.resources.network.external_ip
                    clustername = cluster.spec.name
                    clusteruuid = cluster.metadata.uuid

                    # Check for a valid cluster
                    if clusterip != {}:
                        # set location representing char 6 and 7 of the cluster name
                        clusterloc = clustername[5:7]
                        # Apply input filters
                        if self.filters == None or clustername.lower() in [filter.lower() for filter in self.filters]:
                            for clusternode in cluster.status.resources.nodes.hypervisor_server_list:
                                clustertype = clusternode.type
                                break
                            cluster = Cluster(clustername, clusteruuid, clusterip, clustertype, clusterloc)
                            # Add cluster to list of clusters
                            self.clusters.append(cluster)
                return resp.ok
            else:
                return ntxError(resp)
        except Exception as e:
            return ntxError(e)

    def getclusterbyname(self, clustername):
        cluster = [cluster for cluster in self.allclusters if clustername == cluster.clustername]
        if len(cluster) == 1:
            return cluster[0]
        return None

    @property
    def getclusters(self):
        return self.clusters


class Ntxvms:

    def __init__(self, clusters, user=None, password=None, sslverify=False, initialrefresh=True):
        self.auth = HTTPBasicAuth(user, password)
        self.sslverify = sslverify
        self.clusters = clusters
        # VMs as dictionary
        self.vms = {}

        if initialrefresh:
            self.refresh()

    def refresh(self):
        print('Start refresh VMs')
        self.vms.clear()

        for cluster in self.clusters:
            print('get VMs on {}'.format(cluster.name))
            self.vms.update(self.pullclustervms(cluster=cluster))

    def pullclustervms(self, cluster):
        payload = {'include_vm_disk_config': 'true'}
        urlbase = 'https://{}:9440/api/nutanix/v2.0/vms'.format(cluster.ip)
        resp = get(urlbase, params=payload, auth=self.auth, verify=self.sslverify)
        vms = {}
        if resp.ok:
            clustervms = Adict(resp.json())
            for vm in clustervms.entities:
                vm['cluster'] = cluster
                vms[vm.uuid] = vm
            return vms
        else:
            print(ntxError(resp))

        return {}

    def gettask(self, vm):
        urlrun = 'https://{clusterip}:9440/api/nutanix/v2.0/tasks/{uuid}'.format(clusterip=vm.cluster.ip,
                                                                                 uuid=vm.taskuuid)

        response = get(urlrun, auth=self.auth, verify=self.sslverify)
        if response.status_code < 400:
            resp = response.json()

            timeout = 0
            taskstatus = resp.get('progress_status', None)
            while taskstatus == 'Running' and timeout < 10:
                time.sleep(3 * timeout)
                response = get(urlrun, auth=self.auth, verify=self.sslverify)
                resp = response.json()
                taskstatus = resp.get('progress_status', None)
                timeout += 1
        vm.taskuuid = None
        return response.ok

    def getvmbyuuid(self, uuid):
        # Return one vm by uuid of the vm
        """
        :param uuid:
        :return:
        """
        return self.vms.get(uuid, None)

    def getvmsbyname(self, vmnamepattern, many=True):
        # Return List of VMs matching pattern
        """
        :param vmnamepattern:
        :param many:
        :return:
        """
        if many:
            vm = [vm for k, vm in self.vms.items() if vmnamepattern in vm.name]
            return vm
        else:
            vm = [vm for k, vm in self.vms.items() if vmnamepattern == vm.name]
            if len(vm) == 1:
                return vm[0]
        return []

    def getdiskuuid(self, vm, index):
        vm = Adict(vm)
        disks = vm.vm_disk_info
        for disk in disks:
            if disk.disk_address.device_bus == 'scsi' and disk.disk_address.device_index == index:
                return disk.disk_address.vmdisk_uuid, disk.storage_container_uuid
        return None

    def getvmsnapshots(self, vmname):
        try:
            vm = self.getvmsbyname(vmname, many=False)
            # Transform vm in Object notation
            vm = Adict(vm)
            if vm:
                # First vm of the match
                payload = {'vm_uuid': vm.uuid}
                url = 'https://{}:9440/api/nutanix/v2.0/snapshots'.format(vm.cluster.ip)
                resp = get(url, params=payload, auth=self.auth, verify=self.sslverify)
                if resp.ok:
                    return resp.json()
                else:
                    return resp.text
            else:
                return ntxError('No VM Match')
        except Exception as e:
            return ntxError(e)

    def restorevmfromsnapshot(self, vmname, snapshotname):
        snapshots = self.getvmsnapshots(vmname)
        if snapshots.getnbentities > 0:
            snaps = [snapshot for snapshot in snapshots.getentities if snapshotname == snapshot['snapshot_name']]
            if len(snaps) > 0:
                # Put first snapshot in Object notation
                snap = Adict(snaps[0])
            # Create Post body
            data = {"transition": False,
                    "snapshot_uuid": snap.uuid
                    }

        url = 'https://{}:9440/api/nutanix/v2.0/vms/{}/restore'.format(snapshots.getcluster.ip, snap.vm_uuid)
        resp = post(url, auth=self.auth, verify=self.sslverify, json=data)

        return resp.ok

    def setvmpowerstate(self, vmname):
        vm = self.getvmsbyname(vmname, many=False)
        if vm:
            # Create Post body
            data = {"transition": "ON"
                    }

        url = 'https://{}:9440/api/nutanix/v2.0/vms/{}/set_power_state'.format(vm.cluster.ip, vm.uuid)
        resp = post(url, auth=self.auth, verify=self.sslverify, json=data)

        return resp.ok

    def delsnapsnots(self, cluster, uuid):
        # First vm of the match
        url = 'https://{clusterip}:9440/api/nutanix/v2.0/snapshots/{uuid}'.format(clusterip=cluster.ip, uuid=uuid)
        resp = delete(url, auth=self.auth, verify=self.sslverify)
        return resp.ok

    def getsnapsnots(self, cluster):
        url = 'https://{}:9440/api/nutanix/v2.0/snapshots'.format(cluster.ip)
        resp = get(url, auth=self.auth, verify=self.sslverify)
        if resp.ok:
            return Adict(resp.json())
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
        url = 'https://{}:9440/api/nutanix/v2.0/snapshots'.format(vm.cluster.ip)
        resp = post(url, auth=self.auth, verify=self.sslverify, json=data)
        if resp.ok:
            vm.taskuuid = resp.json()['task_uuid']

        return resp.ok

    def updatevm(self, vm, data):
        """
        Input example

         datat = {
        "affinity": {
            "policy": "AFFINITY",
            "host_uuids": hosts
        },
        "num_cores_per_vcpu": 1,
        "num_vcpus": 4,
        "memory_mb": 16384,
        "vm_gpus": [
            {
                "device_id": 47,
                "gpu_type": "VIRTUAL",
                "gpu_vendor": "NVIDIA",

            }
        ]}
        ntxvms.updatevm(vm, datat)

        :param vm:
        :param data:
        :return:
        """
        url = 'https://{}:9440/api/nutanix/v2.0/vms/{}'.format(vm.cluster.ip, vm.uuid)
        resp = put(url, auth=self.auth, verify=self.sslverify, json=data)
        if resp.ok:
            vm.taskuuid = resp.json()['task_uuid']

        return resp.ok

    def clonevm(self, vm, data):
        url = 'https://{}:9440/api/nutanix/v2.0/vms/{}/clone'.format(vm.cluster.ip, vm.uuid)
        resp = post(url, auth=self.auth, verify=self.sslverify, json=data)
        if resp.ok:
            vm.taskuuid = resp.json()['task_uuid']

        return resp.ok

    def addvmprotectiondomains(self, vm, protectiondomain):
        data = {
            "uuids": [
                vm.uuid
            ]
        }

        url = 'https://{}:9440/api/nutanix/v2.0/protection_domains/{}/protect_vms'.format(vm.cluster.ip,
                                                                                          protectiondomain)
        resp = post(url, auth=self.auth, verify=self.sslverify, json=data)

        return resp.ok

    def delvmprotectiondomains(self, vm, protectiondomain):
        data = {
            "uuids": [
                vm.uuid
            ]
        }

        url = 'https://{}:9440/api/nutanix/v2.0/protection_domains/{}/protect_vms'.format(vm.cluster.ip,
                                                                                          protectiondomain)
        resp = delete(url, auth=self.auth, verify=self.sslverify, json=data)

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
        resp = post(url, auth=self.auth, verify=self.sslverify, json=data)

        return resp.ok

    def createvmsnapident(self, vm):
        urlrun = '{baseurl}/{api}'.format(baseurl=NTXBASEURL3, api='idempotence_identifiers')
        data = {
            "count": 1,
            "client_identifier": vm.uuid
        }

        response = post(urlrun, data=json.dumps(data), auth=self.auth, verify=self.sslverify)
        if response.ok:
            snapuuid = response.json()
            # return the unique element
            self.identlist.extend(snapuuid.get('uuid_list', []))
        return response.ok

    @property
    def getvmlist(self):
        return self.vms

    def getvmgpu(self, vm):
        return vm.vm_gpus[0].device_name

    def getvmsgpu(self):
        vmsgpu = {}
        for k, vm in self.vms.items():
            if vm.get('gpus_assigned'):
                if vmsgpu.get(vm.vm_gpus[0].device_name):
                    vmsgpu[vm.vm_gpus[0].device_name] += 1
                else:
                    vmsgpu[vm.vm_gpus[0].device_name] = 1
        return vmsgpu

        return vm.vm_gpus[0].device_name

    def getpdlist(self):
        urlrun = '{baseurl}/{api}'.format(baseurl=NTXBASEURL2,
                                          api='protection_domains/PD-NTXCHGR004-BACKUP/dr_snapshots')
        response = get(urlrun, auth=self.auth, verify=self.sslverify)
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
            resp = post(urlrun, auth=self.auth, verify=self.sslverify, data=json.dumps(data))
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
            response = post(urlrun, auth=self.auth, verify=self.sslverify, data=json.dumps(data))
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

        response = post(urlrun, auth=self.auth, verify=self.sslverify, json=data)
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

            response = post(urlrun, auth=self.auth, verify=self.sslverify, json=data)
            return response.json()


class Ntxsnapshots:

    def __init__(self, clusters, user=None, password=None, sslverify=False, initialrefresh=True):
        self.auth = HTTPBasicAuth(user, password)
        self.sslverify = sslverify

        self.clusters = clusters
        # Snapshots as list
        self.snapshots = []

        if initialrefresh:
            self.refresh()

    def refresh(self):
        print('Start refresh Snapshots')
        self.snapshots.clear()

        for cluster in self.clusters:
            print('get VMs snapshots on {}'.format(cluster.name))
            self.snapshots.extend(self.__pullclustersnaphots(cluster))

    def __pullclustersnaphots(self, cluster):
        urlbase = 'https://{}:9440/api/nutanix/v2.0/snapshots'.format(cluster.ip)
        snapshotsraw = get(urlbase, auth=self.auth, verify=self.sslverify)
        if snapshotsraw.ok:
            snapshots = Adict(snapshotsraw.json())
            for snapshot in snapshots.entities:
                snapshot['cluster'] = cluster
            return snapshots.entities
        return []

    @property
    def getsnapshots(self):
        return self.snapshots

    def delsnapsnots(self, cluster, uuid):
        # First vm of the match
        url = 'https://{clusterip}:9440/api/nutanix/v2.0/snapshots'.format(clusterip=cluster.ip, uuid=uuid)
        resp = delete(url, auth=self.auth, verify=self.sslverify)
        return resp.ok


class Ntxhosts:
    def __init__(self, clusters, user=None, password=None, sslverify=False, initialrefresh=True):
        self.auth = HTTPBasicAuth(user, password)
        self.sslverify = sslverify
        self.clusters = clusters
        # Hosts as dictionary
        self.hosts = {}

        if initialrefresh:
            self.refresh()

    def refresh(self):
        print('Start refresh Hosts')
        self.hosts.clear()

        for cluster in self.clusters:
            print('get Hosts on {}'.format(cluster.name))
            self.hosts.update(self.__gethosts(cluster))

    def __gethosts(self, cluster):
        urlrun = 'https://{clusterip}:9440/api/nutanix/v2.0/{api}'.format(clusterip=cluster.ip,
                                                                          api='hosts')
        response = get(urlrun, auth=self.auth, verify=self.sslverify)
        hosts = Adict(response.json())
        hostlist = {}
        for host in hosts.entities:
            hostlist[host.uuid] = Host(name=host.name, uuid=host.uuid, gpus=host.host_gpus, cluster=cluster)
        return hostlist

    @property
    def gethosts(self):
        return self.hosts

    def gethostuuids(self, hostname):
        return [k for k, host in self.hosts.items() if hostname in host.hostname]

    def gethostsaffinity(self, gputype, loc):
        return [k for k, host in self.hosts.items() if
                host.gpus is not None and gputype in host.gpus and host.cluster.loc == loc]

    def gethostsbyname(self, hostpattern, many=True):
        """
        :param hostpattern:
        :param many:
        :return:
        """
        host = [host for k, host in self.hosts.items() if hostpattern in host.name]
        if len(host) > 0:
            return host if many else host[0]
        else:
            return []

    def gethostgpus(self, uuid):
        host = self.hosts.get(uuid, None)
        if host is not None and host.gpus:
            urlrun = 'https://{hostclusterip}:9440/api/nutanix/v2.0/hosts/{uuid}/host_gpus'.format(
                hostclusterip=host.hostcluster.ip, uuid=uuid)
            response = get(urlrun, auth=self.auth, verify=self.sslverify)
            hostgpus = Adict(response.json())

            vgpus = []
            for hostgpu in hostgpus.entities:
                if hostgpu.num_vgpus_allocated > 0:
                    vgpus.append(hostgpu)

            # Return vgpu list
            return vgpus
        else:
            return []
