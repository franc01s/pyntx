Nutanix common libraries
========================

Nutanix library to manage

- VMs
- Snapshots
- Hosts


Example:

.. code-block::

    from nutanix import Ntxclusters, Ntxvms, Ntxsnapshots, Ntxhosts

    clusters = Ntxclusters(user='ITS-VDI-Readonly@swatchgroup.net', password='XXXXXX', sslverify=False, filters=['ntxchbi009', 'ntxchgr010'],initialrefresh=True)

    vms = Ntxvms(clusters=clusters, user='ITS-VDI-Readonly@swatchgroup.net', password='XXXXXX', sslverify=False, initialrefresh=True)

    print(vms.getvmsgpu())





