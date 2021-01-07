#!/usr/bin/env python
# -*- encoding=utf-8 -*-
from zssdk import *

import hashlib
import sys

reload(sys)

sys.setdefaultencoding('utf-8')


def SHA512(msg):
    digest = hashlib.sha512(msg).hexdigest()
    return digest


def DEBUG(msg):
    print '\033[1;31;m{}\033[0m'.format(msg)


# Configure
configure(hostname='192.168.1.101', context_path='/zstack')
# LogIn
action = LogInByAccountAction()
action.accountName = "admin"
action.password = SHA512("password")
account = action.call().value.inventory
sessionId = account.uuid
DEBUG('sessionId = {}'.format(sessionId))

# Create Zone
action = CreateZoneAction()
action.name = "ZONE-1"
action.sessionId = sessionId
zone = action.call().value.inventory
zoneId = zone.uuid
DEBUG('zoneId = {}'.format(zoneId))

# Create Cluster
action = CreateClusterAction()
action.name = 'Cluster-1'
action.zoneUuid = "c3f205794ee545c8afc719eb95c0fc42"
action.hypervisorType = "KVM"
action.sessionId = sessionId
cluster = action.call().value.inventory
clusterId = cluster.uuid
DEBUG('clusterId = {}'.format(clusterId))

# Add KVM Host
action = AddKVMHostAction()
action.name = "Host-2"
action.managementIp = "192.168.1.107"
action.username = "root"
action.password = "password"
action.clusterUuid = "6765e32647b44344a51124ab2c04e37a"
action.sessionId = sessionId
action.call()  # failed to poll the result after 15 seconds

# Add Image Storage
action = AddSftpBackupStorageAction()
action.hostname = "192.168.1.108"
action.username = "root"
action.password = "password"
action.url = "/zstack_bs"
action.name = "BS-1"
action.zoneUuid = "c3f205794ee545c8afc719eb95c0fc42"
action.sessionId = sessionId
imageStorage = action.call().value.inventory
imageStorageId = imageStorage.uuid
DEBUG('imageStorageId = {}'.format(imageStorageId))
# Attach Image Storage to Zone
action = AttachBackupStorageToZoneAction()
action.zoneUuid = "c3f205794ee545c8afc719eb95c0fc42"
action.backupStorageUuid = imageStorageId
action.sessionId = sessionId
attachInfo = action.call().value.inventory
attachInfoId = attachInfo.uuid
DEBUG('attachInfoId = {}'.format(attachInfoId))

# Add Local Primary Storage
action = AddLocalPrimaryStorageAction()
action.name = "PS-1"
action.url = "/zstack_ps"
action.zoneUuid = "c3f205794ee545c8afc719eb95c0fc42"
action.sessionId = sessionId
localStorage = action.call().value.inventory
localStorageId = localStorage.uuid
DEBUG('localStorageId = {}'.format(localStorageId))
# Attach Local Primary Storage to Cluster
action = AttachPrimaryStorageToClusterAction()
action.clusterUuid = "6765e32647b44344a51124ab2c04e37a"
action.primaryStorageUuid = localStorageId
action.sessionId = sessionId
attachInfo = action.call().value.inventory
attachInfoId = attachInfo.uuid
DEBUG('attachInfoId = {}'.format(attachInfoId))

# Create Instance Offering
action = CreateInstanceOfferingAction()
action.name = "InstanceOffering-1"
action.cpuNum = 1
action.memorySize = 1073741824  # 1G
action.sessionId = sessionId
instanceOffering = action.call().value.inventory
instanceOfferingId = instanceOffering.uuid
DEBUG('instanceOfferingId = {}'.format(instanceOfferingId))

# Add Image
action = AddImageAction()
action.name = "Image-1"
action.url = "file:///opt/zstack-dvd/zstack-image-1.4.qcow2"
action.format = "qcow2"
action.backupStorageUuids = ["032cc0270b754a6bbd5f6e0491815770"]
action.platform = "Linux"
action.sessionId = sessionId
image = action.call().value.inventory
imageId = image.uuid
DEBUG('imageId = {}'.format(imageId))

# Add L2PublicNetwork
action = CreateL2NoVlanNetworkAction()
action.name = "L2Public-1"
action.zoneUuid = "c3f205794ee545c8afc719eb95c0fc42"
action.physicalInterface = "ens192"
action.sessionId = sessionId
l2Network = action.call().value.inventory
l2NetworkId = l2Network.uuid
DEBUG('l2NetworkId = {}'.format(l2NetworkId))
# Attach L2PublicNetwork to Cluster
action = AttachL2NetworkToClusterAction()
action.l2NetworkUuid = l2NetworkId
action.clusterUuid = "6765e32647b44344a51124ab2c04e37a"
action.sessionId = sessionId
attachInfo = action.call().value.inventory
attachInfoId = attachInfo.uuid
DEBUG('attachInfoId = {}'.format(attachInfoId))

# Add L2PrivateNetwork
action = CreateL2VlanNetworkAction()
action.vlan = 1000
action.name = 'L2Private-1'
action.zoneUuid = "c3f205794ee545c8afc719eb95c0fc42"
action.physicalInterface = 'ens192'
action.sessionId = sessionId
l2Network = action.call().value.inventory
l2NetworkId = l2Network.uuid
DEBUG('l2NetworkId = {}'.format(l2NetworkId))
# Attach L2PrivateNetwork to Cluster
action = AttachL2NetworkToClusterAction()
action.l2NetworkUuid = l2NetworkId
action.clusterUuid = "6765e32647b44344a51124ab2c04e37a"
action.sessionId = sessionId
attachInfo = action.call().value.inventory
attachInfoId = attachInfo.uuid
DEBUG('attachInfoId = {}'.format(attachInfoId))

# Create L3PublicNetwork
action = CreateL3NetworkAction()
action.name = "L3Public-1"
action.type = "L3BasicNetwork"
action.l2NetworkUuid = "d562ec1087f7438caed536863f760d3e"
action.category = "Public"
action.sessionId = sessionId
l3Network = action.call().value.inventory
l3NetworkId = l3Network.uuid
DEBUG('l3NetworkId = {}'.format(l3NetworkId))
# Add IP Range to L3PublicNetwork
action = AddIpRangeAction()
action.l3NetworkUuid = l3NetworkId
action.name = "IpRange-1"
action.startIp = "192.168.1.171"
action.endIp = "192.168.1.180"
action.netmask = "255.255.255.0"
action.gateway = "192.168.1.1"
action.ipRangeType = "Normal"
action.sessionId = sessionId
ipRange = action.call().value.inventory
ipRangeId = ipRange.uuid
DEBUG('ipRangeId = {}'.format(ipRangeId))
# Add DNS to L3PublicNetwork
action = AddDnsToL3NetworkAction()
action.l3NetworkUuid = l3NetworkId
action.dns = "8.8.8.8"
action.sessionId = sessionId
dns = action.call().value.inventory
dnsId = dns.uuid
DEBUG('dnsId = {}'.format(dnsId))
# For Normal DHCP
# Attach Network Services to L3PrivateNetwork
securityGroupNetworkServiceProvider = "6a5648ac17c648ae90ed5459fb62e5fc"
flatNetworkServiceProvider = "cff293f15c81443f8b54138471a2f1f4"
action = AttachNetworkServiceToL3NetworkAction()
action.l3NetworkUuid = l3NetworkId
# admin >>>QueryNetworkServiceProvider
# "networkServices": {
#     "6a5648ac17c648ae90ed5459fb62e5fc": ["SecurityGroup"],
#     "cff293f15c81443f8b54138471a2f1f4": ["Userdata", "DHCP"]
# }
action.networkServices = {
    securityGroupNetworkServiceProvider: ["SecurityGroup"],
    flatNetworkServiceProvider: ["Userdata", "DHCP"]
}
action.sessionId = sessionId
action.call()
DEBUG('Successfully attach network service to l3network')

# Add Router Image
action = AddImageAction()
action.name = "RouterImage-1"
action.url = "file:///opt/zstack-dvd/zstack-vrouter-3.10.2.qcow2"
action.platform = "Linux"
action.system = "true"
action.format = "qcow2"
action.backupStorageUuids = ["032cc0270b754a6bbd5f6e0491815770"]
action.sessionId = sessionId
image = action.call().value.inventory
imageId = image.uuid
DEBUG('imageId = {}'.format(imageId))

# Create Router Standard
action = CreateVirtualRouterOfferingAction()
action.name = "RouterStandard-1"
action.cpuNum = 1
action.memorySize = 1073741824  # 1G
action.zoneUuid = "c3f205794ee545c8afc719eb95c0fc42"
action.imageUuid = "53c2c6b25bd14d25972ab05e0d961f48"
action.managementNetworkUuid = "4c831592b12c4631b7612bcfca057eac"
action.publicNetworkUuid = "4c831592b12c4631b7612bcfca057eac"
action.type = "VirtualRouter"
action.sessionId = sessionId
routerStandard = action.call().value.inventory
routerStandardId = routerStandard.uuid
DEBUG('routerStandardId = {}'.format(routerStandardId))

# Create L3PrivateNetwork
action = CreateL3NetworkAction()
action.name = "L3Private-1"
action.type = "L3BasicNetwork"
action.l2NetworkUuid = "e07fc8e5834e420e8befa988602a03ab"
action.category = "Private"
action.systemTags = ["virtualRouterOffering::2875e1b373514769bed9e96ab104dc61"]
action.sessionId = sessionId
l3Network = action.call().value.inventory
l3NetworkId = l3Network.uuid
DEBUG('l3NetworkId = {}'.format(l3NetworkId))
# Add IP Range by CIDR
action = AddIpRangeByNetworkCidrAction()
action.name = "IpRange-2"
action.l3NetworkUuid = l3NetworkId
action.networkCidr = "172.20.233.0/24"
action.gateway = "172.20.233.1"
action.sessionId = sessionId
ipRange = action.call().value.inventory
ipRangeId = ipRange.uuid
DEBUG('ipRangeId = {}'.format(ipRangeId))
# Add DNS to L3PrivateNetwork
action = AddDnsToL3NetworkAction()
action.l3NetworkUuid = l3NetworkId
action.dns = "8.8.8.8"
action.sessionId = sessionId
dns = action.call().value.inventory
dnsId = dns.uuid
DEBUG('dnsId = {}'.format(dnsId))
# For Router
# Attach Network Services to L3PrivateNetwork
vrouterNetworkServiceProvider = "6aac44ea36c94742a8693051e0610307"
securityGroupNetworkServiceProvider = "38ec87620e184ba2bd885aaa06657c77"
flatNetworkServiceProvider = "79275ca277e4413fa1759da4b4227a02"
action = AttachNetworkServiceToL3NetworkAction()
action.l3NetworkUuid = l3NetworkId
action.networkServices = {
    vrouterNetworkServiceProvider: ["IPsec", "VRouterRoute", "CentralizedDNS", "VipQos", "SNAT", "LoadBalancer", "PortForwarding", "Eip", "DNS"],
    securityGroupNetworkServiceProvider: ["SecurityGroup"],
    flatNetworkServiceProvider: ["Userdata", "DHCP"]
}
action.sessionId = sessionId
action.call()
DEBUG('Successfully attach network service to l3network')

# Create VM Instance
action = CreateVmInstanceAction()
action.name = "VM-1"
action.instanceOfferingUuid = "96da64bfc42d4f03a3aed55f1cc3171c"
action.imageUuid = "de82e3d2d39f4a459be1d9193f41f9d4"
action.l3NetworkUuids = ["5667394780c849a6af53737752115174"]
action.defaultL3NetworkUuid = "5667394780c849a6af53737752115174"
action.dataDiskOfferingUuids = []
action.sessionId = sessionId
action.call()

# Request VM Console
action = GetVmConsoleAddressAction()
action.uuid = "639895a2f17f42a7bd840f2e340c0c40"
action.sessionId = sessionId
consoleInfo = action.call().value
consoleUrl = "vnc://{}:{}".format(consoleInfo.hostIp, consoleInfo.port)
DEBUG('Successfully open console: {}'.format(consoleUrl))

# LogOut
action = LogOutAction()
action.sessionUuid = sessionId
action.call()
DEBUG('Successfully delete session')
