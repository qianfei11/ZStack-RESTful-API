package cn.b3ale;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;

import org.zstack.sdk.*;

public class CreateVM {
    public static String SHA512(String str) {
        String strRes = null;
        if (str != null && str.length() > 0) {
            try {
                MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
                messageDigest.update(str.getBytes());
                byte buffer[] = messageDigest.digest();
                StringBuffer strHex = new StringBuffer();
                for (int i = 0; i < buffer.length; i++) {
                    String b = Integer.toHexString(buffer[i] & 0xff);
                    if (b.length() == 1) {
                        strHex.append("0");
                    }
                    strHex.append(b);
                }
                strRes = strHex.toString();
            } catch (NoSuchAlgorithmException e) {
                // TODO: handle exception
                e.printStackTrace();
            }
        }
        return strRes;
    }

    public static void main(String[] args) throws UnsupportedEncodingException {
        // Configure
        ZSConfig.Builder zBuilder = new ZSConfig.Builder();
        zBuilder.setContextPath("zstack");
        zBuilder.setHostname("192.168.1.101");
        ZSClient.configure(zBuilder.build());

        // LogIn
        String sessionId = null;
        LogInByAccountAction logInByAccountAction = new LogInByAccountAction();
        logInByAccountAction.accountName = "admin";
        logInByAccountAction.password = SHA512("password");
        LogInByAccountAction.Result logInByAccountActionRes = logInByAccountAction.call();
        if (logInByAccountActionRes.error == null) {
            sessionId = logInByAccountActionRes.value.getInventory().getUuid();
            System.out.println(String.format("sessionId = %s", sessionId));
        } else {
            logInByAccountActionRes.throwExceptionIfError();
        }

        // Create Zone
        String zoneId = null;
        CreateZoneAction createZoneAction = new CreateZoneAction();
        createZoneAction.name = "ZONE-1";
        createZoneAction.sessionId = sessionId;
        CreateZoneAction.Result createZoneActionRes = createZoneAction.call();
        if (createZoneActionRes.error == null) {
            zoneId = createZoneActionRes.value.getInventory().getUuid();
            System.out.println(String.format("zoneId = %s", zoneId));
        } else {
            createZoneActionRes.throwExceptionIfError();
        }

        // Create Cluster
        String clusterId = null;
        CreateClusterAction createClusterAction = new CreateClusterAction();
        createClusterAction.zoneUuid = "67872e9cd7e049808672bcfe9abca851";
        createClusterAction.name = "Cluster-1";
        createClusterAction.hypervisorType = "KVM";
        createClusterAction.sessionId = sessionId;
        CreateClusterAction.Result createClusterActionRes = createClusterAction.call();
        if (createClusterActionRes.error == null) {
            clusterId = createClusterActionRes.value.getInventory().getUuid();
            System.out.println(String.format("clusterId = %s", clusterId));
        } else {
            createClusterActionRes.throwExceptionIfError();
        }

        // Add KVM Host
        // Name of network-interface should be same as the Host's
        String hostId = null;
        AddKVMHostAction addKVMHostAction = new AddKVMHostAction();
        addKVMHostAction.username = "root";
        addKVMHostAction.password = "password";
        addKVMHostAction.name = "Host-1";
        addKVMHostAction.managementIp = "192.168.1.101";
        addKVMHostAction.clusterUuid = "5ef9f78784bb4548a13f9fad0187751e";
        addKVMHostAction.sessionId = sessionId;
        AddKVMHostAction.Result addKVMHostActionRes = addKVMHostAction.call();
        if (addKVMHostActionRes.error == null) {
            hostId = addKVMHostActionRes.value.getInventory().getUuid();
            System.out.println(String.format("hostId = %s", hostId));
        } else {
            addKVMHostActionRes.throwExceptionIfError();
        }

        // Add Image Storage
        String imageStorageId = null;
        AddSftpBackupStorageAction addSftpBackupStorageAction = new AddSftpBackupStorageAction();
        addSftpBackupStorageAction.hostname = "192.168.1.101";
        addSftpBackupStorageAction.username = "root";
        addSftpBackupStorageAction.password = "password";
        addSftpBackupStorageAction.url = "/zstack_bs";
        addSftpBackupStorageAction.name = "BS-1";
        addSftpBackupStorageAction.sessionId = sessionId;
        AddSftpBackupStorageAction.Result addSftpBackupStorageActionRes = addSftpBackupStorageAction.call();
        if (addSftpBackupStorageActionRes.error == null) {
            imageStorageId = addSftpBackupStorageActionRes.value.getInventory().getUuid();
            System.out.println(String.format("imageStorageId = %s", imageStorageId));
        } else {
            addSftpBackupStorageActionRes.throwExceptionIfError();
        }
        // Attach Image Storage to Zone
        String attachImageStorageInfoId = null;
        AttachBackupStorageToZoneAction attachBackupStorageToZoneAction = new AttachBackupStorageToZoneAction();
        attachBackupStorageToZoneAction.zoneUuid = "67872e9cd7e049808672bcfe9abca851";
        attachBackupStorageToZoneAction.backupStorageUuid = imageStorageId;
        attachBackupStorageToZoneAction.sessionId = sessionId;
        AttachBackupStorageToZoneAction.Result attachBackupStorageToZoneActionRes = attachBackupStorageToZoneAction
                .call();
        if (attachBackupStorageToZoneActionRes.error == null) {
            attachImageStorageInfoId = attachBackupStorageToZoneActionRes.value.getInventory().getUuid();
            System.out.println(String.format("attachImageStorageInfoId = %s", attachImageStorageInfoId));
        } else {
            attachBackupStorageToZoneActionRes.throwExceptionIfError();
        }

        // Add Local Primary Storage
        String localStorageId = null;
        AddLocalPrimaryStorageAction addLocalPrimaryStorageAction = new AddLocalPrimaryStorageAction();
        addLocalPrimaryStorageAction.url = "/zstack_ps";
        addLocalPrimaryStorageAction.name = "PS-1";
        addLocalPrimaryStorageAction.zoneUuid = "67872e9cd7e049808672bcfe9abca851";
        addLocalPrimaryStorageAction.sessionId = sessionId;
        AddLocalPrimaryStorageAction.Result addLocalPrimaryStorageActionRes = addLocalPrimaryStorageAction.call();
        if (addLocalPrimaryStorageActionRes.error == null) {
            localStorageId = addLocalPrimaryStorageActionRes.value.getInventory().getUuid();
            System.out.println(String.format("localStorageId = %s", localStorageId));
        } else {
            addLocalPrimaryStorageActionRes.throwExceptionIfError();
        }
        // Attach Local Primary Storage to Cluster
        String attachLocalStorageInfoId = null;
        AttachPrimaryStorageToClusterAction attachPrimaryStorageToClusterAction = new AttachPrimaryStorageToClusterAction();
        attachPrimaryStorageToClusterAction.clusterUuid = "5ef9f78784bb4548a13f9fad0187751e";
        attachPrimaryStorageToClusterAction.primaryStorageUuid = localStorageId;
        attachPrimaryStorageToClusterAction.sessionId = sessionId;
        AttachPrimaryStorageToClusterAction.Result attachPrimaryStorageToClusterActionRes = attachPrimaryStorageToClusterAction
                .call();
        if (attachPrimaryStorageToClusterActionRes.error == null) {
            attachLocalStorageInfoId = attachPrimaryStorageToClusterActionRes.value.getInventory().getUuid();
            System.out.println(String.format("attachLocalStorageInfoId = %s", attachLocalStorageInfoId));
        } else {
            attachPrimaryStorageToClusterActionRes.throwExceptionIfError();
        }

        // Create Instance Offering
        String instanceOfferingId = null;
        CreateInstanceOfferingAction createInstanceOfferingAction = new CreateInstanceOfferingAction();
        createInstanceOfferingAction.name = "InstanceOffering-1";
        createInstanceOfferingAction.cpuNum = 1;
        createInstanceOfferingAction.memorySize = 1073741824; // 1G
        createInstanceOfferingAction.sessionId = sessionId;
        CreateInstanceOfferingAction.Result createInstanceOfferingActionRes = createInstanceOfferingAction.call();
        if (createInstanceOfferingActionRes.error == null) {
            instanceOfferingId = createInstanceOfferingActionRes.value.getInventory().getUuid();
            System.out.println(String.format("instanceOfferingId = %s", instanceOfferingId));
        } else {
            createInstanceOfferingActionRes.throwExceptionIfError();
        }

        // Add Image
        String imageId = null;
        AddImageAction addImageAction = new AddImageAction();
        addImageAction.name = "Image-1";
        addImageAction.url = "file:///opt/zstack-dvd/zstack-image-1.4.qcow2";
        addImageAction.platform = "Linux";
        addImageAction.format = "qcow2";
        addImageAction.backupStorageUuids = new ArrayList<String>(
                Arrays.asList(String.format("%s", "3ea0d19b555e4394b0def348bb645f66")));
        ;
        addImageAction.sessionId = sessionId;
        AddImageAction.Result addImageActionRes = addImageAction.call();
        if (addImageActionRes.error == null) {
            imageId = addImageActionRes.value.getInventory().getUuid();
            System.out.println(String.format("imageId = %s", imageId));
        } else {
            addImageActionRes.throwExceptionIfError();
        }

        // Add L2PublicNetwork
        String l2NetworkId = null;
        CreateL2NoVlanNetworkAction createL2NoVlanNetworkAction = new CreateL2NoVlanNetworkAction();
        createL2NoVlanNetworkAction.name = "L2Public-1";
        createL2NoVlanNetworkAction.zoneUuid = "67872e9cd7e049808672bcfe9abca851";
        createL2NoVlanNetworkAction.physicalInterface = "em2";
        createL2NoVlanNetworkAction.sessionId = sessionId;
        CreateL2NoVlanNetworkAction.Result createL2NoVlanNetworkActionRes = createL2NoVlanNetworkAction.call();
        if (createL2NoVlanNetworkActionRes.error == null) {
            l2NetworkId = createL2NoVlanNetworkActionRes.value.getInventory().getUuid();
            System.out.println(String.format("l2NetworkId = %s", l2NetworkId));
        } else {
            createL2NoVlanNetworkActionRes.throwExceptionIfError();
        }
        // Attach L2PublicNetwork to Cluster
        String attachL2NetworkInfoId = null;
        AttachL2NetworkToClusterAction attachL2NetworkToClusterAction = new AttachL2NetworkToClusterAction();
        attachL2NetworkToClusterAction.l2NetworkUuid = l2NetworkId;
        attachL2NetworkToClusterAction.clusterUuid = "5ef9f78784bb4548a13f9fad0187751e";
        attachL2NetworkToClusterAction.sessionId = sessionId;
        AttachL2NetworkToClusterAction.Result attachL2NetworkToClusterActionRes = attachL2NetworkToClusterAction.call();
        if (attachL2NetworkToClusterActionRes.error == null) {
            attachL2NetworkInfoId = attachL2NetworkToClusterActionRes.value.getInventory().getUuid();
            System.out.println(String.format("attachL2NetworkInfoId = %s", attachL2NetworkInfoId));
        } else {
            attachL2NetworkToClusterActionRes.throwExceptionIfError();
        }

        // Add L2PrivateNetwork
        String l2VlanNetworkId = null;
        CreateL2VlanNetworkAction createL2VlanNetworkAction = new CreateL2VlanNetworkAction();
        createL2VlanNetworkAction.vlan = 1000;
        createL2VlanNetworkAction.name = "L2Private-1";
        createL2VlanNetworkAction.zoneUuid = "67872e9cd7e049808672bcfe9abca851";
        createL2VlanNetworkAction.physicalInterface = "em2";
        createL2VlanNetworkAction.sessionId = sessionId;
        CreateL2VlanNetworkAction.Result createL2VlanNetworkActionRes = createL2VlanNetworkAction.call();
        if (createL2VlanNetworkActionRes.error == null) {
            l2VlanNetworkId = createL2VlanNetworkActionRes.value.getInventory().getUuid();
            System.out.println(String.format("l2VlanNetworkId = %s", l2VlanNetworkId));
        } else {
            createL2VlanNetworkActionRes.throwExceptionIfError();
        }
        // Attach L2PrivateNetwork to Cluster
        String attachL2VlanNetworkInfoId = null;
        AttachL2NetworkToClusterAction attachL2NetworkToClusterAction = new AttachL2NetworkToClusterAction();
        attachL2NetworkToClusterAction.l2NetworkUuid = l2VlanNetworkId;
        attachL2NetworkToClusterAction.clusterUuid = "5ef9f78784bb4548a13f9fad0187751e";
        attachL2NetworkToClusterAction.sessionId = sessionId;
        AttachL2NetworkToClusterAction.Result attachL2NetworkToClusterActionRes = attachL2NetworkToClusterAction.call();
        if (attachL2NetworkToClusterActionRes.error == null) {
            attachL2VlanNetworkInfoId = attachL2NetworkToClusterActionRes.value.getInventory().getUuid();
            System.out.println(String.format("attachL2VlanNetworkInfoId = %s", attachL2VlanNetworkInfoId));
        } else {
            attachL2NetworkToClusterActionRes.throwExceptionIfError();
        }

        // Create L3Network
        String l3PublicNetworkId = null;
        CreateL3NetworkAction createL3NetworkAction = new CreateL3NetworkAction();
        createL3NetworkAction.name = "L3Public-1";
        createL3NetworkAction.type = "L3BasicNetwork";
        createL3NetworkAction.l2NetworkUuid = "9cd8b2ef024947bcbfcd1b5bc5a3df2b";
        createL3NetworkAction.category = "Public";
        createL3NetworkAction.sessionId = sessionId;
        CreateL3NetworkAction.Result createL3NetworkActionRes = createL3NetworkAction.call();
        if (createL3NetworkActionRes.error == null) {
            l3PublicNetworkId = createL3NetworkActionRes.value.getInventory().getUuid();
            System.out.println(String.format("l3PublicNetworkId = %s", l3PublicNetworkId));
        } else {
            createL3NetworkActionRes.throwExceptionIfError();
        }
        // Add IP Range to L3Network
        String publicIpRangeId = null;
        AddIpRangeAction addIpRangeAction = new AddIpRangeAction();
        addIpRangeAction.l3NetworkUuid = l3PublicNetworkId;
        addIpRangeAction.name = "IpRange-1";
        addIpRangeAction.startIp = "192.168.1.171";
        addIpRangeAction.endIp = "192.168.1.180";
        addIpRangeAction.netmask = "255.255.255.0";
        addIpRangeAction.gateway = "192.168.1.1";
        addIpRangeAction.ipRangeType = "Normal";
        addIpRangeAction.sessionId = sessionId;
        AddIpRangeAction.Result addIpRangeActionRes = addIpRangeAction.call();
        if (addIpRangeActionRes.error == null) {
            publicIpRangeId = addIpRangeActionRes.value.getInventory().getUuid();
            System.out.println(String.format("publicIpRangeId = %s", publicIpRangeId));
        } else {
            addIpRangeActionRes.throwExceptionIfError();
        }
        // Add DNS to L3Network
        String publicDnsId = null;
        AddDnsToL3NetworkAction addDnsToL3NetworkAction = new AddDnsToL3NetworkAction();
        addDnsToL3NetworkAction.l3NetworkUuid = l3PublicNetworkId;
        addDnsToL3NetworkAction.dns = "8.8.8.8";
        addDnsToL3NetworkAction.sessionId = sessionId;
        AddDnsToL3NetworkAction.Result addDnsToL3NetworkActionRes = addDnsToL3NetworkAction.call();
        if (addDnsToL3NetworkActionRes.error == null) {
            publicDnsId = addDnsToL3NetworkActionRes.value.getInventory().getUuid();
            System.out.println(String.format("publicDnsId = %s", publicDnsId));
        } else {
            addDnsToL3NetworkActionRes.throwExceptionIfError();
        }
        // For Normal DHCP
        // Attach Network Services to L3PrivateNetwork
        String securityGroupNetworkServiceProvider = "6a5648ac17c648ae90ed5459fb62e5fc";
        String flatNetworkServiceProvider = "cff293f15c81443f8b54138471a2f1f4";
        AttachNetworkServiceToL3NetworkAction attachNetworkServiceToL3NetworkAction = new AttachNetworkServiceToL3NetworkAction();
        attachNetworkServiceToL3NetworkAction.l3NetworkUuid = l3PublicNetworkId;
        HashMap<String, List<String>> services = new HashMap<String, List<String>>();
        services.put(securityGroupNetworkServiceProvider, Arrays.asList("SecurityGroup"));
        services.put(flatNetworkServiceProvider, Arrays.asList("Userdata", "DHCP"));
        attachNetworkServiceToL3NetworkAction.networkServices = services;
        attachNetworkServiceToL3NetworkAction.sessionId = sessionId;
        AttachNetworkServiceToL3NetworkAction.Result attachNetworkServiceToL3NetworkActionRes = attachNetworkServiceToL3NetworkAction
                .call();
        if (attachNetworkServiceToL3NetworkActionRes.error == null) {
            System.out.println("Successfully attach network service to l3network");
        } else {
            attachNetworkServiceToL3NetworkActionRes.throwExceptionIfError();
        }

        // Add Router Image
        String routerImageId = null;
        AddImageAction addImageAction = new AddImageAction();
        addImageAction.name = "RouterImage-1";
        addImageAction.url = "file:///opt/zstack-dvd/zstack-vrouter-3.10.2.qcow2";
        addImageAction.platform = "Linux";
        addImageAction.system = true;
        addImageAction.format = "qcow2";
        addImageAction.backupStorageUuids = new ArrayList<String>(
                Arrays.asList(String.format("%s", "3ea0d19b555e4394b0def348bb645f66")));
        ;
        addImageAction.sessionId = sessionId;
        AddImageAction.Result addImageActionRes = addImageAction.call();
        if (addImageActionRes.error == null) {
            routerImageId = addImageActionRes.value.getInventory().getUuid();
            System.out.println(String.format("routerImageId = %s", routerImageId));
        } else {
            addImageActionRes.throwExceptionIfError();
        }

        // Create Router Standard
        String routerStandardId = null;
        CreateVirtualRouterOfferingAction createVirtualRouterOfferingAction = new CreateVirtualRouterOfferingAction();
        createVirtualRouterOfferingAction.zoneUuid = "67872e9cd7e049808672bcfe9abca851";
        createVirtualRouterOfferingAction.managementNetworkUuid = "091ed38119bf42b984029cfc3eab6b6f";
        createVirtualRouterOfferingAction.publicNetworkUuid = "091ed38119bf42b984029cfc3eab6b6f";
        createVirtualRouterOfferingAction.imageUuid = "85cebfcf542e4892b2342a1c07d999c2";
        createVirtualRouterOfferingAction.name = "RouterStandard-1";
        createVirtualRouterOfferingAction.cpuNum = 8;
        createVirtualRouterOfferingAction.memorySize = 8589934592l; // 8G
        createVirtualRouterOfferingAction.type = "VirtualRouter";
        createVirtualRouterOfferingAction.sessionId = sessionId;
        CreateVirtualRouterOfferingAction.Result createVirtualRouterOfferingActionRes = createVirtualRouterOfferingAction
                .call();
        if (createVirtualRouterOfferingActionRes.error == null) {
            routerStandardId = createVirtualRouterOfferingActionRes.value.getInventory().getUuid();
            System.out.println(String.format("routerStandardId = %s", routerStandardId));
        } else {
            createVirtualRouterOfferingActionRes.throwExceptionIfError();
        }

        // Create L3PrivateNetwork
        String l3PrivateNetworkId = null;
        CreateL3NetworkAction createL3NetworkAction = new CreateL3NetworkAction();
        createL3NetworkAction.name = "L3Private-1";
        createL3NetworkAction.type = "L3BasicNetwork";
        createL3NetworkAction.l2NetworkUuid = "236fa74c381d4fd8a0b3c33968d88763";
        createL3NetworkAction.category = "Private";
        createL3NetworkAction.systemTags = new ArrayList<String>(
                Arrays.asList(String.format("virtualRouterOffering::%s", "21770c2567d54505af9d8c6865ef5011")));
        createL3NetworkAction.sessionId = sessionId;
        CreateL3NetworkAction.Result createL3NetworkActionRes = createL3NetworkAction.call();
        if (createL3NetworkActionRes.error == null) {
            l3PrivateNetworkId = createL3NetworkActionRes.value.getInventory().getUuid();
            System.out.println(String.format("l3PrivateNetworkId = %s", l3PrivateNetworkId));
        } else {
            createL3NetworkActionRes.throwExceptionIfError();
        }
        // Add IP Range by CIDR
        String ipRangeIdByCidr = null;
        AddIpRangeByNetworkCidrAction addIpRangeByNetworkCidrAction = new AddIpRangeByNetworkCidrAction();
        addIpRangeByNetworkCidrAction.name = "IpRange-2";
        addIpRangeByNetworkCidrAction.l3NetworkUuid = l3PrivateNetworkId;
        addIpRangeByNetworkCidrAction.networkCidr = "172.20.233.0/24";
        addIpRangeByNetworkCidrAction.gateway = "172.20.233.1";
        addIpRangeByNetworkCidrAction.sessionId = sessionId;
        AddIpRangeByNetworkCidrAction.Result addIpRangeByNetworkCidrActionRes = addIpRangeByNetworkCidrAction.call();
        if (addIpRangeByNetworkCidrActionRes.error == null) {
            ipRangeIdByCidr = addIpRangeByNetworkCidrActionRes.value.getInventory().getUuid();
            System.out.println(String.format("ipRangeIdByCidr = %s", ipRangeIdByCidr));
        } else {
            addIpRangeByNetworkCidrActionRes.throwExceptionIfError();
        }
        // Add DNS to L3PrivateNetwork
        String privateDnsId = null;
        AddDnsToL3NetworkAction addDnsToL3NetworkAction = new AddDnsToL3NetworkAction();
        addDnsToL3NetworkAction.l3NetworkUuid = l3PrivateNetworkId;
        addDnsToL3NetworkAction.dns = "8.8.8.8";
        addDnsToL3NetworkAction.sessionId = sessionId;
        AddDnsToL3NetworkAction.Result addDnsToL3NetworkActionRes = addDnsToL3NetworkAction.call();
        if (addDnsToL3NetworkActionRes.error == null) {
            privateDnsId = addDnsToL3NetworkActionRes.value.getInventory().getUuid();
            System.out.println(String.format("privateDnsId = %s", privateDnsId));
        } else {
            addDnsToL3NetworkActionRes.throwExceptionIfError();
        }
        // For Router
        // Attach Network Services to L3PrivateNetwork
        String vrouterNetworkServiceProvider = "101baee663544e3f9a40fe0636cd694f";
        String securityGroupNetworkServiceProvider = "6a5648ac17c648ae90ed5459fb62e5fc";
        String flatNetworkServiceProvider = "cff293f15c81443f8b54138471a2f1f4";
        AttachNetworkServiceToL3NetworkAction attachNetworkServiceToL3NetworkAction = new AttachNetworkServiceToL3NetworkAction();
        attachNetworkServiceToL3NetworkAction.l3NetworkUuid = l3PrivateNetworkId;
        HashMap<String, List<String>> services = new HashMap<String, List<String>>();
        services.put(vrouterNetworkServiceProvider, Arrays.asList("IPsec", "VRouterRoute", "CentralizedDNS", "VipQos",
                "SNAT", "LoadBalancer", "PortForwarding", "Eip", "DNS"));
        services.put(securityGroupNetworkServiceProvider, Arrays.asList("SecurityGroup"));
        services.put(flatNetworkServiceProvider, Arrays.asList("Userdata", "DHCP"));
        attachNetworkServiceToL3NetworkAction.networkServices = services;
        attachNetworkServiceToL3NetworkAction.sessionId = sessionId;
        AttachNetworkServiceToL3NetworkAction.Result attachNetworkServiceToL3NetworkActionRes = attachNetworkServiceToL3NetworkAction
                .call();
        if (attachNetworkServiceToL3NetworkActionRes.error == null) {
            System.out.println("Successfully attach network service to l3network");
        } else {
            attachNetworkServiceToL3NetworkActionRes.throwExceptionIfError();
        }

        // Create VM Instance
        String vmId = null;
        CreateVmInstanceAction createVmInstanceAction = new CreateVmInstanceAction();
        createVmInstanceAction.name = "VM-1";
        createVmInstanceAction.instanceOfferingUuid = "554ee516f0804212877787e367cfee0a";
        createVmInstanceAction.imageUuid = "fb14b88413b849578679298163772c5d";
        createVmInstanceAction.l3NetworkUuids = new ArrayList<String>(
                Arrays.asList(String.format("%s", "4b3a41af2b634f1da0f7fae5734c0b92")));
        createVmInstanceAction.defaultL3NetworkUuid = "4b3a41af2b634f1da0f7fae5734c0b92";
        createVmInstanceAction.dataDiskOfferingUuids = new ArrayList<String>(Arrays.asList());
        createVmInstanceAction.sessionId = sessionId;
        CreateVmInstanceAction.Result createVmInstanceActionRes = createVmInstanceAction.call();
        if (createVmInstanceActionRes.error == null) {
            vmId = createVmInstanceActionRes.value.getInventory().getUuid();
            System.out.println(String.format("vmId = %s", vmId));
        } else {
            createVmInstanceActionRes.throwExceptionIfError();
        }

        // Request VM Console
        GetVmConsoleAddressAction getVmConsoleAddressAction = new GetVmConsoleAddressAction();
        getVmConsoleAddressAction.uuid = "2c1106bd54b042daa8d7459fb2744906";
        getVmConsoleAddressAction.sessionId = sessionId;
        GetVmConsoleAddressAction.Result getVmConsoleAddressActionRes = getVmConsoleAddressAction.call();
        if (getVmConsoleAddressActionRes.error == null) {
            GetVmConsoleAddressResult consoleInfo = getVmConsoleAddressActionRes.value;
            System.out.println(
                    String.format("Successfully open console: vnc://%s:%s", consoleInfo.hostIp, consoleInfo.port));
        } else {
            getVmConsoleAddressActionRes.throwExceptionIfError();
        }

        // LogOut
        LogOutAction logOutActionAction = new LogOutAction();
        logOutActionAction.sessionUuid = sessionId;
        LogOutAction.Result logOutActionActionRes = logOutActionAction.call();
        if (logOutActionActionRes.error == null) {
            System.out.println("Successfully delete session");
        } else {
            logOutActionActionRes.throwExceptionIfError();
        }
    }
}
