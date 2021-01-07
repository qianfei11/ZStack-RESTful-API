# ZStack RESTful API

ZStack 3.10.0 提供原生 RESTful 支持，可以通过 REST 定义的架构设计原则和约束条件，并使用支持 HTTP 的编程语言进行开发。API 支持的操作资源的方式：

| 方法名 |                                           描述                                            |
| :----: | :---------------------------------------------------------------------------------------: |
|  GET   |                  获取资源信息。所有的查询 API 以及读 API 均使用该方法。                   |
|  POST  |                                      创建一个资源。                                       |
|  PUT   | 修改一个资源。所有对资源的修改操作，以及类 RPC 调用的操作，例如启动虚拟机，均使用该方法。 |
| DELETE |                                      删除一个资源。                                       |

> 相关的日志信息可以在管理节点的 `/usr/local/zstack/apache-tomcat/logs/management-server.log` 中查看。

## Java SDK

> Java 封装的 API 在管理节点的 `/usr/local/zstack/apache-tomcat-8.5.57/webapps/zstack/WEB-INF/lib/sdk-3.10.0.jar` 中

```java
// Configure
ZSConfig.Builder zBuilder = new ZSConfig.Builder();
zBuilder.setContextPath("zstack");
zBuilder.setHostname("192.168.1.101");
ZSClient.configure(zBuilder.build());
```

### 登录/注销用户

```java
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

// LogOut
LogOutAction logOutActionAction = new LogOutAction();
logOutActionAction.sessionUuid = sessionId;
LogOutAction.Result logOutActionActionRes = logOutActionAction.call();
if (logOutActionActionRes.error == null) {
    System.out.println("Successfully delete session");
} else {
    logOutActionActionRes.throwExceptionIfError();
}
```

### 创建/查询/删除区域

```java
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

// Query Zone
QueryZoneAction queryZoneAction = new QueryZoneAction();
queryZoneAction.conditions = new ArrayList<String>(Arrays.asList());
queryZoneAction.sessionId = sessionId;
List<String> zones = new ArrayList<String>(Arrays.asList());
QueryZoneAction.Result queryZoneActionRes = queryZoneAction.call();
if (queryZoneActionRes.error == null) {
    List<ZoneInventory> objs = queryZoneActionRes.value.getInventories();
    objs.forEach((obj) -> {
        String zoneId = obj.getUuid();
        zones.add(zoneId);
        System.out.println(String.format("zoneId = %s", zoneId));
    });
} else {
    queryZoneActionRes.throwExceptionIfError();
}

// Delete Zone
DeleteZoneAction deleteZoneAction = new DeleteZoneAction();
deleteZoneAction.uuid = zoneId;
deleteZoneAction.sessionId = sessionId;
DeleteZoneAction.Result deleteZoneActionRes = action.call();
if (deleteZoneActionRes.error == null) {
    System.out.println("Successfully delete zone");
} else {
    deleteZoneActionRes.throwExceptionIfError();
}
```

### 创建/查询/删除集群

```java
// Create Cluster
String clusterId = null;
CreateClusterAction createClusterAction = new CreateClusterAction();
createClusterAction.zoneUuid = zoneId;
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

// Query Cluster
QueryClusterAction queryClusterAction = new QueryClusterAction();
queryClusterAction.conditions = new ArrayList<String>(Arrays.asList());
queryClusterAction.sessionId = sessionId;
List<String> clusters = new ArrayList<String>(Arrays.asList());
QueryClusterAction.Result queryClusterActionRes = queryClusterAction.call();
if (queryClusterActionRes.error == null) {
    List<ClusterInventory> objs = queryClusterActionRes.value.getInventories();
    objs.forEach((obj) -> {
        String clusterId = obj.getUuid();
        clusters.add(clusterId);
        System.out.println(String.format("clusterId = %s", clusterId));
    });
} else {
    queryClusterActionRes.throwExceptionIfError();
}

// Delete Cluster
DeleteClusterAction deleteClusterAction = new DeleteClusterAction();
deleteClusterAction.uuid = cluster;
deleteClusterAction.sessionId = sessionId;
DeleteClusterAction.Result deleteClusterActionRes = deleteClusterAction.call();
if (deleteClusterActionRes.error == null) {
    System.out.println("Successfully delete cluster");
} else {
    deleteClusterActionRes.throwExceptionIfError();
}
```

### 添加/查询/删除物理机

```java
// Add KVM Host
// Name of network-interface should be same as the Host's
String hostId = null;
AddKVMHostAction addKVMHostAction = new AddKVMHostAction();
addKVMHostAction.username = "root";
addKVMHostAction.password = "password";
addKVMHostAction.name = "Host-1";
addKVMHostAction.managementIp = "192.168.1.101";
addKVMHostAction.clusterUuid = clusterId;
addKVMHostAction.sessionId = sessionId;
AddKVMHostAction.Result addKVMHostActionRes = addKVMHostAction.call();
if (addKVMHostActionRes.error == null) {
    hostId = addKVMHostActionRes.value.getInventory().getUuid();
    System.out.println(String.format("hostId = %s", hostId));
} else {
    addKVMHostActionRes.throwExceptionIfError();
}

// Query Host
QueryHostAction queryHostAction = new QueryHostAction();
queryHostAction.conditions = new ArrayList<String>(Arrays.asList());
queryHostAction.sessionId = sessionId;
List<String> hosts = new ArrayList<String>(Arrays.asList());
QueryHostAction.Result queryHostActionRes = queryHostAction.call();
if (queryHostActionRes.error == null) {
    List<HostInventory> objs = queryHostActionRes.value.getInventories();
    objs.forEach((obj) -> {
        String hostId = obj.getUuid();
        hosts.add(hostId);
        System.out.println(String.format("hostId = %s", hostId));
    });
} else {
    queryHostActionRes.throwExceptionIfError();
}

// Delete Host
DeleteHostAction deleteHostAction = new DeleteHostAction();
deleteHostAction.uuid = hostId;
deleteHostAction.sessionId = sessionId;
DeleteHostAction.Result deleteHostActionRes = deleteHostAction.call();
if (deleteHostActionRes.error == null) {
    System.out.println("Successfully delete host");
} else {
    deleteHostActionRes.throwExceptionIfError();
}
```

### 添加/加载/查询/卸载/删除镜像服务器

```java
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
attachBackupStorageToZoneAction.zoneUuid = zoneId;
attachBackupStorageToZoneAction.backupStorageUuid = imageStorageId;
attachBackupStorageToZoneAction.sessionId = sessionId;
AttachBackupStorageToZoneAction.Result attachBackupStorageToZoneActionRes = attachBackupStorageToZoneAction.call();
if (attachBackupStorageToZoneActionRes.error == null) {
    attachImageStorageInfoId = attachBackupStorageToZoneActionRes.value.getInventory().getUuid();
    System.out.println(String.format("attachImageStorageInfoId = %s", attachImageStorageInfoId));
} else {
    attachBackupStorageToZoneActionRes.throwExceptionIfError();
}

// Query Image Storage
QueryBackupStorageAction queryBackupStorageAction = new QueryBackupStorageAction();
queryBackupStorageAction.conditions = new ArrayList<String>(Arrays.asList());
queryBackupStorageAction.sessionId = sessionId;
imageStorages = new ArrayList<String>(Arrays.asList());
QueryBackupStorageAction.Result queryBackupStorageActionRes = action.call();
if (queryBackupStorageActionRes.error == null) {
    List<BackupStorageInventory> objs = queryBackupStorageActionRes.value.getInventories();
    objs.forEach((obj) -> {
        String imageStorageId = obj.getUuid();
        hosts.add(imageStorageId);
        System.out.println(String.format("imageStorageId = %s", imageStorageId));
    });
} else {
    queryBackupStorageActionRes.throwExceptionIfError();
}

// Detach Image Storage from Zone
DetachBackupStorageFromZoneAction detachBackupStorageFromZoneAction = new DetachBackupStorageFromZoneAction();
detachBackupStorageFromZoneAction.zoneUuid = zoneId;
detachBackupStorageFromZoneAction.backupStorageUuid = imageStorageId;
detachBackupStorageFromZoneAction.sessionId = sessionId;
DetachBackupStorageFromZoneAction.Result detachBackupStorageFromZoneActionRes = detachBackupStorageFromZoneAction.call();
if (detachBackupStorageFromZoneActionRes.error == null) {
    System.out.println("Successfully detach imageStorage from zone");
} else {
    detachBackupStorageFromZoneActionRes.throwExceptionIfError();
}

// Delete Image Storage
DeleteBackupStorageAction deleteBackupStorageAction = new DeleteBackupStorageAction();
deleteBackupStorageAction.uuid = imageStorageId;
deleteBackupStorageAction.sessionId = sessionId;
DeleteBackupStorageAction.Result deleteBackupStorageActionRes = deleteBackupStorageAction.call();
if (deleteBackupStorageActionRes.error == null) {
    System.out.println("Successfully delete imageStorage");
} else {
    deleteBackupStorageActionRes.throwExceptionIfError();
}
```

### 添加/加载/查询/卸载/删除主存储

```java
// Add Local Primary Storage
String localStorageId = null;
AddLocalPrimaryStorageAction addLocalPrimaryStorageAction = new AddLocalPrimaryStorageAction();
addLocalPrimaryStorageAction.url = "/zstack_ps";
addLocalPrimaryStorageAction.name = "PS-1";
addLocalPrimaryStorageAction.zoneUuid = zoneId;
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
attachPrimaryStorageToClusterAction.clusterUuid = clusterId;
attachPrimaryStorageToClusterAction.primaryStorageUuid = localStorageId;
attachPrimaryStorageToClusterAction.sessionId = sessionId;
AttachPrimaryStorageToClusterAction.Result attachPrimaryStorageToClusterActionRes = attachPrimaryStorageToClusterAction.call();
if (attachPrimaryStorageToClusterActionRes.error == null) {
    attachLocalStorageInfoId = attachPrimaryStorageToClusterActionRes.value.getInventory().getUuid();
    System.out.println(String.format("attachLocalStorageInfoId = %s", attachLocalStorageInfoId));
} else {
    attachPrimaryStorageToClusterActionRes.throwExceptionIfError();
}

// Query Local Primary Storage
QueryPrimaryStorageAction queryPrimaryStorageAction = new QueryPrimaryStorageAction();
queryPrimaryStorageAction.conditions = new ArrayList<String>(Arrays.asList());
queryPrimaryStorageAction.sessionId = sessionId;
List<String> localStorages = new ArrayList<String>(Arrays.asList());
QueryPrimaryStorageAction.Result queryPrimaryStorageActionRes = queryPrimaryStorageAction.call();
if (queryPrimaryStorageActionRes.error == null) {
    List<PrimaryStorageInventory> objs = queryPrimaryStorageActionRes.value.getInventories();
    objs.forEach((obj) -> {
        String localStorageId = obj.getUuid();
        hosts.add(localStorageId);
        System.out.println(String.format("localStorageId = %s", localStorageId));
    });
} else {
    queryPrimaryStorageActionRes.throwExceptionIfError();
}

// Detach Local Primary Storage from Cluster
DetachPrimaryStorageFromClusterAction detachPrimaryStorageFromClusterAction = new DetachPrimaryStorageFromClusterAction();
detachPrimaryStorageFromClusterAction.clusterUuid = clusterId;
detachPrimaryStorageFromClusterAction.primaryStorageUuid = localStorageId;
detachPrimaryStorageFromClusterAction.sessionId = sessionId;
DetachPrimaryStorageFromClusterAction.Result detachPrimaryStorageFromClusterActionRes = detachPrimaryStorageFromClusterAction.call();
if (detachPrimaryStorageFromClusterActionRes.error == null) {
    System.out.println("Successfully detach localStorage from cluster");
} else {
    detachPrimaryStorageFromClusterActionRes.throwExceptionIfError();
}

// Delete Local Primary Storage
DeletePrimaryStorageAction deletePrimaryStorageAction = new DeletePrimaryStorageAction();
deletePrimaryStorageAction.uuid = localStorageId;
deletePrimaryStorageAction.sessionId = sessionId;
DeletePrimaryStorageAction.Result deletePrimaryStorageActionRes = deletePrimaryStorageAction.call();
if (deletePrimaryStorageActionRes.error == null) {
    System.out.println("Successfully delete localStorage");
} else {
    deletePrimaryStorageActionRes.throwExceptionIfError();
}
```

### 添加/查询/删除计算规格

```java
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

// Query Instance Offering
QueryInstanceOfferingAction queryInstanceOfferingAction = new QueryInstanceOfferingAction();
queryInstanceOfferingAction.conditions = new ArrayList<String>(Arrays.asList());
queryInstanceOfferingAction.sessionId = sessionId;
List<String> instanceOfferings = new ArrayList<String>(Arrays.asList());
QueryInstanceOfferingAction.Result queryInstanceOfferingActionRes = queryInstanceOfferingAction.call();
if (queryInstanceOfferingActionRes.error == null) {
    List<InstanceOfferingInventory> objs = queryInstanceOfferingActionRes.value.getInventories();
    objs.forEach((obj) -> {
        String instanceOfferingId = obj.getUuid();
        instanceOfferings.add(instanceOfferingId);
        System.out.println(String.format("instanceOfferingId = %s", instanceOfferingId));
    });
} else {
    queryInstanceOfferingActionRes.throwExceptionIfError();
}

// Delete Instance Offering
DeleteInstanceOfferingAction deleteInstanceOfferingAction = new DeleteInstanceOfferingAction();
deleteInstanceOfferingAction.uuid = instanceOfferingId;
deleteInstanceOfferingAction.sessionId = sessionId;
DeleteInstanceOfferingAction.Result deleteInstanceOfferingActionRes = deleteInstanceOfferingAction.call();
if (deleteInstanceOfferingActionRes.error == null) {
    System.out.println("Successfully delete instanceOffering");
} else {
    deleteInstanceOfferingActionRes.throwExceptionIfError();
}
```

### 添加/查询/删除/彻底删除镜像

```java
// Add Image
String imageId = null;
AddImageAction addImageAction = new AddImageAction();
addImageAction.name = "Image-1";
addImageAction.url = "file:///opt/zstack-dvd/zstack-image-1.4.qcow2";
addImageAction.platform = "Linux";
addImageAction.format = "qcow2";
addImageAction.backupStorageUuids = new ArrayList<String>(Arrays.asList(String.format("%s", imageStorageId)));;
addImageAction.sessionId = sessionId;
AddImageAction.Result addImageActionRes = addImageAction.call();
if (addImageActionRes.error == null) {
    imageId = addImageActionRes.value.getInventory().getUuid();
    System.out.println(String.format("imageId = %s", imageId));
} else {
    addImageActionRes.throwExceptionIfError();
}

// Query Image
QueryImageAction queryImageAction = new QueryImageAction();
queryImageAction.conditions = new ArrayList<String>(Arrays.asList());
queryImageAction.sessionId = sessionId;
List<String> images = new ArrayList<String>(Arrays.asList());
QueryImageAction.Result queryImageActionRes = queryImageAction.call();
if (queryImageActionRes.error == null) {
    List<ImageInventory> objs = queryImageActionRes.value.getInventories();
    objs.forEach((obj) -> {
        String imageId = obj.getUuid();
        hosts.add(imageId);
        System.out.println(String.format("imageId = %s", imageId));
    });
} else {
    queryImageActionRes.throwExceptionIfError();
}

// Delete Image
DeleteImageAction deleteImageAction = new DeleteImageAction();
deleteImageAction.uuid = imageId;
deleteImageAction.backupStorageUuids = imageStorageId;
deleteImageAction.sessionId = sessionId;
DeleteImageAction.Result deleteImageActionRes = deleteImageAction.call();
if (deleteImageActionRes.error == null) {
    System.out.println("Successfully delete image");
} else {
    deleteImageActionRes.throwExceptionIfError();
}

// Expunge Image
ExpungeImageAction expungeImageAction = new ExpungeImageAction();
expungeImageAction.uuid = imageId;
expungeImageAction.backupStorageUuids = imageStorageId;
expungeImageAction.sessionId = sessionId;
ExpungeImageAction.Result expungeImageActionRes = expungeImageAction.call();
if (expungeImageActionRes.error == null) {
    System.out.println("Successfully expunge image");
} else {
    expungeImageActionRes.throwExceptionIfError();
}
```

### 添加/加载/查询/卸载/删除二级网络

```java
// Add L2NoVlanNetwork
String l2NetworkId = null;
CreateL2NoVlanNetworkAction createL2NoVlanNetworkAction = new CreateL2NoVlanNetworkAction();
createL2NoVlanNetworkAction.name = "L2Public-1";
createL2NoVlanNetworkAction.zoneUuid = zoneId;
createL2NoVlanNetworkAction.physicalInterface = "eth0";
createL2NoVlanNetworkAction.sessionId = sessionId;
CreateL2NoVlanNetworkAction.Result createL2NoVlanNetworkActionRes = createL2NoVlanNetworkAction.call();
if (createL2NoVlanNetworkActionRes.error == null) {
    l2NetworkId = createL2NoVlanNetworkActionRes.value.getInventory().getUuid();
    System.out.println(String.format("l2NetworkId = %s", l2NetworkId));
} else {
    createL2NoVlanNetworkActionRes.throwExceptionIfError();
}

// Attach L2Network to Cluster
String attachL2NetworkInfoId = null;
AttachL2NetworkToClusterAction attachL2NetworkToClusterAction = new AttachL2NetworkToClusterAction();
attachL2NetworkToClusterAction.l2NetworkUuid = l2NetworkId;
attachL2NetworkToClusterAction.clusterUuid = clusterId;
attachL2NetworkToClusterAction.sessionId = sessionId;
AttachL2NetworkToClusterAction.Result attachL2NetworkToClusterActionRes = attachL2NetworkToClusterAction.call();
if (attachL2NetworkToClusterActionRes.error == null) {
    attachL2NetworkInfoId = attachL2NetworkToClusterActionRes.value.getInventory().getUuid();
    System.out.println(String.format("attachL2NetworkInfoId = %s", attachL2NetworkInfoId));
} else {
    attachL2NetworkToClusterActionRes.throwExceptionIfError();
}

// Query L2Network
QueryL2NetworkAction queryL2NetworkAction = new QueryL2NetworkAction();
queryL2NetworkAction.conditions = new ArrayList<String>(Arrays.asList());
queryL2NetworkAction.sessionId = sessionId;
List<String> l2Networks = new ArrayList<String>(Arrays.asList());
QueryL2NetworkAction.Result queryL2NetworkActionRes = queryL2NetworkAction.call();
if (queryL2NetworkActionRes.error == null) {
    List<L2NetworkInventory> objs = queryL2NetworkActionRes.value.getInventories();
    objs.forEach((obj) -> {
        String l2NetworkId = obj.getUuid();
        l2Networks.add(l2NetworkId);
        System.out.println(String.format("l2NetworkId = %s", l2NetworkId));
    });
} else {
    queryL2NetworkActionRes.throwExceptionIfError();
}

// Detach L2Network from Cluster
DetachL2NetworkFromClusterAction detachL2NetworkFromClusterAction = new DetachL2NetworkFromClusterAction();
detachL2NetworkFromClusterAction.l2NetworkUuid = l2NetworkId;
detachL2NetworkFromClusterAction.clusterUuid = clusterId;
detachL2NetworkFromClusterAction.sessionId = sessionId;
DetachL2NetworkFromClusterAction.Result detachL2NetworkFromClusterActionRes = detachL2NetworkFromClusterAction.call();
if (detachL2NetworkFromClusterActionRes.error == null) {
    System.out.println("Successfully detach l2Network from cluster");
} else {
    detachL2NetworkFromClusterActionRes.throwExceptionIfError();
}

// Delete L2Network
DeleteL2NetworkAction deleteL2NetworkAction = new DeleteL2NetworkAction();
deleteL2NetworkAction.l2NetworkUuid = l2NetworkId;
deleteL2NetworkAction.sessionId = sessionId;
DeleteL2NetworkAction.Result deleteL2NetworkActionRes = deleteL2NetworkAction.call();
if (deleteL2NetworkActionRes.error == null) {
    System.out.println("Successfully delete l2Network");
} else {
    deleteL2NetworkActionRes.throwExceptionIfError();
}
```

#### 添加/查询二级 VLAN 网络

```java
// Add L2VlanNetwork
String l2VlanNetworkId = null;
CreateL2VlanNetworkAction createL2VlanNetworkAction = new CreateL2VlanNetworkAction();
createL2VlanNetworkAction.vlan = 1000;
createL2VlanNetworkAction.name = 'L2Private-1';
createL2VlanNetworkAction.zoneUuid = zoneId;
createL2VlanNetworkAction.physicalInterface = 'eth0';
createL2VlanNetworkAction.sessionId = sessionId;
CreateL2VlanNetworkAction.Result createL2VlanNetworkActionRes = createL2VlanNetworkAction.call();
if (createL2VlanNetworkActionRes.error == null) {
    l2VlanNetworkId = createL2VlanNetworkActionRes.value.getInventory().getUuid();
    System.out.println(String.format("l2VlanNetworkId = %s", l2VlanNetworkId));
} else {
    createL2VlanNetworkActionRes.throwExceptionIfError();
}

// Query L2VlanNetwork
QueryL2VlanNetworkAction queryL2VlanNetworkAction = new QueryL2VlanNetworkAction();
queryL2VlanNetworkAction.conditions = new ArrayList<String>(Arrays.asList());
queryL2VlanNetworkAction.sessionId = sessionId;
List<String> l2VlanNetworks = new ArrayList<String>(Arrays.asList());
QueryL2VlanNetworkAction.Result queryL2VlanNetworkActionRes = queryL2VlanNetworkAction.call();
if (queryL2VlanNetworkActionRes.error == null) {
    List<L2VlanNetworkInventory> objs = queryL2VlanNetworkActionRes.value.getInventories();
    objs.forEach((obj) -> {
        String l2VlanNetworkId = obj.getUuid();
        l2VlanNetworks.add(l2VlanNetworkId);
        System.out.println(String.format("l2VlanNetworkId = %s", l2VlanNetworkId));
    });
} else {
    queryL2VlanNetworkActionRes.throwExceptionIfError();
}
```

### 添加/查询/删除三级网络

```java
// Create L3Network
String l3NetworkId = null;
CreateL3NetworkAction createL3NetworkAction = new CreateL3NetworkAction();
createL3NetworkAction.name = "L3Public-1";
createL3NetworkAction.type = "L3BasicNetwork";
createL3NetworkAction.l2NetworkUuid = l2NetworkId;
createL3NetworkAction.category = "Public";
createL3NetworkAction.sessionId = sessionId;
CreateL3NetworkAction.Result createL3NetworkActionRes = createL3NetworkAction.call();
if (createL3NetworkActionRes.error == null) {
    l3NetworkId = createL3NetworkActionRes.value.getInventory().getUuid();
    System.out.println(String.format("l3NetworkId = %s", l3NetworkId));
} else {
    createL3NetworkActionRes.throwExceptionIfError();
}

// Query L3Network
QueryL3NetworkAction queryL3NetworkAction = new QueryL3NetworkAction();
queryL3NetworkAction.conditions = new ArrayList<String>(Arrays.asList());
queryL3NetworkAction.sessionId = sessionId;
List<String> l3Networks = new ArrayList<String>(Arrays.asList());
QueryL3NetworkAction.Result queryL3NetworkActionRes = queryL3NetworkAction.call();
if (queryL3NetworkActionRes.error == null) {
    List<L3NetworkInventory> objs = queryL3NetworkActionRes.value.getInventories();
    objs.forEach((obj) -> {
        String l3NetworkId = obj.getUuid();
        l3Networks.add(l3NetworkId);
        System.out.println(String.format("l3NetworkId = %s", l3NetworkId));
    });
} else {
    queryL3NetworkActionRes.throwExceptionIfError();
}

// Delete L3Network
DeleteL3NetworkAction deleteL3NetworkAction = new DeleteL3NetworkAction();
deleteL3NetworkAction.uuid = l3NetworkId;
deleteL3NetworkAction.sessionId = sessionId;
DeleteL3NetworkAction.Result deleteL3NetworkActionRes = deleteL3NetworkAction.call();
if (deleteL3NetworkActionRes.error == null) {
    System.out.println("Successfully delete l3Network");
} else {
    deleteL3NetworkActionRes.throwExceptionIfError();
}
```

### 添加/查询/删除网络段

```java
// Add IP Range to L3Network
String ipRangeId = null;
AddIpRangeAction addIpRangeAction = new AddIpRangeAction();
addIpRangeAction.l3NetworkUuid = l3NetworkId;
addIpRangeAction.name = "IpRange-1";
addIpRangeAction.startIp = "192.168.1.2";
addIpRangeAction.endIp = "192.168.1.254";
addIpRangeAction.netmask = "255.255.255.0";
addIpRangeAction.gateway = "192.168.1.1";
addIpRangeAction.ipRangeType = "Normal";
addIpRangeAction.sessionId = sessionId;
AddIpRangeAction.Result addIpRangeActionRes = addIpRangeAction.call();
if (addIpRangeActionRes.error == null) {
    ipRangeId = addIpRangeActionRes.value.getInventory().getUuid();
    System.out.println(String.format("ipRangeId = %s", ipRangeId));
} else {
    addIpRangeActionRes.throwExceptionIfError();
}

// Add IP Range by CIDR
String ipRangeIdByCidr = null;
AddIpRangeByNetworkCidrAction addIpRangeByNetworkCidrAction = new AddIpRangeByNetworkCidrAction();
addIpRangeByNetworkCidrAction.name = "IpRange-2";
addIpRangeByNetworkCidrAction.l3NetworkUuid = l3NetworkId;
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

// Query IP Range
QueryIpRangeAction queryIpRangeAction = new QueryIpRangeAction();
queryIpRangeAction.conditions = new ArrayList<String>(Arrays.asList());
queryIpRangeAction.sessionId = sessionId;
List<String> ipRanges = new ArrayList<String>(Arrays.asList());
QueryIpRangeAction.Result queryIpRangeActionRes = queryIpRangeAction.call();
if (queryIpRangeActionRes.error == null) {
    List<IpRangeInventory> objs = queryIpRangeActionRes.value.getInventories();
    objs.forEach((obj) -> {
        String ipRangeId = obj.getUuid();
        ipRanges.add(ipRangeId);
        System.out.println(String.format("ipRangeId = %s", ipRangeId));
    });
} else {
    queryIpRangeActionRes.throwExceptionIfError();
}

// Delete IP Range
DeleteIpRangeAction deleteIpRangeAction = new DeleteIpRangeAction();
deleteIpRangeAction.uuid = ipRangeId;
deleteIpRangeAction.sessionId = sessionId;
DeleteIpRangeAction.Result deleteIpRangeActionRes = deleteIpRangeAction.call();
if (deleteIpRangeActionRes.error == null) {
    System.out.println("Successfully delete ipRange");
} else {
    deleteIpRangeActionRes.throwExceptionIfError();
}
```

### 添加/删除 DNS

```java
// Add DNS to L3Network
String dnsId = null;
AddDnsToL3NetworkAction addDnsToL3NetworkAction = new AddDnsToL3NetworkAction();
addDnsToL3NetworkAction.l3NetworkUuid = l3NetworkId;
addDnsToL3NetworkAction.dns = "8.8.8.8";
addDnsToL3NetworkAction.sessionId = sessionId;
AddDnsToL3NetworkAction.Result addDnsToL3NetworkActionRes = addDnsToL3NetworkAction.call();
if (addDnsToL3NetworkActionRes.error == null) {
    dnsId = addDnsToL3NetworkActionRes.value.getInventory().getUuid();
    System.out.println(String.format("dnsId = %s", dnsId));
} else {
    addDnsToL3NetworkActionRes.throwExceptionIfError();
}

// Remove DNS from L3Network
RemoveDnsFromL3NetworkAction removeDnsFromL3NetworkAction = new RemoveDnsFromL3NetworkAction();
removeDnsFromL3NetworkAction.l3NetworkUuid = l3NetworkId;
removeDnsFromL3NetworkAction.dns = "8.8.8.8";
removeDnsFromL3NetworkAction.sessionId = sessionId;
RemoveDnsFromL3NetworkAction.Result removeDnsFromL3NetworkActionRes = removeDnsFromL3NetworkAction.call();
if (removeDnsFromL3NetworkActionRes.error == null) {
    System.out.println("Successfully delete dns");
} else {
    removeDnsFromL3NetworkActionRes.throwExceptionIfError();
}
```

### 创建/查询云路由规格

```java
// Create Router Standard
String routerStandardId = null;
CreateVirtualRouterOfferingAction createVirtualRouterOfferingAction = new CreateVirtualRouterOfferingAction();
createVirtualRouterOfferingAction.zoneUuid = zoneId;
createVirtualRouterOfferingAction.managementNetworkUuid = l3NetworkId;
createVirtualRouterOfferingAction.publicNetworkUuid = l3NetworkId;
createVirtualRouterOfferingAction.imageUuid = imageId;
createVirtualRouterOfferingAction.name = "RouterStandard-1";
createVirtualRouterOfferingAction.cpuNum = 1;
createVirtualRouterOfferingAction.memorySize = 1073741824; // 1G
createVirtualRouterOfferingAction.type = "VirtualRouter";
createVirtualRouterOfferingAction.sessionId = sessionId;
CreateVirtualRouterOfferingAction.Result createVirtualRouterOfferingActionRes = createVirtualRouterOfferingAction.call();
if (createVirtualRouterOfferingActionRes.error == null) {
    routerStandardId = createVirtualRouterOfferingActionRes.value.getInventory().getUuid();
    System.out.println(String.format("routerStandardId = %s", routerStandardId));
} else {
    createVirtualRouterOfferingActionRes.throwExceptionIfError();
}

// Query Router Standard
QueryVirtualRouterOfferingAction queryVirtualRouterOfferingAction = new QueryVirtualRouterOfferingAction();
queryVirtualRouterOfferingAction.conditions = new ArrayList<String>(Arrays.asList());
queryVirtualRouterOfferingAction.sessionId = sessionId;
List<String> routerStandards = new ArrayList<String>(Arrays.asList());
QueryVirtualRouterOfferingAction.Result queryVirtualRouterOfferingActionRes = queryVirtualRouterOfferingAction.call();
if (queryVirtualRouterOfferingActionRes.error == null) {
    List<HostInventory> objs = queryVirtualRouterOfferingActionRes.value.getInventories();
    objs.forEach((obj) -> {
        String routerStandardId = obj.getUuid();
        routerStandards.add(routerStandardId);
        System.out.println(String.format("routerStandardId = %s", routerStandardId));
    });
} else {
    queryVirtualRouterOfferingActionRes.throwExceptionIfError();
}
```

### 创建/查询/删除/彻底删除云主机

```java
// Create VM Instance
String vmId = null;
CreateVmInstanceAction createVmInstanceAction = new CreateVmInstanceAction();
createVmInstanceAction.name = "VM-1";
createVmInstanceAction.instanceOfferingUuid = instanceOfferingId;
createVmInstanceAction.imageUuid = imageId;
createVmInstanceAction.l3NetworkUuids = new ArrayList<String>(Arrays.asList(String.format("%s", l3NetworkId)));
createVmInstanceAction.defaultL3NetworkUuid = l3NetworkId;
createVmInstanceAction.dataDiskOfferingUuids = new ArrayList<String>(Arrays.asList());
createVmInstanceAction.sessionId = sessionId;
CreateVmInstanceAction.Result createVmInstanceActionRes = createVmInstanceAction.call();
if (createVmInstanceActionRes.error == null) {
    vmId = createVmInstanceActionRes.value.getInventory().getUuid();
    System.out.println(String.format("vmId = %s", vmId));
} else {
    createVmInstanceActionRes.throwExceptionIfError();
}

// Query VM Instance
QueryVmInstanceAction queryVmInstanceAction = new QueryVmInstanceAction();
queryVmInstanceAction.conditions = new ArrayList<String>(Arrays.asList());
queryVmInstanceAction.sessionId = sessionId;
List<String> vms = new ArrayList<String>(Arrays.asList());
QueryVmInstanceAction.Result queryVmInstanceActionRes = queryVmInstanceAction.call();
if (queryVmInstanceActionRes.error == null) {
    List<VmInstanceInventory> objs = queryVmInstanceActionRes.value.getInventories();
    objs.forEach((obj) -> {
        String vmId = obj.getUuid();
        vms.add(vmId);
        System.out.println(String.format("vmId = %s", vmId));
    });
} else {
    queryVmInstanceActionRes.throwExceptionIfError();
}

// Destroy VM Instance
DestroyVmInstanceAction destroyVmInstanceAction = new DestroyVmInstanceAction();
destroyVmInstanceAction.uuid = vmId;
destroyVmInstanceAction.sessionId = sessionId;
DestroyVmInstanceAction.Result destroyVmInstanceActionRes = destroyVmInstanceAction.call();
if (destroyVmInstanceActionRes.error == null) {
    System.out.println("Successfully delete vm");
} else {
    destroyVmInstanceActionRes.throwExceptionIfError();
}

// Expunge VM Instance
ExpungeVmInstanceAction expungeVmInstanceAction = new ExpungeVmInstanceAction();
expungeVmInstanceAction.uuid = vmId;
expungeVmInstanceAction.sessionId = sessionId;
ExpungeVmInstanceAction.Result expungeVmInstanceActionRes = expungeVmInstanceAction.call();
if (expungeVmInstanceActionRes.error == null) {
    System.out.println("Successfully expunge vm");
} else {
    expungeVmInstanceActionRes.throwExceptionIfError();
}
```

### 获取 VNC 接口

```java
// Request VM Console
GetVmConsoleAddressAction getVmConsoleAddressAction = new GetVmConsoleAddressAction();
getVmConsoleAddressAction.uuid = vmId;
getVmConsoleAddressAction.sessionId = sessionId;
GetVmConsoleAddressAction.Result getVmConsoleAddressActionRes = getVmConsoleAddressAction.call();
if (getVmConsoleAddressActionRes.error == null) {
    GetVmConsoleAddressResult consoleInfo = getVmConsoleAddressActionRes.value;
    System.out.println(String.format("Successfully open console: vnc://%s:%s", consoleInfo.hostIp, consoleInfo.port));
} else {
    getVmConsoleAddressActionRes.throwExceptionIfError();
}
```

### Example

完整的创建过程示例：

```java
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
AttachBackupStorageToZoneAction.Result attachBackupStorageToZoneActionRes = attachBackupStorageToZoneAction.call();
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
AttachPrimaryStorageToClusterAction.Result attachPrimaryStorageToClusterActionRes = attachPrimaryStorageToClusterAction.call();
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
addImageAction.backupStorageUuids = new ArrayList<String>(Arrays.asList(String.format("%s", "3ea0d19b555e4394b0def348bb645f66")));;
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
String securityGroupNetworkServiceProvider = "38ec87620e184ba2bd885aaa06657c77";
String flatNetworkServiceProvider = "79275ca277e4413fa1759da4b4227a02";
AttachNetworkServiceToL3NetworkAction attachNetworkServiceToL3NetworkAction = new AttachNetworkServiceToL3NetworkAction();
attachNetworkServiceToL3NetworkAction.l3NetworkUuid = l3PublicNetworkId;
HashMap<String, List<String>> services = new HashMap<String, List<String>>();
services.put(securityGroupNetworkServiceProvider, Arrays.asList("SecurityGroup"));
services.put(flatNetworkServiceProvider, Arrays.asList("Userdata", "DHCP"));
attachNetworkServiceToL3NetworkAction.networkServices = services;
attachNetworkServiceToL3NetworkAction.sessionId = sessionId;
AttachNetworkServiceToL3NetworkAction.Result attachNetworkServiceToL3NetworkActionRes = attachNetworkServiceToL3NetworkAction.call();
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
addImageAction.backupStorageUuids = new ArrayList<String>(Arrays.asList(String.format("%s", "3ea0d19b555e4394b0def348bb645f66")));;
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
CreateVirtualRouterOfferingAction.Result createVirtualRouterOfferingActionRes = createVirtualRouterOfferingAction.call();
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
createL3NetworkAction.systemTags = new ArrayList<String>(Arrays.asList(String.format("virtualRouterOffering::%s", "21770c2567d54505af9d8c6865ef5011")));
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
services.put(vrouterNetworkServiceProvider, Arrays.asList("IPsec", "VRouterRoute", "CentralizedDNS", "VipQos", "SNAT", "LoadBalancer", "PortForwarding", "Eip", "DNS"));
services.put(securityGroupNetworkServiceProvider, Arrays.asList("SecurityGroup"));
services.put(flatNetworkServiceProvider, Arrays.asList("Userdata", "DHCP"));
attachNetworkServiceToL3NetworkAction.networkServices = services;
attachNetworkServiceToL3NetworkAction.sessionId = sessionId;
AttachNetworkServiceToL3NetworkAction.Result attachNetworkServiceToL3NetworkActionRes = attachNetworkServiceToL3NetworkAction.call();
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
createVmInstanceAction.l3NetworkUuids = new ArrayList<String>(Arrays.asList(String.format("%s", "4b3a41af2b634f1da0f7fae5734c0b92")));
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
    System.out.println(String.format("Successfully open console: vnc://%s:%s", consoleInfo.hostIp, consoleInfo.port));
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
```

## Python SDK

> Python 封装的 SDK 在管理节点根目录下的 `/usr/local/zstack/apache-tomcat-8.5.57/webapps/zstack/WEB-INF/classes/tools/zssdk.py` 中

首先需要调用 `configure` 对相关信息进行配置：

```python
# Configure
configure(hostname="192.168.1.101", context_path="/zstack")
```

### 登录/注销用户

```python
# LogIn
action = LogInByAccountAction()
action.accountName = "admin"
action.password = SHA512("password")
account = action.call().value.inventory
sessionId = account.uuid
DEBUG('sessionId = {}'.format(sessionId))

# LogOut
action = LogOutAction()
action.sessionUuid = sessionId
action.call()
DEBUG('Successfully delete session')
```

### 创建/查询/删除区域

```python
# Create Zone
action = CreateZoneAction()
action.name = "ZONE-1"
action.sessionId = sessionId
zone = action.call().value.inventory
zoneId = zone.uuid
DEBUG('zoneId = {}'.format(zoneId))

# Query Zone
action = QueryZoneAction()
action.conditions = []
action.sessionId = sessionId
zones = []
objs = action.call().value.inventories
for obj in objs:
    zones.append(obj.uuid)
DEBUG(zones)

# Delete Zone
action = DeleteZoneAction()
action.uuid = zoneId
action.sessionId = sessionId
action.call()
DEBUG('Successfully delete zone')
```

### 创建/查询/删除集群

```python
# Create Cluster
action = CreateClusterAction()
action.zoneUuid = zoneId
action.name = 'Cluster-1'
action.hypervisorType = "KVM"
action.sessionId = sessionId
cluster = action.call().value.inventory
clusterId = cluster.uuid
DEBUG('clusterId = {}'.format(clusterId))

# Query Cluster
action = QueryClusterAction()
action.conditions = []
action.sessionId = sessionId
clusters = []
objs = action.call().value.inventories
for obj in objs:
    clusters.append(obj.uuid)
DEBUG(clusters)

# Delete Cluster
action = DeleteClusterAction()
action.uuid = clusterId
action.sessionId = sessionId
action.call()
DEBUG('Successfully delete cluster')
```

### 添加/查询/删除物理机

```python
# Add KVM Host
# Name of network-interface should be same as the Host's
action = AddKVMHostAction()
action.username = "root"
action.password = "password"
action.name = "Host-1"
action.managementIp = "192.168.1.101"
action.clusterUuid = clusterId
action.sessionId = sessionId
host = action.call().value.inventory
hostId = host.uuid
DEBUG('hostId = {}'.format(hostId))

# Query Host
action = QueryHostAction()
action.conditions = []
action.sessionId = sessionId
hosts = []
objs = action.call().value.inventories
for obj in objs:
    hosts.append(obj.uuid)
DEBUG(hosts)

# Delete Host
action = DeleteHostAction()
action.uuid = hostId
action.sessionId = sessionId
action.call()
DEBUG('Successfully delete host')
```

### 添加/加载/查询/卸载/删除镜像服务器

```python
# Add Image Storage
action = AddSftpBackupStorageAction()
action.hostname = "192.168.1.101"
action.username = "root"
action.password = "password"
action.url = "/zstack_bs"
action.name = "BS-1"
action.sessionId = sessionId
imageStorage = action.call().value.inventory
imageStorageId = imageStorage.uuid
DEBUG('imageStorageId = {}'.format(imageStorageId))

# Attach Image Storage to Zone
action = AttachBackupStorageToZoneAction()
action.zoneUuid = zoneId
action.backupStorageUuid = imageStorageId
action.sessionId = sessionId
attachInfo = action.call().value.inventory
attachInfoId = attachInfo.uuid
DEBUG('attachInfoId = {}'.format(attachInfoId))

# Query Image Storage
action = QueryBackupStorageAction()
action.conditions = []
action.sessionId = sessionId
imageStorages = []
objs = action.call().value.inventories
for obj in objs:
    imageStorages.append(obj.uuid)
DEBUG(imageStorages)

# Detach Image Storage from Zone
action = DetachBackupStorageFromZoneAction()
action.zoneUuid = zoneId
action.backupStorageUuid = imageStorageId
action.sessionId = sessionId
action.call()
DEBUG('Successfully detach primaryStorage from cluster')

# Delete Image Storage
action = DeleteBackupStorageAction()
action.uuid = imageStorageId
action.sessionId = sessionId
action.call()
DEBUG('Successfully delete imageStorage')
```

### 添加/加载/查询/卸载/删除主存储

```python
# Add Local Primary Storage
action = AddLocalPrimaryStorageAction()
action.url = "/zstack_ps"
action.name = "PS-1"
action.zoneUuid = zoneId
action.sessionId = sessionId
localStorage = action.call().value.inventory
localStorageId = localStorage.uuid
DEBUG('localStorageId = {}'.format(localStorageId))

# Attach Local Primary Storage to Cluster
action = AttachPrimaryStorageToClusterAction()
action.clusterUuid = clusterId
action.primaryStorageUuid = localStorageId
action.sessionId = sessionId
attachInfo = action.call().value.inventory
attachInfoId = attachInfo.uuid
DEBUG('attachInfoId = {}'.format(attachInfoId))

# Query Local Primary Storage
action = QueryPrimaryStorageAction()
action.conditions = []
action.sessionId = sessionId
localStorages = []
objs = action.call().value.inventories
for obj in objs:
    localStorages.append(obj.uuid)
DEBUG(localStorages)

# Detach Local Primary Storage from Cluster
action = DetachPrimaryStorageFromClusterAction()
action.clusterUuid = clusterId
action.primaryStorageUuid = localStorageId
action.sessionId = sessionId
action.call()
DEBUG('Successfully detach primaryStorage from cluster')

# Delete Local Primary Storage
action = DeletePrimaryStorageAction()
action.uuid = localStorageId
action.sessionId = sessionId
action.call()
DEBUG('Successfully delete primaryStorage')
```

### 添加/查询/删除计算规格

```python
# Create Instance Offering
action = CreateInstanceOfferingAction()
action.name = "InstanceOffering-1"
action.cpuNum = 1
action.memorySize = 1073741824  # 1G
action.sessionId = sessionId
instanceOffering = action.call().value.inventory
instanceOfferingId = instanceOffering.uuid
DEBUG('instanceOfferingId = {}'.format(instanceOfferingId))

# Query Instance Offering
action = QueryInstanceOfferingAction()
action.conditions = []
action.sessionId = sessionId
instanceOfferings = []
objs = action.call().value.inventories
for obj in objs:
    instanceOfferings.append(obj.uuid)
DEBUG(instanceOfferings)

# Delete Instance Offering
action = DeleteInstanceOfferingAction()
action.uuid = instanceOfferingId
action.sessionId = sessionId
action.call()
DEBUG('Successfully delete instanceOffering')
```

### 添加/查询/删除/彻底删除镜像

```python
# Add Image
action = AddImageAction()
action.name = "Image-1"
action.url = "file:///opt/zstack-dvd/zstack-image-1.4.qcow2"
action.platform = "Linux"
action.format = "qcow2"
action.backupStorageUuids = [imageStorageId]
action.sessionId = sessionId
image = action.call().value.inventory
imageId = image.uuid
DEBUG('imageId = {}'.format(imageId))

# Query Image
action = QueryImageAction()
action.conditions = []
action.sessionId = sessionId
images = []
objs = action.call().value.inventories
for obj in objs:
    images.append(obj.uuid)
DEBUG(images)

# Delete Image
action = DeleteImageAction()
action.uuid = imageId
action.backupStorageUuids = imageStorageId
action.sessionId = sessionId
action.call()
DEBUG('Successfully delete image')

# Expunge Image
action = ExpungeImageAction()
action.imageUuid = imageId
action.backupStorageUuids = [imageStorageId]
action.sessionId = sessionId
action.call()
DEBUG('Successfully expunge image')
```

### 添加/加载/查询/卸载/删除二级网络

```python
# Add L2NoVlanNetwork
action = CreateL2NoVlanNetworkAction()
action.name = "L2Public-1"
action.zoneUuid = zoneId
action.physicalInterface = "eth0"
action.sessionId = sessionId
l2Network = action.call().value.inventory
l2NetworkId = l2Network.uuid
DEBUG('l2NetworkId = {}'.format(l2NetworkId))

# Attach L2Network to Cluster
action = AttachL2NetworkToClusterAction()
action.l2NetworkUuid = l2NetworkId
action.clusterUuid = clusterId
action.sessionId = sessionId
attachInfo = action.call().value.inventory
attachInfoId = attachInfo.uuid
DEBUG('attachInfoId = {}'.format(attachInfoId))

# Query L2Network
action = QueryL2NetworkAction()
action.conditions = []
action.sessionId = sessionId
l2Networks = []
objs = action.call().value.inventories
for obj in objs:
    l2Networks.append(obj.uuid)
DEBUG(l2Networks)

# Detach L2Network from Cluster
action = DetachL2NetworkFromClusterAction()
action.l2NetworkUuid = l2NetworkId
action.clusterUuid = clusterId
action.sessionId = sessionId
action.call()
DEBUG('Successfuly detach l2Network from cluster')

# Delete L2Network
action = DeleteL2NetworkAction()
action.uuid = l2NetworkId
action.sessionId = sessionId
action.call()
DEBUG('Successfully delete l2Network')
```

#### 添加/查询二级 VLAN 网络

```python
# Add L2VlanNetwork
action = CreateL2VlanNetworkAction()
action.vlan = 1000
action.name = 'L2Private-1'
action.zoneUuid = zoneId
action.physicalInterface = 'eth0'
action.sessionId = sessionId
l2Network = action.call().value.inventory
l2NetworkId = l2Network.uuid
DEBUG('l2NetworkId = {}'.format(l2NetworkId))

# Query L2VlanNetwork
action = QueryL2VlanNetworkAction()
action.conditions = []
action.sessionId = sessionId
l2VlanNetworks = []
objs = action.call().value.inventories
for obj in objs:
    l2VlanNetworks.append(obj.uuid)
DEBUG(l2VlanNetworks)
```

### 添加/查询/删除三级网络

```python
# Create L3Network
action = CreateL3NetworkAction()
action.name = "L3Public-1"
action.type = "L3BasicNetwork"
action.l2NetworkUuid = l2NetworkId
action.category = "Public"
action.sessionId = sessionId
l3Network = action.call().value.inventory
l3NetworkId = l3Network.uuid
DEBUG('l3NetworkId = {}'.format(l3NetworkId))

# Query L3Network
action = QueryL3NetworkAction()
action.conditions = []
action.sessionId = sessionId
l3Networks = []
objs = action.call().value.inventories
for obj in objs:
    l3Networks.append(obj.uuid)
DEBUG(l3Networks)

# Delete L3Network
action = DeleteL3NetworkAction()
action.uuid = l3NetworkId
action.sessionId = sessionId
action.call()
DEBUG('Successfully delete l3Network')
```

### 添加/查询/删除网络段

```python
# Add IP Range to L3Network
action = AddIpRangeAction()
action.l3NetworkUuid = l3NetworkId
action.name = "IpRange-1"
action.startIp = "192.168.1.2"
action.endIp = "192.168.1.254"
action.netmask = "255.255.255.0"
action.gateway = "192.168.1.1"
action.ipRangeType = "Normal"
action.sessionId = sessionId
ipRange = action.call().value.inventory
ipRangeId = ipRange.uuid
DEBUG('ipRangeId = {}'.format(ipRangeId))

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

# Query IP Range
action = QueryIpRangeAction()
action.conditions = []
action.sessionId = sessionId
ipRanges = []
objs = action.call().value.inventories
for obj in objs:
    ipRanges.append(obj.uuid)
DEBUG(ipRanges)

# Delete IP Range
action = DeleteIpRangeAction()
action.uuid = ipRangeId
action.sessionId = sessionId
action.call()
DEBUG('Successfully delete ipRange')
```

### 添加/删除 DNS

```python
# Add DNS to L3Network
action = AddDnsToL3NetworkAction()
action.l3NetworkUuid = l3NetworkId
action.dns = "8.8.8.8"
action.sessionId = sessionId
dns = action.call().value.inventory
dnsId = dns.uuid
DEBUG('dnsId = {}'.format(dnsId))

# Remove DNS from L3Network
action = RemoveDnsFromL3NetworkAction()
action.l3NetworkUuid = l3NetworkId
action.dns = '8.8.8.8'
action.sessionId = sessionId
action.call()
```

### 创建/查询云路由规格

```python
# Create Router Standard
action = CreateVirtualRouterOfferingAction()
action.zoneUuid = zoneId
action.managementNetworkUuid = l3NetworkId
action.publicNetworkUuid = l3NetworkId
action.imageUuid = imageId
action.name = "RouterStandard-1"
action.cpuNum = 1
action.memorySize = 1073741824 # 1G
action.type = "VirtualRouter"
action.sessionId = sessionId
routerStandard = action.call().value.inventory
routerStandardId = routerStandard.uuid
DEBUG('routerStandardId = {}'.format(routerStandardId))

# Query Router Standard
action = QueryVirtualRouterOfferingAction()
action.conditions = []
action.sessionId = sessionId
routerStandards = []
objs = action.call().value.inventories
for obj in objs:
    routerStandards.append(obj.uuid)
DEBUG(routerStandards)
```

### 创建/查询/删除/彻底删除云主机

```python
# Create VM Instance
action = CreateVmInstanceAction()
action.name = "VM-1"
action.instanceOfferingUuid = instanceOfferingId
action.imageUuid = imageId
action.l3NetworkUuids = [l3NetworkId]
action.defaultL3NetworkUuid = l3NetworkId
action.dataDiskOfferingUuids = []
action.sessionId = sessionId
vm = action.call().value.inventory
vmId = vm.uuid
DEBUG('vmId = {}'.format(vmId))

# Query VM Instance
action = QueryVmInstanceAction()
action.conditions = []
action.sessionId = sessionId
vms = []
objs = action.call().value.inventories
for obj in objs:
    vms.append(obj.uuid)
DEBUG(vms)

# Destroy VM Instance
action = DestroyVmInstanceAction()
action.uuid = vmId
action.sessionId = sessionId
action.call()
DEBUG('Successfully delete vm')

# Expunge VM Instance
action = ExpungeVmInstanceAction()
action.uuid = vmId
action.sessionId = sessionId
action.call()
DEBUG('Successfully expunge vm')
```

### 获取 VNC 接口

```python
# Request VM Console
action = GetVmConsoleAddressAction()
action.uuid = vmId
action.sessionId = sessionId
consoleInfo = action.call().value
consoleUrl = "vnc://{}:{}".format(consoleInfo.hostIp, consoleInfo.port)
DEBUG('Successfully open console: {}'.format(consoleUrl))
```

### Example

完整的创建过程示例：

```python
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
action.zoneUuid = "f21e0124d19b4cef8c395814e69cb126"
action.hypervisorType = "KVM"
action.sessionId = sessionId
cluster = action.call().value.inventory
clusterId = cluster.uuid
DEBUG('clusterId = {}'.format(clusterId))

# Add KVM Host
# Name of network-interface should be same as the Host's
action = AddKVMHostAction()
action.name = "Host-1"
action.managementIp = "192.168.1.101"
action.username = "root"
action.password = "password"
action.clusterUuid = "3395ed25b4834c938d07ba1465403715"
action.sessionId = sessionId
host = action.call().value.inventory
hostId = host.uuid
DEBUG('hostId = {}'.format(hostId))

# Add Image Storage
action = AddSftpBackupStorageAction()
action.hostname = "192.168.1.101"
action.username = "root"
action.password = "password"
action.url = "/zstack_bs"
action.name = "BS-1"
action.zoneUuid = "f21e0124d19b4cef8c395814e69cb126"
action.sessionId = sessionId
imageStorage = action.call().value.inventory
imageStorageId = imageStorage.uuid
DEBUG('imageStorageId = {}'.format(imageStorageId))
# Attach Image Storage to Zone
action = AttachBackupStorageToZoneAction()
action.zoneUuid = "f21e0124d19b4cef8c395814e69cb126"
action.backupStorageUuid = imageStorageId
action.sessionId = sessionId
attachInfo = action.call().value.inventory
attachInfoId = attachInfo.uuid
DEBUG('attachInfoId = {}'.format(attachInfoId))

# Add Local Primary Storage
action = AddLocalPrimaryStorageAction()
action.name = "PS-1"
action.url = "/zstack_ps"
action.zoneUuid = "f21e0124d19b4cef8c395814e69cb126"
action.sessionId = sessionId
localStorage = action.call().value.inventory
localStorageId = localStorage.uuid
DEBUG('localStorageId = {}'.format(localStorageId))
# Attach Local Primary Storage to Cluster
action = AttachPrimaryStorageToClusterAction()
action.clusterUuid = "3395ed25b4834c938d07ba1465403715"
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
action.backupStorageUuids = ["470bb4c65f9b4f8e905ae0cd3d27a96d"]
action.platform = "Linux"
action.sessionId = sessionId
image = action.call().value.inventory
imageId = image.uuid
DEBUG('imageId = {}'.format(imageId))

# Add L2PublicNetwork
action = CreateL2NoVlanNetworkAction()
action.name = "L2Public-1"
action.zoneUuid = "f21e0124d19b4cef8c395814e69cb126"
action.physicalInterface = "em2"
action.sessionId = sessionId
l2Network = action.call().value.inventory
l2NetworkId = l2Network.uuid
DEBUG('l2NetworkId = {}'.format(l2NetworkId))
# Attach L2PublicNetwork to Cluster
action = AttachL2NetworkToClusterAction()
action.l2NetworkUuid = l2NetworkId
action.clusterUuid = "3395ed25b4834c938d07ba1465403715"
action.sessionId = sessionId
attachInfo = action.call().value.inventory
attachInfoId = attachInfo.uuid
DEBUG('attachInfoId = {}'.format(attachInfoId))

# Add L2PrivateNetwork
action = CreateL2VlanNetworkAction()
action.vlan = 1000
action.name = 'L2Private-1'
action.zoneUuid = "f21e0124d19b4cef8c395814e69cb126"
action.physicalInterface = 'em2'
action.sessionId = sessionId
l2Network = action.call().value.inventory
l2NetworkId = l2Network.uuid
DEBUG('l2NetworkId = {}'.format(l2NetworkId))
# Attach L2PrivateNetwork to Cluster
action = AttachL2NetworkToClusterAction()
action.l2NetworkUuid = l2NetworkId
action.clusterUuid = "3395ed25b4834c938d07ba1465403715"
action.sessionId = sessionId
attachInfo = action.call().value.inventory
attachInfoId = attachInfo.uuid
DEBUG('attachInfoId = {}'.format(attachInfoId))

# Create L3PublicNetwork
action = CreateL3NetworkAction()
action.name = "L3Public-1"
action.type = "L3BasicNetwork"
action.l2NetworkUuid = "892453b9c4804a488338b433ec2767a0"
action.category = "Public"
action.sessionId = sessionId
l3Network = action.call().value.inventory
l3NetworkId = l3Network.uuid
DEBUG('l3NetworkId = {}'.format(l3NetworkId))
# Add IP Range to L3PublicNetwork
action = AddIpRangeAction()
action.l3NetworkUuid = l3NetworkId
action.name = "IpRange-1"
action.startIp = "192.168.1.151"
action.endIp = "192.168.1.160"
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
action.backupStorageUuids = ["470bb4c65f9b4f8e905ae0cd3d27a96d"]
action.sessionId = sessionId
image = action.call().value.inventory
imageId = image.uuid
DEBUG('imageId = {}'.format(imageId))

# Create Router Standard
action = CreateVirtualRouterOfferingAction()
action.name = "RouterStandard-1"
action.cpuNum = 8
action.memorySize = 8589934592 # 8G
action.zoneUuid = "f21e0124d19b4cef8c395814e69cb126"
action.imageUuid = "5e888b42748847faa6e003c576146884"
action.managementNetworkUuid = "c68c0110ac794c8d97ef9cd59b35c4af"
action.publicNetworkUuid = "c68c0110ac794c8d97ef9cd59b35c4af"
action.type = "VirtualRouter"
action.sessionId = sessionId
routerStandard = action.call().value.inventory
routerStandardId = routerStandard.uuid
DEBUG('routerStandardId = {}'.format(routerStandardId))

# Create L3PrivateNetwork
action = CreateL3NetworkAction()
action.name = "L3Private-1"
action.type = "L3BasicNetwork"
action.l2NetworkUuid = "6c46253c7c2d4fe29b689b31616c4182"
action.category = "Private"
action.systemTags = ["virtualRouterOffering::43818866c4794f5e9ddb32a3d0fa2942"]
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
vrouterNetworkServiceProvider = "101baee663544e3f9a40fe0636cd694f"
securityGroupNetworkServiceProvider = "6a5648ac17c648ae90ed5459fb62e5fc"
flatNetworkServiceProvider = "cff293f15c81443f8b54138471a2f1f4"
action = AttachNetworkServiceToL3NetworkAction()
action.l3NetworkUuid = l3NetworkId
# admin >>>QueryNetworkServiceProvider
# "networkServices": {
#     "101baee663544e3f9a40fe0636cd694f": ["IPsec", "VRouterRoute", "CentralizedDNS", "VipQos", "SNAT", "LoadBalancer", "PortForwarding", "Eip", "DNS"],
#     "6a5648ac17c648ae90ed5459fb62e5fc": ["SecurityGroup"],
#     "cff293f15c81443f8b54138471a2f1f4": ["Userdata", "DHCP"]
# }
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
action.instanceOfferingUuid = "778c1d7222ed4034a97b57d9f62be4a2"
action.imageUuid = "30dd091ef9af431c95d46d4f560c82d9"
action.l3NetworkUuids = ["efaa3fc85bf446e5b83b0d035a272b78"]
action.defaultL3NetworkUuid = "efaa3fc85bf446e5b83b0d035a272b78"
action.dataDiskOfferingUuids = []
action.sessionId = sessionId
vm = action.call().value.inventory
vmId = vm.uuid
DEBUG('vmId = {}'.format(vmId))

# Request VM Console
action = GetVmConsoleAddressAction()
action.uuid = "e4c4b3ff442d4a479c41073390fcf872"
action.sessionId = sessionId
consoleInfo = action.call().value
consoleUrl = "vnc://{}:{}".format(consoleInfo.hostIp, consoleInfo.port)
DEBUG('Successfully open console: {}'.format(consoleUrl))

# LogOut
action = LogOutAction()
action.sessionUuid = sessionId
action.call()
DEBUG('Successfully delete session')
```

# References

[ZStack RESTful API cookbook](https://www.zybuluo.com/meilei007/note/675498)<br>
[zstackio/api-cookbook](https://github.com/zstackio/api-cookbook)<br>
[API 使用规范 - 开发手册 - ZStack](https://www.zstack.io/help/dev_manual/dev_guide/)

_2020.12.29 by B3ale_
