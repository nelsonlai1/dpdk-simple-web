## VMware 6.0 下安装的完整过程

1. 下载ISO文件

登录vmware vcenter， 选择一个物理机，“设置/安全配置文件/往下拉，服务/编辑"

SSH 启动

登录物理机，下载ISO文件

ssh root@x.x.x.x(x.x.x.x是vmware物理机的IP)，登录后，df可以查看目录

cd 到存储所在目录，下载http://mirrors.ustc.edu.cn/ubuntu-releases/artful/ubuntu-17.10.1-server-amd64.iso

我的做法是：

```
cd /vmfs/volumes/netapp/ISO
http://mirrors.ustc.edu.cn/ubuntu-releases/artful/ubuntu-17.10.1-server-amd64.iso
```

登录vmware center中，关闭 SSH服务

2. 新建虚拟机

vmware vcenter中，新建虚拟机

```
ESXi 6.0及更高版本

客户机操作系统：Linux
客户机操作系统版本：Ubuntu Linux(64位）

CPU 2
内存 2048M
硬盘 16GB
网络 新添加一个网卡，网卡类型用默认的VMXNET3

其他默认
```

3. 虚拟机开机, 安装系统

编辑设置，把ubuntu-17.10.1-server-amd64.iso连接到CDROM

安装系统

```
选择 Install Ubuntu Server
几乎都默认选择即可，有些地方需要确认一下
输入DNS服务器IP、一个普通用户帐号和密码
```

4. 基本配置

奇怪的是安装系统时没有让我输入IP地址，也没有让我选择安装sshd，也许是被我不小心跳过了。

启用后用普通帐号登录，执行`ip addr`，可以看到网卡名称分别是 ens160和ens192(ens160是机器上网的网卡，ens192是专用于DPDK处理的网卡)，都是没有IP地址的

ubuntu 17.10不再使用/etc/network/interfaces，而是使用netplan管理网卡配置

请参见 https://websiteforstudents.com/configuring-static-ips-ubuntu-17-10-servers/

```
sudo vi /etc/netplan/01-netcfg.yaml

# This file describes the network interfaces available on your system
# For more information, see netplan(5).
network:
  version: 2
  renderer: networkd
  ethernets:
    ens160:
      dhcp6: no
      addresses: [222.195.81.232/24]
      gateway4: 222.195.81.1
      nameservers:
              addresses: [ 202.38.64.1,202.38.64.17]


修改后执行 sudo netplan apply

此后网络就通了

然后执行

sudo apt-get update
sudo apt-get upgrade
sudo apt-get install openssh-server
sudo reboot

重新启动

后面就可以从其他机器ssh登录了

```

5. dpdk的安装


```
sudo bash

apt-get install gcc git make libnuma-dev

ln -s /usr/bin/python3 /usr/bin/python

cd /usr/src
wget https://fast.dpdk.org/rel/dpdk-18.02.tar.xz
xzcat dpdk-18.02.tar.xz | tar xvf -

cd dpdk-18.02
export RTE_SDK=$PWD
export RTE_TARGET=x86_64-native-linuxapp-gcc
make install T=${RTE_TARGET}

modprobe uio
insmod /usr/src/dpdk-18.02/x86_64-native-linuxapp-gcc/kmod/igb_uio.ko
mkdir /mnt/huge
mount -t hugetlbfs nodev /mnt/huge
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
/usr/src/dpdk-18.02/usertools/dpdk-devbind.py --bind igb_uio ens92

```

6. DPDK 测试程序的安装
```
cd /usr/src/
git clone https://github.com/bg6cq/dpdk-simple-web.git
cd dpdk-simple-web
source env_vars

make

测试程序运行  注意这里的IP是 222.195.81.231，是DPDK专用接口的IP地址，跟主机的地址完全无关，我这里正好是相连的

/usr/src/dpdk-simple-web/build/printreq -c1 -n1 -- 222.195.81.231


从其他机器访问  http://222.195.81.231 可以看到测试网页
