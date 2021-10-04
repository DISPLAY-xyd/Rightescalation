特权升级所使用的技术
我们假设现在我们在远程系统上有外壳。根据我们渗透进去的方式，我们
可能没有“ root”特权。以下提到的技术可用于获取系统上的“ root”访问权
限。

- 内核漏洞
- 以root身份运行的程序
- 已安装的软件
- 弱密码/重用密码/纯文本密码
- 内部服务
- Suid配置错误
- 滥用sudo权利
- 由root调用的可写脚本
- 路径配置错误
- Cronjobs
- 卸载的文件系统



### 信息收集

（Linux）特权提升的TIps：

- 信息信息，更多的信息收集，信息收集是整个渗透测试过程的
- 整理信息，分析收集的信息和整理信息。
- 搜索漏洞- 知道要搜索什么以及在哪里可以找到漏洞利用代码。
- 修改代码- 修改漏洞利用程序，使其适合目前的渗透。并非每种漏洞都能
- 为“现成”的每个系统工作。漏洞看环境
- 尝试攻击- 为（很多）尝试和错误做好准备。

### 操作系统

什么是发行类型？什么版本的？

```bash
cat /etc/issue
cat /etc/*-release
cat /etc/lsb-release # Debian based
cat /etc/redhat-release # Redhat based
```

什么是内核版本？是64位吗？

```bash
cat /proc/version
uname -a uname -mrs
rpm -q kernel
dmesg | grep Linux
ls /boot | grep vmlinuz-
```

环境变量中可能存在密码或API密钥

```bash
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout
env set

```

### 路径（Path)

如果您对该变量内的任何文件夹都具有写权限，则可以劫持某些库或二进制
文件：PATH

```batch
echo $ PATH
```

### 应用与服务

哪些服务正在运行？哪个服务具有哪个用户特权？

```bash
ps aux
ps -ef top
cat /etc/services
```

### root正在运行哪些服务

```bash
ps aux | grep root ps -ef | grep root
```

### 查看安装的应用程序及版本

```bash
ls -alh /usr/bin/
ls -alh /sbin/
dpkg -l
rpm -qa
ls -alh /var/cache/apt/archivesO
ls -alh /var/cache/yum/
```

## 服务设置是否配置错误？是否附有（脆弱的）插件？

```bash
cat /etc/syslog.conf
cat /etc/chttp.conf
cat /etc/lighttpd.conf
cat /etc/cups/cupsd.conf
cat /etc/inetd.conf
cat /etc/apache2/apache2.conf
cat /etc/my.conf
cat /etc/httpd/conf/httpd.conf
cat /opt/lampp/etc/httpd.conf
ls -aRl /etc/ | awk '$1 ~ /^.*r.*/
```

### 计划任务

```bash
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
```

### 是否有纯文本用户名和/或密码

```bash
grep -i user [filename]
grep -i pass [filename]
grep -C 5 "password" [filename]
find . -name "*.php" -print0 | xargs -0 grep -i -n "var $password"
```

### 通讯与网络

系统具有哪些NIC？它是否连接到另一个网络？

```bash
/sbin/ifconfig -a
cat /etc/network/interfaces
cat /etc/sysconfig/network
```

网络信息

```bash
cat /etc/resolv.conf
cat /etc/sysconfig/network
cat /etc/networks
iptables -L
hostname
dnsdomainname
```

其他哪些用户和主机正在与系统通信？

```bash
# Linux
netstat -anlp
netstat -ano

lsof -i
lsof -i :80 grep 80 /etc/services
netstat -antup
netstat -antpx
netstat -tulpn
chkconfig --list chkconfig --list | grep 3:on
last
w

```

IP缓存

```bash
arp -e
route
/sbin/route -nee
```

端口转发

FPipe.exe -l [本地端口] -r [远程端口] -s [本地端口] [本地IP]

FPipe.exe -l 80 -r 80 -s 80 192.168.1.7

注意：ssh-[L / R] [本地端口]：[远程IP]：[远程端口] [本地用户] @ [本地IP]

```bash
ssh -L 8080:127.0.0.1:80 root@192.168.1.7 # Local Port
ssh -R 8080:127.0.0.1:80 root@192.168.1.7 # Remote Port
```

### 机密信息和用户

last
cat /etc/passwd | cut -d: -f1 # List of users
grep -v -E "^#" /etc/passwd |
awk -F: '$3 == 0 { print $1}' # List of super users awk -F: '($3 == "0") {pri
cat /etc/sudoers
sudo -l

敏感文件

cat /etc/passwd
cat /etc/group
cat /etc/shadow
