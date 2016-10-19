#!/bin/sh
#Change domain.com by your domain name
#Change SSH_PORT by your ssh port
#Change LOG_PORT by your log server listening port
#Change LOG_SERVER by your log server IP
#Change YOUR_ALLOWED_IP by your allowed ip
mount -o remount,nodev,nosuid,noexec /tmp
mount --bind /tmp /var/tmp
mount -o remount,nodev /home
mount -o remount,nodev,nosuid,noexec /dev/shm

sed -i '/^\/dev\/mapper\/centos-tmp/ s/defaults/defaults,nodev,nosuid,noexec/' /etc/fstab
#sed -i '/^\/dev\/mapper\/centos-var_tmp/ s/defaults/defaults,nodev,nosuid,noexec/' /etc/fstab
sed -i '/^\/dev\/mapper\/centos-home/ s/defaults/defaults,nodev/' /etc/fstab
sed -i '/^\/dev\/shm/ s/defaults/defaults,nodev,nosuid,noexec/' /etc/fstab
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
echo "install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install vfat /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
options ipv6 disable=1" >> /etc/modprobe.d/CIS.conf
systemctl disable autofs
yum -y check-update
yum -y update
yum -y upgrade
gpg --quiet --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
sed -i 's/gpgcheck=0/gpgcheck=1/g' /etc/yum.conf
yum -y install firewalld aide prelink libselinux ntp tcp_wrappers iptables rsyslog policycoreutils-python
systemctl enable firewalld
/usr/sbin/aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
echo "PRELINKING=no" >> /etc/sysconfig/prelink
echo "0 5 * * * /usr/sbin/aide --check" >> /var/spool/cron/root
chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg
#!/bin/sh -e
cat << EOF2 >> /etc/grub.d/01_users
cat << EOF
set superusers="bootuser"
password_pbkdf2 bootuser grub.pbkdf2.sha512.10000.FE4D934335A0A9CB1B8E748713D1BDE766BB4041DEB297DB11674A1270BFC9B934C054B1BFEE8839AF9AE7DAD1F70D34D919FB617F09606636AC0EBE680F48FF.E01B493CA2F06BB62E03164F97FC98D6DB6A61BA5603DB299F98B5A08DE519C48730ECBBA0EB86BCE0DCFB02AF4C6EE19D9DF17F214CAE502D2078B4B8C59AC7
EOF
EOF2
grub2-mkconfig > /boot/grub2/grub.cfg
sed -i '/^ExecStart=/ c ExecStart=-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"' /usr/lib/systemd/system/rescue.service
sed -i '/^ExecStart=/ c ExecStart=-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"' /usr/lib/systemd/system/emergency.service
sed -i '/End/ i * hard core 0' /etc/security/limits.conf
sed -i '$ a fs.suid_dumpable = 0' /etc/sysctl.conf
sed -i '$ a kernel.randomize_va_space = 2' /etc/sysctl.conf
prelink -ua
yum -y remove prelink troubleshoot mcstrans xorg-x11* ypbind rsh talk telnet openldap-clients wpa_supplicant
#vi /etc/default/grub GRUB_CMDLINE_LINUX_DEFAULT="quiet"
#SELINUX=enforcing
#SELINUXTYPE=targeted
ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }'
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
echo "******************************************
* This is an COMPANY system, restricted *
* to authorized individuals. This system *
* is subject to monitoring. By logging   *
* into this system you agree to have all *
* your communications monitored.         *
* Unauthorized users, access, and/or     *
* modification will be prosecuted.       *
******************************************" > /etc/motd
chown root:root /etc/motd /etc/issue /etc/issue.net
chmod 644 /etc/motd /etc/issue /etc/issue.net
chkconfig chargen-dgram off
chkconfig chargen-stream off
chkconfig daytime-dgram off
chkconfig daytime-stream off
chkconfig discard-dgram off
chkconfig discard-stream off
chkconfig echo-dgram off
chkconfig echo-stream off
chkconfig time-dgram off
chkconfig time-stream off
chkconfig tftp off
systemctl disable xinetd
touch /etc/ntp.conf
echo "driftfile /var/lib/ntp/drift
restrict default nomodify notrap nopeer noquery
restrict 127.0.0.1
restrict ::1
server ntp.domain.com
includefile /etc/ntp/crypto/pw
keys /etc/ntp/keys
disable monitor
restrict -4 default kod nomodify notrap nopeer noquery
restrict -6 default kod nomodify notrap nopeer noquery" > /etc/ntp.conf
touch /etc/sysconfig/ntpd
echo 'OPTIONS="-u ntp:ntp"' > /etc/sysconfig/ntpd
systemctl disable avahi-daemon
systemctl disable cups
systemctl disable dhcpd
systemctl disable slapd
systemctl disable nfs
systemctl disable rpcbind
systemctl disable named
systemctl disable vsftpd
systemctl disable httpd
systemctl disable dovecot
systemctl disable smb
systemctl disable squid
systemctl disable snmpd
systemctl disable ypserv
systemctl disable rsh.socket
systemctl disable rlogin.socket
systemctl disable rexec.socket
systemctl disable telnet.socket
systemctl disable tftp.socket
systemctl disable rsyncd
systemctl disable ntalk
echo "fs.suid_dumpable = 0
fs.file-max = 9512000
kernel.randomize_va_space = 2
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "ALL: YOUR_ALLOWED_IP/32" >> /etc/hosts.allow
echo "ALL: ALL" >> /etc/hosts.deny
chown root:root /etc/hosts.deny /etc/hosts.allow
/bin/chmod 644 /etc/hosts.deny /etc/hosts.allow
sed -i '/^max_log_file/ c max_log_file = 1024' /etc/audit/auditd.conf
sed -i '/^space_left_action/ c space_left_action = email' /etc/audit/auditd.conf
sed -i '/^action_mail_act/ c action_mail_acct = root' /etc/audit/auditd.conf
sed -i '/^admin_space_left_action/ c admin_space_left_action = halt' /etc/audit/auditd.conf
sed -i '$ a max_log_file_action = keep_logs' /etc/audit/auditd.conf
systemctl enable auditd
sed -i s/'^GRUB_CMDLINE_LINUX="'/'GRUB_CMDLINE_LINUX="audit=1 '/ /etc/default/grub
echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/selinux/ -p wa -k MAC-policy
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope
-w /var/log/sudo.log -p wa -k actions
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-e 2" >> /etc/audit/rules.d/audit.rules
systemctl enable rsyslog
sed -i '/RULES/a auth,user.* /var/log/messages\nkern.* /var/log/kern.log\ndaemon.* /var/log/daemon.log\nsyslog.* /var/log/syslog\nlpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.log' /etc/rsyslog.conf
sed -i 's/$FileCreateMode/$FileCreateMode 0640/g' /etc/rsyslog.conf
sed -i '$ i *.* @@LOG_SERVER:LOG_PORT' /etc/rsyslog.conf
find /var/log -type f -exec chmod g-wx,o-rwx {} +
systemctl enable crond
chown root:root /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d
chmod og-rwx /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d
[[ -w /etc/at.deny ]] && rm /etc/at.deny
[[ -w /etc/cron.deny ]] && rm /etc/cron.deny
touch /etc/at.allow /etc/cron.allow
chown root:root /etc/at.allow /etc/cron.allow
chmod og-rwx /etc/at.allow /etc/cron.allow
echo "Protocol 2
LogLevel INFO
X11Forwarding no
MaxAuthTries 4
IgnoreRhosts yes
HostbasedAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
PermitUserEnvironment no
Ciphers aes128-ctr,aes192-ctr,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com
ClientAliveInterval 300
ClientAliveCountMax 0
LoginGraceTime 60
AllowGroups wheel localadminusergroup
DenyUsers ALL
DenyGroups ALL
Banner /etc/issue.net
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
SyslogFacility AUTHPRIV
AuthorizedKeysFile      .ssh/authorized_keys
PasswordAuthentication yes
ChallengeResponseAuthentication no
GSSAPIAuthentication yes
GSSAPICleanupCredentials no
UsePAM yes
AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE
AcceptEnv XMODIFIERS
Subsystem       sftp    /usr/libexec/openssh/sftp-server" > /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config
echo "minlen=14
dcredit=-1
ucredit=-1
ocredit=-1
lcredit=-1" >> /etc/security/pwquality.conf
content="$(egrep -v "^#|^auth" /etc/pam.d/password-auth)"
echo -e "auth required pam_env.so
auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900
auth required pam_deny.so\n$content" > /etc/pam.d/password-auth
system_auth='/etc/pam.d/system-auth'
content="$(egrep -v "^#|^auth" ${system_auth})"
echo -e "auth required pam_env.so
auth sufficient pam_unix.so remember=5
auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900
auth required pam_deny.so\n$content" > ${system_auth}
#password requisite pam_pwquality.so try_first_pass retry=3
sed -i '/^password *sufficient/ s/pam_unix.so/pam_unix.so remember=5 sha512/' /etc/pam.d/system-auth
login_defs=/etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/' ${login_defs}
sed -i 's/^PASS_MIN_DAYS.*$/PASS_MIN_DAYS 7/' ${login_defs}
sed -i 's/^PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' ${login_defs}
useradd -D -f 30
root_gid="$(id -g root)"
if [[ "${root_gid}" -ne 0 ]] ; then 
  usermod -g 0 root
fi
cp /etc/securetty /etc/securetty.orig   
echo console > /etc/securetty
echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
chmod 644 /etc/passwd
chmod 600 /etc/passwd-
chmod 600 /etc/shadow-
chmod 000 /etc/shadow
chmod 000 /etc/gshadow
chmod 600 /etc/gshadow-
chmod 644 /etc/group
chmod 600 /etc/group-
chown root:root /etc/passwd
chown root:root /etc/passwd-
chown root:root /etc/shadow
chown root:root /etc/shadow-
chown root:root /etc/gshadow
chown root:root /etc/gshadow-
chown root:root /etc/group
chown root:root /etc/group-
bashrc='/etc/bashrc'
line_num=$(grep -n "^[[:space:]]*umask" ${bashrc} | head -1 | cut -d: -f1)
sed -i ${line_num}s/002/077/ ${bashrc}
cat << EOF >> /etc/profile.d/cis.sh
#!/bin/bash
umask 077
EOF
pam_su='/etc/pam.d/su'
line_num="$(grep -n "^\#auth[[:space:]]*required[[:space:]]*pam_wheel.so[[:space:]]*use_uid" ${pam_su} | cut -d: -f1)"
sed -i "${line_num} a auth		required	pam_wheel.so use_uid" ${pam_su}
echo "
HISTFILESIZE=1000000
HISTSIZE=1000000
HISTTIMEFORMAT='%F %T '
PROMPT_COMMAND='history -a'" >> /root/.bashrc
semanage port -a -t syslogd_port_t -p tcp LOG_PORT
semanage port -a -t ssh_port_t -p tcp SSH_PORT
