#!/bin/sh
mount -o remount,nodev,nosuid,noexec /tmp
mount --bind /tmp /var/tmp
mount -o remount,nodev /home
mount -o remount,nodev,nosuid,noexec /dev/shm
echo "install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true" >> /etc/modprobe.d/CIS.conf
yum -y install firewalld
systemctl enable firewalld
gpg --quiet --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
sed -i 's/gpgcheck=0/gpgcheck=1/g' /etc/yum.conf
yum -y check-update
yum -y update
yum -y install aide
yum -y install prelink
/usr/sbin/aide --init -B 'database_out=file:/var/lib/aide/aide.db.gz'
echo "PRELINKING=no" >> /etc/sysconfig/prelink

echo "0 5 * * * /usr/sbin/aide --check" >> /var/spool/cron/root

ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }'
chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg
sed -i '/End/ i * hard core 0' /etc/security/limits.conf
sed -i '$ a fs.suid_dumpable = 0' /etc/sysctl.conf
sed -i '$ a kernel.randomize_va_space = 2' /etc/sysctl.conf

[[ -w /etc/issue ]] && rm /etc/issue
[[ -w /etc/issue.net ]] && rm /etc/issue.net
touch /etc/issue /etc/issue.net
chown root:root /etc/issue /etc/issue.net
chmod 644 /etc/issue /etc/issue.net

touch /etc/ntp.conf
echo "driftfile /var/lib/ntp/drift
restrict default nomodify notrap nopeer noquery
restrict 127.0.0.1
restrict ::1
server ntp.[YOUR_DOMAIN]
includefile /etc/ntp/crypto/pw
keys /etc/ntp/keys
disable monitor
restrict default kod nomodify notrap nopeer noquery
restrict -6 default kod nomodify notrap nopeer noquery" > /etc/ntp.conf
#sed -i '/^server/ c server time.nist.gov' /etc/ntp.conf
#echo "restrict default kod nomodify notrap nopeer noquery
#restrict -6 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
touch /etc/sysconfig/ntpd
echo 'OPTIONS="-u ntp:ntp"' > /etc/sysconfig/ntpd
#sed -i '/^OPTIONS/ c OPTIONS="-u ntp:ntp"' /etc/sysconfig/ntpd
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
yum -y install tcp_wrappers
echo "ALL: 172.20.16.45/32" >> /etc/hosts.allow
/bin/chmod 644 /etc/hosts.allow
echo "ALL: ALL" >> /etc/hosts.deny
chown root:root /etc/hosts.deny
/bin/chmod 644 /etc/hosts.deny
yum -y install rsyslog
systemctl enable rsyslog
sed -i '/RULES/a auth,user.* /var/log/messages\nkern.* /var/log/kern.log\ndaemon.* /var/log/daemon.log\nsyslog.* /var/log/syslog\nlpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.logi' /etc/rsyslog.conf
#sed -i 's/#$ModLoad imtcp/$ModLoad imtcp.so/g' /etc/rsyslog.conf
#sed -i 's/#$InputTCPServerRun 514/$InputTCPServerRun 514/g' /etc/rsyslog.conf
sed -i '/^max_log_file/ c max_log_file = 1024' /etc/audit/auditd.conf
sed -i '/^space_left_action/ c space_left_action = email' /etc/audit/auditd.conf
sed -i '/^action_mail_act/ c action_mail_acct = root' /etc/audit/auditd.conf
sed -i '/^admin_space_left_action/ c admin_space_left_action = halt' /etc/audit/auditd.conf
sed -i '$ a max_log_file_action = keep_logs' /etc/audit/auditd.conf

systemctl enable auditd

touch /var/log/daemon.log
chown root:root /var/log/daemon.log
chmod g-wx,o-rwx /var/log/daemon.log

touch /var/log/kern.log
chown root:root /var/log/kern.log
chmod g-wx,o-rwx /var/log/kern.log
touch /var/log/syslog
chown root:root /var/log/syslog
chmod g-wx,o-rwx /var/log/syslog
touch /var/log/unused.log
chown root:root /var/log/unused.log
chmod g-wx,o-rwx /var/log/unused.log
sed -i '$ i *.* @@[YOUR_LOG_SERVER]:[PORT]' /etc/rsyslog.conf

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
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
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
-w /var/log/sudo.log -p wa -k actions
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k modules
-e 2" >> /etc/audit/rules.d/audit.rules

find / -xdev -perm -4000 -o -perm -2000 -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }' >> /etc/audit/rules.d/audit.rules

sed -i '1 a /var/log/boot.log' /etc/logrotate.d/syslog

chown root:root /etc/anacrontab	/etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d
chmod 600 /etc/anacrontab /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d

[[ -w /etc/at.deny ]] && rm /etc/at.deny
[[ -w /etc/cron.deny ]] && rm /etc/cron.deny
touch /etc/at.allow /etc/cron.allow
chown root:root /etc/at.allow /etc/cron.allow
chmod 600 /etc/at.allow /etc/cron.allow

#yum install cronie-anacron
#systemctl enable crond
#chown root:root /etc/anacrontab
#chmod og-rwx /etc/anacrontab
#chown root:root /etc/crontab
#chmod og-rwx /etc/tab

#chown root:root /etc/cron.hourly
#chmod og-rwx /etc/cron.hourly

#chown root:root /etc/cron.daily
#chmod og-rwx /etc/cron.daily

#chown root:root /etc/cron.weekly
#chmod og-rwx /etc/cron.weekly

#chown root:root /etc/cron.monthly
#chmod og-rwx /etc/cron.monthly

#chown root:root /etc/cron.d
#chmod og-rwx /etc/cron.d

#rm /etc/at.deny
#touch /etc/at.allow
#chown root:root /etc/at.allow
#chmod og-rwx /etc/at.allow

#touch /etc/cron.allow

#/bin/rm /etc/cron.deny
#/bin/rm /etc/at.deny
#chmod og-rwx /etc/cron.allow
#chmod og-rwx /etc/at.allow
#chown root:root /etc/cron.allow
#chown root:root /etc/at.allow

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
ClientAliveInterval 300
ClientAliveCountMax 0
AllowUsers [USERNAME]
AllowGroups wheel
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
chmod 600 /etc/ssh/sshd_config

echo "minlen=14
dcredit=-1
ucredit=-1
ocredit=-1
lcredit=-1" >> /etc/security/pwquality.conf

echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
echo "******************************************
* This is an [COMPANY] system, restricted *
* to authorized individuals. This system *
* is subject to monitoring. By logging   *
* into this system you agree to have all *
* your communications monitored.         *
* Unauthorized users, access, and/or     *
* modification will be prosecuted.       *
******************************************" > /etc/motd


cat << EOF >> /etc/fstab
/tmp      /var/tmp    none    bind    0 0
none	/dev/shm	tmpfs	nosuid,nodev,noexec	0 0
EOF

echo umask 027 >> /etc/sysconfig/init

ntp_conf='/etc/ntp.conf'
sed -i "s/^restrict default/restrict default kod/" ${ntp_conf}
line_num="$(grep -n "^restrict default" ${ntp_conf} | cut -f1 -d:)"
sed -i "${line_num} a restrict -6 default kod nomodify notrap nopeer noquery" ${ntp_conf}
sed -i s/'^OPTIONS="-g"'/'OPTIONS="-g -u ntp:ntp -p \/var\/run\/ntpd.pid"'/ /etc/sysconfig/ntpd


#!/bin/sh -e
cat << EOF2 >> /etc/grub.d/01_users
cat << EOF
set superusers="[BOOTUSER]"password_pbkdf2 [BOOTUSER] [BOOTUSER_PASSWORD]
EOF
EOF2

sed -i s/'^GRUB_CMDLINE_LINUX="'/'GRUB_CMDLINE_LINUX="audit=1 '/ /etc/default/grub
grub_cfg='/boot/grub2/grub.cfg'
grub2-mkconfig -o ${grub_cfg}

#cd /usr/lib/systemd/system
#rm default.target
#ln -s multi-user.target default.target

#chown root:root /etc/rsyslog.conf
#chmod 600 /etc/rsyslog.conf

login_defs=/etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/' ${login_defs}
sed -i 's/^PASS_MIN_DAYS.*$/PASS_MIN_DAYS 7/' ${login_defs}
sed -i 's/^PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' ${login_defs}

root_gid="$(id -g root)"
if [[ "${root_gid}" -ne 0 ]] ; then 
  usermod -g 0 root
fi

bashrc='/etc/bashrc'
line_num=$(grep -n "^[[:space:]]*umask" ${bashrc} | head -1 | cut -d: -f1)
sed -i ${line_num}s/002/077/ ${bashrc}
cat << EOF >> /etc/profile.d/cis.sh
#!/bin/bash
umask 077
EOF

chown root:root ${grub_cfg}
chmod 600 ${grub_cfg}
chmod 644 /etc/passwd
chmod 000 /etc/shadow
chmod 000 /etc/gshadow
chmod 644 /etc/group
chown root:root /etc/passwd
chown root:root /etc/shadow
chown root:root /etc/gshadow
chown root:root /etc/group

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

sed -i '/^password *sufficient/ s/pam_unix.so/pam_unix.so remember=5/' /etc/pam.d/system-auth

cp /etc/securetty /etc/securetty.orig
#> /etc/securetty   
echo console > /etc/securetty

pam_su='/etc/pam.d/su'
line_num="$(grep -n "^\#auth[[:space:]]*required[[:space:]]*pam_wheel.so[[:space:]]*use_uid" ${pam_su} | cut -d: -f1)"
sed -i "${line_num} a auth		required	pam_wheel.so use_uid" ${pam_su}
usermod -G wheel root

yum remove -y wpa_supplicant

sed -i '/^\/dev\/mapper\/centos-home/ s/defaults/defaults,nodev/' /etc/fstab
sed -i '/^\/dev\/mapper\/centos-tmp/ s/defaults/defaults,nodev,nosuid,noexec/' /etc/fstab

#useradd -D -f 35

# if [ $UID -gt 199 ] && [ "`id -gn`" = "`id -un`" ]; then
#       umask 077
#    else
#       umask 022
#    fi
echo "
HISTFILESIZE=1000000
HISTSIZE=1000000
HISTTIMEFORMAT='%F %T '
PROMPT_COMMAND='history -a'" >> /root/.bashrc
semanage port -a -t syslogd_port_t -p tcp [LOG_PORT]
yum -y install policycoreutils-python
semamage port -a -t ssh_port_t -p tcp [SSH_PORT]
