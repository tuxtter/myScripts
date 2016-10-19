#!/bin/sh
#Replace OPENOTP_SERVER_IP by your OpenOTP server IP.
#Change LinuxAdminGroup by your AD Group for Linux Administrators
#Change mydomain and MYDOMAIN by your domain name
#Change LocalAdminGroup by your Local Admin Group
#Change AdminDomainUser by a domain admin user
#Change SSH_PORT by your ssh port
yum -y install wget realmd sssd oddjob oddjob-mkhomedir adcli samba-common ntpdate ntp
mkdir /root/downloads
cd /root/downloads
wget wget http://www.rcdevs.com/repos/redhat/pam_openotp-1.0.12-0.x86_64.rpm
wget http://www.rcdevs.com/repos/redhat/rcdevs_libs-1.0.14-2.x86_64.rpm
rpm -i rcdevs_libs-1.0.14-2.x86_64.rpm
rpm -i pam_openotp-1.0.12-0.x86_64.rpm
sed -i '/^server_url/ c server_url "https://[OPENOTP_SERVER_IP]/openotp/"' /etc/openotp/openotp.conf
sed -i '/^client_id/ c client_id "PTELK01"' /etc/openotp/openotp.conf
sed -i '$ a password_mode = 1' /etc/openotp/openotp.conf
echo "#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth        required      pam_env.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth sufficient pam_openotp.so
auth        required      pam_deny.so

account     required      pam_unix.so
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     required      pam_permit.so

password    requisite     pam_cracklib.so try_first_pass retry=3
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so" > /etc/pam.d/sshd
echo "Protocol 2
Port SSH_PORT
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
AllowGroups wheel LinuxAdminGroup@mydomain.com LocalAdminGroup
DenyUsers ALL
DenyGroups ALL
Banner /etc/issue.net
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
SyslogFacility AUTHPRIV
AuthorizedKeysFile      .ssh/authorized_keys
PasswordAuthentication yes
ChallengeResponseAuthentication yes
GSSAPIAuthentication yes
GSSAPICleanupCredentials no
UsePAM yes
AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE
AcceptEnv XMODIFIERS
Subsystem       sftp    /usr/libexec/openssh/sftp-server" > /etc/ssh/sshd_config
systemctl enable ntpd.service
ntpdate ntp.mydomain.com
realm join --user=AdminDomainUser@mydomain.com MYDOMAIN.COM
realm permit -g LinuxAdminGroup@mydomain.com
realm permit AdminDomainUser@mydomain.com
authconfig --enablesssd --enablesssdauth --enablemkhomedir --update
echo "[domain/default]

autofs_provider = ldap
ldap_schema = rfc2307bis
krb5_realm = MYDOMAIN.COM
ldap_search_base = dc=mydomain,dc=com
id_provider = ldap
auth_provider = ldap
chpass_provider = ldap
ldap_uri = ldap://127.0.0.1/
ldap_id_use_start_tls = False
cache_credentials = True
ldap_tls_cacertdir = /etc/openldap/cacerts
[sssd]
default_domain_suffix = mydomain.com
domains = default, mydomain.com
config_file_version = 2
services = nss, pam, autofs

[domain/mydomain.com]
default_domain_suffix = mydomain.com
ad_domain = mydomain.com
krb5_realm = MYDOMAIN.COM
realmd_tags = manages-system joined-with-samba
cache_credentials = True
id_provider = ad
krb5_store_password_if_offline = True
default_shell = /bin/bash
ldap_id_mapping = True
use_fully_qualified_names = True
create_homedir = True
fallback_homedir = /home/%u@%d
access_provider = simple
simple_allow_groups = LinuxAdminGroup@mydomain.com
simple_allow_users = AdminDomainUser
[autofs]" > /etc/sssd/sssd.conf
chmod 600 /etc/sssd/sssd.conf
service ntpd restart
service sshd restart
service sssd restart
chkconfig sssd on
setsebool -P authlogin_yubikey 1
sed -i '$ a %LinuxAdminGroup@mydomain.com ALL=(ALL) ALL' /etc/sudoers
cd /home
mkhomedir_helper AdminDomainUser 0077 /etc/skel
yum -y install policycoreutils-python
semanage port -a -t ssh_port_t -p tcp SSH_PORT
firewall-cmd --permanent --zone=public --add-port=SSH_PORT/tcp
service firewalld restart
