ifconfig
sockstat -4 -6
freebsd-update fetch
freebsd-update install
pkg update
pkg upgrade
sysrc ifconfig_em1="inet 192.168.30.1/24 up"
service netif restart
pkg install -y gsed bash bash-completion sudo isc-dhcp44-server-4.4.2_1 apache24-2.4.48 bind916-9.16.18 curl php74 mod_php74 php74-mbstring php74-pecl-mcrypt php74-zlib php74-curl php74-gd php74-json mariadb105-server-10.5.10 mariadb105-client-10.5.10 php74-mysqli pure-ftpd openssl
sysrc dhcpd_enable=YES
sysrc named_enable="YES"
sysrc apache24_enable="yes"
sysrc mysql_enable="yes"
sysrc mysql_args="--bind-address=127.0.0.1"
sysrc pureftpd_enable=yes
cat << EOF > /usr/local/etc/dhcpd.conf
authoritative;
log-facility local7;

subnet 192.168.30.0 netmask 255.255.255.0 {
  range 192.168.30.51 192.168.30.100;
  option routers 192.168.30.1;
  option domain-name-servers 8.8.8.8;
  option domain-name "ellanoteama.net";
  option broadcast-address 192.168.30.255;
  default-lease-time 600;
  max-lease-time 7200;
}
EOF
sed -i -e '/listen-on/ s/127.0.0.1;/127.0.0.1; 192.168.30.1;/g' /usr/local/etc/namedb/named.conf
gsed -i -e '/listen-on/a\ forwarders { 8.8.8.8; };' /usr/local/etc/namedb/named.conf
cat << EOF >> /usr/local/etc/namedb/named.conf
zone "ellanoteama.net" {
        type master;
        file "/usr/local/etc/namedb/master/db.ellanoteama.net";
};

zone "30.168.192.in-addr.arpa" {
        type master;
        file "/usr/local/etc/namedb/master/ellanoteama.net.rev";
};
EOF
cat << EOF > /usr/local/etc/namedb/master/db.ellanoteama.net
\$TTL    604800
@       IN      SOA     ns1.ellanoteama.net.       admin.ellanoteama.net. (
                        2018101901;     Serial
                        3H;             Refresh
                        15M;            Retry
                        2W;             Expiry
                        1D );           Minimum

; name servers - NS records
        IN      NS      ns1.ellanoteama.net.

; name servers - A records
ns1.ellanoteama.net.       IN      A       192.168.30.1

; other servers - A records
www.ellanoteama.net.       IN      A       192.168.30.1
ftp.ellanoteama.net.       IN      A       192.168.30.1
dns1.ellanoteama.net.       IN      A       192.168.30.1
mysql.ellanoteama.net.       IN      A       192.168.30.1
dxtr.ellanoteama.net.       IN      A       192.168.30.1
EOF
cat << EOF > /usr/local/etc/namedb/master/ellanoteama.net.rev
\$TTL 3h
@ SOA ellanoteama.net. ns1.ellanoteama.net. 42 1d 12h 1w 3h
        ; Serial, Refresh, Retry, Expire, Neg. cache TTL

        NS      localhost.

1   PTR     www.ellanoteama.net
1   PTR     ftp.ellanoteama.net
1   PTR     dns1.ellanoteama.net
EOF
cat << EOF > /etc/resolv.conf
nameserver 127.0.0.1
EOF
cat << EOF > /usr/local/etc/apache24/Includes/php.conf
<IfModule dir_module>
    DirectoryIndex index.php index.html
    <FilesMatch "\.php\$">
        SetHandler application/x-httpd-php
    </FilesMatch>
    <FilesMatch "\.phps\$">
        SetHandler application/x-httpd-php-source
    </FilesMatch>
</IfModule>
EOF
cp /usr/local/etc/pure-ftpd.conf.sample /usr/local/etc/pure-ftpd.conf
sed -i -e 's/^VerboseLog.*$/VerboseLog                   yes/g' /usr/local/etc/pure-ftpd.conf
sed -i -e 's/^# PureDB.*$/PureDB                       \/usr\/local\/etc\/pureftpd.pdb/g' /usr/local/etc/pure-ftpd.conf
sed -i -e 's/^# CreateHomeDir.*$/CreateHomeDir                yes/g' /usr/local/etc/pure-ftpd.conf
service isc-dhcpd start
service named start
service apache24 start
service mysql-server start
/usr/local/bin/mysql_secure_installation
service mysql-server restart
service pure-ftpd start
pw useradd vftp -s /sbin/nologin -w no -d /home/vftp -c "Virtual User Pure-FTPd" -m
pure-pw useradd dxtr -u vftp -g vftp -d /home/vftp/dxtr
pure-pw mkdb
service pure-ftpd restart
ifconfig
sockstat -4 -6
nslookup ftp.ellanoteama.net
nslookup www.ellanoteama.net
nslookup 192.168.30.1
curl http://www.ellanoteama.net
ftp ftp.ellanoteama.net
echo '<?php phpinfo();  ?>' | tee -a /usr/local/www/apache24/data/info.php
curl http://www.ellanoteama.net/info.php
echo "Done!"
