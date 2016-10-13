#!/bin/sh
#Descargar todo en el home del usuario
cd $HOME
#Actualizar repositorio de paquetes
yum update
yum upgrade
#Instalar requerimientos
yum install -y wget httpd php gcc glibc glibc-common gd gd-devel make net-snmp unzip
#Instalar nagios
wget https://assets.nagios.com/downloads/nagioscore/releases/nagios-4.2.1.tar.gz#_ga=1.88476888.2126431863.1464631277
tar xvfz nagios-4.2.1.tar.gz
useradd nagios
groupadd nagcmd
usermod -a -G nagcmd nagios
cd nagios-4.2.1
./configure --with-command-group=nagcmd
make all
make install
make install-init
make install-config
make install-commandmode
make install-webconf
cp -R contrib/eventhandlers/ /usr/local/nagios/libexec/
chown -R nagios:nagios /usr/local/nagios/libexec/eventhandlers
#Instalar plugins
cd $HOME
wget https://nagios-plugins.org/download/nagios-plugins-2.1.2.tar.gz#_ga=1.53415403.2126431863.1464631277
tar xvfz nagios-plugins-2.1.2.tar.gz
cd nagios-plugins-2.1.2
./configure --with-nagios-user=nagios --with-nagios-group=nagios
make
make install
chkconfig --add nagios
chkconfig nagios on
service nagios start
#Crear password de administrador de nagios
htpasswd -c /usr/local/nagios/etc/htpasswd.users nagiosadmin
#Iniciamos el servidor web
sed -i '/^DocumentRoot/ c DocumentRoot "/usr/local/nagios/share"' /etc/httpd/conf/httpd.conf
chkconfig httpd on
service httpd start
