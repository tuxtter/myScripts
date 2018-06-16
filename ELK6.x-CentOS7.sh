#!/bin/sh
yum update -y
yum upgrade -y
wget --no-cookies --no-check-certificate --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F; oraclelicense=accept-securebackup-cookie" "http://download.oracle.com/otn-pub/java/jdk/8u172-b11/a58eab1ec242421181065cdc37240b08/jdk-8u172-linux-x64.rpm"
wget --no-cookies --no-check-certificate --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F; oraclelicense=accept-securebackup-cookie" "http://download.oracle.com/otn-pub/java/jdk/8u172-b11/a58eab1ec242421181065cdc37240b08/jre-8u172-linux-x64.rpm"
rpm -ivh jdk-8u172-linux-x64.rpm
rpm -ivh jre-8u172-linux-x64.rpm
rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
echo "[logstash-6.x]
name=Elastic repository for 6.x packages
baseurl=https://artifacts.elastic.co/packages/6.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md" > /etc/yum.repos.d/elasticsearch.repo
yum update -y
yum -y install elasticsearch kibana logstash
chkconfig --add kibana
chkconfig --add logstash
chkconfig --add elasticsearch
chkconfig logstash on
chkconfig elasticsearch on
chkconfig kibana on
/usr/share/logstash/bin/logstash-plugin install logstash-output-email
echo "cluster.name: elk01
node.name: elk01-nodo01
bootstrap.memory_lock: true
network.host: 127.0.0.1" >> /etc/elasticsearch/elasticsearch.yml
sed -i 's/-Xms1g/-Xms32g/g' /etc/elasticsearch/jvm.options
sed -i 's/-Xmx1g/-Xmx32g/g' /etc/elasticsearch/jvm.options
echo "ES_HOME=/usr/share/elasticsearch
CONF_DIR=/etc/elasticsearch
DATA_DIR=/var/lib/elasticsearch
LOG_DIR=/var/log/elasticsearch
PID_DIR=/var/run/elasticsearch
ES_USER=elasticsearch
ES_GROUP=elasticsearch
ES_STARTUP_SLEEP_TIME=5
MAX_OPEN_FILES=9965536" >> /etc/sysconfig/elasticsearch
echo 'server.port: 5601
server.host: "localhost"
server.name: "ELK06"
elasticsearch.url: "http://localhost:9200"
elasticsearch.preserveHost: true
kibana.index: ".kibana"
kibana.defaultAppId: "discover"' >> /etc/kibana/kibana.yml
service elasticsearch start
service logstash start
service kibana start
