#!/bin/sh
yum update -y
yum upgrade -y
rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
cat > /etc/yum.repos.d/elasticsearch.repo << EOF
[elasticsearch-6.x]
name=Elasticsearch repository for 6.x packages
baseurl=https://artifacts.elastic.co/packages/6.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF
curl -Lo jre-8-linux-x64.rpm --header "Cookie: oraclelicense=accept-securebackup-cookie" "https://download.oracle.com/otn-pub/java/jdk/8u202-b08/1961070e4c9b4e26a04e7f5a083f551e/jre-8u202-linux-x64.rpm"
curl -Lo jdk-8-linux-x64.rpm --header "Cookie: oraclelicense=accept-securebackup-cookie" "https://download.oracle.com/otn-pub/java/jdk/8u202-b08/1961070e4c9b4e26a04e7f5a083f551e/jdk-8u202-linux-x64.rpm"
rpm -qlp jre-8-linux-x64.rpm > /dev/null 2>&1 && echo "Java package downloaded successfully" || echo "Java package did not download successfully"
yum -y install jre-8-linux-x64.rpm
rm -f jre-8-linux-x64.rpm
rpm -qlp jdk-8-linux-x64.rpm > /dev/null 2>&1 && echo "Java package downloaded successfully" || echo "Java package did not download successfully"
yum -y install jdk-8-linux-x64.rpm
rm -f jdk-8-linux-x64.rpm
yum update -y
yum -y install elasticsearch logstash
systemctl daemon-reload
systemctl enable elasticsearch.service
chmod g+w /etc/elasticsearch
usermod -a -G ossec logstash
systemctl daemon-reload
systemctl enable logstash.service
wget https://artifacts.elastic.co/downloads/kibana/kibana-oss-6.6.0-x86_64.rpm
rpm -iv kibana-oss-6.6.0-x86_64.rpm
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
ES_STARTUP_SLEEP_TIME=5
MAX_OPEN_FILES=9965536" >> /etc/sysconfig/elasticsearch
rm -rf /usr/share/kibana/optimize/bundles
echo 'server.port: 5601
server.host: "0.0.0.0
server.name: "ELK01
elasticsearch.url: "http://localhost:9200"
elasticsearch.preserveHost: true
kibana.index: ".kibana"
kibana.defaultAppId: "discover"' >> /etc/kibana/kibana.yml
systemctl start elasticsearch.service
systemctl start logstash.service
systemctl daemon-reload
systemctl enable kibana.service
systemctl start kibana.service
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/elasticsearch.repo
