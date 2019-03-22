#!/bin/sh
# This script install OpenDistro for Elasticsearch tested in a CentOS clean installation.
curl https://d3g5vo6xdbdb9a.cloudfront.net/yum/opendistroforelasticsearch-artifacts.repo -o /etc/yum.repos.d/opendistroforelasticsearch-artifacts.repo
yum update
yum install -y java-1.8.0-openjdk-devel unzip elasticsearch-oss-6.5.4 opendistroforelasticsearch opendistroforelasticsearch-kibana
ln -s /usr/lib/jvm/java-1.8.0/lib/tools.jar /usr/share/elasticsearch/lib/
systemctl daemon-reload
usermod -a -G ossec logstash
systemctl enable elasticsearch.service
systemctl enable kibana.service
systemctl enable logstash.service
service elasticsearch start
service kibana start
mkdir $HOME/perf-top
curl https://d3g5vo6xdbdb9a.cloudfront.net/downloads/perftop/perf-top-0.7.0.0-LINUX.zip -o $HOME/perf-top-0.7.0.0-LINUX.zip
unzip $HOME/perf-top-0.7.0.0-LINUX.zip
$HOME/perf-top-linux --dashboard $HOME/dashboards/ClusterOverview.json
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/opendistroforelasticsearch-artifacts.repo
# Check cluster health
curl -XGET 'https://localhost:9200/_cluster/health?pretty=true' --insecure -u admin:admin
# Verify listening ports
netstat -tapn | grep LISTEN
