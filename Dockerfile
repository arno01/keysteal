FROM debian:10

# install dependencies
RUN apt-get update
RUN apt-get install -qq -y \
    wget \
    apt-transport-https \
    gnupg

# add the elastic package gpg key
RUN wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -

# add the repo
RUN echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-7.x.list

# install everything
RUN apt-get update
RUN apt-get install -qq -y \
    elasticsearch \
    kibana \
    logstash \
    filebeat

CMD "/bin/bash"