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

# install Go tool chain
RUN wget -q https://golang.org/dl/go1.16.5.linux-amd64.tar.gz -O /tmp/go.tar.gz
RUN tar -C /usr/local -xzf /tmp/go.tar.gz
ENV PATH="${PATH}:/usr/local/go/bin"

CMD "/bin/bash"