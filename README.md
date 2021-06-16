# keysteal
Red team tool for decrypting Elastic keystores

## Docker Test Environment

You can use the provided `Dockerfile` and `docker-compose.yml` files to drop into a Debian 10 container with Elasticsearch, Kibana, Logstash, and Filebeat already installed. The current directory is mounted at `/keysteal`.

```
$ docker compose build
[...]
$ docker compose run --rm elk
root@66185ee5b017:/#
```

## Links

https://www.elastic.co/guide/en/logstash/current/keystore.html
https://www.elastic.co/guide/en/beats/filebeat/current/keystore.html
https://www.elastic.co/guide/en/beats/filebeat/current/command-line-options.html#keystore-command
https://www.elastic.co/guide/en/elasticsearch/reference/current/secure-settings.html
https://www.elastic.co/guide/en/elasticsearch/reference/current/elasticsearch-keystore.html