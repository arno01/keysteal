# keysteal
Red team tool for decrypting Elastic keystores

Currently supports:

- [ ] Elasticsearch
- [x] Kibana
- [ ] Logstash
- [ ] Filebeat

## Docker Test Environment

You can use the provided `Dockerfile` and `docker-compose.yml` files to drop into a Debian 10 container with Elasticsearch, Kibana, Logstash, and Filebeat already installed. The current directory is mounted at `/keysteal`.

```
$ docker compose build
[...]
$ docker compose run --rm elk
root@66185ee5b017:/#
```