# Credstore

**This is not an official Google product**

Credstore is a centralized server providing authentication-by-proxy model. Users
or services can trade auth tokens for per-service per-rpc tokens.

## Sample config

```yaml
scopes:
- name: vmregistry-all
  service: api.VMRegistry
  method: '*'
- name: keyserver-all
  service: api.KeyServer
  method: '*'

clients:
- vmregistry
- metaserver
- keyserver
- microdhcpd

authorizations:
- {client: metaserver, scope: vmregistry-all, via: vmregistry.global.example.com}
- {client: metaserver, scope: keyserver-all,  via: keyserver.global.example.com}
- {client: microdhcpd, scope: vmregistry-all, via: vmregistry.global.example.com}
```
