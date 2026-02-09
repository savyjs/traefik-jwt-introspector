# JWT Middleware API Validator - Keycloak Introspect

JWT Middleware API Validator is a middleware plugin for [Traefik](https://github.com/containous/traefik) which verifies a jwt token and adds the payload as injected header to the request


Meaning that if the authorization code is in the request, it will get checked, and if it does, the request will go through.
The way the request is checked is by sending a POST request to a realm introspection endpoint configured per realm (`validateAPIUrl` or `baseAuthUrl` + `realmName`).
If it returns a { active: true , ... } response, it will go through.

If you want to check that a request is authenticated you'll need to verify that there is a `Authorization` header in your request.
You can also check the header that is injected `ProxyHeaderName`  which is `injectedPayload` by default.

We delete it from the incoming requests, just in case.

This plugin is heavily inspired by : https://github.com/23deg/jwt-middleware 



## Configuration

Start with command
```yaml
command:
  - "--experimental.plugins.traefik-jwt-optional-api-validator.modulename=github.com/savyjs/traefik-jwt-optional-api-validator"
  - "--experimental.plugins.traefik-jwt-optional-api-validator.version=v0.0.14"
```

Activate plugin in your config (origin-based realms)

```yaml
http:
  middlewares:
    my-jwt-middleware:
      plugin:
        traefik-jwt-optional-api-validator:
          proxyHeaderName: injectedPayload
          authHeader: Authorization
          headerPrefix: Bearer
          optional: true
          logLevel: debug
          baseAuthUrl: https://auth.my-domain.com
          defaultRealm: realm-1
          originRealmMap:
            domain-1.com: realm-1
            domain-2.com: realm-2
          realms:
            - realmName: realm-1
              clientId: gateway
              clientSecret: your-secret
            - realmName: realm-2
              clientId: gateway
              clientSecret: your-secret
```

The realm is selected using the `Origin` header host (without port) and the `originRealmMap` entry. If `Origin` is missing or not mapped, `defaultRealm` is used; when `defaultRealm` is not set, the first `realms` entry is used.
`logLevel` can be one of `none`, `all`, `error`, `info`, `debug` (default: `none`). Logs do not include tokens or secrets.

Use as docker-compose label  
```yaml
  labels:
        - "traefik.http.routers.my-service.middlewares=my-jwt-middleware@file"
```
