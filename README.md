# JWT Middleware

JWT Middleware is a middleware plugin for [Traefik](https://github.com/containous/traefik) which verifies a jwt token and adds the payload as injected header to the request
This version of the fork allows one to specify that the authorization code is optional. 

Meaning that if the authorization code is in the request, it will get checked, and if it does, the request will go through.

Meaning that if you want to check that a request is authenticated you'll need to verify that there is a `Authorization` header in your request.

## Configuration

Start with command
```yaml
command:
  - "--experimental.plugins.jwt-middleware.modulename=github.com/sorasful/traefik-jwt-optional-nofork"
  - "--experimental.plugins.jwt-middleware.version=v0.0.3"
```

Activate plugin in your config  

```yaml
http:
  middlewares:
    my-jwt-middleware:
      plugin:
        jwt-middleware:
          secret: SECRET
          proxyHeaderName: injectedPayload
          authHeader: Authorization
          headerPrefix: Bearer
          optional: true
```

Use as docker-compose label  
```yaml
  labels:
        - "traefik.http.routers.my-service.middlewares=my-jwt-middleware@file"
```
