# JWT Middleware API Validator - Keycloak Introspect

JWT Middleware API Validator is a middleware plugin for [Traefik](https://github.com/containous/traefik) which verifies a jwt token and adds the payload as injected header to the request


Meaning that if the authorization code is in the request, it will get checked, and if it does, the request will go through.
The way the request is checked is by sending a GET request to a specific endpoint that you can override with `ValidateAPIUrl`. 
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

Activate plugin in your config  

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
          clientID: 
          clientSecret:
          validateAPIUrl: http://yourKeycloakDomainAPI/realms/realm-name/protocol/openid-connect/token/introspect
```

Use as docker-compose label  
```yaml
  labels:
        - "traefik.http.routers.my-service.middlewares=my-jwt-middleware@file"
```
