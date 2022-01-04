# flora-auth-jwt

![](https://github.com/florajs/auth-jwt/workflows/ci/badge.svg)
[![NPM version](https://img.shields.io/npm/v/flora-auth-jwt.svg?style=flat)](https://www.npmjs.com/package/flora-auth-jwt)
[![NPM downloads](https://img.shields.io/npm/dm/flora-auth-jwt.svg?style=flat)](https://www.npmjs.com/package/flora-auth-jwt)

JSON Web Token authentication for Flora.

## Usage

This plugin for the Flora API framework enables authentication with JSON Web Tokens.

Authenticated requests contain a JSON Web Token either

- in the `Authorization` header field (e.g. `Authorization: Bearer eyJhb...`), or
- in the `access_token` body parameter, or
- in the `access_token` query parameter.

Additionally, when calling `flora` internally (without HTTP), the `access_token` property of the `flora.Request` object is used.

### Optional authentication

If the `credentialsRequired` option is set to `true` (default), an `AuthenticationError` (`ERR_MISSING_TOKEN`) is thrown if no valid token is found. If set to `false` and no token is used, `request._auth` is set to `null` or whatever the `validate` function returns.

### Implementing authorization

By default, the contents of the JSON Web Token are saved to `request._auth`.

When further processing is needed, an async `validate` function can be specified, which may transform the JWT contents to something application specific.

## Example

```js
const flora = require('flora');
const floraAuthJwt = require('flora-auth-jwt');

const server = new flora.Server('./config.js');

server.register('auth-jwt', floraAuthJwt, {
    secret: 'My Secret Key',
    algorithms: ['HS256'], // optional
    credentialsRequired: false, // default: false
    validate: async (jwt, request) => {
        // return value will go to request._auth
        return { userId: jwt.sub };
    }
});
server.run();
```

## License

[MIT](LICENSE)
