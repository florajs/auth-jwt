# flora-auth-jwt

[![Build Status](https://travis-ci.org/godmodelabs/flora-auth-jwt.svg?branch=master)](https://travis-ci.org/godmodelabs/flora-auth-jwt)
[![NPM version](https://badge.fury.io/js/flora-auth-jwt.svg)](https://www.npmjs.com/package/flora-auth-jwt)
[![Dependencies](https://img.shields.io/david/godmodelabs/flora-auth-jwt.svg)](https://david-dm.org/godmodelabs/flora-auth-jwt)

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
    credentialsRequired: false, // default: true
    validate: async (jwt, request) => {
        // return value will go to request._auth
        return { userId: jwt.sub };
    }
});
server.run();
```

## License

[MIT](LICENSE)
