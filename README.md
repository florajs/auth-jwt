# flora-auth-jwt

[![Build Status](https://travis-ci.org/godmodelabs/flora-auth-jwt.svg?branch=master)](https://travis-ci.org/godmodelabs/flora-auth-jwt)
[![NPM version](https://badge.fury.io/js/flora-auth-jwt.svg)](https://www.npmjs.com/package/flora-auth-jwt)
[![Dependencies](https://img.shields.io/david/godmodelabs/flora-auth-jwt.svg)](https://david-dm.org/godmodelabs/flora-auth-jwt)

JSON Web Token authentication for Flora.

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
