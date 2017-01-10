flora-auth-jwt
==============

JSON Web Token authentication for Flora.

Example
-------

```js
const flora = require('flora');
const floraAuth = require('flora-auth-jwt');

const server = new flora.Server('./config.js');

server.register({
    secret: 'My Secret Key',
    credentialsRequired: false, // default: true
    validate: (jwt, request, cb) => {
        // callback value will go to request._auth
        return cb(null, { userId: jwt.sub });
    }
});
server.run();
```
