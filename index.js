'use strict';

const jwt = require('jsonwebtoken');
const { AuthenticationError, RequestError } = require('flora-errors');

/**
 * @param {flora.Api} api - Api instance
 * @param {object} options - Plugin options
 * @param {string} options.secret - JWT secret
 * @param {boolean} [options.credentialsRequired] - Fail on requests without JWT (default: false)
 */
module.exports = (api, options) => {
    if (typeof options !== 'object') throw new Error('options must be an object');
    if (!options.secret) throw new Error('options must contain a "secret" property');

    options.credentialsRequired = !!options.credentialsRequired;

    api.on('request', async ev => {
        const request = ev.request;

        // decode and verify JSON Web Token
        async function decode(token) {
            if (!token) {
                if (typeof options.validate !== 'function') {
                    request._auth = null;
                    return null;
                }

                const validated = await options.validate(null, request);
                request._auth = validated || null;
                return null;
            }

            return new Promise((resolve, reject) => {
                api.log.trace('Verifying JWT: ' + token);

                jwt.verify(token, options.secret, (err, decoded) => {
                    if (err && err.message === 'jwt expired') {
                        api.log.trace(err);
                        const e = new AuthenticationError('Expired token received for JSON Web Token validation');
                        e.code = 'ERR_TOKEN_EXPIRED';
                        return reject(e);
                    }

                    if (err) {
                        api.log.trace(err);
                        const e = new AuthenticationError('Invalid signature received for JSON Web Token validation');
                        e.code = 'ERR_INVALID_TOKEN_SIGNATURE';
                        return reject(e);
                    }

                    api.log.trace('Verified authentication token: ', decoded);

                    if (typeof options.validate !== 'function') {
                        request._auth = decoded;
                        return resolve();
                    }

                    return resolve(
                        options.validate(decoded, request).then(validated => {
                            if (!request._auth) request._auth = validated || decoded;
                        })
                    );
                });
            });
        }

        // already authenticated
        if (request._auth) return null;

        // request parameter "access_token" (POST, GET or native)
        if (request.access_token) {
            api.log.trace('Using access_token in request parameters: ' + request.access_token);
            return decode(request.access_token);
        }

        // HTTP "Authorization" header
        if (request._httpRequest && request._httpRequest.headers.authorization) {
            const parts = request._httpRequest.headers.authorization.split(' ');
            if (parts.length !== 2) throw new RequestError('Bad HTTP authentication header format');
            if (parts[0].toLowerCase() !== 'bearer') return null;
            if (parts[1].split('.').length !== 3) {
                throw new RequestError('Bad HTTP authentication header format');
            }

            api.log.trace('Using token from HTTP Authorization header: ' + parts[1]);
            return decode(parts[1]);
        }

        return decode(null);
    });

    if (options.credentialsRequired) return;

    api.on('request', ev => {
        if (ev.request._auth || !options.credentialsRequired) return;
        const e = new AuthenticationError('No authorization token was found');
        e.code = 'ERR_MISSING_TOKEN';
        throw e;
    });
};
