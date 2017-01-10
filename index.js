'use strict';

const jwt = require('jsonwebtoken');
const { AuthenticationError, RequestError } = require('flora-errors');

exports.name = 'auth-jwt';

exports.register = function register(api, options) {
    if (typeof options !== 'object') throw new Error('opts must be an object');
    if (!options.secret) throw new Error('opts must contain a "secret" property');

    options.credentialsRequired = !!options.credentialsRequired;

    api.on('request', (ev, next) => {
        const request = ev.request;

        // decode and verify JSON Web Token
        function decode(token, callback) {
            if (!token) {
                if (typeof options.validate !== 'function') {
                    request._auth = null;
                    callback();
                    return;
                }
                options.validate(null, request, (validationErr, validated) => {
                    if (validationErr) return callback(validationErr);
                    request._auth = validated || null;
                    return callback();
                });
                return;
            }

            api.log.trace('Verifying JWT: ' + token);

            jwt.verify(token, options.secret, (err, decoded) => {
                if (err && err.message === 'jwt expired') {
                    api.log.trace(err);
                    return callback(new AuthenticationError('Expired token received for JSON Web Token validation'));
                } else if (err) {
                    api.log.trace(err);
                    return callback(new AuthenticationError('Invalid signature received for JSON Web Token validation'));
                }

                api.log.trace('Verified authentication token: ', decoded);

                if (typeof options.validate !== 'function') {
                    request._auth = decoded;
                    return callback();
                }

                return options.validate(decoded, request, (validationErr, validated) => {
                    if (validationErr) return callback(validationErr);
                    if (!request._auth) request._auth = validated || decoded;
                    return callback();
                });
            });
        }

        // already authenticated
        if (request._auth) return next();

        // request parameter "access_token" (POST, GET or native)
        if (request.access_token) {
            api.log.trace('Using access_token in request parameters: ' + request.access_token);
            return decode(request.access_token, next);
        }

        // HTTP "Authorization" header
        if (request._httpRequest && request._httpRequest.headers.authorization) {
            const parts = request._httpRequest.headers.authorization.split(' ');
            if (parts.length !== 2) return next(new RequestError('Bad HTTP authentication header format'));
            if (parts[0].toLowerCase() !== 'bearer') return next();
            if (parts[1].split('.').length !== 3) {
                return next(new RequestError('Bad HTTP authentication header format'));
            }

            api.log.trace('Using token from HTTP Authorization header: ' + parts[1]);
            return decode(parts[1], next);
        }

        return decode(null, next);
    });

    if (options.credentialsRequired) return;

    api.on('request', (ev, next) => {
        if (ev.request._auth || !options.credentialsRequired) return next();
        return next(new AuthenticationError('No authorization token was found'));
    });
};
