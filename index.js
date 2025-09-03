'use strict';

const jwt = require('jsonwebtoken');
const { AuthenticationError, RequestError } = require('@florajs/errors');

/**
 * @param {string} token
 * @param {string | jwt.GetPublicKeyOrSecret} secretOrPublicKey
 * @param {jwt.VerifyOptions} options
 * @returns {jwt.JwtPayload}
 */
function verify(token, secretOrPublicKey, options) {
    return new Promise((resolve, reject) => {
        jwt.verify(token, secretOrPublicKey, options, (err, decoded) => {
            if (err) return reject(err);
            return resolve(decoded);
        });
    });
}

/**
 * @param {import('flora').Api} api - Api instance
 * @param {{ secret: string | jwt.GetPublicKeyOrSecret; algorithms?: string[]; credentialsRequired?: boolean; validate?: (decoded: any, request: import('flora').Request) => Promise<any> }} options
 */
module.exports = (api, options) => {
    if (typeof options !== 'object') throw new Error('options must be an object');
    if (!options.secret) throw new Error('options must contain a "secret" property');

    options.credentialsRequired = !!options.credentialsRequired;

    api.on('request', async ({ request }) => {
        /**
         * @param {string} token
         */
        async function decode(token) {
            let decoded = null;
            if (token) {
                api.log.trace('Verifying JWT: ' + token);

                /** @type {{ algorithms?: string[] }} */
                const verifyOptions = {};
                if (options.algorithms) verifyOptions.algorithms = options.algorithms;

                try {
                    decoded = await verify(token, options.secret, verifyOptions);
                } catch (err) {
                    api.log.trace(err);

                    if (err.message === 'jwt expired') {
                        const e = new AuthenticationError('Expired token received for JSON Web Token validation');
                        e.code = 'ERR_TOKEN_EXPIRED';
                        throw e;
                    }

                    if (err.message === 'invalid algorithm') {
                        const e = new AuthenticationError(
                            'Invalid token algorithm received for JSON Web Token validation'
                        );
                        e.code = 'ERR_INVALID_ALGORITHM';
                        throw e;
                    }

                    const e = new AuthenticationError('Invalid signature received for JSON Web Token validation');
                    e.code = 'ERR_INVALID_TOKEN_SIGNATURE';
                    throw e;
                }

                api.log.trace('Verified authentication token: ', decoded);
            }

            const validated =
                typeof options.validate === 'function' ? await options.validate(decoded, request) : decoded;

            if (!request._auth) request._auth = validated;

            if (options.credentialsRequired && !request._auth) {
                const e = new AuthenticationError('No authorization token was found');
                e.code = 'ERR_MISSING_TOKEN';
                throw e;
            }
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
            if (parts[0].toLowerCase() !== 'bearer') return decode(null);
            if (parts[1].split('.').length !== 3) {
                throw new RequestError('Bad HTTP authentication header format');
            }

            api.log.trace('Using token from HTTP Authorization header: ' + parts[1]);
            return decode(parts[1]);
        }

        return decode(null);
    });
};
