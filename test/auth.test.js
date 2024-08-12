'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert');
const PromiseEventEmitter = require('promise-events');
const log = require('abstract-logging');
const jwt = require('jsonwebtoken');

const floraAuthJwt = require('../');

class ApiMock extends PromiseEventEmitter {
    constructor() {
        super();
        this.log = log;
    }
}

describe('auth-jwt', () => {
    let api;
    const secret = 'mySecret';

    beforeEach(() => {
        api = new ApiMock();
    });

    it('should be a function', () => {
        assert.equal(typeof floraAuthJwt, 'function');
    });

    it('should require options', () => {
        assert.throws(() => floraAuthJwt(api), { message: 'options must be an object' });
    });

    it('should require options.secret', () => {
        assert.throws(() => floraAuthJwt(api, {}), { message: 'options must contain a "secret" property' });
    });

    it('do nothing if request._auth is already set', () => {
        const request = { _auth: 'AUTH' };
        floraAuthJwt(api, { secret: 'mySecret' });
        api.emit('request', { request });
        assert.equal(request._auth, 'AUTH');
    });

    it('add _auth property, even if request.access_token is not set', async () => {
        const request = {};
        floraAuthJwt(api, { secret: 'mySecret' });
        await api.emit('request', { request });
        assert.strictEqual(request._auth, null);
    });

    it('decodes JWT', async () => {
        const request = {
            access_token: jwt.sign({ foo: 'bar' }, secret, {
                noTimestamp: true,
                algorithm: 'HS256'
            })
        };
        floraAuthJwt(api, { secret });
        await api.emit('request', { request });
        assert.deepEqual(request._auth, { foo: 'bar' });
    });

    it('decodes JWT in HTTP header', async () => {
        const token = jwt.sign({ foo: 'bar' }, secret, {
            noTimestamp: true,
            algorithm: 'HS256'
        });
        const request = { _httpRequest: { headers: { authorization: 'Bearer ' + token } } };
        floraAuthJwt(api, { secret });
        await api.emit('request', { request });
        assert.deepEqual(request._auth, { foo: 'bar' });
    });

    it('throws when HTTP header is malformed', async () => {
        const request = { _httpRequest: { headers: { authorization: 'Bearer invalid' } } };
        floraAuthJwt(api, { secret });
        assert.rejects(async () => await api.emit('request', { request }), { name: 'RequestError' });
    });

    it('do nothing HTTP header type is wrong', async () => {
        const request = { _httpRequest: { headers: { authorization: 'foo invalid.invalid.invalid' } } };
        floraAuthJwt(api, { secret });
        await api.emit('request', { request });
        assert.strictEqual(request._auth, null);
    });

    it('throws when token in HTTP header is invalid', () => {
        const request = {
            _httpRequest: { headers: { authorization: 'Bearer invalid.invalid.invalid' } }
        };
        floraAuthJwt(api, { secret });
        assert.rejects(() => api.emit('request', { request }), { name: 'AuthenticationError' });
    });

    it('decodes JWT when secret is a function', async () => {
        const request = {
            access_token: jwt.sign({ foo: 'bar' }, secret, {
                noTimestamp: true,
                algorithm: 'HS256'
            })
        };
        floraAuthJwt(api, { secret: (header, callback) => callback(null, secret) });
        await api.emit('request', { request });
        assert.deepEqual(request._auth, { foo: 'bar' });
    });

    it('throws if JWT has expired', async () => {
        const request = {
            access_token: jwt.sign({ foo: 'bar' }, secret, {
                noTimestamp: true,
                algorithm: 'HS256',
                expiresIn: -1
            })
        };
        floraAuthJwt(api, { secret });
        assert.rejects(
            async () => await api.emit('request', { request }),
            (err) => {
                assert.strictEqual(err.name, 'AuthenticationError');
                assert.strictEqual(err.code, 'ERR_TOKEN_EXPIRED');
                return true;
            }
        );
    });

    it('throws if access_token is not a JWT', async () => {
        const request = { access_token: 'xyzzy' };
        floraAuthJwt(api, { secret: 'foo' });
        assert.rejects(
            async () => await api.emit('request', { request }),
            (err) => {
                assert.strictEqual(err.name, 'AuthenticationError');
                assert.strictEqual(err.code, 'ERR_INVALID_TOKEN_SIGNATURE');
                return true;
            }
        );
    });

    it('throws if secret is wrong', async () => {
        const request = {
            access_token: jwt.sign({ foo: 'bar' }, secret, {
                noTimestamp: true,
                algorithm: 'HS256'
            })
        };
        floraAuthJwt(api, { secret: 'foo' });
        assert.rejects(
            async () => await api.emit('request', { request }),
            (err) => {
                assert.strictEqual(err.name, 'AuthenticationError');
                assert.strictEqual(err.code, 'ERR_INVALID_TOKEN_SIGNATURE');
                return true;
            }
        );
    });

    it('throws if wrong algorithm is used', async () => {
        const request = {
            access_token: jwt.sign({ foo: 'bar' }, secret, {
                noTimestamp: true,
                algorithm: 'HS384'
            })
        };
        floraAuthJwt(api, { secret, algorithms: ['HS256'] });
        assert.rejects(
            async () => await api.emit('request', { request }),
            (err) => {
                assert.strictEqual(err.name, 'AuthenticationError');
                assert.strictEqual(err.code, 'ERR_INVALID_ALGORITHM');
                return true;
            }
        );
    });

    it('throws if algorithm "none" is used', async () => {
        const request = {
            access_token: jwt.sign(
                {
                    foo: 'bar'
                },
                secret,
                {
                    noTimestamp: true,
                    algorithm: 'none'
                }
            )
        };
        floraAuthJwt(api, { secret });
        assert.rejects(
            async () => await api.emit('request', { request }),
            (err) => {
                assert.strictEqual(err.name, 'AuthenticationError');
                assert.strictEqual(err.code, 'ERR_INVALID_TOKEN_SIGNATURE');
                return true;
            }
        );
    });

    it('throws if access_token is not set and credentialsRequired is true', async () => {
        const request = {};
        floraAuthJwt(api, { secret, credentialsRequired: true });
        assert.rejects(
            async () => await api.emit('request', { request }),
            (err) => {
                assert.strictEqual(err.name, 'AuthenticationError');
                assert.strictEqual(err.code, 'ERR_MISSING_TOKEN');
                return true;
            }
        );
    });

    it('expect validate function to be called', async () => {
        const request = {};
        floraAuthJwt(api, {
            secret: 'mySecret',
            validate: async () => 'validate_executed'
        });
        await api.emit('request', { request });
        assert.equal(request._auth, 'validate_executed');
    });
});
