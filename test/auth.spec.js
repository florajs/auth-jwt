/* global describe, it, beforeEach */

'use strict';

const PromiseEventEmitter = require('promise-events');
const log = require('abstract-logging');
const jwt = require('jsonwebtoken');
const { expect } = require('chai');
const { AuthenticationError } = require('flora-errors');

const floraAuthJwt = require('../');

class ApiMock extends PromiseEventEmitter {
    constructor() {
        super();
        this.log = log;
    }
}

describe('flora-auth-jwt', () => {
    let api;
    const secret = 'mySecret';

    beforeEach(() => {
        api = new ApiMock();
    });

    it('should be a function', () => {
        expect(floraAuthJwt).to.be.a('function');
    });

    it('should require options', () => {
        expect(() => floraAuthJwt(api)).to.throw(Error, 'options must be an object');
    });

    it('should require options.secret', () => {
        expect(() => floraAuthJwt(api, {})).to.throw(Error, 'options must contain a "secret" property');
    });

    it('do nothing if request._auth is already set', () => {
        const request = {
            _auth: 'AUTH',
        };
        floraAuthJwt(api, { secret: 'mySecret' });
        api.emit('request', { request });
        expect(request._auth).to.equal('AUTH');
    });

    it('do nothing if request.access_token is not set', () => {
        const request = {};
        floraAuthJwt(api, { secret: 'mySecret' });
        api.emit('request', { request });
        expect(request._auth).to.not.exist;
    });

    it('decodes JWT', async () => {
        const request = {
            access_token: jwt.sign(
                {
                    foo: 'bar',
                },
                secret,
                {
                    noTimestamp: true,
                    algorithm: 'HS256',
                }
            ),
        };
        floraAuthJwt(api, { secret });
        await api.emit('request', { request });
        expect(request._auth).to.eql({ foo: 'bar' });
    });

    it('throws if JWT has expired', (done) => {
        const request = {
            access_token: jwt.sign(
                {
                    foo: 'bar',
                },
                secret,
                {
                    noTimestamp: true,
                    algorithm: 'HS256',
                    expiresIn: -1,
                }
            ),
        };
        floraAuthJwt(api, { secret });
        api.emit('request', { request })
            .then(() => {
                done(new Error('Error should have been thrown'));
            })
            .catch((err) => {
                expect(err).to.be.instanceOf(AuthenticationError);
                expect(err.code).to.eql('ERR_TOKEN_EXPIRED');
                done();
            });
    });

    it('throws if access_token is not a JWT', (done) => {
        const request = {
            access_token: 'xyzzy',
        };
        floraAuthJwt(api, { secret: 'foo' });
        api.emit('request', { request })
            .then(() => {
                done(new Error('Error should have been thrown'));
            })
            .catch((err) => {
                expect(err).to.be.instanceOf(AuthenticationError);
                expect(err.code).to.eql('ERR_INVALID_TOKEN_SIGNATURE');
                done();
            });
    });

    it('throws if secret is wrong', (done) => {
        const request = {
            access_token: jwt.sign(
                {
                    foo: 'bar',
                },
                secret,
                {
                    noTimestamp: true,
                    algorithm: 'HS256',
                }
            ),
        };
        floraAuthJwt(api, { secret: 'foo' });
        api.emit('request', { request })
            .then(() => {
                done(new Error('Error should have been thrown'));
            })
            .catch((err) => {
                expect(err).to.be.instanceOf(AuthenticationError);
                expect(err.code).to.eql('ERR_INVALID_TOKEN_SIGNATURE');
                done();
            });
    });

    it('throws if wrong algorithm is used', (done) => {
        const request = {
            access_token: jwt.sign(
                {
                    foo: 'bar',
                },
                secret,
                {
                    noTimestamp: true,
                    algorithm: 'HS384',
                }
            ),
        };
        floraAuthJwt(api, { secret, algorithms: ['HS256'] });
        api.emit('request', { request })
            .then(() => {
                done(new Error('Error should have been thrown'));
            })
            .catch((err) => {
                expect(err).to.be.instanceOf(AuthenticationError);
                expect(err.code).to.eql('ERR_INVALID_ALGORITHM');
                done();
            });
    });

    it('throws if algorithm "none" is used', (done) => {
        const request = {
            access_token: jwt.sign(
                {
                    foo: 'bar',
                },
                secret,
                {
                    noTimestamp: true,
                    algorithm: 'none',
                }
            ),
        };
        floraAuthJwt(api, { secret });
        api.emit('request', { request })
            .then(() => {
                done(new Error('Error should have been thrown'));
            })
            .catch((err) => {
                expect(err).to.be.instanceOf(AuthenticationError);
                expect(err.code).to.eql('ERR_INVALID_TOKEN_SIGNATURE');
                done();
            });
    });

    it('throws if access_token is not set and credentialsRequired is true', (done) => {
        const request = {};
        floraAuthJwt(api, { secret, credentialsRequired: true });
        api.emit('request', { request })
            .then(() => {
                done(new Error('Error should have been thrown'));
            })
            .catch((err) => {
                expect(err).to.be.instanceOf(AuthenticationError);
                expect(err.code).to.eql('ERR_MISSING_TOKEN');
                done();
            });
    });
});
