var Code = require('code'),
	Hapi = require('hapi'),
	Lab = require('lab'),
	internals = {},
	lab = exports.lab = Lab.script(),
	describe = lab.describe,
	it = lab.it,
	expect = Code.expect;

describe('quest authentication with udid', function () {

	it('returns a reply on successful auth', function (done) {

	    var server = new Hapi.Server();
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
	        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

	        var request = { method: 'POST', url: '/', headers: { authorization: internals.facebookHeader('asd123ads123asd') } };

	        server.inject(request, function (res) {

	            expect(res.result).to.equal('ok');
	            done();
	        });
	    });
	});

	it('returns an error on wrong scheme', function (done) {

	    var server = new Hapi.Server();
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
	        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

	        var request = { method: 'POST', url: '/', headers: { authorization: 'Steve something' } };

	        server.inject(request, function (res) {

	            expect(res.statusCode).to.equal(401);
	            done();
	        });
	    });
	});

	it('returns a reply on successful double auth', function (done) {

	    var handler = function (request, reply) {

	        var options = { method: 'POST', url: '/inner', headers: { authorization: internals.facebookHeader('asd123ads123asd') }, credentials: request.auth.credentials };
	        server.inject(options, function (res) {

	            return reply(res.result);
	        });
	    };

	    var server = new Hapi.Server();
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
	        server.route({ method: 'POST', path: '/', handler: handler });
	        server.route({ method: 'POST', path: '/inner', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

	        var request = { method: 'POST', url: '/', headers: { authorization: internals.facebookHeader('asd123ads123asd') } };

	        server.inject(request, function (res) {

	            expect(res.result).to.equal('ok');
	            done();
	        });
	    });
	});

	it('returns a reply on failed optional auth', function (done) {

	    var server = new Hapi.Server();
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
	        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: { mode: 'optional' } } });

	        var request = { method: 'POST', url: '/' };

	        server.inject(request, function (res) {

	            expect(res.result).to.equal('ok');
	            done();
	        });
	    });
	});

	it('returns an error on guid', function (done) {

	    var server = new Hapi.Server();
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
	        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

	        var request = { method: 'POST', url: '/', headers: { authorization: internals.facebookHeader('098765432') } };

	        server.inject(request, function (res) {

	            expect(res.statusCode).to.equal(401);
	            done();
	        });
	    });
	});

	it('returns an error on bad header format', function (done) {

	    var server = new Hapi.Server();
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
	        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

	        var request = { method: 'POST', url: '/', headers: { authorization: 'basic' } };

	        server.inject(request, function (res) {

	            expect(res.result).to.exist();
	            expect(res.statusCode).to.equal(400);
	            expect(res.result.isMissing).to.equal(undefined);
	            done();
	        });
	    });
	});

	it('returns an error on bad header format', function (done) {

	    var server = new Hapi.Server();
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
	        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

	        var request = { method: 'POST', url: '/', headers: { authorization: 'guest' } };

	        server.inject(request, function (res) {

	            expect(res.result).to.exist();
	            expect(res.statusCode).to.equal(400);
	            expect(res.result.isMissing).to.equal(undefined);
	            done();
	        });
	    });
	});

	it('returns an error on bad header internal syntax', function (done) {

	    var server = new Hapi.Server();
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
	        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

	        var request = { method: 'POST', url: '/', headers: { authorization: 'Token 123123123' } };

	        server.inject(request, function (res) {

	            expect(res.result).to.exist();
	            expect(res.statusCode).to.equal(400);
	            expect(res.result.isMissing).to.equal(undefined);
	            done();
	        });
	    });
	});

	it('returns an error on bad header (missing provider) internal syntax', function (done) {

		var server = new Hapi.Server();
		server.connection();
		server.register(require('../'), function (err) {

			expect(err).to.not.exist();
			server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
			server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

			
			var request = { method: 'POST', url: '/', headers: { 
				authorization: 'Token ' + (new Buffer(':1234567890', 'utf8')).toString('base64')
			}};

			server.inject(request, function (res) {

				expect(res.result).to.exist();
				expect(res.statusCode).to.equal(400);
				expect(res.result.isMissing).to.equal(undefined);
				done();
			});
		});
	});
	
	it('returns an error on bad header (missing token) internal syntax', function (done) {

		var server = new Hapi.Server();
		server.connection();
		server.register(require('../'), function (err) {

			expect(err).to.not.exist();
			server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
			server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });


			var request = { method: 'POST', url: '/', headers: {
				authorization: 'Token ' + (new Buffer('token:', 'utf8')).toString('base64')
			}};

			server.inject(request, function (res) {

				expect(res.result).to.exist();
				expect(res.statusCode).to.equal(400);
				expect(res.result.isMissing).to.equal(undefined);
				done();
			});
		});
	});
	
	it('returns an error on internal token lookup error', function (done) {

	    var server = new Hapi.Server({ debug: false });
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
	        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

	        var request = { method: 'POST', url: '/', headers: { authorization: internals.facebookHeader('aaa000bbb000ccc') } };

	        server.inject(request, function (res) {

	            expect(res.result).to.exist();
	            expect(res.statusCode).to.equal(500);
	            done();
	        });
	    });
	});

	it('returns an error on non-object credentials error', function (done) {

	    var server = new Hapi.Server({ debug: false });
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
	        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

	        var request = { method: 'POST', url: '/', headers: { authorization: internals.facebookHeader('invalid1') } };

	        server.inject(request, function (res) {

	            expect(res.result).to.exist();
	            expect(res.statusCode).to.equal(500);
	            done();
	        });
	    });
	});

	it('returns an error on missing credentials error', function (done) {

	    var server = new Hapi.Server({ debug: false });
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
	        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

		    var request = { method: 'POST', url: '/', headers: { authorization: internals.facebookHeader('invalid1') } };

	        server.inject(request, function (res) {

	            expect(res.result).to.exist();
	            expect(res.statusCode).to.equal(500);
	            done();
	        });
	    });
	});

	it('returns an error on insufficient scope', function (done) {

	    var server = new Hapi.Server();
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
	        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: { scope: 'x' } } });

		    var request = { method: 'POST', url: '/', headers: { authorization: internals.facebookHeader('asd123ads123asd') } };

	        server.inject(request, function (res) {

	            expect(res.result).to.exist();
	            expect(res.statusCode).to.equal(403);
	            done();
	        });
	    });
	});

	it('returns an error on insufficient scope specified as an array', function (done) {

	    var server = new Hapi.Server();
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
	        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: { scope: ['x', 'y'] } } });

		    var request = { method: 'POST', url: '/', headers: { authorization: internals.facebookHeader('asd123ads123asd') } };

	        server.inject(request, function (res) {

	            expect(res.result).to.exist();
	            expect(res.statusCode).to.equal(403);
	            done();
	        });
	    });
	});

	it('authenticates scope specified as an array', function (done) {

	    var server = new Hapi.Server();
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
	        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: { scope: ['x', 'y', 'a'] } } });

		    var request = { method: 'POST', url: '/', headers: { authorization: internals.facebookHeader('asd123ads123asd') } };

	        server.inject(request, function (res) {

	            expect(res.result).to.exist();
	            expect(res.statusCode).to.equal(200);
	            done();
	        });
	    });
	});

	it('should ask for credentials if server has one default strategy', function (done) {

	    var server = new Hapi.Server();
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();

	        server.auth.strategy('default', 'mix-auth', { validateFunc: internals.user });
	        server.route({
	            path: '/',
	            method: 'GET',
	            config: {
	                auth: 'default',
	                handler: function (request, reply) {

	                    return reply('ok');
	                }
	            }
	        });

		    var validOptions = { method: 'GET', url: '/', headers: { authorization: internals.facebookHeader('asd123ads123asd') } };
	        server.inject(validOptions, function (res) {

	            expect(res.result).to.exist();
	            expect(res.statusCode).to.equal(200);

	            server.inject('/', function (res) {

	                expect(res.result).to.exist();
	                expect(res.statusCode).to.equal(401);
	                done();
	            });
	        });
	    });
	});


	it('cannot add a route that has payload validation required', function (done) {

	    var server = new Hapi.Server();
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });

	        var fn = function () {

	            server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: { mode: 'required', payload: 'required' } } });
	        };

	        expect(fn).to.throw('Payload validation can only be required when all strategies support it in path: /');
	        done();
	    });
	});

	it('cannot add a route that has payload validation as optional', function (done) {

	    var server = new Hapi.Server();
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });

	        var fn = function () {

	            server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: { mode: 'required', payload: 'optional' } } });
	        };

	        expect(fn).to.throw('Payload authentication requires at least one strategy with payload support in path: /');
	        done();
	    });
	});

	it('can add a route that has payload validation as none', function (done) {

	    var server = new Hapi.Server();
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });

	        var fn = function () {

	            server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: { mode: 'required', payload: false } } });
	        };

	        expect(fn).to.not.throw();
	        done();
	    });
	});
});


internals.facebookHeader = function (token) {
    return 'Token ' + (new Buffer('facebook:' + token, 'utf8')).toString('base64');
};


internals.user = function (method, authData, callback) {
    if (authData.provider === 'facebook') {

	    if (authData.token === 'asd123ads123asd') {
		    return callback(null, true, {
			    user: 'john',
			    scope: ['a'],
			    tos: '1.0.0'
		    });
	    } else if (authData.token === 'aaa000bbb000ccc') {
		    return callback(Hapi.error.internal('boom'));
	    } else if (authData.token === 'invalid1') {
		    return callback(null, true, 'bad');
	    } else if (authData.token === 'invalid2') {
		    return callback(null, true, null);
	    }

    } else {
	    return callback(Hapi.error.internal('boom'));
    }

    return callback(null, false);
};
