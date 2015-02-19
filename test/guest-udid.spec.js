var Code = require('code'),
	Hapi = require('hapi'),
	Lab = require('lab'),
	internals = {},
	lab = exports.lab = Lab.script(),
	describe = lab.describe,
	it = lab.it,
	expect = Code.expect;

describe('Guest authentication with udid', function () {

	it('validation method should be executed within the scope of request', function (done) {
		var server = new Hapi.Server(),
			request;

		server.connection();
		server.register(require('../'), function (err) {
			expect(err).to.not.exist();
			server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: function () {
				var request = this;
				expect(request.raw.req).to.be.an.object();
				expect(request.raw.res).to.be.an.object();
				done();
			} });

			request = { method: 'POST', url: '/', headers: { authorization: internals.header('1234567890') } };
			server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });
			server.inject(request);
		});
	});
	
	it('should return  a reply on successful auth', function (done) {

	    var server = new Hapi.Server();
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
	        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

	        var request = { method: 'POST', url: '/', headers: { authorization: internals.header('1234567890') } };

	        server.inject(request, function (res) {

	            expect(res.result).to.equal('ok');
	            done();
	        });
	    });
	});

	it('should return  an error on wrong scheme', function (done) {

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

	it('should return  a reply on successful double auth', function (done) {

	    var handler = function (request, reply) {

	        var options = { method: 'POST', url: '/inner', headers: { authorization: internals.header('1234567890') }, credentials: request.auth.credentials };
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

	        var request = { method: 'POST', url: '/', headers: { authorization: internals.header('1234567890') } };

	        server.inject(request, function (res) {

	            expect(res.result).to.equal('ok');
	            done();
	        });
	    });
	});

	it('should return  a reply on failed optional auth', function (done) {

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

	it('should return  an error on guid', function (done) {

	    var server = new Hapi.Server();
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
	        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

	        var request = { method: 'POST', url: '/', headers: { authorization: internals.header('098765432') } };

	        server.inject(request, function (res) {

	            expect(res.statusCode).to.equal(401);
	            done();
	        });
	    });
	});

	it('should return  an error on bad header format', function (done) {

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

	it('should return  an error on bad header format', function (done) {

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

	it('should return  an error on bad header internal syntax', function (done) {

	    var server = new Hapi.Server();
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
	        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

	        var request = { method: 'POST', url: '/', headers: { authorization: 'guest 123123123' } };

	        server.inject(request, function (res) {

	            expect(res.result).to.exist();
	            expect(res.statusCode).to.equal(400);
	            expect(res.result.isMissing).to.equal(undefined);
	            done();
	        });
	    });
	});

	it('should return  an error on internal udid lookup error', function (done) {

	    var server = new Hapi.Server({ debug: false });
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
	        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

	        var request = { method: 'POST', url: '/', headers: { authorization: internals.header('000111222') } };

	        server.inject(request, function (res) {

	            expect(res.result).to.exist();
	            expect(res.statusCode).to.equal(500);
	            done();
	        });
	    });
	});

	it('should return  an error on non-object credentials error', function (done) {

	    var server = new Hapi.Server({ debug: false });
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
	        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

	        var request = { method: 'POST', url: '/', headers: { authorization: internals.header('invalid1') } };

	        server.inject(request, function (res) {

	            expect(res.result).to.exist();
	            expect(res.statusCode).to.equal(500);
	            done();
	        });
	    });
	});

	it('should return  an error on missing credentials error', function (done) {

	    var server = new Hapi.Server({ debug: false });
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
	        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

		    var request = { method: 'POST', url: '/', headers: { authorization: internals.header('invalid1') } };

	        server.inject(request, function (res) {

	            expect(res.result).to.exist();
	            expect(res.statusCode).to.equal(500);
	            done();
	        });
	    });
	});

	it('should return  an error on insufficient scope', function (done) {

	    var server = new Hapi.Server();
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
	        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: { scope: 'x' } } });

		    var request = { method: 'POST', url: '/', headers: { authorization: internals.header('1234567890') } };

	        server.inject(request, function (res) {

	            expect(res.result).to.exist();
	            expect(res.statusCode).to.equal(403);
	            done();
	        });
	    });
	});

	it('should return  an error on insufficient scope specified as an array', function (done) {

	    var server = new Hapi.Server();
	    server.connection();
	    server.register(require('../'), function (err) {

	        expect(err).to.not.exist();
	        server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.user });
	        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: { scope: ['x', 'y'] } } });

		    var request = { method: 'POST', url: '/', headers: { authorization: internals.header('1234567890') } };

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

		    var request = { method: 'POST', url: '/', headers: { authorization: internals.header('1234567890') } };

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

		    var validOptions = { method: 'GET', url: '/', headers: { authorization: internals.header('1234567890') } };
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
});

internals.header = function (udid) {
    return 'Guest ' + (new Buffer('udid:' + udid, 'utf8')).toString('base64');
};


internals.user = function (method, authData, callback) {
    if (authData.udid === '1234567890') {
        return callback(null, true, {
            user: 'john',
            scope: ['a'],
            tos: '1.0.0'
        });
    }
    else if (authData.udid === '000111222') {
        return callback(Hapi.error.internal('boom'));
    }
    else if (authData.udid === 'invalid1') {
        return callback(null, true, 'bad');
    }
    else if (authData.udid === 'invalid2') {
        return callback(null, true, null);
    }

    return callback(null, false);
};
