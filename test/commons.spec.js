var Code = require('code'),
	Hapi = require('hapi'),
	Lab = require('lab'),
	internals = {},
	lab = exports.lab = Lab.script(),
	describe = lab.describe,
	it = lab.it,
	expect = Code.expect;

describe('Mix-Auth commons', function () {
	
	it('cannot add a route that has payload validation required', function (done) {

		var server = new Hapi.Server();
		server.connection();
		server.register(require('../'), function (err) {

			expect(err).to.not.exist();
			server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.validateFunc });

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
			server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.validateFunc });

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
			server.auth.strategy('default', 'mix-auth', 'required', { validateFunc: internals.validateFunc });

			var fn = function () {

				server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: { mode: 'required', payload: false } } });
			};

			expect(fn).to.not.throw();
			done();
		});
	});

});

internals.validateFunc = function (method, authData, callback) {
	return callback(null, true);
};