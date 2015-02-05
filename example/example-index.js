var Bcrypt = require('bcrypt'),
	Hapi = require('hapi'),
	HapiAppMixAuth = require('../'), // require('hapi-app-mix-auth'),
	server = new Hapi.Server();



var user = {
	username: 'john',
	password: '$2a$10$iqJSHD.BGr0E2IxQwYgJmeP3NvhPrXAeLSaGCj6IR/XU5QtjVu5Tm',   // 'secret'
	name: 'John Smith',
	token: 'asd000asd000asd',
	id: '2133d32a'
};

var validate = function (method, authObject, callback) {
	switch(method) {
		case 'basic':
			Bcrypt.compare(authObject.password, user.password, function (err, isValid) {
				callback(err, isValid, { id: user.id, name: user.name });
			});
			break;
		case 'oauth':
			if (authObject.token === user.token) {
				callback(null, true, { id: user.id, name: user.name });
			}
			break;
		case 'guest':
			if (authObject.udid) {
				callback(null, true, { guest: true, udid: authObject.udid });
			}
			break;
		default:
			return callback(null, false);
			break;
	}
};

server.connection({port: 8080});
server.register(HapiAppMixAuth, function (err) {
	server.auth.strategy('mix-auth', 'mix-auth', { validateFunc: validate });
	server.route({
		method: 'GET',
		path: '/',
		config: {
			auth: 'mix-auth',
			handler: function (response, reply) {
				reply(response.auth.credentials);
			}
		}
	});
});
server.start();