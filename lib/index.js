// Load modules

var Boom = require('boom'),
	Hoek = require('hoek'),
	internals = {};



exports.register = function (plugin, options, next) {

    plugin.auth.scheme('mix-auth', internals.implementation);
    next();
};

exports.register.attributes = {
	pkg: require('../package.json')
};

internals.LABEL = 'mix-auth';
internals.settings = {};

internals.implementation = function (server, options) {
    
	var scheme = {};
	
    Hoek.assert(options, 'Missing basic auth strategy options');
    Hoek.assert(typeof options.validateFunc === 'function', 'options.validateFunc must be a valid function in basic scheme');

	internals.settings = Hoek.clone(options);


	scheme.authenticate = function (request, reply) {

        var req = request.raw.req,
	        authorization = req.headers.authorization,
	        authObject = {},
	        parts, method;


        if (!authorization) {
            return reply(Boom.unauthorized(null, internals.LABEL));
        }

        parts = authorization.split(/\s+/);

        if (parts.length !== 2) {
	        return reply(Boom.badRequest('Bad HTTP authentication header format', internals.LABEL));
        }

        method = parts[0].toLowerCase();
        switch(method) {
	        case "basic":
		        authObject = internals.getUsernameAndPassword(parts[1]);
		        break;
	        case "guest":
		        authObject = internals.getUDID(parts[1]);
		        break;
	        case "token":
		        authObject = internals.getToken(parts[1]);
		        break;
	        default:
		        authObject.error = Boom.unauthorized('Bad header internal syntax', internals.LABEL);
		        break;
        }
        if (authObject.error) {
	        return reply(authObject.error);
        }

        internals.settings.validateFunc(method, authObject.data, function (err, isValid, credentials) {

            credentials = credentials || null;

            if (err) {
                return reply(err, null, { credentials: credentials });
            }

            if (!isValid) {
                return reply(Boom.unauthorized('Bad username or password', internals.LABEL), null, { credentials: credentials });
            }

            if (!credentials ||
                typeof credentials !== 'object') {

                return reply(Boom.badImplementation('Bad credentials object received for ' + internals.LABEL + ' validation'));
            }

            // Authenticated

            return reply.continue({ credentials: credentials });
        });
    };

    return scheme;
};


internals.getUsernameAndPassword = function (loginPasswordHash, reply) {
	var credentialsPart = new Buffer(loginPasswordHash, 'base64').toString(),
		sep = credentialsPart.indexOf(':'),
		authObject = {
			error : null,
			data : {}
		};

	if (sep === -1) {
		authObject.error = Boom.badRequest('Bad header internal syntax', internals.LABEL);
		return authObject;
	}

	authObject.data.username = credentialsPart.slice(0, sep);
	authObject.data.password = credentialsPart.slice(sep + 1);

	if (!authObject.data.username && !internals.settings.allowEmptyUsername) {
		authObject.error = Boom.unauthorized('HTTP authentication header missing username', internals.LABEL);
		return authObject;
	}

	return authObject;
};

internals.getUDID = function (guidHash) {
	var credentialsPart = new Buffer(guidHash, 'base64').toString(),
		sep = credentialsPart.indexOf(':'),
		authObject = {
			error : null,
			data : {}
		};

	if (sep === -1 || credentialsPart.slice(0, sep) !== 'udid') {
		authObject.error = Boom.badRequest('Bad header internal syntax', internals.LABEL);
		return authObject;
	}

	authObject.data.udid = credentialsPart.slice(sep + 1);

	return authObject;
};

internals.getToken = function (tokenHash) {
	var credentialsPart = new Buffer(tokenHash, 'base64').toString(),
		sep = credentialsPart.indexOf(':'),
		authObject = {
			error : null,
			data : {}
		};

	if (sep === -1) {
		authObject.error = Boom.badRequest('Bad header internal syntax', internals.LABEL);
		return authObject;
	}

	authObject.data.provider = credentialsPart.slice(0, sep);
	authObject.data.token = credentialsPart.slice(sep + 1);

	if (!authObject.provider) {
		authObject.error = Boom.unauthorized('HTTP authentication header missing provider', internals.LABEL);
		return authObject;
	}

	if (!authObject.token) {
		authObject.error = Boom.unauthorized('HTTP authentication header missing token', internals.LABEL);
		return authObject;
	}

	return authObject;
};


