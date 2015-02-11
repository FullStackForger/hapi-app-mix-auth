# hapi-app-mix-auth

<!-- 
[![  ][ Build Status](https://secure.travis-ci.org/hapijs/hapi-auth-basic.png)](http://travis-ci.org/hapijs/hapi-auth-basic)
-->

## Hapi App Mix Auth Schema

It is a non-standard authentication schema, that supports three different authentication methods:
 - **Basic** authentication, same as original basic schema, combination of username and password passed regular way in the request `Authorisation` header
 - **Oauth** authentication is created for client authenticati'ng themselves with 3rd party oauth `access_token`. It requires combination of provider and token passed in request `Authorisation` header
 - **Guest** authentication is created for temporary guest access for clients authenticating themselves with just UDID. It requires combination of _'udid'_ keyword and UDID passed in request `Authorisation` header  

It has been design tu support annonymose authentication from portable devices. 
It allows athenticating users with regular login and password combination or
3rd party token, such us Facebook `access_token`.

Additionally it supports annonymouse user authenticating only the clients device by its UDID. That allows to store client information that can be assign to the user, once it's registered.

#### Disclaimer

**Hapi Mix Auth** borrows heavily from Erran Hammer's [hapi-auth-basic](https://github.com/hapijs/hapi-auth-basic) thus it uses original hapi licences
and obviously it passses all original tests.

Hapi Mix Auth authorisation schema was originally forked from **hapi-auth-basic v.2.0.0.RC** and extended to meet additional custom authentication criteria. Code is fully tested and tests cover all three implemented
authentication methods. 

## Guide

The `'mix-auth'` scheme takes the following options:

- `validateFunc` - (required) a user lookup and password validation function with the signature `function(username, password, callback)` where:
    - `method` - string that contains `basic`, `oauth` or `quest`
	- `object` - authentication object received from the client
        - `object.username` - decoded username for `basic` authentication
        - `object.password` - decoded password for `basic` authentication
        - `object.provider` - decoded provider for `oauth` authentication
        - `object.token` - decoded access token for `basic` authentication
        - `object.udid` - decoded UDID for `guest` authentication
    - `callback` - a callback function with the signature `function(err, isValid, credentials)` where:
        - `err` - an internal error.
        - `isValid` - `true` if both the username was found and the password matched, otherwise `false`.
        - `credentials` - a credentials object passed back to the application in `request.auth.credentials`. Typically, `credentials` are only
          included when `isValid` is `true`, but there are cases when the application needs to know who tried to authenticate even when it fails (e.g. with authentication mode `'try'`).
- `allowEmptyUsername` - (optional) if `true`, allows making requests with an empty username. Defaults to `false`.

## Example

You can run below script from project _example_ folder and check out tests for detailed usage.

```javascript
var Bcrypt = require('bcrypt'),
    Hapi = require('hapi'),
    HapiAppMixAuth = require('hapi-app-mix-auth'),
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
```

### Testing request

#### Basic authentication

__credentials:__
user: _'john'_ , password _'secret'_

```
curl -X GET -H "Authorization:Basic am9objpzZWNyZXQ=" -H "Cache-Control:no-cache" http://localhost:8080
```

Server will respond with: `{"id":"2133d32a","name":"John Smith"}`

#### Oauth authentication

__credentials:__
provider: _'facebook'_ and token _'asd000asd000asd'_

```
curl -X GET -H "Authorization:Oauth dG9rZW46YXNkMDAwYXNkMDAwYXNk" -H "Cache-Control:no-cache" http://localhost:8080
```

Server will respond with: `{"id":"2133d32a","name":"John Smith"}`

#### Guest authentication

__credentials:__
udid: _'1qaz2qaz3qaz'_

```
curl -X GET -H "Authorization:Guest dWRpZDoxcWF6MnFhejNxYXo=" -H "Cache-Control:no-cache" http://localhost:8080
```

Server will respond with: `{"guest":true,"udid":"1qaz2qaz3qaz"}`


