[![Latest Version](https://img.shields.io/packagist/v/tigerwill90/xsrf-middleware.svg?style=flat-square)](https://packagist.org/packages/tigerwill90/xsrf-middleware)
[![License MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](LICENSE.md)
[![Build Status](https://travis-ci.org/tigerwill90/xsrf-middleware.svg?branch=master)](https://travis-ci.org/tigerwill90/xsrf-middleware)
[![codecov](https://codecov.io/gh/tigerwill90/xsrf-middleware/branch/master/graph/badge.svg)](https://codecov.io/gh/tigerwill90/xsrf-middleware)


# PSR-7 & PSR-15 : CSRF Protection alternative for JWT/Branca Authentication token

Csrf protection based on double submit pattern, cookie - JWT/Branca alternative.

I am new to the php world and this is my first middleware.
It is based on [PSR-7 JWT Authentication Middleware](https://github.com/tuupola/slim-jwt-auth) from
[Tuupola](https://github.com/tuupola). **This middleware is designed to work with
JWT/Branca Authentication method and can be used with any framework using PSR-7 or PSR-15 style middlewares (since v1.1.0). It has been tested with [Slim Framework](https://www.slimframework.com/)**.

This middleware does **not** provide ways to generate Branca/JWT token. However you can find all you
needs for generate token with links bellow.

* [Firebase/php-jwt](https://github.com/firebase/php-jwt)
* [Tuupola/branca-php](https://github.com/tuupola/branca-php)
* [Tuupola/base62](https://github.com/tuupola/base62)

The goal is to protect rest api again [Cross-site request forgery](https://en.wikipedia.org/wiki/Cross-site_request_forgery)
attak, using double submit cookie pattern (stateless).

### How it's work ?

A double submit cookie is defined as sending a random value in both a
cookie (httponly) and as a request parameter, with the server verifying if the cookie value
and request value match.

When a user authenticate to a site

* Generate token with pseudorandom value
* Generate JWT, branca and set one of payload attribute with the token generated
* Set a `httponly` cookie value with the token generated
* Return all to frontend

When a user try to access ressource

* Attach JWT/Branca token to header request (cookies will be automatically attached)
* Send request

When you perform an unsafe operation `[POST | PUT | PATCH | DELETE]` to you api, the middleware inspect both token and cookie to check if value match.

### Dependencies

* [dflydev-fig-cookies](https://github.com/dflydev/dflydev-fig-cookies)
* [tuupola/callable-handler](https://github.com/tuupola/callable-handler)
* [tuupola/http-factory](https://github.com/tuupola/http-factory)
* php-fig standards


### Install

````
composer require tigerwill90/xsrf-middleware
````

### Usage

Configuration options are passed as an array. There is no mandatory parameter.

```php
$app = new Slim\App

$app->add(new Tigerwill90\Middleware\XsrfProtection([]));
```

When a request is made, the middleware inspect both token and cookie to check if value match. If cookie or token
is not found, the server will respond with `401 Unauthorized`

### Optional parameters
#### Path
The optional `path` parameter allows you to specify which ressources of your api is protected by
the double submit pattern. It can be either a string or an array. You do not need to specify each URL.

Default parameter is `/`
```php
$app = new Slim\App

$app->add(new Tigerwill90\Middleware\XsrfProtection([
    "path" => "/api" /* or ["/api", "/admin"]*/
]));
```

In this example, everything starting with `/api` will be protected.

#### Passthrough

The optional `passthrough` parameter allows you to specify an exceptions to `path` parameter.
It can be either a string or an array.

Default parameter is `null`
```php
$app = new Slim\App

$app->add(new Tigerwill90\Middleware\XsrfProtection([
    "path" => ["/api", "/admin"],
    "passthrough" => "/api/orders"
]));
```

In this example, everything starting with `/api` and `/admin` will be protected, **except** `/api/orders`

#### Cookie 

The optional `cookie` parameter allow you to specify the name of your anti-csrf cookie.

Default parameter is `xCsrf`
 ```php
 $app = new Slim\App
 
 $app->add(new Tigerwill90\Middleware\XsrfProtection([
     "path" => ["/api", "/admin"],
     "cookie" => "csrfcookie"
 ]));
 ```
 
 In this example, if the cookie "csrfcookie" exist, the middleware will compare his value with
 the specified JWT/Branca token `claim` value.
 
 #### Token
 
 According to [PSR-7 JWT Authentication Middleware](https://github.com/tuupola/slim-jwt-auth) documentation, when the token
 is decoded successfully and authentication succees, the contents of decoded token is saved as attribute
 to the `$request`. The optional `token` parameter allows you to specify the attribute name of JWT/Branca token
 that the middleware needs to find in `$request`.
 
 Default parameter is `token`
  ```php
$app = new Slim\App

$app->add(new Tigerwill90\Middleware\XsrfProtection([
  "path" => ["/api", "/admin"],
  "token" => "jwt"
]));
  ```
 
 #### Payload
 
 **Alternatively** you can pass the contents of decoded token in the optional `payload` parameter.
 
 Default value is `null`
 `````php
 $app = new Slim\App
 
$app->add(new Tigerwill90\Middleware\XsrfProtection([
   "path" => ["/api", "/admin"],
   "payload" => $container["decoded"]
]));
 `````
 
 #### Claim
 Beauty of JWT/Branca is that you can pass extra data in the token such roles, rights, etc... Therby, we can
 compare a specified claims with ``httponly`` cookie.
 
 ```php
 [
    "uid" => 1,
    "iat" => "1428819941",
    "exp" => "1744352741",
    "aud" => "www.example.com",
    "roles" => [1,0,1,1,1],
    "xsrf" => "thepseudorandomvaluegeneratedforbothcookieandtoken"
 ]
 
 ```
 
 The optional `claim` parameter allows you to specify the name of the `claim` that the middleware need to find in decoded JWT/Branca token.
 
 Default value is `csrf`
```php
$app = new Slim\App

$app->add(new Tigerwill90\Middleware\XsrfProtection([
  "path" => ["/api", "/admin"],
  "claim" => "xsrf"
]));
```

According to this example, when a request is send to your api, you should have in the header a 
`httponly` cookie and an `authorization` token who have both `thepseudorandomvaluegeneratedforbothcookieandtoken`
setted as value.

#### Logger

The optional `logger` parameter allows you to pass a PSR-3 compatible logger to deal with debugging.

````php
use Monolog\Logger;
use Monolog\Handler\RotatingFileHandler;
use Monolog\Formatter\LineFormatter;

$app = new Slim\App

$logger = new Logger("slim");
$formatter = new LineFormatter(
    "[%datetime%] [%level_name%]: %message% %context%\n",
    null,
    true,
    true
);

$rotating = new RotatingFileHandler(__DIR__ . "/logs/xsrf.log", 0, Logger::DEBUG);
$rotating->setFormatter($formatter);
$logger->pushHandler($rotating);

$app->add(new Tigerwill90\Middleware\XsrfProtection([
  "path" => ["/api", "/admin"],
  "claim" => "xsrf",
  "logger" => $logger
]));
````

In this example we pass an instance of [Logger](https://github.com/projek-xyz/slim-monolog) `$logger` to the middleware.

````
[2017-12-06 01:14:05] [WARNING]: Payload not found in parameter 
[2017-12-06 01:14:05] [DEBUG]: Token and cookie don't match, access denied ! 
````

#### Error

Error is called when access is denied. It receives last error message in arguments.

````php
$app = new Slim\App

$app->add(new Tigerwill90\Middleware\XsrfProtection([
  "path" => ["/api", "/admin"],
  "claim" => "xsrf",
  "error" => function ($response, $arguments) {
       $data["message"] = $arguments["message];
       return $response
                ->withHeader("Content-Type", "application/json")
                ->write(json_encode($data));
  }
]));
````

### Implementation with JWT/Branca Authentication Middleware

Branca/JWT Authentication Middleware need to run before Xsrf Middleware protection.

```php
$container = $app->getContainer();

$container["XsrfProtection"] = function($c) {
    function new \Tigerwill90\Middleware\XsrfProtection([
        "path" => "/api",
        "passthrough" => ["/api/users/signin", "/api/users/token"],
        "cookie" => "xCsrf",
        "token" => "jwt",
        "claim" => "xsrf"
    ]);
};

 $container["JwtAuthentication"] = function($c) {
    return new \Slim\Middleware\JwtAuthentication([
        "secure" => true,
        "path" => "/api",
        "passthrough" => ["/api/users/signin", "/api/users/token"],
        "attribute" => "jwt",
        "secret" => getenv("JWT_SECRET")
    ]);
 };
 
 $app->add("XsrfProtection");
 $app->add("JwtAuthentication");
```

### Testing

```
phpunit
```

### Next Feature

* Ability to find JWT/Branca in cookie and match with request csrf parameter.

### License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.