[![Latest Stable Version](https://poser.pugx.org/tigerwill90/xsrf-middleware/v/stable)](https://packagist.org/packages/tigerwill90/xsrf-middleware)
[![Latest Unstable Version](https://poser.pugx.org/tigerwill90/xsrf-middleware/v/unstable)](https://packagist.org/packages/tigerwill90/xsrf-middleware)
[![License MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](LICENSE.md)
[![Build Status](https://travis-ci.org/tigerwill90/xsrf-middleware.svg?branch=master)](https://travis-ci.org/tigerwill90/xsrf-middleware)
[![codecov](https://codecov.io/gh/tigerwill90/xsrf-middleware/branch/master/graph/badge.svg)](https://codecov.io/gh/tigerwill90/xsrf-middleware)


# PSR-7 & PSR-15 : CSRF Protection alternative for JWT/Branca Authentication token

Csrf protection based on double submit pattern, cookie - JWT/Branca alternative.

It is based on [PSR-7 JWT Authentication Middleware](https://github.com/tuupola/slim-jwt-auth) from
[Tuupola](https://github.com/tuupola). **This middleware is designed to work with
JWT/Branca Authentication method and can be used with any framework using PSR-7 or PSR-15 style middlewares (since v1.1.0). It has been tested with [Slim Framework](https://www.slimframework.com/)**.

This middleware does **not** provide ways to generate Branca/JWT token. However you can find all you
needs for generate token with links bellow.

* [Firebase/php-jwt](https://github.com/firebase/php-jwt)
* [Tuupola/branca-php](https://github.com/tuupola/branca-php)
* [Tuupola/base62](https://github.com/tuupola/base62)

The goal is to protect rest api again [Cross-site request forgery](https://en.wikipedia.org/wiki/Cross-site_request_forgery)
attak, using double submit pattern (stateless).

### How it's work ?

Sometimes you want save your Jwt/Branca token in a http only cookie. Since it's not possible to grab it, your payload content is safe. It's particularly true
for JWT who have no-encrypted payload. BUT, this protection expose your api to CSRF attack.

When a user authenticate to a site

* generate an anti-csrf `token` with pseudorandom value
* generate `JWT` or `Branca` and set one of payload attribute with the previously `token` generated
* send `JWT` or `Branca` to frontend in a `http-only`, `secure` cookie.
* send the previously `token` generated in the response body

When an authenticated api consumer want access to your api, you need to attach the anti-csrf `token` as

* eventually a cookie with unique name
* a header proprieties
* a request body parameter

For all unsafe operation `[POST | PUT | PATCH | DELETE]` to you api, the middleware inspect both `token` and `JWT` or `Branca` in `http-only` cookie to check if value match 
and return [401 status](https://httpstatuses.com/401) if not.

### Dependencies

* [dflydev-fig-cookies](https://github.com/dflydev/dflydev-fig-cookies)
* [tuupola/callable-handler](https://github.com/tuupola/callable-handler)
* [tuupola/http-factory](https://github.com/tuupola/http-factory)
* [rybakit/msgpack](https://packagist.org/packages/rybakit/msgpack)
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

#### AntiCsrf 

The optional `anticsrf` parameter allow you to specify the name of your anti-csrf cookie, header or parameter.

Default parameter is `xCsrf`
 ```php
 $app = new Slim\App
 
 $app->add(new Tigerwill90\Middleware\XsrfProtection([
     "path" => ["/api", "/admin"],
     "anticsrf" => "xCsrf"
 ]));
 ```
 
 In this example, if the cookie, header or request parameter "xCsrf" exist, the middleware will compare his value with
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

#### MessagePack

The optional `msgpack` parameter allows you to use the [MessagePack](https://msgpack.org/) serialization format.

Default value is `false`

````php
$app = new Slim\App
 
$app->add(new Tigerwill90\Middleware\XsrfProtection([
   "path" => ["/api", "/admin"],
   "payload" => $container["decoded"]
   "msgpack" => true
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
        "anticsrf" => "xCsrf",
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

### License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.