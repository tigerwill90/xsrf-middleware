# slim3-xsrf-middleware

Csrf protection based on double submit pattern, cookie - JWT alternative.

I am really new to the php world (programming too) and this is my first middleware,
currently in developpement, for Slim 3 framework. This middleware is very inspired
by [PSR-7 JWT Authentication Middleware](https://github.com/tuupola/slim-jwt-auth) from
[Tuupola](https://github.com/tuupola).

The goal is to protect rest api again [Cross-site request forgery](https://en.wikipedia.org/wiki/Cross-site_request_forgery)
attak, using double submit cookie pattern (stateless).

### How it's work ?

A double submit cookie is defined as sending a random value in both a
cookie (httponly) and as a request parameter, with the server verifying if the cookie value
and request value match.

When a user authenticates to a site

* Generate token with pseudorandom value

````
use \Tuupola\Base62;

$token = (new Base62)->encode(random_bytes(24))
````

* Generate JWT, branca (or what else ?) and set one of payload attribute with the token generated

````
use \Datetime;
use \Firebase\JWT\JWT;

$now = new DateTime();
$future = new DateTime("now +60 minutes");

$payload = [
    "uid" => 1,
    "iat" => $now->getTimeStamp(),
    "exp" => $future->getTimeStamp(),
    "xsrf" => $token // your previous generated token
];

$encode = JWT::encode($payload, $secret, "HS256");
````

* Set a cookie value with the token generated

````
use Dflydev\FigCookies\FigResponseCookies;

$response = FigResponseCookies::set($response, SetCookie::create('xsrf')
      ->withValue($cookietoken)
      ->withSecure(true)
      ->withHttpOnly(true)
);
````

* Return response with jwt and cookie

Now, when your frontend send a request to your api, you just need to attach jwt to header.  

## Getting Started



````
composer require tigerwill90/xsrf-middleware
````

## Setup, test and dependencies

Coming soon

