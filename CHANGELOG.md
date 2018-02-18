# Changelog

All notable changes to this project will be documented in this file, in reverse chronological order by release.

## [1.3.1-stable](https://github.com/tigerwill90/xsrf-middleware/compare/1.3.0...1.3.1)
##### 2018.02.19
* Bug fix for undefined index when no anti-csrf token is found
* PSR1 & PSR2 coding style

## [1.3.0-stable](https://github.com/tigerwill90/xsrf-middleware/compare/1.2.1...1.3.0)
##### 2018.02.17
Double submit pattern with json alternative is only relevant when Branca/JWT is in a `http-only` cookie. It's particularly
true for JWT who have no-encrypted payload. In http-only cookie, you payload is safe but unsafe again CSRF attack.
* Anti-csrf value is
    * can be found in a anti-csrf cookie (manually setted from client with a different name than original cookie)
    * can be found in header
    * can be found in request parameter
* Jwt/Branca should be always in http-only cookie (it's different for oAuth)
* Refactor some line of code to match with this pattern
* Add unpacking method for MessagePack format

## [1.2.1-stable](https://github.com/tigerwill90/xsrf-middleware/compare/1.2.0...1.2.1)
##### 2018.02.06
* Anti csrf can be find in header
* Cookie option is now anticsrf option
* More test

## 1.2.0-stable
##### 2018.02.15
* Only double submit check for unsafe methods

## 1.1.0
##### 2018.02.13
* Refactor to PHP 7.1
* PSR-7 and PSR-15 support
* Minor improvement

## 1.0.3-release
##### 2017.12.05
* Add support PSR-3 logger
* Add error message
* New sets of tests
* Some code modification
* Stable release

## 1.0.2-beta
##### 2017.11.28
* New tag for packagiste

## 1.0.1-beta
##### 2017.11.28
* New payload parameter
* Passing decoded token in parameter

## 1.0.0-beta
##### 2017.11.20
* Major bug fix
* Support for Branca/JWT Authentication Middleware
* Unit test