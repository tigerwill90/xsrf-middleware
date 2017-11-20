<?php
/**
 * This file is part of xcsrf-middleware package
 *
 * Copyright (c) 2017 Sylvain Muller
 *
 * Project home : https://github.com/tigerwill90/slim3-xsrf-middleware
 * License : MIT
 */

declare(strict_types=1);

namespace Tigerwill90\Middleware;

require __DIR__ . '/../vendor/autoload.php';

use Slim\Http\Request;
use Slim\Http\Response;
use Slim\Http\Uri;
use Slim\Http\Headers;
use Slim\Http\Body;

use Branca\Branca;
use Dflydev\FigCookies\Cookie;
use Dflydev\FigCookies\FigRequestCookies;

const KEY = "supersecretkeyyoushouldnotcommit";
const XSRF = "csrftoken";

class XsrfProtectionBrancaTest extends \PHPUnit_Framework_TestCase  {

    public function requestFactory() : Request {

        $uri = Uri::createFromString('http://dummy.apitest.com/api/signin');
        $headers = new Headers();
        $cookies = [];
        $serverParams = [];
        $body = new Body(fopen('php://temp', 'r+'));
        return new Request('GET', $uri, $headers, $cookies, $serverParams, $body);

    }

    /** @test */
    public function testShouldMatchAndReturn200() : void {

        $request = $this->requestFactory();
        $response = new Response();

        $branca = new Branca(KEY);

        $payload = [
            "uid" => 1,
            "csrf" => XSRF,
            "scope" => [1,0,1,1]
        ];

        $request = FigRequestCookies::set($request, Cookie::create('xCsrf', XSRF));

        $encoded =  $branca->encode(json_encode($payload));
        $decoded =  $branca->decode($encoded);

        $request = $request->withAttribute("token",$decoded);

        $xsrfProtection = new XsrfProtection([]);

        $next = function(Request $request, Response $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    /** @test */
    public function testShouldNotMatchAndReturn401() : void {

        $request = $this->requestFactory();
        $response = new Response();

        $branca = new Branca(KEY);
        $payload = [
            "uid" => 1,
            "csrf" => XSRF,
            "scope" => [1,0,1,1]
        ];

        $request = FigRequestCookies::set($request, Cookie::create('xCsrf', "xsrfNotMatch"));

        $encoded =  $branca->encode(json_encode($payload));
        $decoded =  $branca->decode($encoded);

        $request = $request->withAttribute("token",$decoded);

        $xsrfProtection = new XsrfProtection([]);

        $next = function(Request $request, Response $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
    }

    /** @test */
    public function testShouldNotFindClaimAndReturn401() : void {

        $request = $this->requestFactory();
        $response = new Response();

        $branca = new Branca(KEY);
        $payload = [
            "uid" => 1,
            "noRightClaim" => XSRF,
            "scope" => [1,0,1,1]
        ];

        $request = FigRequestCookies::set($request, Cookie::create('xCsrf', XSRF));

        $encoded =  $branca->encode(json_encode($payload));
        $decoded =  $branca->decode($encoded);

        $request = $request->withAttribute("token",$decoded);

        $xsrfProtection = new XsrfProtection([]);

        $next = function(Request $request, Response $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
    }

    /** @test */
    public function testShouldNotFindClaimInStringAndReturn401() : void {

        $request = $this->requestFactory();
        $response = new Response();

        $branca = new Branca(KEY);
        $payload = "payloadshouldanassociativearray";

        $request = FigRequestCookies::set($request, Cookie::create('xCsrf', XSRF));

        $encoded =  $branca->encode($payload);
        $decoded =  $branca->decode($encoded);

        $request = $request->withAttribute("token",$decoded);

        $xsrfProtection = new XsrfProtection([]);

        $next = function(Request $request, Response $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
    }

    /** @test */
    public function testShouldNotFindCookieAndReturn401() : void {

        $request = $this->requestFactory();
        $response = new Response();

        $branca = new Branca(KEY);
        $payload = [
            "uid" => 1,
            "csrf" => XSRF,
            "scope" => [1,0,1,1]
        ];

        $request = FigRequestCookies::set($request, Cookie::create('noRightCookieName', XSRF));

        $encoded =  $branca->encode(json_encode($payload));
        $decoded =  $branca->decode($encoded);

        $request = $request->withAttribute("token",$decoded);

        $xsrfProtection = new XsrfProtection([]);

        $next = function(Request $request, Response $response) {
            $response->getBody()->write("Fou");
        };

        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
    }
}