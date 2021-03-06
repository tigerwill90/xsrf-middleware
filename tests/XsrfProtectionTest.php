<?php
/**
 * This file is part of xcsrf-middleware package
 *
 * Copyright (c) 2017 Sylvain Muller
 *
 * Project home : https://github.com/tigerwill90/slim3-xsrf-middleware
 * License : MIT
 */

namespace Tigerwill90\Middleware;

use MessagePack\Packer;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Http\Request;
use Slim\Http\Response;
use Slim\Http\Uri;
use Slim\Http\Headers;
use Slim\Http\Body;

use Psr\Log\NullLogger;
use Psr\Log\LogLevel;

use Monolog\Logger;
use Monolog\Handler\RotatingFileHandler;
use Monolog\Formatter\LineFormatter;

use Dflydev\FigCookies\Cookie;
use Dflydev\FigCookies\FigRequestCookies;

use PHPUnit\Framework\TestCase;

final class XsrfProtectionTest extends TestCase
{

    private const XSRF = "csrftoken";

    public function requestFactory(string $method = "POST") : Request
    {

        $uri = Uri::createFromString('http://dummy.apitest.com/api/signin');
        $headers = new Headers();
        $cookies = [];
        $serverParams = [];
        $body = new Body(fopen('php://temp', 'r+'));
        return new Request($method, $uri, $headers, $cookies, $serverParams, $body);
    }

    public function loggerFactory() :  Logger
    {
        $logger = new Logger("slim");
        $formatter = new LineFormatter(
            "[%datetime%] [%level_name%]: %message% %context%\n",
            null,
            true,
            true
        );
        $rotating = new RotatingFileHandler(__DIR__ . "/xsrf.log", 0, Logger::DEBUG);
        $rotating->setFormatter($formatter);
        $logger->pushHandler($rotating);
        return $logger;
    }

    public function testShouldBeTrue() : void
    {
        $this->assertTrue(true);
    }

    public function testShouldReturn200WithIgnoredRoute() : void
    {
        $request = $this->requestFactory();
        $response = new Response();
        $logger = $this->loggerFactory();

        $xsrfProtection = new XsrfProtection([
            "passthrough" => ["/api"],
            "logger" => $logger
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldReturn200WithSafeMethods() : void
    {
        $request = $this->requestFactory("GET");
        $response = new Response();
        $logger = $this->loggerFactory();

        $xsrfProtection = new XsrfProtection([
            "logger" => $logger
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldReturn200WithPayloadSetAsParameterAndCookie() : void
    {
        $request = $this->requestFactory();
        $response = new Response();

        $payload = [
            "uid" => 1,
            "csrf" => self::XSRF,
            "scope" => [1,0,1,1]
        ];

        $request = FigRequestCookies::set($request, Cookie::create('xCsrf', self::XSRF));

        $xsrfProtection = new XsrfProtection([
            "payload" => $payload,
            "path" => "/api/signin"
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };


        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldReturn200WithPayloadSetAsParameterAndHeader() : void
    {
        $request = $this->requestFactory();
        $response = new Response();

        $payload = [
            "uid" => 1,
            "csrf" => self::XSRF,
            "scope" => [1,0,1,1]
        ];

        $request = $request->withHeader("xCsrf", self::XSRF);

        $xsrfProtection = new XsrfProtection([
            "payload" => $payload,
            "path" => "/api/signin"
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };


        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldReturn200WithPayloadSetAsParameterAndParam() : void
    {
        $request = $this->requestFactory();
        $response = new Response();

        $payload = [
            "uid" => 1,
            "csrf" => self::XSRF,
            "scope" => [1,0,1,1]
        ];

        $request = $request->withParsedBody(["xCsrf" => self::XSRF]);

        $xsrfProtection = new XsrfProtection([
            "payload" => $payload,
            "path" => "/api/signin"
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };


        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldReturn200WithPayloadSetAsRequestAttribute() : void
    {
        $request = $this->requestFactory();
        $response = new Response();

        $payload = [
            "uid" => 1,
            "csrf" => self::XSRF,
            "scope" => [1,0,1,1]
        ];

        $request = $request->withAttribute("token", $payload)->withHeader("xCsrf", self::XSRF);

        $xsrfProtection = new XsrfProtection([]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };


        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldReturn200WithJsonEncodedPayload() : void
    {
        $request = $this->requestFactory();
        $response = new Response();

        $payload = json_encode([
            "uid" => 1,
            "csrf" => self::XSRF,
            "scope" => [1,0,1,1]
        ]);

        $request = FigRequestCookies::set($request, Cookie::create('xCsrf', self::XSRF));

        $request = $request->withAttribute("token", $payload);

        $xsrfProtection = new XsrfProtection([]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };


        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldReturn200WithPayloadInAttributeAndSerializedMessagePackFormat() : void
    {
        $request = $this->requestFactory();
        $response = new Response();

        $payload = [
            "uid" => 1,
            "csrf" => self::XSRF,
            "scope" => [1,0,1,1]
        ];

        $packer = new Packer();
        $packed = $packer->pack($payload);

        $request = FigRequestCookies::set($request, Cookie::create('xCsrf', self::XSRF));

        $request = $request->withAttribute("token", $packed);

        $xsrfProtection = new XsrfProtection([
            "msgpack" => true
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };


        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldReturn200WithPayloadAndSerializedMessagePackFormat() : void
    {
        $request = $this->requestFactory();
        $response = new Response();

        $payload = [
            "uid" => 1,
            "csrf" => self::XSRF,
            "scope" => [1,0,1,1]
        ];

        $packer = new Packer();
        $packed = $packer->pack($payload);

        $request = FigRequestCookies::set($request, Cookie::create('xCsrf', self::XSRF));

        $xsrfProtection = new XsrfProtection([
            "payload" => $packed,
            "msgpack" => true
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };


        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldReturn401WithoutRightCookieValue() : void
    {
        $request = $this->requestFactory();
        $response = new Response();
        $logger = $this->loggerFactory();

        $payload = [
            "uid" => 1,
            "csrf" => self::XSRF,
            "scope" => [1,0,1,1]
        ];

        $request = FigRequestCookies::set($request, Cookie::create('xCsrf', "xsrfNotMatch"));

        $request = $request->withAttribute("token", $payload);

        $xsrfProtection = new XsrfProtection([
            "logger" => $logger,
            "error" => function (ResponseInterface $response, $arguments) {
                $response->getBody()->write($arguments["message"]);
                return $response;
            }
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };


        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("Token and anti csrf don't match, access denied !", $response->getBody());
    }

    public function testShouldReturn401WithoutRightHeaderValue() : void
    {
        $request = $this->requestFactory();
        $response = new Response();
        $logger = $this->loggerFactory();

        $payload = [
            "uid" => 1,
            "csrf" => self::XSRF,
            "scope" => [1,0,1,1]
        ];

        $request = $request->withAttribute("token", $payload)->withHeader("xCsrf", "xsrfNotMatch");

        $xsrfProtection = new XsrfProtection([
            "logger" => $logger,
            "error" => function (ResponseInterface $response, $arguments) {
                $response->getBody()->write($arguments["message"]);
                return $response;
            }
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };


        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("Token and anti csrf don't match, access denied !", $response->getBody());
    }

    public function testShouldReturn401WithoutRightParamValue() : void
    {
        $request = $this->requestFactory();
        $response = new Response();
        $logger = $this->loggerFactory();

        $payload = [
            "uid" => 1,
            "csrf" => self::XSRF,
            "scope" => [1,0,1,1]
        ];

        $request = $request->withAttribute("token", $payload)->withParsedBody(["xCsrf" => "xsrfNotMatch"]);

        $xsrfProtection = new XsrfProtection([
            "logger" => $logger,
            "error" => function (ResponseInterface $response, $arguments) {
                $response->getBody()->write($arguments["message"]);
                return $response;
            }
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };


        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("Token and anti csrf don't match, access denied !", $response->getBody());
    }

    public function testShouldReturn401WithoutRightClaimValue() : void
    {
        $request = $this->requestFactory();
        $response = new Response();
        $logger = $this->loggerFactory();

        $payload = [
            "uid" => 1,
            "csrf" => "xsrfNotMatch",
            "scope" => [1,0,1,1]
        ];

        $request = FigRequestCookies::set($request, Cookie::create('xCsrf', self::XSRF));

        $request = $request->withAttribute("token", $payload);

        $xsrfProtection = new XsrfProtection([
            "logger" => $logger,
            "error" => function (ResponseInterface $response, $arguments) {
                $response->getBody()->write($arguments["message"]);
                return $response;
            }
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };


        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("Token and anti csrf don't match, access denied !", $response->getBody());
    }

    public function testShouldReturn401WithoutRightClaim() : void
    {
        $request = $this->requestFactory();
        $response = new Response();
        $logger = $this->loggerFactory();

        $payload = [
            "uid" => 1,
            "noRightClaim" => self::XSRF,
            "scope" => [1,0,1,1]
        ];

        $request = FigRequestCookies::set($request, Cookie::create('xCsrf', self::XSRF));

        $request = $request->withAttribute("token", $payload);

        $xsrfProtection = new XsrfProtection([
            "logger" => $logger,
            "error" => function (ResponseInterface $response, $arguments) {
                $response->getBody()->write($arguments["message"]);
                return $response;
            }
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };


        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("Claim not found in token", $response->getBody());
    }

    public function testShouldReturn401WithoutClaim() : void
    {
        $request = $this->requestFactory();
        $response = new Response();
        $logger = $this->loggerFactory();

        $payload = [
            "uid" => 1,
            "scope" => [1,0,1,1]
        ];

        $request = FigRequestCookies::set($request, Cookie::create('xCsrf', self::XSRF));

        $request = $request->withAttribute("token", $payload);

        $xsrfProtection = new XsrfProtection([
            "logger" => $logger,
            "error" => function (ResponseInterface $response, $arguments) {
                $response->getBody()->write($arguments["message"]);
                return $response;
            }
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("Claim not found in token", $response->getBody());
    }

    public function testShouldReturn401WithoutValueInClaim() : void
    {
        $request = $this->requestFactory();
        $response = new Response();
        $logger = $this->loggerFactory();

        $payload = [
            "uid" => 1,
            "csrf" => "",
            "scope" => [1,0,1,1]
        ];

        $request = FigRequestCookies::set($request, Cookie::create('xCsrf', self::XSRF));

        $request = $request->withAttribute("token", $payload);

        $xsrfProtection = new XsrfProtection([
            "logger" => $logger,
            "error" => function (ResponseInterface $response, $arguments) {
                $response->getBody()->write($arguments["message"]);
                return $response;
            }
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("No random key find in claim", $response->getBody());
    }

    public function testShouldReturn401WithStringPayload() : void
    {
        $request = $this->requestFactory();
        $response = new Response();
        $logger = $this->loggerFactory();

        $payload = "payloadshouldanassociativearray";

        $request = FigRequestCookies::set($request, Cookie::create('xCsrf', self::XSRF));

        $request = $request->withAttribute("token", $payload);

        $xsrfProtection = new XsrfProtection([
            "logger" => $logger
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testShouldReturn401WithoutPayloadInAttribute() : void
    {
        $request = $this->requestFactory();
        $response = new Response();
        $logger = $this->loggerFactory();

        $request = FigRequestCookies::set($request, Cookie::create('xCsrf', self::XSRF));

        $xsrfProtection = new XsrfProtection([
            "logger" => $logger,
            "error" => function (ResponseInterface $response, $arguments) {
                $response->getBody()->write($arguments["message"]);
                return $response;
            }
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };


        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("Payload not found in request attribute", $response->getBody());
    }

    public function testShouldReturn401WithoutRightAntiCsrfName() : void
    {
        $request = $this->requestFactory();
        $response = new Response();
        $logger = $this->loggerFactory();

        $payload = [
            "uid" => 1,
            "noRightClaim" => self::XSRF,
            "scope" => [1,0,1,1]
        ];

        $request = FigRequestCookies::set($request, Cookie::create('noRightCookieName', self::XSRF));

        $request = $request->withAttribute("token", $payload);

        $xsrfProtection = new XsrfProtection([
            "logger" => $logger,
            "error" => function (ResponseInterface $response, $arguments) {
                $response->getBody()->write($arguments["message"]);
                return $response;
            }
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("Anti csrf not found", $response->getBody());
    }

    public function testShouldReturn401WithoutCookieOrHeaderOrParam() : void
    {
        $request = $this->requestFactory();
        $response = new Response();
        $logger = $this->loggerFactory();

        $payload = [
            "uid" => 1,
            "csrf" => self::XSRF,
            "scope" => [1,0,1,1]
        ];

        $request = $request->withAttribute("token", $payload);

        $xsrfProtection = new XsrfProtection([
            "logger" => $logger,
            "error" => function (ResponseInterface $response, $arguments) {
                $response->getBody()->write($arguments["message"]);
                return $response;
            }
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("Anti csrf not found", $response->getBody());
    }

    public function testShouldReturn401AndCallError() : void
    {
        $request = $this->requestFactory();
        $response = new Response();
        $logger = $this->loggerFactory();

        $payload = [
            "uid" => 1,
            "csrf" => self::XSRF,
            "scope" => [1,0,1,1]
        ];

        $request = FigRequestCookies::set($request, Cookie::create('noRightCookieName', self::XSRF));

        $request = $request->withAttribute("token", $payload);

        $test = false;
        $xsrfProtection = new XsrfProtection([
            "logger" => $logger,
            "error" => function ($response, $arguments) use (&$test) {
                $test = true;
            }
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertTrue($test);
    }

    public function testShouldReturn401CallErrorAndModifyBody() : void
    {
        $request = $this->requestFactory();
        $response = new Response();
        $logger = $this->loggerFactory();

        $payload = [
            "uid" => 1,
            "csrf" => self::XSRF,
            "scope" => [1,0,1,1],
            "logger" => $logger
        ];

        $request = $request->withAttribute("token", $payload);

        $test = false;
        $xsrfProtection = new XsrfProtection([
            "logger" => $logger,
            "error" => function (ResponseInterface $response, $arguments) use (&$test) {
                $test = true;
                $response->getBody()->write($arguments["message"]);
                return $response;
            }
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };


        $response = $xsrfProtection($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertTrue($test);
        $this->assertEquals("Anti csrf not found", $response->getBody());
    }

    public function testShouldGetAndSetPath() : void
    {
        $xsrfProtection = new XsrfProtection([]);
        $this->assertEquals(["/"], $xsrfProtection->getPath());
        $xsrfProtection->setPath("/api");
        $this->assertEquals(["/api"], $xsrfProtection->getPath());
    }

    public function testShouldGetAndSetPassthrough() : void
    {
        $xsrfProtection = new XsrfProtection([]);
        $xsrfProtection->setPassthrough("/api");
        $this->assertEquals(["/api"], $xsrfProtection->getPassthrough());
    }

    public function testShouldGetAndSetPayload() : void
    {
        $payload = ["uid" => 1, "name" => "John Doe"];
        $xsrfProtection = new XsrfProtection([]);
        $xsrfProtection->setPayload($payload);
        $this->assertEquals($payload, $xsrfProtection->getPayload());
    }

    public function testShouldTransformPayload() : void
    {
        $payload = ["uid" => 1, "name" => "John Doe"];
        $xsrfProtection = new XsrfProtection([]);
        $this->assertEquals($payload, $xsrfProtection->transformPayload(json_encode($payload)));
    }

    public function testShouldGetAndSetAntiCsrf() : void
    {
        $xsrfProtection = new XsrfProtection([]);
        $this->assertEquals("xCsrf", $xsrfProtection->getAnticsrf());
        $xsrfProtection->setAnticsrf("dummyCookie");
        $this->assertEquals("dummyCookie", $xsrfProtection->getAnticsrf());
    }

    public function testShouldGetAndSetToken() : void
    {
        $xsrfProtection = new XsrfProtection([]);
        $this->assertEquals("token", $xsrfProtection->getToken());
        $xsrfProtection->setToken("dummyToken");
        $this->assertEquals("dummyToken", $xsrfProtection->getToken());
    }

    public function testShouldGetAndSetClaim() : void
    {
        $xsrfProtection = new XsrfProtection([]);
        $this->assertEquals("csrf", $xsrfProtection->getClaim());
        $xsrfProtection->setClaim("dummyClaim");
        $this->assertEquals("dummyClaim", $xsrfProtection->getClaim());
    }

    public function testShouldGetAndSetError() : void
    {
        $xsrfProtection = new XsrfProtection([]);
        $error = function () {
            $x = 1;
            $y = 2;
            return $x + $y;
        };
        $xsrfProtection->setError($error);
        $this->assertEquals($error, $xsrfProtection->getError());
    }

    public function testShouldGetAndSetMessage() : void
    {
        $xsrfProtection = new XsrfProtection([]);
        $xsrfProtection->setMessage("Token not found");
        $this->assertEquals("Token not found", $xsrfProtection->getMessage());
    }

    public function testShouldSetAndGetLogger() : void
    {
        $xsrfProtection = new XsrfProtection([]);
        $logger = new NullLogger;
        $xsrfProtection->setLogger($logger);
        $this->assertNull($xsrfProtection->log(LogLevel::WARNING, "Token not found"));
        $this->assertEquals($logger, $xsrfProtection->getLogger());
    }

    public function testShouldSetAndGetMsgpack() : void
    {
        $xsrfProtection = new XsrfProtection([]);
        $this->assertFalse($xsrfProtection->getMsgpack());
        $xsrfProtection->setMsgpack(true);
        $this->assertTrue($xsrfProtection->getMsgpack());
    }
}
