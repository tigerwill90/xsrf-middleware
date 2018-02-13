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

use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use Dflydev\FigCookies\FigRequestCookies;
use Closure;
use Tuupola\Http\Factory\ResponseFactory;
use Tuupola\Middleware\DoublePassTrait;

final class XsrfProtection implements MiddlewareInterface {

    use DoublePassTrait;
    
    /**
     * Default options can be overridden
     */
    private $options = [
        "path" => "/",
        "passthrough" => null,
        "payload" => null,
        "cookie" => "xCsrf",
        "token" => "token",
        "claim" => "csrf",
        "error" => null
    ];

    /**
     * PSR-3 compliant logger
     */
    protected $logger;

    /**
     * Last error message
     */
    protected $message;

    /**
     * Create a new middleware instance
     * @param array
     */
    public function __construct(array $options = []) {
        /* Store passed in options overwriting any defaults. */
        $this->setOptions($options);
    }

    /**
     * Process a request in PSR-15 style
     *
     * @param Request $request
     * @param RequestHandlerInterface $handler
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function process(Request $request, RequestHandlerInterface $handler) : Response {
        $uri = "/" . $request->getUri()->getPath();
        $uri = preg_replace("#/+#", "/", $uri);

        // if request match with passthrough, no need double submit check
        foreach ((array)$this->options["passthrough"] as $passthrough) {
            $passthrough = rtrim($passthrough, "/");
            if (!!preg_match("@^{$passthrough}(/.*)?$@", $uri)) {
                $this->log(LogLevel::INFO, "Route ignored, access granted");
                return $handler->handle($request);
            }
        }

        // if request match with path, double submit check
        foreach ((array)$this->options["path"] as $path) {
            $path = rtrim($path, "/");
            if (!!preg_match("@^{$path}(/.*)?$@", $uri)) {

                // If cookie cannot be found, return 401 Unauthorized
                if (null === $cookievalue = $this->fetchCookie($request)) {
                    $response = (new ResponseFactory)->createResponse(401);
                    return $this->error($response, [
                        "message" => $this->message
                    ]);
                }

                // If payload is null and token cannot be found in request, return 401 Unauthorized
                if(!isset($this->options["payload"])) {
                    $message = "Payload not found in options";
                    $this->log(LogLevel::WARNING, $message);
                    if (false === $this->fetchToken($request)) {
                        $response = (new ResponseFactory)->createResponse(401);
                        return $this->error($response, [
                            "message" => $this->message
                        ]);
                    }
                }

                // If claim cannot be found, return 401 Unauthorized
                if (false === $this->fetchClaim()) {
                    $response = (new ResponseFactory)->createResponse(401);
                    return $this->error($response, [
                        "message" => $this->message
                    ]);
                }

                // If csrf cookie don't match with claim, return 401 Unauthorized
                if (false === $this->validateToken($cookievalue)) {
                    $response = (new ResponseFactory)->createResponse(401);
                    return $this->error($response, [
                        "message" => $this->message
                    ]);
                }
            }
        }

        return $handler->handle($request);
    }

    /**
     * Call the error handler if it exists
     *
     * @param Response $response
     * @param array $arguments
     * @return Response
     */
    private function error(Response $response, array $arguments) : Response {
        if (\is_callable($this->options["error"])) {
            $handlerResponse = $this->options["error"]($response, $arguments);
            if ($handlerResponse instanceof Response) {
                return $handlerResponse;
            }
        }
        return $response;
    }

    /**
     * Set options from given array (overwrite defaults)
     *
     * @param array $data Array of options.
     * @return self
     */
    private function setOptions(array $data = []) : self {
        foreach ($data as $key => $value) {
            $method = "set" . ucfirst($key);
            if (method_exists($this, $method)) {
                \call_user_func(array($this, $method), $value);
            }
        }
        return $this;
    }

    /**
     * Check if cookie exist
     *
     * @param Request $request
     * @return null|string
     */
    public function fetchCookie(Request $request) : ?string {
        $message = "Cookie not found";
        $csrfcookie = FigRequestCookies::get($request, $this->options["cookie"]);
        $csrfvalue = $csrfcookie->getValue();
        if (!isset($csrfvalue)) {
            $this->message = $message;
            $this->log(LogLevel::DEBUG, $message);
            return null;
        }
        return $csrfvalue;
    }

    /**
     * Check if payload exist in request attribute
     *
     * @param Request $request
     * @return bool
     */
    public function fetchToken(Request $request) : bool {
        $message = "Payload not found in request attribute";
        $decode = $request->getAttribute($this->options["token"]);
        if (!isset($decode)) {
            $this->message = $message;
            $this->log(LogLevel::DEBUG, $message);
            return false;
        }
        $this->options["payload"] = $decode;
        return true;
    }

    /**
     * Check if claim exist
     *
     * @return bool
     */
    public function fetchClaim() : bool {
        $decode = $this->transformPayload($this->options["payload"]);
        if (!array_key_exists($this->options["claim"],$decode)) {
            $this->message = "Claim not found in token";
            $this->log(LogLevel::DEBUG, $this->message);
            return false;
        }
        if (empty($decode[$this->options["claim"]])) {
            $this->message = "No random key find in claim";
            $this->log(LogLevel::DEBUG, $this->message);
            return false;
        }

        return true;
    }

    /**
     * Check if cookie value match with jwt claim value
     *
     * @param $cookievalue
     * @return bool
     */
    public function validateToken(string $cookievalue) : bool {
        $message = "Token and cookie ";
        $decode = $this->transformPayload($this->options["payload"]);
        if ($decode[$this->options["claim"]] === $cookievalue) {
            $this->log(LogLevel::DEBUG, $message . "match, access granted !");
            return true;
        }
        $this->message = $message . "don't match, access denied !";
        $this->log(LogLevel::DEBUG, $message . "don't match, access denied !");
        return false;
    }

    /**
     * Set a custom path route (overwrite default)
     *
     * @param string[] or string $path
     * @return self
     */
    public function setPath($path) : self {
        $this->options["path"] = $path;
        return $this;
    }

    /**
     * get the path route option
     *
     * @return array
     */
    public function getPath() : array {
        return (array)$this->options["path"];
    }

    /**
     * Set a custom passthrough route (overwrite default)
     *
     * @param string[] or string $passthrough
     * @return self
     */
    public function setPassthrough($passthrough) : self {
        $this->options["passthrough"] = $passthrough;
        return $this;
    }

    /**
     * get the passthrough route option
     *
     * @return string
     */
    public function getPassthrough() : array {
        return (array)$this->options["passthrough"];
    }

    /**
     * Set payload given in parameter
     *
     * @param $payload
     * @return $this
     */
    public function setPayload($payload) : self {
        $this->options["payload"] = $payload;
        return $this;
    }

    /**
     * Get payload
     *
     * @return array
     */
    public function getPayload() : array {
        return $this->transformPayload($this->options["payload"]);
    }

    /**
     * transform payload to valid array
     *
     * @param $payload
     * @return array
     */
    public function transformPayload($payload) : array {
        if (\is_string($payload)) {
            $isValideDecodedJson = json_decode($payload, true);
            if (json_last_error() === JSON_ERROR_NONE) {
                return (array)$isValideDecodedJson;
            }
        }
        return (array)$this->options["payload"];
    }

    /**
     * Set a custom cookie name (overwrite default)
     *
     * @param string $cookie
     * @return self
     */
    public function setCookie(string $cookie) : self {
        $this->options["cookie"] = $cookie;
        return $this;
    }

    /**
     * get the cookie name option
     *
     * @return string
     */
    public function getCookie() : string {
        return $this->options["cookie"];
    }

    /**
     * Set a custom token name (overwrite default)
     *
     * @param string $token
     * @return self
     */
    public function setToken(string $token) : self {
        $this->options["token"] = $token;
        return $this;
    }

    /**
     * get the token name option
     *
     * @return string
     */
    public function getToken() : string {
        return $this->options["token"];
    }

    /**
     * Set a custom claim name (overwrite default)
     *
     * @param string $claim
     * @return self
     */
    public function setClaim(string $claim) : self {
        $this->options["claim"] = $claim;
        return $this;
    }

    /**
     * Get the claim name option
     *
     * @return string
     */
    public function getClaim() : string {
        return $this->options["claim"];
    }

    /**
     * Set a custom PSR-3 compliant logger
     *
     * @param LoggerInterface|null $logger
     * @return $this
     */
    public function setLogger(LoggerInterface $logger = null) : self {
        $this->logger = $logger;
        return $this;
    }

    /**
     * Get PSR-3 compliant logger
     *
     * @return mixed
     */
    public function getLogger() : LoggerInterface {
        return $this->logger;
    }

    /**
     * Log messages with a PSR-3 compliant logger
     *
     * @param $level
     * @param $message
     * @param array $context
     * @return mixed
     */
    public function log($level, $message, array $context = []) : ?bool {
        if ($this->logger) {
            return $this->logger->log($level, $message, $context);
        }
        return false;
    }

    /**
     * Set the last error message
     *
     * @param $message
     * @return $this
     */
    public function setMessage(string $message) : self {
        $this->message = $message;
        return $this;
    }

    /**
     * Get the last error message
     *
     * @return mixed
     */
    public function getMessage() : string {
        return $this->message;
    }

    /**
     * Set the error handler
     *
     * @param $error
     * @return $this
     */
    public function setError(Closure $error) : self {
        $this->options["error"] = $error;
        return $this;
    }

    /**
     * Get the error handler
     *
     * @return mixed
     */
    public function getError() : Closure {
        return $this->options["error"];
    }
}