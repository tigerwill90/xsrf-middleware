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

use Psr\Http\Message\RequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use Dflydev\FigCookies\FigRequestCookies;

class XsrfProtection {

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
     * Call the middleware
     *
     * @param \Psr\Http\Message\RequestInterface $request
     * @param \Psr\Http\Message\ResponseInterface $response
     * @param callable $next
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function __invoke(Request $request, Response $response, callable $next) {
        $uri = "/" . $request->getUri()->getPath();
        $uri = preg_replace("#/+#", "/", $uri);

        // if request match with passthrough, no need double submit check
        foreach ((array)$this->options["passthrough"] as $passthrough) {
            $passthrough = rtrim($passthrough, "/");
            if (!!preg_match("@^{$passthrough}(/.*)?$@", $uri)) {
                $this->log(LogLevel::INFO, "Route ignored, access granted");
                return $next($request, $response);
            }
        }

        $cookiename = $this->getCookie();
        $tokenname = $this->getToken();
        $claimname = $this->getClaim();

        // if request match with path, double submit check
        foreach ((array)$this->options["path"] as $path) {
            $path = rtrim($path, "/");
            if (!!preg_match("@^{$path}(/.*)?$@", $uri)) {

                // If cookie cannot be found, return 401 Unauthorized
                if (false === $cookie = $this->fetchCookie($request,$cookiename)) {
                    return $this->error($request, $response, [
                        "message" => $this->message
                    ])->withStatus(401);
                }

                // If payload is null and token cannot be found in request, return 401 Unauthorized
                if(!isset($this->options["payload"])) {
                    $message = "Payload not found in parameter";
                    $this->log(LogLevel::WARNING, $message);
                    if (false === $token = $this->fetchToken($request,$tokenname)) {
                        return $this->error($request, $response, [
                            "message" => $this->message
                        ])->withStatus(401);
                    }
                }

                // If claim cannot be found, return 401 Unauthorized
                if (false === $claim = $this->fetchClaim($claimname)) {
                    return $this->error($request, $response, [
                        "message" => $this->message
                    ])->withStatus(401);
                }

                // If csrf cookie don't match with claim, return 401 Unauthorized
                if (false === $match = $this->validateToken($request,$cookiename,$claimname)) {
                    return $this->error($request, $response, [
                        "message" => $this->message
                    ])->withStatus(401);
                }
            }
        }

        return $next($request, $response);
    }

    /**
     * Call the error handler if it exists
     *
     * @param Request $request
     * @param Response $response
     * @param $arguments
     * @return Response
     */
    public function error(Request $request, Response $response, $arguments) {
        if (is_callable($this->options["error"])) {
            $handler_response = $this->options["error"]($request, $response, $arguments);
            if (is_a($handler_response, "\Psr\Http\Message\ResponseInterface")) {
                return $handler_response;
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
    private function setOptions(array $data = []) {
        foreach ($data as $key => $value) {
            $method = "set" . ucfirst($key);
            if (method_exists($this, $method)) {
                call_user_func(array($this, $method), $value);
            }
        }
        return $this;
    }

    /**
     * Check if cookie exist
     *
     * @param \Psr\Http\Message\RequestInterface $request
     * @param name of the cookie $cookiename
     * @return boolean
     */
    public function fetchCookie(Request $request,$cookiename) {
        $message = "Cookie not found";
        $csrfcookie = FigRequestCookies::get($request, $cookiename);
        $csrfvalue = $csrfcookie->getValue();
        if (!isset($csrfvalue)) {
            $this->message = $message;
            $this->log(LogLevel::DEBUG, $message);
            return false;
        }
        return true;
    }

    /**
     * Check if payload exist in request attribute
     *
     * @param \Psr\Http\Message\RequestInterface $request
     * @param name of the token $tokenname
     * @return boolean
     */
    public function fetchToken(Request $request,$tokenname) {
        $message = "Payload not found in request attribute";
        $decode = $request->getAttribute($tokenname);
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
     * @param \Psr\Http\Message\RequestInterface $request
     * @param name of the token $tokenname
     * @param name of the claim $claimname
     * @return boolean
     */
    public function fetchClaim($claimname) {
        $decode = $this->transformPayload($this->options["payload"]);
        if (!array_key_exists($claimname,$decode)) {
            $this->message = "Claim not found in token";
            $this->log(LogLevel::DEBUG, $this->message);
            return false;
        }
        if (empty($decode[$claimname])) {
            $this->message = "No random key find in claim";
            $this->log(LogLevel::DEBUG, $this->message);
            return false;
        }

        return true;
    }

    /**
     * Check if cookie value match with jwt claim value
     *
     * @param \Psr\Http\Message\RequestInterface $request
     * @param name of the cookie $cookiename
     * @param name of the token $tokenname
     * @param name of the claim $claimname
     * @return boolean
     */
    public function validateToken(Request $request,$cookiename,$claimname) {
        $message = "Token and cookie don't match, access";
        $decode = $this->transformPayload($this->options["payload"]);
        $csrfcookie = FigRequestCookies::get($request, $cookiename);
        $csrfvalue = $csrfcookie->getValue();
        if ($decode[$claimname] === $csrfvalue) {
            $this->log(LogLevel::DEBUG, $message . " granted !");
            return true;
        }
        $this->message = $message . " denied !";
        $this->log(LogLevel::DEBUG, $message . " denied !");
        return false;
    }

    /**
     * Set a custom path route (overwrite default)
     *
     * @param string[] or string $path
     * @return self
     */
    public function setPath($path){
        $this->options["path"] = $path;
        return $this;
    }

    /**
     * get the path route option
     *
     * @return string
     */
    public function getPath(){
        return $this->options["path"];
    }

    /**
     * Set a custom passthrough route (overwrite default)
     *
     * @param string[] or string $passthrough
     * @return self
     */
    public function setPassthrough($passthrough){
        $this->options["passthrough"] = $passthrough;
        return $this;
    }

    /**
     * get the passthrough route option
     *
     * @return string
     */
    public function getPassthrough(){
        return $this->options["passthrough"];
    }

    /**
     * Set payload given in parameter
     *
     * @param $payload
     * @return $this
     */
    public function setPayload($payload) {
        $this->options["payload"] = $payload;
        return $this;
    }

    /**
     * Get payload
     *
     * @return array
     */
    public function getPayload() {
        return $this->options["payload"];
    }

    /**
     * transform payload to valid array
     *
     * @param $payload
     * @return array
     */
    public function transformPayload($payload) {
        if (is_string($payload)) {
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
    public function setCookie($cookie){
        $this->options["cookie"] = $cookie;
        return $this;
    }

    /**
     * get the cookie name option
     *
     * @return string
     */
    public function getCookie(){
        return $this->options["cookie"];
    }

    /**
     * Set a custom token name (overwrite default)
     *
     * @param string $token
     * @return self
     */
    public function setToken($token){
        $this->options["token"] = $token;
        return $this;
    }

    /**
     * get the token name option
     *
     * @return string
     */
    public function getToken(){
        return $this->options["token"];
    }

    /**
     * Set a custom claim name (overwrite default)
     *
     * @param string $claim
     * @return self
     */
    public function setClaim($claim){
        $this->options["claim"] = $claim;
        return $this;
    }

    /**
     * Get the claim name option
     *
     * @return string
     */
    public function getClaim(){
        return $this->options["claim"];
    }

    /**
     * Set a custom PSR-3 compliant logger
     *
     * @param LoggerInterface|null $logger
     * @return $this
     */
    public function setLogger(LoggerInterface $logger = null) {
        $this->logger = $logger;
        return $this;
    }

    /**
     * Get PSR-3 compliant logger
     *
     * @return mixed
     */
    public function getLogger() {
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
    public function log($level, $message, array $context = []) {
        if ($this->logger) {
            return $this->logger->log($level, $message, $context);
        }
    }

    /**
     * Set the last error message
     *
     * @param $message
     * @return $this
     */
    public function setMessage($message) {
        $this->message = $message;
        return $this;
    }

    /**
     * Get the last error message
     *
     * @return mixed
     */
    public function getMessage() {
        return $this->message;
    }

    /**
     * Set the error handler
     *
     * @param $error
     * @return $this
     */
    public function setError($error) {
        $this->options["error"] = $error;
        return $this;
    }

    /**
     * Get the error handler
     *
     * @return mixed
     */
    public function getError() {
        return $this->options["error"];
    }
}