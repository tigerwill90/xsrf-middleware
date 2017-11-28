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
        "claim" => "csrf"
    ];

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
                    return $response->withStatus(401);
                }

                // If payload is null and token cannot be found in request, return 401 Unauthorized
                if(!isset($this->options["payload"])) {
                    if (false === $token = $this->fetchToken($request,$tokenname)) {
                        return $response->withStatus(401);
                    }
                }

                // If claim cannot be found, return 401 Unauthorized
                if (false === $claim = $this->fetchClaim($claimname)) {
                    return $response->withStatus(401);
                }

                // If csrf cookie don't match with claim, return 401 Unauthorized
                if (false === $match = $this->validateToken($request,$cookiename,$claimname)) {
                    return $response->withStatus(401);
                }
            }
        }

        return $next($request, $response);
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
    public function fetchCookie($request,$cookiename) {
        $csrfcookie = FigRequestCookies::get($request, $cookiename);
        $csrfvalue = $csrfcookie->getValue();
        if (!isset($csrfvalue)) {
            return false;
        }
        return true;
    }

    /**
     * Check if token exist
     *
     * @param \Psr\Http\Message\RequestInterface $request
     * @param name of the token $tokenname
     * @return boolean
     */
    public function fetchToken($request,$tokenname) {
        $decode = $request->getAttribute($tokenname);
        if (!isset($decode)) {
            return false;
        }
        $this->setPayload($decode);
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
        $decode = $this->getPayload();
        if(!is_array($decode)) {
            return false;
        }
        if (!array_key_exists($claimname,$decode)) {
            return false;
        }
        if (!isset($decode[$claimname])) {
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
    public function validateToken($request,$cookiename,$claimname) {
        $decode = $this->getPayload();
        $csrfcookie = FigRequestCookies::get($request, $cookiename);
        $csrfvalue = $csrfcookie->getValue();
        if ($decode[$claimname] === $csrfvalue) {
            return true;
        }
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
     * Get payload and if json, decode it
     *
     * @return array
     */
    public function getPayload() {
        if (is_string($this->options["payload"])) {
            $isValideDecodedJson = json_decode($this->options["payload"], true);
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
}