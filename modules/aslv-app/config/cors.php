<?php

/*

|--------------------------------------------------------------------------
| VLH-CTF ASLV M3 — CORS configuration (deliberately inert)
|--------------------------------------------------------------------------
|
| The module's CORS story is owned by App\Http\Middleware\ReflectOriginCors,
| appended to the api middleware group: every /api/* response that carries an
| Origin header reflects it VERBATIM in Access-Control-Allow-Origin together
| with Access-Control-Allow-Credentials: true (the M2↔M3 trust edge, arch
| §5.2). That reflection is the deliberate misconfiguration players exploit.
|
| The framework's config-driven HandleCors middleware sits in the default
| GLOBAL stack. With the stock paths below ('api/*', origins '*', credentials
| false) it would intercept /api/* first and overwrite the reflected header
| with 'Access-Control-Allow-Origin: *' — breaking credentialed cross-origin
| reads entirely. Empty `paths` keeps HandleCors fully out of the way so
| ReflectOriginCors is the only CORS authority in this app.
|
*/

return [

    'paths' => [],

    'allowed_methods' => ['*'],

    'allowed_origins' => ['*'],

    'allowed_origins_patterns' => [],

    'allowed_headers' => ['*'],

    'exposed_headers' => [],

    'max_age' => 0,

    'supports_credentials' => false,

];
