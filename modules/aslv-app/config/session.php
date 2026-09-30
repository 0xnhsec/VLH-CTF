<?php

return [

    'driver' => env('SESSION_DRIVER', 'file'),

    'lifetime' => (int) env('SESSION_LIFETIME', 120),

    'expire_on_close' => env('SESSION_EXPIRE_ON_CLOSE', false),

    'encrypt' => env('SESSION_ENCRYPT', false),

    'files' => storage_path('framework/sessions'),

    'connection' => env('SESSION_CONNECTION'),

    'table' => env('SESSION_TABLE', 'sessions'),

    'store' => env('SESSION_STORE'),

    'lottery' => [2, 100],

    'cookie' => env('SESSION_COOKIE', 'aslv_app_session'),

    /*
    |----------------------------------------------------------------------
    | Session cookie domain
    |----------------------------------------------------------------------
    | .aslv.lab on purpose: the session cookie is shared across tenant
    | subdomains (single-organization SSO feel). That is what makes the M3
    | IDOR playable: log in on one tenant subdomain, then request the
    | innocent's tenant subdomain with the same cookie while the endpoint
    | validates the HOST tenant instead of the session owner.
    */
    'path' => env('SESSION_PATH', '/'),

    'domain' => env('SESSION_DOMAIN', '.aslv.lab'),

    'secure' => env('SESSION_SECURE_COOKIE', false),

    'http_only' => env('SESSION_HTTP_ONLY', true),

    'same_site' => env('SESSION_SAMESITE', 'lax'),

    'partitioned' => env('SESSION_PARTITIONED_COOKIE', false),

];
