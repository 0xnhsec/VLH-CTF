<?php

return [

    /*
    |--------------------------------------------------------------------------
    | VLH-CTF ASLV M3 lab configuration
    |--------------------------------------------------------------------------
    */

    // Base lab domain; tenant subdomains are <tenant>.<domain>.
    'domain' => env('LAB_DOMAIN', 'aslv.lab'),

    // Reserved subdomains that never count as tenants (they are routed to
    // other modules by the gateways).
    'reserved_tenants' => [
        'www', 'auth', 'mail', 'collector', 'attacker', 'edge',
        'internal', 'app', 'api', 'portal', 'victim', 'stub',
    ],
];
