<?php

/*
|--------------------------------------------------------------------------
| VLH-CTF ASLV M3 — Laravel 11 bootstrap
|--------------------------------------------------------------------------
|
| Minimal but standard Laravel 11 application bootstrap. Two routing files:
| routes/web.php (session + CSRF group) and routes/api.php (automatically
| prefixed with /api by the framework).
|
| Middleware notes:
|  - ResolveTenant is appended to the web group and prepended to the api
|    group: it derives the tenant from the Host header (<tenant>.aslv.lab)
|    and stores it as a request attribute. The documents endpoint performs a
|    MISPLACED authorization check against that host-derived tenant instead
|    of the session owner — that is the M3 IDOR.
|  - The api group additionally gets the stateful-API middleware stack
|    (EncryptCookies + AddQueuedCookiesToResponse + StartSession — the same
|    pattern laravel/sanctum uses for cookie-authenticated APIs) so
|    /api/documents/* can be authorized with the login session.
|  - ReflectOriginCors appends the reflected-ACAO CORS trust edge (arch §5.2
|    M2↔M3) to every /api/* response that carries an Origin header.
|  - LogActivity writes the shared activity rows (JSONL + optional
|    ACTIVITY_SINK) for both groups.
*/

use App\Http\Middleware\LogActivity;
use App\Http\Middleware\ReflectOriginCors;
use App\Http\Middleware\ResolveTenant;
use Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Session\Middleware\StartSession;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
    )
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->web(append: [
            ResolveTenant::class,
            LogActivity::class,
        ]);

        $middleware->api(prepend: [
            EncryptCookies::class,
            AddQueuedCookiesToResponse::class,
            StartSession::class,
            ResolveTenant::class,
        ]);
        $middleware->api(append: [
            ReflectOriginCors::class,
            LogActivity::class,
        ]);
    })
    // withExceptions() registers the framework's default exception handler
    // binding (Illuminate\Contracts\Debug\ExceptionHandler). Without it every
    // exception — 404s included — collapses into an empty 500 because the
    // container cannot resolve the handler.
    ->withExceptions(function (Exceptions $exceptions) {
        //
    })
    ->create();
