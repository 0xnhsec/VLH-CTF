<?php

use App\Http\Controllers\AdminController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\SupportController;
use App\Http\Middleware\LogActivity;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| VLH-CTF ASLV M3 — web routes (session + CSRF group)
|--------------------------------------------------------------------------
|
| The web group (bootstrap/app.php) carries the standard Laravel stack plus
| ResolveTenant (derives the browsing tenant from the Host header) and
| LogActivity (activity JSONL + optional ACTIVITY_SINK).
|
| Endpoint map (see README.md for the full story):
|
|  GET  /                         welcome / login form
|  GET  /login                    same form (redirect target; authed → /dashboard)
|  POST /login                    session login (username + password)
|  POST /logout                   logout
|  GET  /dashboard                own documents + own tickets            (auth)
|  GET  /support/tickets          support desk — LEGIT leak point        (auth)
|  GET  /admin/users              user directory — proper admin gate    (auth+admin)
|  GET  /admin/users/impersonate  MISPLACED check — the M3 BAC bypass   (auth)
|  GET  /internal/activity        activity feed, NDJSON (TUI/infra only)
*/

// Welcome / login form. The tenant attribute shows which tenant subdomain
// the player is browsing from (ResolveTenant middleware).
Route::get('/', [AuthController::class, 'showLogin'])->name('welcome');
Route::get('/login', [AuthController::class, 'showLogin'])->name('login');
Route::post('/login', [AuthController::class, 'login'])->name('login.attempt');
Route::post('/logout', [AuthController::class, 'logout'])->name('logout');

Route::middleware('auth')->group(function () {
    // Own documents + own tickets (authed landing page).
    Route::get('/dashboard', [AuthController::class, 'dashboard'])->name('dashboard');

    // Support desk — every authenticated user sees EVERY ticket. The
    // innocent's seeded ticket references her private document URL and her
    // tenant subdomain: the legitimate leak point (arch §7.0).
    Route::get('/support/tickets', [SupportController::class, 'index'])->name('support.tickets');

    // THE M3 BAC bypass (arch §7.0): the MISPLACED check verifies the TARGET
    // user's role, never the caller's — any authenticated user can
    // impersonate the admin and receive the BAC-flagged admin document.
    // Accepts ?user_id=<id|username>.
    Route::get('/admin/users/impersonate', [AdminController::class, 'impersonate'])
        ->name('admin.users.impersonate');
});

// Vertical BAC wall, properly gated: 'can:admin' resolves Gate::define in
// AppServiceProvider — testers and the innocent get 403 here. Registered
// after the static impersonate path (both are exact matches, so ordering is
// belt and braces only).
Route::get('/admin/users', [AdminController::class, 'index'])
    ->middleware(['auth', 'can:admin'])
    ->name('admin.users');

// Activity feed (CONTRACT §6 / TUI FR-8): latest 5000 rows as NDJSON.
// Infra-only, no auth (the TUI polls with Host: collector.aslv.lab). In
// full mode this route is unreachable: the gateway serves collector.aslv
// .lab from the M2 portal and 404s /internal/* on every vhost that reaches
// this app; the standalone sidecar only exposes it on the collector vhost.
Route::get('/internal/activity', function () {
    $lines = LogActivity::tail(5000);

    return response(
        $lines === [] ? '' : implode("\n", $lines)."\n",
        200,
        ['Content-Type' => 'application/x-ndjson', 'Cache-Control' => 'no-store']
    );
})->name('internal.activity');
