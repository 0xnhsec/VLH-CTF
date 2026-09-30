<?php

use App\Http\Controllers\DocumentController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| VLH-CTF ASLV M3 — API routes (auto-prefixed with /api)
|--------------------------------------------------------------------------
|
| The api group (bootstrap/app.php) is the stateful-API stack: cookies +
| StartSession prepended, ResolveTenant for the Host-derived tenant, then
| ReflectOriginCors appended — every /api/* response carrying an Origin
| header reflects it verbatim in Access-Control-Allow-Origin with
| Access-Control-Allow-Credentials: true (the M2↔M3 trust edge, arch §5.2).
|
| Endpoint map:
|
|  GET /api/documents            own documents only (correct ownership check)
|  GET /api/documents/{uuid}     THE M3 IDOR: the document's tenant is
|                                validated against the HOST-derived tenant,
|                                not the session owner — browsing via the
|                                owner's tenant subdomain grants access.
|  OPTIONS /api/**               preflight surface for the reflected CORS edge
*/

Route::middleware('auth')->group(function () {
    // Own documents only — the correct ownership check (the shortcut test:
    // this must remain the ONLY documented list of what a session may read).
    Route::get('/documents', [DocumentController::class, 'index'])
        ->name('api.documents.index');

    // THE M3 IDOR (arch §7.0, "misplaced check"). GET /api/documents/{uuid}
    // compares $document->tenant against the tenant resolved from the Host
    // header — a request via <owner-tenant>.aslv.lab with any authenticated
    // session reads the innocent's private vault (flag + pivot material).
    Route::get('/documents/{uuid}', [DocumentController::class, 'show'])
        ->whereUuid('uuid')
        ->name('api.documents.show');
});

// Preflight surface so browser exploits that send custom headers get a
// reflected-ACAO answer from ReflectOriginCors (the group middleware wraps
// this route like any other). Unauthenticated by design — preflights carry
// no credentials.
Route::options('/{any}', fn () => response('', 204))->where('any', '.*');
