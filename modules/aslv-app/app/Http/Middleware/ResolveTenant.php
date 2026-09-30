<?php

namespace App\Http\Middleware;

use App\Models\User;
use Closure;
use Illuminate\Http\Request;

/**
 * Derives the tenant context from the Host header (<tenant>.aslv.lab) and
 * stores it as request attributes:
 *
 *   tenant       — the tenant slug from the Host header (or null)
 *   tenant_known — whether any user actually owns that home_tenant
 *
 * Per arch §7.2, tenant isolation is display-level only: this middleware
 * never blocks anything. The M3 IDOR lives in DocumentController, which
 * validates the document's tenant against THIS host-derived attribute
 * instead of the session owner.
 */
class ResolveTenant
{
    public function handle(Request $request, Closure $next)
    {
        $reserved = (array) config('lab.reserved_tenants', []);
        $domain = (string) config('lab.domain', 'aslv.lab');

        $host = strtolower((string) $request->headers->get('Host', ''));
        $host = preg_replace('/:\d+$/', '', $host) ?? $host;
        $host = trim($host, '.');

        if ($host !== '' && $domain !== '') {
            $pattern = '/^([a-z0-9-]+)\.'.preg_quote($domain, '/').'$/';
            if (preg_match($pattern, $host, $m) === 1) {
                $tenant = $m[1];
                if (! in_array($tenant, $reserved, true)) {
                    $request->attributes->set('tenant', $tenant);
                    $request->attributes->set(
                        'tenant_known',
                        User::where('home_tenant', $tenant)->exists()
                    );
                }
            }
        }

        return $next($request);
    }
}
