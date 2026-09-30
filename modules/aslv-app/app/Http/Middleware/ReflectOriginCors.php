<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The M2↔M3 CORS trust edge (arch §5.2): every /api/* response that carries
 * an Origin request header reflects it verbatim in
 * Access-Control-Allow-Origin together with Access-Control-Allow-Credentials:
 * true. In full mode this is what a page hosted on M2's attacker vhost reads
 * cross-site with the victim's cookies. In standalone it is a harmless
 * always-on misconfiguration to explore.
 */
class ReflectOriginCors
{
    public function handle(Request $request, Closure $next): Response
    {
        if ($request->isMethod('OPTIONS')) {
            return $this->withCors($request, response('', 204, [
                'Allow' => 'GET, OPTIONS',
            ]));
        }

        return $this->withCors($request, $next($request));
    }

    private function withCors(Request $request, Response $response): Response
    {
        $origin = $request->headers->get('Origin');

        if ($origin !== null && $origin !== '') {
            $response->headers->set('Access-Control-Allow-Origin', $origin); // deliberate reflection
            $response->headers->set('Access-Control-Allow-Credentials', 'true');
            $response->headers->set('Access-Control-Allow-Methods', 'GET, OPTIONS');
            $response->headers->set('Access-Control-Allow-Headers', $request->headers->get('Access-Control-Request-Headers') ?? 'content-type');
            $response->headers->set('Vary', 'Origin');
        }

        return $response;
    }
}
