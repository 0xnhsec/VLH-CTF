<?php

namespace App\Http\Controllers;

use App\Models\Ticket;
use Illuminate\Http\Request;
use Illuminate\View\View;

class SupportController extends Controller
{
    /**
     * The support desk sees every ticket — that is the LEGITIMATE leak point
     * (arch §7.0: "UUID only via chained leak point"). The innocent's seeded
     * ticket references her private document URL and her tenant subdomain,
     * which is everything an attacker needs for the cross-tenant IDOR.
     */
    public function index(Request $request): View
    {
        return view('tickets', [
            'tickets' => Ticket::orderBy('id')->get(),
            'tenant' => $request->attributes->get('tenant'),
        ]);
    }
}
