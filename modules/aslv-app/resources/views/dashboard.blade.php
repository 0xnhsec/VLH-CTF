@extends('layouts.app')

@section('title', 'Dashboard')

@section('content')
    <h1>Dashboard</h1>
    <p class="meta">
        signed in as <b>{{ $user->username }}</b> ·
        role {{ $user->role }} ·
        home tenant <code>{{ $user->home_tenant }}</code>
        (<code>{{ $user->home_tenant }}.{{ config('lab.domain') }}</code>)
    </p>
    <p class="hint">
        Session cookies are shared across every tenant subdomain of
        {{ config('lab.domain') }} — single-organization SSO feel.
    </p>

    <h2>Documents</h2>
    @if ($documents->isEmpty())
        <p class="empty">No documents in your vault.</p>
        <p class="hint">
            The document API lives at <code>GET /api/documents</code> (your list)
            and <code>GET /api/documents/{uuid}</code> (one document).
        </p>
    @else
        <table>
            <thead>
                <tr>
                    <th>title</th>
                    <th>tenant</th>
                    <th>uuid</th>
                    <th></th>
                </tr>
            </thead>
            <tbody>
                @foreach ($documents as $document)
                    <tr>
                        <td>{{ $document->title }}</td>
                        <td><code>{{ $document->tenant }}</code></td>
                        <td><code>{{ $document->uuid }}</code></td>
                        <td><a href="{{ url('/api/documents/'.$document->uuid) }}">open (JSON)</a></td>
                    </tr>
                @endforeach
            </tbody>
        </table>
    @endif

    <h2>Your recent support tickets</h2>
    @if ($tickets->isEmpty())
        <p class="empty">You have not opened any tickets.</p>
    @else
        @foreach ($tickets as $ticket)
            <div class="ticket">
                <div class="subject">#{{ $ticket->id }} · {{ $ticket->subject }}</div>
                <div class="meta">from {{ $ticket->requester_username }} · {{ $ticket->created_at?->toIso8601String() }}</div>
                <pre>{{ $ticket->body }}</pre>
            </div>
        @endforeach
    @endif
    <p class="hint">
        Need help? <a href="{{ url('/support/tickets') }}">Open the support desk →</a>
    </p>

    <h2>Administration</h2>
    <p class="hint">
        <a href="{{ url('/admin/users') }}">GET /admin/users</a> — full user
        directory, administrators only.
    </p>
@endsection
