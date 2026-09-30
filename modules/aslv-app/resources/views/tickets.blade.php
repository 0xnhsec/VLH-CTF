@extends('layouts.app')

@section('title', 'Support desk')

@section('content')
    <h1>Support desk</h1>
    <p class="hint">
        Every tenant's ticket lands on this desk — the support team sees all of
        them, regardless of tenant.
    </p>

    @forelse ($tickets as $ticket)
        <div class="ticket">
            <div class="subject">#{{ $ticket->id }} · {{ $ticket->subject }}</div>
            <div class="meta">
                from {{ $ticket->requester_username }} ·
                {{ $ticket->created_at?->toIso8601String() }}
                @if ($ticket->doc_ref)
                    · ref <code>{{ $ticket->doc_ref }}</code>
                @endif
            </div>
            <pre>{{ $ticket->body }}</pre>
        </div>
    @empty
        <p class="empty">No tickets.</p>
    @endforelse
@endsection
