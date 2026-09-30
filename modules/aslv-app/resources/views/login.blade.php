@extends('layouts.app')

@section('title', 'Sign in')

@section('content')
    <div class="card">
        <h1>Tenant sign-in</h1>
        <p class="hint">
            One organization, one session cookie for
            <code>*.{{ config('lab.domain') }}</code>, one tenant per subdomain.
        </p>

        @if ($errors->any())
            <div class="errors">{{ $errors->first() }}</div>
        @endif

        <form method="POST" action="{{ url('/login') }}">
            @csrf
            <label>
                username
                <input type="text" name="username" value="{{ old('username') }}" autocomplete="username" autofocus required>
            </label>
            <label>
                password
                <input type="password" name="password" autocomplete="current-password" required>
            </label>
            <label class="chk">
                <input type="checkbox" name="remember" value="1"> remember me on this device
            </label>
            <button type="submit" class="primary">sign in</button>
        </form>

        <p class="hint">
            Known tester accounts (see the player guide):
            <code>0xnhsec / vlh-tester-01</code> ·
            <code>Noshiro / vlh-tester-02</code>
        </p>
    </div>
@endsection
