<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="referrer" content="no-referrer">
    <title>@yield('title', 'Tenant App') · ASLV</title>
    <style>
        :root {
            --bg: #0a0f0a;
            --panel: #0e1a10;
            --panel-2: #101f13;
            --line: #1c3320;
            --green: #4ade80;
            --green-dim: #2f6b45;
            --text: #d7f5dc;
            --dim: #86b390;
            --red: #ef4444;
        }
        * { box-sizing: border-box; }
        html, body { margin: 0; padding: 0; }
        body {
            background: var(--bg);
            color: var(--text);
            font-family: ui-monospace, "JetBrains Mono", "Fira Code", "Cascadia Mono", Menlo, Consolas, monospace;
            font-size: 14px;
            line-height: 1.6;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        a { color: var(--green); text-decoration: none; }
        a:hover { text-decoration: underline; }
        code {
            background: var(--panel-2);
            border: 1px solid var(--line);
            border-radius: 3px;
            padding: 0 4px;
            color: var(--green);
            word-break: break-all;
        }
        header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 8px 16px;
            padding: 12px 20px;
            border-bottom: 1px solid var(--line);
            background: var(--panel);
        }
        header .brand { color: var(--text); font-weight: 700; letter-spacing: .5px; }
        header .brand span { color: var(--green); }
        nav { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
        nav a { color: var(--dim); }
        nav a.active, nav a:hover { color: var(--green); text-decoration: none; }
        nav form { display: inline; margin: 0; }
        nav button {
            background: none;
            border: 1px solid var(--line);
            color: var(--dim);
            font: inherit;
            padding: 2px 8px;
            border-radius: 3px;
            cursor: pointer;
        }
        nav button:hover { color: var(--red); border-color: var(--red); }
        .chip {
            font-size: 12px;
            color: var(--dim);
            border: 1px dashed var(--line);
            border-radius: 999px;
            padding: 1px 10px;
        }
        .chip b { color: var(--green); font-weight: 600; }
        main { flex: 1; width: 100%; max-width: 980px; margin: 0 auto; padding: 28px 20px 40px; }
        h1 { font-size: 20px; color: var(--green); margin: 0 0 4px; font-weight: 600; }
        h2 { font-size: 15px; color: var(--green); margin: 28px 0 10px; font-weight: 600; border-bottom: 1px solid var(--line); padding-bottom: 4px; }
        .hint { color: var(--dim); font-size: 12.5px; margin: 2px 0 18px; }
        .card {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 6px;
            padding: 24px 26px;
            max-width: 460px;
        }
        label { display: block; margin: 12px 0; color: var(--dim); font-size: 13px; }
        label input[type=text], label input[type=password] {
            display: block;
            width: 100%;
            margin-top: 4px;
            background: var(--bg);
            color: var(--text);
            border: 1px solid var(--line);
            border-radius: 4px;
            padding: 8px 10px;
            font: inherit;
        }
        label input:focus { outline: 1px solid var(--green); border-color: var(--green); }
        label.chk { display: flex; align-items: center; gap: 8px; }
        button.primary {
            background: var(--green-dim);
            color: #eafff0;
            border: 1px solid var(--green);
            border-radius: 4px;
            padding: 9px 16px;
            font: inherit;
            cursor: pointer;
            margin-top: 6px;
        }
        button.primary:hover { background: var(--green); color: #06120a; }
        .errors {
            border: 1px solid var(--red);
            color: var(--red);
            background: rgba(239, 68, 68, .07);
            border-radius: 4px;
            padding: 8px 12px;
            margin: 10px 0;
        }
        table { border-collapse: collapse; width: 100%; margin-top: 8px; }
        th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
        th { color: var(--dim); font-weight: 600; font-size: 12.5px; }
        .meta { color: var(--dim); font-size: 12.5px; margin: 0 0 6px; }
        .ticket {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 6px;
            padding: 14px 18px;
            margin: 14px 0;
        }
        .ticket .subject { color: var(--green); font-weight: 600; }
        .ticket pre {
            white-space: pre-wrap;
            word-break: break-word;
            margin: 8px 0 0;
            color: var(--text);
            font-family: inherit;
        }
        .empty { color: var(--dim); font-style: italic; }
        footer {
            border-top: 1px solid var(--line);
            color: var(--green-dim);
            font-size: 11.5px;
            padding: 10px 20px;
            background: var(--panel);
        }
    </style>
</head>
<body>
<header>
    <div class="brand">ASLV<span>::</span>tenant-app</div>
    <nav>
        @auth
            <a href="{{ url('/dashboard') }}">dashboard</a>
            <a href="{{ url('/support/tickets') }}">support</a>
            <a href="{{ url('/admin/users') }}">admin</a>
            <form method="POST" action="{{ url('/logout') }}">
                @csrf
                <button type="submit">logout ({{ auth()->user()->username }})</button>
            </form>
        @endauth
        @guest
            <a href="{{ url('/login') }}">sign in</a>
        @endguest
        @php
            $browsing = request()->attributes->get('tenant');
        @endphp
        <span class="chip">
            @if ($browsing)
                browsing: <b>{{ $browsing }}</b>@if (request()->attributes->get('tenant_known')) (known tenant)@else (unrecognized)@endif
            @else
                browsing: shared origin (no tenant subdomain)
            @endif
        </span>
    </nav>
</header>
<main>
    @yield('content')
</main>
<footer>VLH-CTF · ASLV M3 · aslv-app · unit m3 · tenant isolation is display-level only</footer>
</body>
</html>
