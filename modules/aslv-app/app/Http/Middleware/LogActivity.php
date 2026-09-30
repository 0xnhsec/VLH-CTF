<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Shared activity telemetry (CONTRACT: every module logs activity rows
 * {ts, identifier, is_authenticated, data, latency_ms}).
 *
 * Rows are appended to /data/activity.jsonl and, when ACTIVITY_SINK is set
 * (full mode → the M0 collector's /ingest), POSTed there fire-and-forget
 * with a 1s timeout. GET /internal/activity (routes/web.php) serves the
 * latest 5000 rows as NDJSON.
 */
class LogActivity
{
    public const LOG_PATH = '/data/activity.jsonl';

    public function handle(Request $request, Closure $next): Response
    {
        return $next($request);
    }

    public function terminate(Request $request, Response $response): void
    {
        try {
            $start = defined('LARAVEL_START') ? LARAVEL_START : microtime(true);
            $user = $request->user();

            $row = [
                'ts' => gmdate('Y-m-d\TH:i:s\Z'),
                'identifier' => $user
                    ? (string) $user->username
                    : ($request->ip() ?: 'unknown').'/anon',
                'is_authenticated' => (bool) $user,
                'data' => sprintf(
                    '%s %s -> %d',
                    $request->getMethod(),
                    '/'.ltrim($request->path(), '/'),
                    $response->getStatusCode()
                ),
                'latency_ms' => round((microtime(true) - $start) * 1000, 2),
                'unit' => 'm3',
            ];

            $this->append($row);
            $this->sink($row);
        } catch (\Throwable $e) {
            // never break the request because of telemetry
        }
    }

    /** @param array<string,mixed> $row */
    private function append(array $row): void
    {
        @file_put_contents(self::LOG_PATH, json_encode($row)."\n", FILE_APPEND | LOCK_EX);
    }

    /** @param array<string,mixed> $row */
    private function sink(array $row): void
    {
        $sink = trim((string) env('ACTIVITY_SINK', ''));
        if ($sink === '') {
            return;
        }

        try {
            $parts = parse_url($sink);
            if ($parts === false || ! isset($parts['host'])) {
                return;
            }
            $scheme = $parts['scheme'] ?? 'http';
            if (! in_array($scheme, ['http', 'https'], true)) {
                return;
            }
            $host = $parts['host'];
            $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);
            $path = ($parts['path'] ?? '/').(isset($parts['query']) ? '?'.$parts['query'] : '');

            $body = json_encode($row);
            if ($body === false) {
                return;
            }

            $timeout = 1.0;
            $socket = @fsockopen($host, $port, $errno, $errstr, $timeout);
            if ($socket === false) {
                return;
            }
            stream_set_timeout($socket, 1);
            $req = "POST {$path} HTTP/1.1\r\n"
                ."Host: {$host}\r\n"
                ."Content-Type: application/x-ndjson\r\n"
                .'Content-Length: '.strlen($body)."\r\n"
                ."Connection: close\r\n\r\n"
                .$body;
            @fwrite($socket, $req);
            @fclose($socket); // fire-and-forget
        } catch (\Throwable $e) {
            // best effort only
        }
    }

    /** @return list<string> the latest $n activity lines, newest first */
    public static function tail(int $n = 5000): array
    {
        if (! is_file(self::LOG_PATH)) {
            return [];
        }
        $lines = @file(self::LOG_PATH, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            return [];
        }
        if (count($lines) > $n) {
            $lines = array_slice($lines, count($lines) - $n);
        }

        return array_reverse($lines);
    }
}
