<?php

namespace Database\Seeders;

use App\Models\Document;
use App\Models\Ticket;
use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

/**
 * VLH-CTF ASLV M3 seeder — runs on EVERY container start
 * (`php artisan migrate --seed --force` from entrypoint.sh) and is
 * idempotent: it wipes the lab tables and reseeds them from freshly
 * generated material, so flags and secrets regenerate every restart
 * (CONTRACT §3).
 *
 * Flag flow: entrypoint.sh writes fresh ASLV{IDOR-...} / ASLV{BAC-...}
 * values to /data/flag-idor.txt + /data/flag-bac.txt on every boot; this
 * seeder reads them and plants them into the seeded documents. If a file
 * is missing or malformed (manual `db:seed`, partial volume) the seeder
 * mints its own and writes the file back. Every planted flag is appended
 * to /registry/flags.ndjson (unit "m3", resource-resident, note "held"),
 * with a /data/registry-fallback.ndjson fallback when the registry volume
 * is not writable.
 *
 * Secrets (innocent/admin passwords, api keys) are written ONLY to
 * /data/seed.json — never to any view, response or log the player sees.
 */
class DatabaseSeeder extends Seeder
{
    public function run(): void
    {
        $domain = (string) config('lab.domain', 'aslv.lab');

        // ---- flags (CONTRACT §3) -------------------------------------------
        $idorFlag = $this->loadOrMintFlag('/data/flag-idor.txt', 'IDOR');
        $bacFlag = $this->loadOrMintFlag('/data/flag-bac.txt', 'BAC');

        $this->registerFlag($idorFlag, 'IDOR');
        $this->registerFlag($bacFlag, 'BAC');

        // ---- wipe (child-first; FK constraints are on) ----------------------
        DB::table('documents')->truncate();
        DB::table('tickets')->truncate();
        DB::table('sessions')->truncate();
        DB::table('users')->truncate();

        // ---- org-wide seed spec (full mode may sync the innocent across
        // modules via INNOCENT_* env — same variable names as aslv-api M4) ---
        $username = trim((string) env('INNOCENT_USERNAME', ''));
        if ($username === '') {
            $username = 'usr_'.bin2hex(random_bytes(2)); // usr_<4 hex>, like the sibling modules
        }

        $password = trim((string) env('INNOCENT_PASSWORD', ''));
        if ($password === '') {
            $password = Str::random(16);
        }

        $apiKey = trim((string) env('INNOCENT_API_KEY', ''));
        if ($apiKey === '') {
            $apiKey = bin2hex(random_bytes(16)); // 32 hex
        }

        $userUuid = trim((string) env('INNOCENT_UUID', ''));
        if ($userUuid === '') {
            $userUuid = (string) Str::uuid();
        }

        $docUuid = trim((string) env('INNOCENT_DOC_UUID', ''));
        if ($docUuid === '') {
            $docUuid = (string) Str::uuid();
        }

        // Tenant slugs must survive ResolveTenant's host pattern
        // ([a-z0-9-]+.aslv.lab) — "t-" . $username would carry an underscore
        // for usr_XXXX names and never resolve. Same tenant derivation as
        // aslv-api (M4) / aslv-identity (M5): t + first 6 hex of
        // sha256("aslv-tenant:<username>"), so cross-module pivot material
        // (M4's order note leaks this subdomain) stays consistent.
        $tenantFor = static fn (string $u): string => 't'.substr(hash('sha256', 'aslv-tenant:'.$u), 0, 6);

        $innocentTenant = $tenantFor($username);

        // ---- users ----------------------------------------------------------
        $tester1 = User::create([
            'uuid' => (string) Str::uuid(),
            'username' => '0xnhsec',
            'password' => Hash::make('vlh-tester-01'),
            'role' => 'tester',
            'home_tenant' => $tenantFor('0xnhsec'),
            'email' => '0xnhsec@'.$domain,
            'api_key' => bin2hex(random_bytes(16)),
        ]);

        User::create([
            'uuid' => (string) Str::uuid(),
            'username' => 'Noshiro',
            'password' => Hash::make('vlh-tester-02'),
            'role' => 'tester',
            'home_tenant' => $tenantFor('Noshiro'),
            'email' => 'noshiro@'.$domain,
            'api_key' => bin2hex(random_bytes(16)),
        ]);

        $adminPassword = Str::random(16);

        $admin = User::create([
            'uuid' => (string) Str::uuid(),
            'username' => 'admin',
            'password' => Hash::make($adminPassword),
            'role' => 'admin',
            'home_tenant' => 't-admin',
            'email' => 'admin@'.$domain,
            'api_key' => bin2hex(random_bytes(16)),
        ]);

        $innocent = User::create([
            'uuid' => $userUuid,
            'username' => $username,
            'password' => Hash::make($password),
            'role' => 'innocent',
            'home_tenant' => $innocentTenant,
            'email' => $username.'@'.$domain,
            'recovery_email' => $username.'+recovery@'.$domain,
            'api_key' => $apiKey,
        ]);

        // ---- documents (resource-resident flags) ----------------------------

        // The innocent's private vault — carries the IDOR flag + pivot hints.
        Document::create([
            'uuid' => $docUuid,
            'owner_id' => $innocent->id,
            'tenant' => $innocentTenant,
            'title' => 'Personal vault',
            'body' => implode("\n", [
                'Private notes of '.$username.' — tenant '.$innocentTenant.'.',
                '',
                'flag: '.$idorFlag,
                'owner email: '.$innocent->email,
                'pivot: M4 /user/v1/profile leaks identifiers',
            ]),
            'pivot_hint' => 'pivot: M4 /user/v1/profile leaks identifiers',
        ]);

        // Admin-only runbook — carries the BAC flag. Its tenant is the literal
        // slug 'admin' (AdminController::impersonate filters on it), NOT the
        // admin user's home_tenant.
        Document::create([
            'uuid' => (string) Str::uuid(),
            'owner_id' => $admin->id,
            'tenant' => 'admin',
            'title' => 'Operations runbook (admin only)',
            'body' => implode("\n", [
                'Administrative runbook — restricted to platform administrators.',
                '',
                'flag: '.$bacFlag,
            ]),
            'pivot_hint' => 'vertical: full-mode escalation runs through the identity provider (auth.aslv.lab)',
        ]);

        // ---- tickets (the legitimate leak point) ----------------------------

        // The innocent's plea: references /api/documents/{uuid} and her tenant
        // subdomain — everything an attacker needs for the cross-tenant IDOR.
        $ticket = Ticket::create([
            'requester_username' => $innocent->username,
            'subject' => 'Please restore my document',
            'body' => implode("\n", [
                'Hi support team,',
                '',
                'My personal vault document disappeared from the tenant view and I need it restored urgently. It is served at:',
                '',
                'https://'.$innocentTenant.'.'.$domain.'/api/documents/'.$docUuid,
                '',
                'It belongs to my tenant space ('.$innocentTenant.'.'.$domain.') — please restore it there and not into the shared space.',
                '',
                'Thanks,',
                $innocent->username,
            ]),
        ]);
        $ticket->user_id = $innocent->id;
        $ticket->doc_ref = '/api/documents/'.$docUuid;
        $ticket->save();

        // A tester ticket so the desk looks lived-in (no secrets).
        $testerTicket = Ticket::create([
            'requester_username' => $tester1->username,
            'subject' => 'Empty document list on my tenant dashboard',
            'body' => 'My dashboard shows no documents and GET /api/documents returns an empty list. Is that expected for tester tenants?',
        ]);
        $testerTicket->user_id = $tester1->id;
        $testerTicket->save();

        // ---- grading-only seed dump (NEVER player-visible) -------------------
        $dump = [
            'generated_at' => gmdate('Y-m-d\TH:i:s\Z'),
            'unit' => 'm3',
            'innocent' => [
                'username' => $innocent->username,
                'password' => $password,
                'api_key' => $apiKey,
                'uuid' => $userUuid,
                'home_tenant' => $innocentTenant,
                'document_uuid' => $docUuid,
            ],
            'admin' => [
                'username' => $admin->username,
                'password' => $adminPassword,
            ],
            'flags' => [
                'idor' => $idorFlag,
                'bac' => $bacFlag,
            ],
        ];
        @file_put_contents(
            '/data/seed.json',
            json_encode($dump, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n"
        );

        $this->command?->info(sprintf(
            '[m3] seeded: innocent=%s tenant=%s doc=%s (flags held: IDOR/BAC)',
            $innocent->username,
            $innocentTenant,
            $docUuid,
        ));
    }

    /**
     * Read the flag the entrypoint minted for this boot; mint (and write
     * back) ourselves when the file is absent or malformed.
     */
    private function loadOrMintFlag(string $path, string $category): string
    {
        $flag = '';
        if (is_file($path)) {
            $flag = trim((string) @file_get_contents($path));
        }

        if (preg_match('/^ASLV\{'.$category.'-[0-9]{9,}\}$/', $flag) === 1) {
            return $flag;
        }

        $digits = '';
        for ($i = 0; $i < 9; $i++) {
            $digits .= (string) random_int(0, 9);
        }

        $flag = sprintf('ASLV{%s-%s}', $category, $digits);
        @file_put_contents($path, $flag."\n");

        return $flag;
    }

    /**
     * Registry line per CONTRACT §3 (resource-resident, held).
     */
    private function registerFlag(string $flag, string $category): void
    {
        $line = json_encode([
            'flag' => $flag,
            'category' => $category,
            'unit' => 'm3',
            'archetype' => 'resource-resident',
            'minted_at' => gmdate('Y-m-d\TH:i:s\Z'),
            'note' => 'held',
        ])."\n";

        if (@file_put_contents('/registry/flags.ndjson', $line, FILE_APPEND | LOCK_EX) === false) {
            @file_put_contents('/data/registry-fallback.ndjson', $line, FILE_APPEND | LOCK_EX);
        }
    }
}
