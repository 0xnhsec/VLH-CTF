<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
|--------------------------------------------------------------------------
| VLH-CTF ASLV M3 — users
|--------------------------------------------------------------------------
|
| Standard Laravel 11 users structure plus the lab columns the controllers
| and the User model actually use:
|
|  uuid           — the identifier the M4 API leaks (chain A/B pivot material)
|  username       — login + ticket requester identity (Auth::attempt key)
|  home_tenant    — doubles as the tenant subdomain slug (<home_tenant>.<domain>)
|  api_key        — session-bound 32-hex secret (event verifiers elsewhere)
|  recovery_email — secondary address (CSRF-target material on the M2 edge)
|  role           — user|tester|innocent|admin (Gate::define('admin') reads it)
|
| `name` is nullable on purpose: App\Models\User does not mass-assign it and
| no view/controller consumes it — username is the display identity here.
*/

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('name')->nullable();
            $table->string('username')->unique();
            $table->uuid('uuid')->unique();
            $table->string('email')->unique();
            $table->timestamp('email_verified_at')->nullable();
            $table->string('password');
            $table->string('home_tenant')->index();
            $table->string('api_key', 64)->nullable();
            $table->string('recovery_email')->nullable();
            $table->string('role')->default('user');
            $table->rememberToken();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('users');
    }
};
