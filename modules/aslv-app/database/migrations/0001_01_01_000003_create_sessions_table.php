<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
|--------------------------------------------------------------------------
| VLH-CTF ASLV M3 — sessions
|--------------------------------------------------------------------------
|
| Standard Laravel 11 sessions table. SESSION_DRIVER=database (see
| .env.example / entrypoint): the login session that the /api/* stateful
| group reuses for cookie-authenticated document reads lives here.
*/

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('sessions', function (Blueprint $table) {
            $table->string('id')->primary();
            $table->foreignId('user_id')->nullable()->index();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->text('payload');
            $table->integer('last_activity')->index();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('sessions');
    }
};
