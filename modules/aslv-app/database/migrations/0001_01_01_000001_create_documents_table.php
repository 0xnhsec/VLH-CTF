<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
|--------------------------------------------------------------------------
| VLH-CTF ASLV M3 — documents
|--------------------------------------------------------------------------
|
| Resource-resident flag carriers (CONTRACT §3/§6): the innocent's private
| document holds ASLV{IDOR-...} + pivot material, the admin-only document
| holds ASLV{BAC-...}. `tenant` is the misplaced-authorization pivot the
| DocumentController compares against the HOST-derived tenant (the M3 IDOR).
*/

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('documents', function (Blueprint $table) {
            $table->id();
            $table->uuid('uuid')->unique();
            $table->foreignId('owner_id')->constrained('users')->cascadeOnDelete();
            $table->string('tenant')->index();
            $table->string('title');
            $table->text('body');
            $table->text('pivot_hint')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('documents');
    }
};
