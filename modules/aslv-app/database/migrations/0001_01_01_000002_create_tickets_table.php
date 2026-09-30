<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
|--------------------------------------------------------------------------
| VLH-CTF ASLV M3 — tickets
|--------------------------------------------------------------------------
|
| The support desk sees EVERY ticket (SupportController) — the legitimate
| leak point. The innocent's seeded ticket references her private document
| URL (/api/documents/{uuid}) and her tenant subdomain: exactly what an
| attacker needs for the cross-tenant IDOR.
|
| requester_username is the identity the app queries (AuthController +
| Ticket model $fillable); user_id is a nullable normalized FK and doc_ref
| a nullable machine reference to the document the ticket is about (both
| set by the seeder outside of mass assignment).
*/

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('tickets', function (Blueprint $table) {
            $table->id();
            $table->string('requester_username')->index();
            $table->foreignId('user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->string('subject');
            $table->text('body');
            $table->string('doc_ref')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('tickets');
    }
};
