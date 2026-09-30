<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Auth\User as Authenticatable;

/**
 * VLH-CTF ASLV M3 user.
 *
 * home_tenant doubles as the tenant subdomain slug (<home_tenant>.aslv.lab);
 * api_key is the session-bound secret other modules' event verifiers match
 * against; uuid is the identifier the M4 API leaks (chain A/B pivot material).
 */
class User extends Authenticatable
{
    protected $fillable = [
        'uuid',
        'username',
        'password',
        'role',
        'home_tenant',
        'email',
        'recovery_email',
        'api_key',
    ];

    protected $hidden = [
        'password',
        'remember_token',
        'api_key',
    ];

    public function documents()
    {
        return $this->hasMany(Document::class, 'owner_id');
    }
}
