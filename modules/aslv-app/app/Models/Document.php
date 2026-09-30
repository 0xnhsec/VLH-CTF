<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Document extends Model
{
    protected $fillable = [
        'uuid',
        'owner_id',
        'tenant',
        'title',
        'body',
        'pivot_hint',
    ];
}
