<?php

namespace App\Providers;

use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // Vertical BAC gate: /admin/users is protected by 'can:admin'. The
        // bypass is NOT here — it is the misplaced check in
        // AdminController::impersonate (checks the TARGET, not the caller).
        Gate::define('admin', function ($user) {
            return $user instanceof \App\Models\User && $user->role === 'admin';
        });
    }
}
