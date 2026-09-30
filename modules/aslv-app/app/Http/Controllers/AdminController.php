<?php

namespace App\Http\Controllers;

use App\Models\Document;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class AdminController extends Controller
{
    /**
     * Vertical BAC, properly gated: requires role=admin via the 'can:admin'
     * middleware (Gate::define in AppServiceProvider). Testers and the
     * innocent get 403 here — the intended escalation in full mode is the
     * M5-forged-JWT trust edge; in standalone this endpoint demonstrates the
     * wall the misplaced check below fails to be.
     *
     * @return JsonResponse
     */
    public function index(Request $request)
    {
        $users = User::orderBy('id')
            ->get(['id', 'uuid', 'username', 'role', 'home_tenant', 'email', 'recovery_email']);

        return response()->json([
            'users' => $users,
            'note' => 'full directory — admin only',
        ]);
    }

    /**
     * THE M3 BAC bypass (arch §7.0, "vertical: admin-only resource behind
     * escalation"): MISPLACED CHECK — this endpoint verifies that the TARGET
     * user is an administrator, never the CALLER. Any authenticated user can
     * impersonate the admin and receive the admin-only document carrying
     * ASLV{BAC-...}.
     *
     * Accepts ?user_id=<id|username>.
     *
     * @return JsonResponse
     */
    public function impersonate(Request $request)
    {
        $id = trim((string) $request->query('user_id', ''));
        if ($id === '') {
            return response()->json(['error' => 'user_id query parameter required'], 400);
        }

        $target = ctype_digit($id)
            ? User::find((int) $id)
            : User::where('username', $id)->first();

        if ($target === null) {
            return response()->json(['error' => 'no such user'], 404);
        }

        // MISPLACED: the TARGET's role is checked, not the caller's.
        if ($target->role !== 'admin') {
            return response()->json([
                'error' => 'forbidden',
                'reason' => 'target is not an administrator',
            ], 403);
        }

        $document = Document::where('owner_id', $target->id)
            ->where('tenant', 'admin')
            ->first();

        return response()->json([
            'impersonated' => $target->username,
            'role' => $target->role,
            'admin_document' => $document === null ? null : [
                'uuid' => $document->uuid,
                'title' => $document->title,
                'body' => $document->body,
                'pivot_hint' => $document->pivot_hint,
            ],
        ]);
    }
}
