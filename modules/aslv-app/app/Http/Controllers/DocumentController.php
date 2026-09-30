<?php

namespace App\Http\Controllers;

use App\Models\Document;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

class DocumentController extends Controller
{
    /**
     * Own documents only (the CORRECT ownership check — the shortcut test).
     *
     * @return JsonResponse
     */
    public function index(Request $request)
    {
        $documents = Document::where('owner_id', $request->user()->id)
            ->orderBy('title')
            ->get(['uuid', 'title', 'tenant']);

        return response()->json([
            'tenant' => $request->attributes->get('tenant'),
            'documents' => $documents,
        ]);
    }

    /**
     * THE M3 IDOR (arch §7.0): misplaced authorization.
     *
     * The check exists — but it validates the DOCUMENT's tenant against the
     * TENANT DERIVED FROM THE HOST HEADER, not against the session owner.
     * Browsing via the owner's tenant subdomain (Host: <owner>.aslv.lab)
     * grants read access to her private document, flag and pivot material.
     * Misplaced ≠ absent — that is what separates ASLV from DSLTV difficulty.
     *
     * @return JsonResponse
     */
    public function show(Request $request, string $uuid)
    {
        $document = Document::where('uuid', $uuid)->first();
        if ($document === null) {
            throw new NotFoundHttpException('no such document');
        }

        $hostTenant = $request->attributes->get('tenant');

        if ($document->tenant !== $hostTenant) {
            return response()->json([
                'error' => 'forbidden',
                'reason' => 'document tenant does not match the tenant you are browsing from',
                'document_tenant' => $document->tenant,
                'browsing_tenant' => $hostTenant,
            ], 403);
        }

        return response()->json([
            'uuid' => $document->uuid,
            'title' => $document->title,
            'tenant' => $document->tenant,
            'body' => $document->body,
            'pivot_hint' => $document->pivot_hint,
        ]);
    }
}
