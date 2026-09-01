<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Services\ForensicEngineClient;
use Illuminate\Http\JsonResponse;

class ReportController extends Controller
{
    public function __construct(
        private readonly ForensicEngineClient $engine,
    ) {}

    /**
     * Get the forensic report for a scenario.
     */
    public function show(string $id): JsonResponse
    {
        $data = $this->engine->getReport($id);

        return response()->json($data);
    }
}
