<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Services\AuditService;
use App\Services\ForensicEngineClient;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class PipelineController extends Controller
{
    public function __construct(
        private readonly ForensicEngineClient $engine,
        private readonly AuditService $audit,
    ) {}

    /**
     * Run the analysis pipeline.
     */
    public function run(Request $request): JsonResponse
    {
        $useMock = (bool) $request->input('use_mock', false);
        $startTime = microtime(true);

        $data = $this->engine->runPipeline($useMock);

        $durationMs = (int) ((microtime(true) - $startTime) * 1000);

        $this->audit->logPipelineRun([
            'use_mock' => $useMock,
            'duration_ms' => $durationMs,
            'success' => !isset($data['error']),
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
        ]);

        return response()->json($data);
    }

    /**
     * Get pipeline status.
     */
    public function status(): JsonResponse
    {
        return response()->json([
            'status' => 'ready',
            'engine_url' => config('forensic.engine_url'),
            'timestamp' => now()->toIso8601String(),
        ]);
    }
}
