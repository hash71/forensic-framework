<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Services\ForensicEngineClient;
use Illuminate\Http\JsonResponse;

class AnalysisController extends Controller
{
    public function __construct(
        private readonly ForensicEngineClient $engine,
    ) {}

    /**
     * Get rule-based analysis results for a scenario.
     */
    public function rules(string $id): JsonResponse
    {
        $data = $this->engine->getRuleResults($id);

        return response()->json($data);
    }

    /**
     * Get LLM analysis results for a scenario.
     */
    public function llm(string $id): JsonResponse
    {
        $data = $this->engine->getLlmResults($id);

        return response()->json($data);
    }
}
