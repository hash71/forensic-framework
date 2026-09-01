<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Services\ForensicEngineClient;
use Illuminate\Http\JsonResponse;

class EvaluationController extends Controller
{
    public function __construct(
        private readonly ForensicEngineClient $engine,
    ) {}

    /**
     * Get all evaluations.
     */
    public function index(): JsonResponse
    {
        $data = $this->engine->getEvaluation();

        return response()->json($data);
    }

    /**
     * Get evaluation for a specific scenario.
     */
    public function show(string $id): JsonResponse
    {
        $data = $this->engine->getEvaluationForScenario($id);

        return response()->json($data);
    }
}
