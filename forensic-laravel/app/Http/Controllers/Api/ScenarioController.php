<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Services\ForensicEngineClient;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class ScenarioController extends Controller
{
    public function __construct(
        private readonly ForensicEngineClient $engine,
    ) {}

    /**
     * List all scenarios.
     */
    public function index(): JsonResponse
    {
        $data = $this->engine->getScenarios();

        return response()->json($data);
    }

    /**
     * Get a single scenario.
     */
    public function show(string $id): JsonResponse
    {
        $data = $this->engine->getScenario($id);

        return response()->json($data);
    }

    /**
     * Get events for a scenario with optional filters.
     */
    public function events(string $id, Request $request): JsonResponse
    {
        $filters = $request->only(['source_type', 'action', 'user']);
        $data = $this->engine->getEvents($id, $filters);

        return response()->json($data);
    }

    /**
     * Get timeline data for a scenario.
     */
    public function timeline(string $id): JsonResponse
    {
        $data = $this->engine->getTimeline($id);

        return response()->json($data);
    }
}
