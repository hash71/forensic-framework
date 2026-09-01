<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Services\ForensicEngineClient;
use Illuminate\Http\JsonResponse;

class BaselineController extends Controller
{
    public function __construct(
        private readonly ForensicEngineClient $engine,
    ) {}

    /**
     * Get user baselines.
     */
    public function index(): JsonResponse
    {
        $data = $this->engine->getBaselines();

        return response()->json($data);
    }

    /**
     * Get ground truth data.
     */
    public function groundTruth(): JsonResponse
    {
        $data = $this->engine->getGroundTruth();

        return response()->json($data);
    }
}
