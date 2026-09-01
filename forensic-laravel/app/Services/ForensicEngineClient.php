<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class ForensicEngineClient
{
    private string $baseUrl;
    private int $timeout;
    private int $queryTimeout;

    public function __construct()
    {
        $this->baseUrl = rtrim(config('forensic.engine_url'), '/');
        $this->timeout = (int) config('forensic.engine_timeout', 300);
        $this->queryTimeout = (int) config('forensic.query_timeout', 30);
    }

    /**
     * List all scenarios.
     */
    public function getScenarios(): array
    {
        return $this->get('/api/scenarios');
    }

    /**
     * Get a single scenario by ID.
     */
    public function getScenario(string $id): array
    {
        return $this->get("/api/scenarios/{$id}");
    }

    /**
     * Get events for a scenario with optional filters.
     */
    public function getEvents(string $id, array $filters = []): array
    {
        return $this->get("/api/events/{$id}", $filters);
    }

    /**
     * Get timeline data for a scenario.
     */
    public function getTimeline(string $id): array
    {
        return $this->get("/api/timeline/{$id}");
    }

    /**
     * Get rule-based analysis results for a scenario.
     */
    public function getRuleResults(string $id): array
    {
        return $this->get("/api/rules/{$id}");
    }

    /**
     * Get LLM analysis results for a scenario.
     */
    public function getLlmResults(string $id): array
    {
        return $this->get("/api/llm/{$id}");
    }

    /**
     * Get all evaluations.
     */
    public function getEvaluation(): array
    {
        return $this->get('/api/evaluation');
    }

    /**
     * Get evaluation for a specific scenario.
     */
    public function getEvaluationForScenario(string $id): array
    {
        return $this->get("/api/evaluation/{$id}");
    }

    /**
     * Get the forensic report for a scenario.
     */
    public function getReport(string $id): array
    {
        return $this->get("/api/reports/{$id}");
    }

    /**
     * Run the analysis pipeline.
     */
    public function runPipeline(bool $useMock = false): array
    {
        return $this->post('/api/pipeline/run', ['use_mock' => $useMock]);
    }

    /**
     * Get user baselines.
     */
    public function getBaselines(): array
    {
        return $this->get('/api/baselines');
    }

    /**
     * Get ground truth data.
     */
    public function getGroundTruth(): array
    {
        return $this->get('/api/ground-truth');
    }

    /**
     * Perform a GET request to the engine.
     */
    private function get(string $path, array $query = []): array
    {
        try {
            $response = Http::timeout($this->queryTimeout)
                ->get("{$this->baseUrl}{$path}", $query);

            if ($response->successful()) {
                return $response->json() ?? [];
            }

            Log::warning('Forensic engine returned error', [
                'path' => $path,
                'status' => $response->status(),
                'body' => $response->body(),
            ]);

            return [
                'error' => true,
                'message' => "Engine returned HTTP {$response->status()}",
                'status' => $response->status(),
            ];
        } catch (\Exception $e) {
            Log::error('Forensic engine request failed', [
                'path' => $path,
                'error' => $e->getMessage(),
            ]);

            return [
                'error' => true,
                'message' => 'Failed to connect to forensic engine: ' . $e->getMessage(),
            ];
        }
    }

    /**
     * Perform a POST request to the engine.
     */
    private function post(string $path, array $data = []): array
    {
        try {
            $response = Http::timeout($this->timeout)
                ->post("{$this->baseUrl}{$path}", $data);

            if ($response->successful()) {
                return $response->json() ?? [];
            }

            Log::warning('Forensic engine POST returned error', [
                'path' => $path,
                'status' => $response->status(),
                'body' => $response->body(),
            ]);

            return [
                'error' => true,
                'message' => "Engine returned HTTP {$response->status()}",
                'status' => $response->status(),
            ];
        } catch (\Exception $e) {
            Log::error('Forensic engine POST request failed', [
                'path' => $path,
                'error' => $e->getMessage(),
            ]);

            return [
                'error' => true,
                'message' => 'Failed to connect to forensic engine: ' . $e->getMessage(),
            ];
        }
    }
}
