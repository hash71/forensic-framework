<?php

namespace App\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

class AuditService
{
    /**
     * Log a pipeline run event.
     */
    public function logPipelineRun(array $data): void
    {
        $this->store('pipeline_run', $data);
    }

    /**
     * Log an LLM call with request/response details.
     */
    public function logLlmCall(array $data): void
    {
        $this->store('llm_call', $data);
    }

    /**
     * Log an API access event.
     */
    public function logApiAccess(Request $request, mixed $response): void
    {
        $responseData = method_exists($response, 'getData')
            ? json_decode(json_encode($response->getData()), true)
            : (is_array($response) ? $response : ['raw' => (string) $response]);

        $this->store('api_access', [
            'method' => $request->method(),
            'path' => $request->path(),
            'query' => $request->query(),
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
        ], $responseData);
    }

    /**
     * Store an audit log entry.
     */
    private function store(string $action, array $requestData, ?array $responseData = null): void
    {
        try {
            DB::table('audit_logs')->insert([
                'action' => $action,
                'request_data' => json_encode($requestData),
                'response_data' => $responseData !== null ? json_encode($responseData) : null,
                'duration_ms' => $requestData['duration_ms'] ?? null,
                'ip_address' => $requestData['ip_address'] ?? null,
                'user_agent' => $requestData['user_agent'] ?? null,
                'created_at' => now(),
            ]);
        } catch (\Exception $e) {
            Log::error('Failed to write audit log', [
                'action' => $action,
                'error' => $e->getMessage(),
            ]);
        }
    }
}
