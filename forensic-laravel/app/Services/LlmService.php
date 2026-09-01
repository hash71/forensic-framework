<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class LlmService
{
    private string $endpoint;
    private string $model;
    private int $timeout;

    public function __construct()
    {
        $this->endpoint = rtrim(config('forensic.modal_endpoint'), '/');
        $this->model = config('forensic.modal_model', 'fusion-brain');
        $this->timeout = (int) config('forensic.modal_timeout', 300);
    }

    /**
     * Send a prompt to the LLM via Modal endpoint.
     *
     * @param string $prompt The user prompt
     * @param string $systemPrompt Optional system prompt
     * @return array{content: string|null, error: string|null, raw: mixed}
     */
    public function analyze(string $prompt, string $systemPrompt = ''): array
    {
        if (empty($this->endpoint)) {
            return [
                'content' => null,
                'error' => 'Modal endpoint not configured',
                'raw' => null,
            ];
        }

        $messages = [];

        if (!empty($systemPrompt)) {
            $messages[] = [
                'role' => 'system',
                'content' => $systemPrompt,
            ];
        }

        $messages[] = [
            'role' => 'user',
            'content' => $prompt,
        ];

        $payload = [
            'model' => $this->model,
            'messages' => $messages,
            'chat_template_kwargs' => [
                'enable_thinking' => false,
            ],
        ];

        try {
            $response = Http::timeout($this->timeout)
                ->withOptions(['allow_redirects' => ['max' => 5]])
                ->post("{$this->endpoint}/v1/chat/completions", $payload);

            if (!$response->successful()) {
                Log::warning('LLM request failed', [
                    'status' => $response->status(),
                    'body' => $response->body(),
                ]);

                return [
                    'content' => null,
                    'error' => "LLM returned HTTP {$response->status()}",
                    'raw' => $response->json(),
                ];
            }

            $data = $response->json();
            $content = $data['choices'][0]['message']['content'] ?? null;

            if ($content !== null) {
                $content = $this->parseContent($content);
            }

            return [
                'content' => $content,
                'error' => null,
                'raw' => $data,
            ];
        } catch (\Exception $e) {
            Log::error('LLM request exception', [
                'error' => $e->getMessage(),
            ]);

            return [
                'content' => null,
                'error' => 'LLM request failed: ' . $e->getMessage(),
                'raw' => null,
            ];
        }
    }

    /**
     * Parse content from LLM response, handling markdown code blocks.
     */
    private function parseContent(string $content): string
    {
        // Try to extract JSON from markdown code blocks
        if (preg_match('/```(?:json)?\s*\n?(.*?)\n?\s*```/s', $content, $matches)) {
            $jsonCandidate = trim($matches[1]);
            $decoded = json_decode($jsonCandidate, true);

            if (json_last_error() === JSON_ERROR_NONE) {
                return $jsonCandidate;
            }
        }

        // Try to parse the whole content as JSON
        $decoded = json_decode(trim($content), true);
        if (json_last_error() === JSON_ERROR_NONE) {
            return trim($content);
        }

        // Return raw content as-is
        return $content;
    }
}
