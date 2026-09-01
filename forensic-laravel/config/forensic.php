<?php

return [
    'engine_url' => env('FORENSIC_ENGINE_URL', 'http://localhost:8000'),
    'engine_timeout' => env('FORENSIC_ENGINE_TIMEOUT', 300),
    'query_timeout' => env('FORENSIC_QUERY_TIMEOUT', 30),
    'modal_endpoint' => env('MODAL_ENDPOINT', ''),
    'modal_model' => env('MODAL_MODEL', 'fusion-brain'),
    'modal_timeout' => env('MODAL_TIMEOUT', 300),
];
