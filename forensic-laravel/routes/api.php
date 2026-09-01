<?php

use App\Http\Controllers\Api\AnalysisController;
use App\Http\Controllers\Api\BaselineController;
use App\Http\Controllers\Api\EvaluationController;
use App\Http\Controllers\Api\PipelineController;
use App\Http\Controllers\Api\ReportController;
use App\Http\Controllers\Api\ScenarioController;
use Illuminate\Support\Facades\Route;

// Health check
Route::get('/', function () {
    return response()->json([
        'status' => 'ok',
        'service' => 'forensic-laravel',
    ]);
});

// Scenarios
Route::get('/scenarios', [ScenarioController::class, 'index']);
Route::get('/scenarios/{id}', [ScenarioController::class, 'show']);
Route::get('/scenarios/{id}/events', [ScenarioController::class, 'events']);
Route::get('/scenarios/{id}/timeline', [ScenarioController::class, 'timeline']);

// Analysis
Route::get('/analysis/{id}/rules', [AnalysisController::class, 'rules']);
Route::get('/analysis/{id}/llm', [AnalysisController::class, 'llm']);

// Evaluations
Route::get('/evaluations', [EvaluationController::class, 'index']);
Route::get('/evaluations/{id}', [EvaluationController::class, 'show']);

// Reports
Route::get('/reports/{id}', [ReportController::class, 'show']);

// Pipeline
Route::post('/pipeline/run', [PipelineController::class, 'run']);
Route::get('/pipeline/status', [PipelineController::class, 'status']);

// Baselines
Route::get('/baselines', [BaselineController::class, 'index']);
Route::get('/ground-truth', [BaselineController::class, 'groundTruth']);
