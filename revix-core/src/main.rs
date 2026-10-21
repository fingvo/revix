// ============================================================================
// Project: Revix - Open Source Software Reverse Engineering & Binary Inspection Framework
// Author: Sohail MN (Aka Fingvo) - Full Stack Engineer
// Copyright: (c) 2026 Fingvo. All rights reserved.
// License: MIT License
// ============================================================================
// Description: Revix CLI tool and Axum REST API Server providing binary analysis
//              endpoints for the Revix React.js frontend.
// ============================================================================

use axum::{
    extract::{Multipart, Query},
    http::{header, Method, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::{Parser, Subcommand};
use revix_core::{disassembler, inspect_binary};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};

#[derive(Parser, Debug)]
#[command(name = "revix-core")]
#[command(author = "Sohail MN (Aka Fingvo) <fingvo@users.noreply.github.com>")]
#[command(version = "0.1.0")]
#[command(about = "Revix Core Binary Reverse Engineering Engine", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the Revix local HTTP API Server for the React.js workbench
    Serve {
        #[arg(short, long, default_value_t = 8080)]
        port: u16,
    },
    /// Inspect a local binary file and output JSON report to terminal
    Inspect {
        #[arg(short, long)]
        file: String,
    },
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    project: &'static str,
    version: &'static str,
    author: &'static str,
    copyright: &'static str,
}

#[derive(Deserialize)]
struct DisassembleRequest {
    hex_bytes: String,
    base_address: Option<u64>,
    max_instructions: Option<usize>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Inspect { file }) => {
            println!("Reading target binary: {}", file);
            let data = std::fs::read(&file)?;
            let report = inspect_binary(&file, &data);
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Some(Commands::Serve { port }) | None => {
            let port = match cli.command {
                Some(Commands::Serve { port }) => port,
                _ => 8080,
            };

            // Configure permissive CORS layer for local React workbench communication
            let cors = CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]);

            let app = Router::new()
                .route("/health", get(health_handler))
                .route("/api/inspect", post(inspect_upload_handler))
                .route("/api/disassemble", post(disassemble_handler))
                .layer(cors);

            let addr = SocketAddr::from(([127, 0, 0, 1], port));
            println!("============================================================");
            println!("Revix Core Engine Server started at http://{}", addr);
            println!("Author: Sohail MN (Aka Fingvo) - Full Stack Engineer");
            println!("Copyright: (c) 2026 Fingvo. All rights reserved. (MIT License)");
            println!("============================================================");

            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, app).await?;
        }
    }

    Ok(())
}

/// Handler for /health check endpoint
async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "online",
        project: "Revix",
        version: "0.1.0",
        author: "Sohail MN (Aka Fingvo)",
        copyright: "(c) 2026 Fingvo. All rights reserved.",
    })
}

/// Handler for /api/inspect endpoint accepting multipart file uploads
async fn inspect_upload_handler(mut multipart: Multipart) -> Result<impl IntoResponse, (StatusCode, String)> {
    let mut file_name = "uploaded_binary.bin".to_string();
    let mut file_bytes = Vec::new();

    while let Some(field) = multipart.next_field().await.map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))? {
        if let Some(name) = field.file_name() {
            file_name = name.to_string();
        }
        let data = field.bytes().await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        file_bytes.extend_from_slice(&data);
    }

    if file_bytes.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "No file content uploaded".to_string()));
    }

    let report = inspect_binary(&file_name, &file_bytes);
    Ok(Json(report))
}

/// Handler for /api/disassemble endpoint accepting raw hex string bytes
async fn disassemble_handler(Json(payload): Json<DisassembleRequest>) -> Result<impl IntoResponse, (StatusCode, String)> {
    let clean_hex = payload.hex_bytes.replace([' ', '\n', '\r', '\t'], "");
    let bytes = hex::decode(&clean_hex).map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid hex byte string: {}", e)))?;

    let base_addr = payload.base_address.unwrap_or(0x00400000);
    let max_inst = payload.max_instructions.unwrap_or(256);

    let instructions = disassembler::disassemble_stream(&bytes, base_addr, max_inst);
    Ok(Json(instructions))
}
