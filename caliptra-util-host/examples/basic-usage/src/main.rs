//! Basic usage example of the Caliptra Utility Host Library

use caliptra_util_host_core::*;
use caliptra_util_host_transports::{TcpTransport, MockTransport, MockBehavior};
use clap::{Parser, Subcommand, ValueEnum};
use log::{info, error};

#[derive(Parser)]
#[command(name = "caliptra-util-host-example")]
#[command(about = "Example usage of Caliptra Utility Host Library")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    #[arg(short, long, default_value = "info")]
    log_level: LogLevel,
}

#[derive(Subcommand)]
enum Commands {
    /// Test with MCTP transport
    Mctp {
        #[arg(short, long, default_value = "29")]
        endpoint_id: u8,
    },
    /// Test with DOE transport
    Doe,
    /// Test with TCP transport
    Tcp {
        #[arg(short, long, default_value = "localhost")]
        host: String,
        #[arg(short, long, default_value = "8080")]
        port: u16,
    },
    /// Test with Mock transport
    Mock {
        #[arg(short, long)]
        echo: bool,
    },
    /// Run interactive demo
    Demo,
}

#[derive(ValueEnum, Clone)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    let log_level = match cli.log_level {
        LogLevel::Error => "error",
        LogLevel::Warn => "warn", 
        LogLevel::Info => "info",
        LogLevel::Debug => "debug",
        LogLevel::Trace => "trace",
    };
    
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(log_level)
    ).init();
    
    info!("Starting Caliptra Utility Host Library Example");
    
    match cli.command {
        Commands::Mctp { endpoint_id } => {
            test_mctp_transport(endpoint_id).await?;
        },
        Commands::Doe => {
            test_doe_transport().await?;
        },
        Commands::Tcp { host, port } => {
            test_tcp_transport(&host, port).await?;
        },
        Commands::Mock { echo } => {
            test_mock_transport(echo).await?;
        },
        Commands::Demo => {
            run_interactive_demo().await?;
        },
    }
    
    Ok(())
}

async fn test_mctp_transport(endpoint_id: u8) -> Result<()> {
    info!("Testing MCTP transport with endpoint ID: 0x{:02X}", endpoint_id);
    
    // Create MCTP transport
    let transport = Box::new(transport::MctpTransport::new(endpoint_id));
    let mut host = CaliptraUtilHost::new(transport);
    
    // Register built-in command handlers
    register_builtin_handlers(&mut host)?;
    
    // Connect (this would normally connect to actual MCTP endpoint)
    info!("Connecting to MCTP endpoint...");
    // Note: This will fail in the example since we don't have a real MCTP endpoint
    // but demonstrates the API usage
    
    test_spdm_commands(&mut host).await
}

async fn test_doe_transport() -> Result<()> {
    info!("Testing DOE transport");
    
    // Create DOE transport
    let transport = Box::new(transport::DoeTransport::new());
    let mut host = CaliptraUtilHost::new(transport);
    
    // Register built-in command handlers
    register_builtin_handlers(&mut host)?;
    
    // Connect (this would normally connect to actual DOE interface)
    info!("Connecting to DOE interface...");
    
    test_spdm_commands(&mut host).await
}

async fn test_tcp_transport(host_addr: &str, port: u16) -> Result<()> {
    info!("Testing TCP transport: {}:{}", host_addr, port);
    
    // Create TCP transport
    let transport = Box::new(TcpTransport::new(host_addr.to_string(), port));
    let mut host = CaliptraUtilHost::new(transport);
    
    // Register built-in command handlers
    register_builtin_handlers(&mut host)?;
    
    // Try to connect
    info!("Connecting to TCP server...");
    match host.context.transport_mut().connect().await {
        Ok(_) => {
            info!("Successfully connected to TCP server");
            test_all_commands(&mut host).await?;
        },
        Err(e) => {
            error!("Failed to connect to TCP server: {:?}", e);
            info!("Make sure a test server is running on {}:{}", host_addr, port);
        }
    }
    
    Ok(())
}

async fn test_mock_transport(echo: bool) -> Result<()> {
    info!("Testing Mock transport (echo: {})", echo);
    
    // Create mock transport
    let behavior = if echo {
        MockBehavior::Echo
    } else {
        MockBehavior::Success(vec![0x10, 0x84, 0x00, 0x01, 0x00]) // SPDM GET_VERSION response
    };
    
    let transport = Box::new(MockTransport::new(behavior));
    let mut host = CaliptraUtilHost::new(transport);
    
    // Register built-in command handlers  
    register_builtin_handlers(&mut host)?;
    
    // Connect
    host.context.transport_mut().connect().await?;
    info!("Connected to mock transport");
    
    test_all_commands(&mut host).await
}

async fn run_interactive_demo() -> Result<()> {
    info!("Running interactive demo");
    
    // Create mock transport with predefined responses
    let responses = vec![
        vec![0x10, 0x84, 0x00, 0x01, 0x00], // SPDM GET_VERSION response
        vec![0x10, 0x61, 0x00, 0x01, 0x02], // SPDM GET_CAPABILITIES response
        vec![0x00, 0x02, 0x00, 0x00],       // PLDM GET_TID response
        vec![0x50, 0x03, 0x00, 0x00],       // Mailbox response
    ];
    
    let transport = Box::new(MockTransport::sequence_responses(responses));
    let mut host = CaliptraUtilHost::new(transport);
    
    // Register built-in command handlers
    register_builtin_handlers(&mut host)?;
    
    // Connect
    host.context.transport_mut().connect().await?;
    info!("Connected for interactive demo");
    
    // Demonstrate different command types
    info!("\n=== SPDM Commands Demo ===");
    demo_spdm_commands(&mut host).await?;
    
    info!("\n=== PLDM Commands Demo ===");
    demo_pldm_commands(&mut host).await?;
    
    info!("\n=== Mailbox Commands Demo ===");
    demo_mailbox_commands(&mut host).await?;
    
    info!("\n=== Raw Transport Demo ===");
    demo_raw_transport(&mut host).await?;
    
    Ok(())
}

fn register_builtin_handlers(host: &mut CaliptraUtilHost) -> Result<()> {
    host.register_command_handler(Box::new(command::SpdmCommandHandler))?;
    host.register_command_handler(Box::new(command::PldmCommandHandler))?;
    host.register_command_handler(Box::new(command::MailboxCommandHandler))?;
    
    info!("Registered built-in command handlers:");
    for handler_type in host.list_handlers() {
        info!("  - {:?}", handler_type);
    }
    
    Ok(())
}

async fn test_spdm_commands(host: &mut CaliptraUtilHost) -> Result<()> {
    info!("Testing SPDM commands");
    
    // Test SPDM GET_VERSION command
    let cmd = command::Command::new(
        command::CommandType::Spdm,
        command::SpdmCommandHandler::GET_VERSION,
        vec![0x00] // Request parameter
    );
    
    match host.execute_command(cmd).await {
        Ok(result) => {
            info!("SPDM GET_VERSION successful!");
            info!("Response: {:02X?}", result.response_data);
            info!("Execution time: {}ms", result.execution_time_ms);
        },
        Err(e) => {
            error!("SPDM GET_VERSION failed: {:?}", e);
        }
    }
    
    Ok(())
}

async fn test_all_commands(host: &mut CaliptraUtilHost) -> Result<()> {
    test_spdm_commands(host).await?;
    
    // Test PLDM command
    info!("Testing PLDM commands");
    let cmd = command::Command::new(
        command::CommandType::Pldm,
        command::PldmCommandHandler::GET_TID,
        vec![]
    );
    
    match host.execute_command(cmd).await {
        Ok(result) => {
            info!("PLDM GET_TID successful!");
            info!("Response: {:02X?}", result.response_data);
        },
        Err(e) => {
            error!("PLDM GET_TID failed: {:?}", e);
        }
    }
    
    // Test Mailbox command
    info!("Testing Mailbox commands");
    let cmd = command::Command::new(
        command::CommandType::Mailbox,
        command::MailboxCommandHandler::GET_IDEV_CSR,
        vec![]
    );
    
    match host.execute_command(cmd).await {
        Ok(result) => {
            info!("Mailbox GET_IDEV_CSR successful!");
            info!("Response: {:02X?}", result.response_data);
        },
        Err(e) => {
            error!("Mailbox GET_IDEV_CSR failed: {:?}", e);
        }
    }
    
    Ok(())
}

async fn demo_spdm_commands(host: &mut CaliptraUtilHost) -> Result<()> {
    let commands = vec![
        (command::SpdmCommandHandler::GET_VERSION, "GET_VERSION"),
        (command::SpdmCommandHandler::GET_CAPABILITIES, "GET_CAPABILITIES"),
    ];
    
    for (opcode, name) in commands {
        info!("Executing SPDM {}", name);
        
        let cmd = command::Command::new(
            command::CommandType::Spdm,
            opcode,
            vec![0x00]
        ).with_metadata("demo".to_string(), name.to_string());
        
        match host.execute_command(cmd).await {
            Ok(result) => {
                info!("  ✓ {} completed in {}ms", name, result.execution_time_ms);
                info!("  Response ({} bytes): {:02X?}", 
                     result.response_data.len(), 
                     result.response_data.get(..8).unwrap_or(&result.response_data));
            },
            Err(e) => {
                error!("  ✗ {} failed: {:?}", name, e);
            }
        }
    }
    
    Ok(())
}

async fn demo_pldm_commands(host: &mut CaliptraUtilHost) -> Result<()> {
    let commands = vec![
        (command::PldmCommandHandler::GET_TID, "GET_TID"),
        (command::PldmCommandHandler::GET_PLDM_VERSION, "GET_PLDM_VERSION"),
    ];
    
    for (opcode, name) in commands {
        info!("Executing PLDM {}", name);
        
        let cmd = command::Command::new(
            command::CommandType::Pldm,
            opcode,
            vec![]
        ).with_metadata("demo".to_string(), name.to_string());
        
        match host.execute_command(cmd).await {
            Ok(result) => {
                info!("  ✓ {} completed in {}ms", name, result.execution_time_ms);
                info!("  Response ({} bytes): {:02X?}", 
                     result.response_data.len(), 
                     result.response_data.get(..8).unwrap_or(&result.response_data));
            },
            Err(e) => {
                error!("  ✗ {} failed: {:?}", name, e);
            }
        }
    }
    
    Ok(())
}

async fn demo_mailbox_commands(host: &mut CaliptraUtilHost) -> Result<()> {
    let commands = vec![
        (command::MailboxCommandHandler::GET_IDEV_CSR, "GET_IDEV_CSR"),
    ];
    
    for (opcode, name) in commands {
        info!("Executing Mailbox {}", name);
        
        let cmd = command::Command::new(
            command::CommandType::Mailbox,
            opcode,
            vec![]
        ).with_metadata("demo".to_string(), name.to_string());
        
        match host.execute_command(cmd).await {
            Ok(result) => {
                info!("  ✓ {} completed in {}ms", name, result.execution_time_ms);
                info!("  Response ({} bytes): {:02X?}", 
                     result.response_data.len(), 
                     result.response_data.get(..8).unwrap_or(&result.response_data));
            },
            Err(e) => {
                error!("  ✗ {} failed: {:?}", name, e);
            }
        }
    }
    
    Ok(())
}

async fn demo_raw_transport(host: &mut CaliptraUtilHost) -> Result<()> {
    info!("Demonstrating raw transport usage");
    
    let raw_data = vec![0x10, 0x84, 0x00]; // Raw SPDM GET_VERSION
    
    match host.send_raw(&raw_data).await {
        Ok(response) => {
            info!("  ✓ Raw send completed");
            info!("  Sent: {:02X?}", raw_data);
            info!("  Received: {:02X?}", response);
        },
        Err(e) => {
            error!("  ✗ Raw send failed: {:?}", e);
        }
    }
    
    Ok(())
}