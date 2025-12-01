#!/usr/bin/env python3
"""Certificate chain decoder and validator for SPDM certificates.

This script parses certificate chains from SPDM_VALIDATOR_DIR and provides
certificate chain assembly and validation functionality with JSON output support.
"""

import os
import sys
import logging
import argparse
import json
from typing import Optional, Dict, Any
from datetime import datetime
from asn1crypto import x509

from certchain import decode_spdm_certchain, validate_certchain
from decode import skip_cbor_tags
from signed_eat import process_signed_eat
from eat_claims import validate_eat_claims_json

def create_parser():
    """Create and configure the command line argument parser."""
    parser = argparse.ArgumentParser(
        description="Decode SPDM certificate chains with JSON output support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 0                               # Decode slot 0 with pretty JSON output
  %(prog)s 0 --verbose                     # Decode slot 0 with verbose logging
        """
    )
    
    parser.add_argument('slot', type=int,
                       help='Slot ID to decode (e.g., 0, 1, 2)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose/debug logging')
    
    return parser

def setup_logging(level: int = logging.INFO) -> None:
    """Set up logging configuration."""
    logging.basicConfig(
        level=level,
        format='%(name)s - %(levelname)s - %(message)s'
    )


def validate_path() -> str:
    """Validate that SPDM_VALIDATOR_DIR is set and accessible."""
    spdm_validator_dir = os.environ.get('SPDM_VALIDATOR_DIR')
    if not spdm_validator_dir:
        raise ValueError(
            "SPDM_VALIDATOR_DIR environment variable is not set.\n"
            "Please set it like: export SPDM_VALIDATOR_DIR='/path/to/your/certificates'"
        )
    
    if not os.path.isdir(spdm_validator_dir):
        raise ValueError(f"SPDM_VALIDATOR_DIR directory does not exist: {spdm_validator_dir}")
    
    return spdm_validator_dir


def get_spdm_requester_nonce() -> Optional[str]:
    """Get nonce from SPDM_NONCE environment variable and log the result."""
    nonce = os.environ.get('SPDM_NONCE')
    if nonce:
        logging.info("Using SPDM_NONCE: %s", nonce)
    else:
        logging.warning("SPDM_NONCE environment variable not set")
    return nonce


def read_eat() -> bytes:
    """Read EAT from SPDM_VALIDATOR_DIR/measurement_block_fd.bin."""
    spdm_validator_dir = os.environ.get('SPDM_VALIDATOR_DIR')
    if not spdm_validator_dir:
        raise ValueError("SPDM_VALIDATOR_DIR environment variable is not set")
    
    eat_blob_path = os.path.join(spdm_validator_dir, 'measurement_block_fd.bin')
    
    if not os.path.isfile(eat_blob_path):
        raise FileNotFoundError(f"EAT blob file not found: {eat_blob_path}")
    
    with open(eat_blob_path, 'rb') as f:
        eat_data = f.read()
    
    logging.info("Read EAT blob from: %s", eat_blob_path)
    return eat_data


def main():
    """Main entry point for the EAT decoder in JSON format."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level)
    
    try:
        # Validate environment
        spdm_dir = validate_path()
        logging.info("Using SPDM_VALIDATOR_DIR: %s", spdm_dir)
        
        # Get nonce from environment
        nonce = get_spdm_requester_nonce()
        
        # Get certificate chain
        cert_chain_arr = decode_spdm_certchain(args.slot)

        # Parse certificates
        if validate_certchain(cert_chain_arr, verbose=args.verbose) :
            logging.info("Certificate chain validation completed successfully")
        else:
            logging.error("Certificate chain validation failed")
            sys.exit(1)
        
        # Read EAT blob from file
        eat = read_eat()
        
        # Skip CBOR tags to get to COSE data
        cose_sign1_data = skip_cbor_tags(eat)

        if len(cose_sign1_data) != len(eat):
            logging.info(f"Skipped {len(eat) - len(cose_sign1_data)} bytes of CBOR tags")
            logging.info(f"CoseSign1 data first 16 bytes: {cose_sign1_data[:16].hex()}")

        # Process Signed EAT
        eat_claims = process_signed_eat(cose_sign1_data, cert_chain_arr, verbose=args.verbose)

        # Validate EAT claims
        if validate_eat_claims_json(eat_claims, nonce=nonce): 
            logging.info("EAT claims validation completed successfully")

    except Exception as e:
        error_msg = f"Fatal error: {e}"
        logging.error(error_msg)
        
        error_result = {
            'success': False,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }
        print(json.dumps(error_result, indent=2))
        
        sys.exit(1)


if __name__ == "__main__":
    main()