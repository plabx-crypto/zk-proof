#!/usr/bin/env python3
"""Flask-less web server for the ZK Proof GUI.

Uses Python's built-in http.server module - no external dependencies required.
Provides REST API endpoints for range proofs and nullifiers."""

import sys
import json
import secrets
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from poh.group import rand_scalar
from poh import load_group, commit
from poh.rangeproof import prove as range_prove, verify as range_verify
from poh.nullifier import compute_nullifier_from_secret, NullifierRegistry

# Global state
GROUP = load_group()
REGISTRIES = {}  # Per-scope registries


def int_to_hex(x):
    """Convert integer to hex string without '0x' prefix."""
    return format(x, 'x') if x >= 0 else '-' + format(-x, 'x')


class ZKProofHandler(BaseHTTPRequestHandler):
    """HTTP request handler for ZK Proof API."""
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass
    
    def send_json_response(self, data, status=200):
        """Send JSON response with proper headers."""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def send_html_page(self):
        """Send HTML frontend page."""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        with open(Path(__file__).parent / 'frontend' / 'index.html') as f:
            self.wfile.write(f.read().encode())

    def send_static_file(self, filepath, content_type):
        """Send a static file (CSS, JS)."""
        full_path = Path(__file__).parent / filepath
        if not full_path.exists():
            self.send_error_json('File not found', 404)
            return
        
        self.send_response(200)
        self.send_header('Content-Type', content_type + '; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        with open(full_path, 'r') as f:
            self.wfile.write(f.read().encode())

    def send_error_json(self, message, status=400):
        """Send error JSON response."""
        self.send_json_response({'error': message}, status)
    
    def read_json_body(self):
        """Read and parse JSON from request body."""
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            return None
        body = self.rfile.read(content_length)
        try:
            return json.loads(body.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
    
    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        
        if path == '/api/health':
            self.handle_health()
        elif path == '/api/params/fingerprint':
            self.handle_fingerprint()
        elif path == '/api/nullifier/stats':
            self.handle_registry_stats()
        elif path == '/' or path.startswith('/frontend'):
            self.send_html_page()
        elif path == '/styles.css':
            self.send_static_file('frontend/styles.css', 'text/css')
        elif path == '/app.js':
            self.send_static_file('frontend/app.js', 'application/javascript')
        else:
            self.send_error_json('Not found', 404)

    def do_POST(self):
        """Handle POST requests."""
        parsed = urlparse(self.path)
        path = parsed.path
        
        data = self.read_json_body()
        
        if path == '/api/rangeproof/generate':
            self.handle_range_generate(data)
        elif path == '/api/rangeproof/verify':
            self.handle_range_verify(data)
        elif path == '/api/nullifier/generate':
            self.handle_nullifier_generate(data)
        elif path == '/api/nullifier/register':
            self.handle_nullifier_register(data)
        elif path == '/api/nullifier/check':
            self.handle_nullifier_check(data)
        elif path == '/api/nullifier/reset':
            self.handle_nullifier_reset(data)
        else:
            self.send_error_json('Not found', 404)
    
    def handle_health(self):
        """Handle /api/health endpoint."""
        self.send_json_response({
            'status': 'healthy',
            'version': '0.1.0',
            'group_info': {
                'p_bits': GROUP.p.bit_length(),
                'q_bits': GROUP.q.bit_length()
            }
        })
    
    def handle_fingerprint(self):
        """Handle /api/params/fingerprint endpoint."""
        blob = bytearray()
        for val in [GROUP.p, GROUP.q, GROUP.k, GROUP.g, GROUP.h]:
            blob += len(int_to_hex(val).encode()).to_bytes(4, 'big')
            blob += int_to_hex(val).encode()
        import hashlib
        fp = hashlib.sha256(bytes(blob)).hexdigest()
        self.send_json_response({'fingerprint': fp})
    
    def handle_registry_stats(self):
        """Handle /api/nullifier/stats endpoint."""
        scopes = []
        total = 0
        for scope, registry in REGISTRIES.items():
            count = len(registry._used_nullifiers)
            scopes.append({'scope': scope, 'registered_count': count})
            total += count
        self.send_json_response({
            'scopes': sorted(scopes, key=lambda x: x['scope']),
            'total_scopes': len(scopes),
            'total_registered': total
        })
    
    def handle_range_generate(self, data):
        """Handle /api/rangeproof/generate endpoint."""
        if not data:
            return self.send_error_json('No JSON data provided')
        
        value = data.get('value')
        if value is None:
            return self.send_error_json('Missing required field: value')
        
        try:
            value = int(value)
        except (ValueError, TypeError):
            return self.send_error_json('Invalid value: must be an integer')
        
        bits = data.get('bits', 32)
        try:
            bits = int(bits)
        except (ValueError, TypeError):
            return self.send_error_json('Invalid bits: must be an integer')
        
        max_value = (1 << bits) - 1
        if not (0 <= value <= max_value):
            return self.send_error_json(f'Value {value} out of range [0, {max_value}]')
        
        blinding = data.get('blinding')
        if blinding is not None:
            try:
                if isinstance(blinding, str):
                    blinding = int(blinding, 16) if blinding.startswith('0x') else int(blinding)
                else:
                    blinding = int(blinding)
            except (ValueError, TypeError):
                return self.send_error_json('Invalid blinding format')
        
        try:
            if blinding is not None:
                commitment, proof = range_prove(GROUP, value, blinding, bits)
            else:
                # Generate random blinding factor when not provided
                blinding = rand_scalar(GROUP.q)
                commitment, proof = range_prove(GROUP, value, blinding, bits)
            
            bit_proofs = []
            for bp in proof.bit_proofs:
                bit_proofs.append({
                    'a0': int_to_hex(bp.a0),
                    'a1': int_to_hex(bp.a1),
                    'c0': int_to_hex(bp.c0),
                    'c1': int_to_hex(bp.c1),
                    's0': int_to_hex(bp.s0),
                    's1': int_to_hex(bp.s1)
                })
            
            self.send_json_response({
                'success': True,
                'commitment': int_to_hex(commitment),
                'proof': {
                    'bits': proof.bits,
                    'commitment': int_to_hex(proof.commitment),
                    'commitments': [int_to_hex(c) for c in proof.commitments],
                    'bit_proofs': bit_proofs,
                    'consistency_a': int_to_hex(proof.consistency_a),
                    'consistency_s': int_to_hex(proof.consistency_s)
                },
                'bits': bits,
                'value_range': f'[0, 2^{bits})'
            })
        except Exception as e:
            self.send_error_json(f'Error generating proof: {str(e)}', 500)
    
    def handle_range_verify(self, data):
        """Handle /api/rangeproof/verify endpoint."""
        if not data:
            return self.send_error_json('No JSON data provided')
        
        commitment_hex = data.get('commitment')
        proof_data = data.get('proof')
        
        if not commitment_hex or not proof_data:
            return self.send_error_json('Missing required fields: commitment and proof')
        
        try:
            commitment = int(commitment_hex, 16) if isinstance(commitment_hex, str) else int(commitment_hex)
        except (ValueError, TypeError):
            return self.send_error_json('Invalid commitment format')
        
        # Reconstruct RangeProof
        try:
            commitments = tuple(
                int(c, 16) if isinstance(c, str) else c for c in proof_data['commitments']
            )
            
            bit_proofs = []
            for bp in proof_data.get('bit_proofs', []):
                bit_proofs.append(type(proof.bit_proofs[0])(
                    a0=int(bp['a0'], 16) if isinstance(bp['a0'], str) else bp['a0'],
                    a1=int(bp['a1'], 16) if isinstance(bp['a1'], str) else bp['a1'],
                    c0=int(bp['c0'], 16) if isinstance(bp['c0'], str) else bp['c0'],
                    c1=int(bp['c1'], 16) if isinstance(bp['c1'], str) else bp['c1'],
                    s0=int(bp['s0'], 16) if isinstance(bp['s0'], str) else bp['s0'],
                    s1=int(bp['s1'], 16) if isinstance(bp['s1'], str) else bp['s1']
                ))
            
            from poh.rangeproof import RangeProof
            proof = RangeProof(
                bits=proof_data['bits'],
                commitment=int(proof_data['commitment'], 16) if isinstance(proof_data['commitment'], str) else proof_data['commitment'],
                commitments=commitments,
                bit_proofs=tuple(bit_proofs),
                consistency_a=int(proof_data['consistency_a'], 16) if isinstance(proof_data['consistency_a'], str) else proof_data['consistency_a'],
                consistency_s=int(proof_data['consistency_s'], 16) if isinstance(proof_data['consistency_s'], str) else proof_data['consistency_s']
            )
        except (KeyError, TypeError, ValueError) as e:
            return self.send_error_json(f'Invalid proof format: {str(e)}')
        
        is_valid = range_verify(GROUP, commitment, proof)
        
        if is_valid:
            self.send_json_response({
                'valid': True,
                'message': f'Range proof valid. Value in [0, 2^{proof.bits}).',
                'commitment': int_to_hex(commitment),
                'bits': proof.bits
            })
        else:
            self.send_json_response({
                'valid': False,
                'message': 'Range proof verification failed.',
                'commitment': int_to_hex(commitment)
            })
    
    def handle_nullifier_generate(self, data):
        """Handle /api/nullifier/generate endpoint."""
        if not data:
            return self.send_error_json('No JSON data provided')
        
        user_secret_raw = data.get('user_secret')
        scope = data.get('scope', 'poh/v1')
        
        if not user_secret_raw:
            return self.send_error_json('Missing required field: user_secret')
        
        # Convert to bytes
        if isinstance(user_secret_raw, str):
            if user_secret_raw.startswith('0x'):
                try:
                    user_secret = bytes.fromhex(user_secret_raw[2:])
                except ValueError:
                    return self.send_error_json('Invalid hex string for user_secret')
            else:
                user_secret = user_secret_raw.encode()
        else:
            user_secret = user_secret_raw
        
        if isinstance(scope, bytes):
            scope = scope.decode()
        
        try:
            nullifier = compute_nullifier_from_secret(GROUP, scope.encode(), user_secret)
            self.send_json_response({
                'success': True,
                'nullifier': int_to_hex(nullifier),
                'scope': scope
            })
        except Exception as e:
            self.send_error_json(f'Error generating nullifier: {str(e)}', 500)
    
    def handle_nullifier_register(self, data):
        """Handle /api/nullifier/register endpoint."""
        if not data:
            return self.send_error_json('No JSON data provided')
        
        nullifier_hex = data.get('nullifier')
        scope = data.get('scope', 'poh/v1')
        
        if not nullifier_hex:
            return self.send_error_json('Missing required field: nullifier')
        
        try:
            nullifier = int(nullifier_hex, 16) if isinstance(nullifier_hex, str) else int(nullifier_hex)
        except (ValueError, TypeError):
            return self.send_error_json('Invalid nullifier format')
        
        if scope not in REGISTRIES:
            REGISTRIES[scope] = NullifierRegistry()
        
        registry = REGISTRIES[scope]
        is_new = registry.register(nullifier)
        
        if is_new:
            self.send_json_response({
                'registered': True,
                'message': f'Nullifier {nullifier_hex[:20]}... registered in scope "{scope}".',
                'scope': scope,
                'total_registered': len(registry._used_nullifiers)
            })
        else:
            self.send_json_response({
                'registered': False,
                'message': f'Duplicate nullifier detected! Replay attack prevented in scope "{scope}".',
                'scope': scope,
                'is_duplicate': True
            })

    def handle_nullifier_check(self, data):
        """Handle /api/nullifier/check endpoint."""
        if not data:
            return self.send_error_json('No JSON data provided')
        
        nullifier_hex = data.get('nullifier')
        scope = data.get('scope', 'poh/v1')
        
        if not nullifier_hex:
            return self.send_error_json('Missing required field: nullifier')
        
        try:
            nullifier = int(nullifier_hex, 16) if isinstance(nullifier_hex, str) else int(nullifier_hex)
        except (ValueError, TypeError):
            return self.send_error_json('Invalid nullifier format')
        
        if scope not in REGISTRIES:
            REGISTRIES[scope] = NullifierRegistry()
        
        registry = REGISTRIES[scope]
        is_used = nullifier in registry._used_nullifiers
        
        self.send_json_response({
            'is_used': is_used,
            'message': f'Nullifier {nullifier_hex[:20]}... {"has been used" if is_used else "is available"} in scope "{scope}".',
            'scope': scope
        })
    
    def handle_nullifier_reset(self, data):
        """Handle /api/nullifier/reset endpoint."""
        scope = (data or {}).get('scope', 'poh/v1')
        if isinstance(scope, bytes):
            scope = scope.decode()
        
        if scope in REGISTRIES:
            REGISTRIES[scope]._used_nullifiers.clear()
        
        self.send_json_response({
            'success': True,
            'message': f'Registry reset for scope "{scope}".',
            'scope': scope
        })


class ThreadedHTTPServer(HTTPServer):
    """HTTP server with threading support."""
    allow_reuse_address = True
    
    def process_request(self, request, client_address):
        """Handle requests in a new thread."""
        import threading
        thread = threading.Thread(target=self.process_request_thread,
                                 args=(request, client_address))
        thread.daemon = True
        thread.start()
    
    def process_request_thread(self, request, client_address):
        """Process a single request."""
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)


def main():
    """Start the web server."""
    import argparse
    
    parser = argparse.ArgumentParser(description='ZK Proof Web Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8080, help='Port to listen on (default: 8080)')
    
    args = parser.parse_args()
    
    print(f'ZK Proof Web Server')
    print(f'Group parameters: p={GROUP.p.bit_length()} bits, q={GROUP.q.bit_length()} bits')
    print(f'Server running at http://{args.host}:{args.port}')
    print(f'API endpoints available:')
    print(f'  GET  /api/health - Health check')
    print(f'  GET  /api/params/fingerprint - Get params fingerprint')
    print(f'  POST /api/rangeproof/generate - Generate range proof')
    print(f'  POST /api/rangeproof/verify - Verify range proof')
    print(f'  POST /api/nullifier/generate - Generate nullifier')
    print(f'  POST /api/nullifier/register - Register nullifier')
    print(f'  POST /api/nullifier/check - Check nullifier status')
    print(f'  GET  /api/nullifier/stats - Get registry statistics')
    
    server = ThreadedHTTPServer((args.host, args.port), ZKProofHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down...')
        server.shutdown()


if __name__ == '__main__':
    main()
