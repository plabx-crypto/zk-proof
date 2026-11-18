const API_BASE = "http://localhost:8080";

// Tab switching functionality
document.addEventListener('DOMContentLoaded', () => {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            // Remove active class from all buttons and contents
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));

            // Add active class to clicked button and corresponding content
            btn.classList.add('active');
            const tabId = btn.dataset.tab;
            document.getElementById(tabId).classList.add('active');
        });
    });
});

// Helper function for API calls
async function apiCall(endpoint, data) {
    try {
        const response = await fetch(API_BASE + endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        
        if (!response.ok) {
            throw new Error('API request failed: ' + response.status);
        }
        
        return await response.json();
    } catch (error) {
        throw error;
    }
}

// Generate Rangeproof
async function generateRangeproof() {
    const valueInput = document.getElementById('range-value');
    const bitsInput = document.getElementById('range-bits');
    const resultBox = document.getElementById('rangeproof-result');

    const value = parseInt(valueInput.value);
    const bits = parseInt(bitsInput.value) || 64;

    if (isNaN(value) || value < 0) {
        showResult(resultBox, 'Error: Please enter a valid positive number for value', false);
        return;
    }

    try {
        const result = await apiCall('/rangeproof/generate', { value, bits });
        showResult(resultBox, '<strong>Success!</strong><br/>Commitment: ' + 
            (result.commitment ? result.commitment.substring(0, 50) + '...' : '') + '<br/>' +
            '<pre style="white-space: pre-wrap; word-break: break-all;">' + 
            JSON.stringify({ commitment: result.commitment, proof: (result.proof || '').substring(0, 100) + '...' }, null, 2) + 
            '</pre>', true);
    } catch (error) {
        showResult(resultBox, 'Error: ' + error.message, false);
    }
}

// Verify Rangeproof
async function verifyRangeproof() {
    const proofInput = document.getElementById('verify-proof');
    const resultBox = document.getElementById('verify-result');

    try {
        const proofData = JSON.parse(proofInput.value);
        
        if (!proofData.commitment || !proofData.proof) {
            showResult(resultBox, 'Error: Proof must contain both commitment and proof fields', false);
            return;
        }

        const result = await apiCall('/rangeproof/verify', {
            commitment: proofData.commitment,
            proof: proofData.proof
        });

        showResult(resultBox, '<strong>Verification Result:</strong><br/>' + 
            (result.valid ? '<span style="color: #4caf50;">✓ VALID</span>' : '<span style="color: #dc3545;">✗ INVALID</span>') +
            '<pre>' + JSON.stringify(result, null, 2) + '</pre>', result.valid);
    } catch (error) {
        showResult(resultBox, 'Error parsing proof or API error: ' + error.message, false);
    }
}

// Generate Nullifier
async function generateNullifier() {
    const inputInput = document.getElementById('nullifier-input');
    const resultBox = document.getElementById('nullifier-result');

    const userSecret = inputInput.value.trim();

    if (!userSecret) {
        showResult(resultBox, 'Error: Please enter a user secret', false);
        return;
    }

    try {
        const result = await apiCall('/nullifier/generate', { 
            user_secret: userSecret,
            scope: 'poh/v1'
        });
        showResult(resultBox, '<strong>Success!</strong><br/>Nullifier: ' + 
            (result.nullifier ? result.nullifier.substring(0, 50) + '...' : '') + '<br/>' +
            '<pre style="white-space: pre-wrap; word-break: break-all;">' + 
            JSON.stringify(result, null, 2) + 
            '</pre>', true);
    } catch (error) {
        showResult(resultBox, 'Error: ' + error.message, false);
    }
}

// Register Nullifier
async function registerNullifier() {
    const inputInput = document.getElementById('register-nullifier-input');
    const resultBox = document.getElementById('nullifier-register-result');

    const userSecret = inputInput.value.trim();

    if (!userSecret) {
        showResult(resultBox, 'Error: Please enter a user secret', false);
        return;
    }

    try {
        // First generate the nullifier
        const genResult = await apiCall('/nullifier/generate', { 
            user_secret: userSecret,
            scope: 'poh/v1'
        });

        // Then register it
        const result = await apiCall('/nullifier/register', { 
            nullifier: genResult.nullifier,
            scope: 'poh/v1'
        });
        
        showResult(resultBox, '<strong>' + (result.registered ? 'Registered!' : 'Duplicate Detected!') + '</strong><br/>' +
            (result.message || '') + '<br/>' +
            '<pre style="white-space: pre-wrap; word-break: break-all;">' + 
            JSON.stringify(result, null, 2) + 
            '</pre>', result.registered);
    } catch (error) {
        showResult(resultBox, 'Error: ' + error.message, false);
    }
}

// Verify Nullifier
async function verifyNullifier() {
    const inputInput = document.getElementById('verify-nullifier-input');
    const hashInput = document.getElementById('verify-nullifier-hash');
    const resultBox = document.getElementById('nullifier-verify-result');

    const input = inputInput.value.trim();
    const nullifierHash = hashInput.value.trim();

    if (!input || !nullifierHash) {
        showResult(resultBox, 'Error: Please enter both input and nullifier hash', false);
        return;
    }

    try {
        const result = await apiCall('/nullifier/verify', {
            input,
            nullifier: nullifierHash
        });

        showResult(resultBox, '<strong>Verification Result:</strong><br/>' + 
            (result.valid ? '<span style="color: #4caf50;">✓ VALID</span>' : '<span style="color: #dc3545;">✗ INVALID</span>') +
            '<pre>' + JSON.stringify(result, null, 2) + '</pre>', result.valid);
    } catch (error) {
        showResult(resultBox, 'Error verifying nullifier: ' + error.message, false);
    }
}

// Health Check
async function checkHealth() {
    const resultBox = document.getElementById('health-result');

    try {
        const response = await fetch(API_BASE + '/api/health');
        
        if (!response.ok) {
            throw new Error('Health check failed: ' + response.status);
        }
        
        const result = await response.json();
        showResult(resultBox, '<strong>Server Status:</strong><br/><span style="color: #4caf50;">✓ HEALTHY</span>' +
            '<pre>' + JSON.stringify(result, null, 2) + '</pre>', true);
    } catch (error) {
        showResult(resultBox, 'Error: Server not reachable or error occurred.<br/>Make sure the backend is running on ' + API_BASE + '<br/>' + error.message, false);
    }
}

// Helper to display results
function showResult(element, html, isSuccess) {
    element.innerHTML = html;
    
    // Clear previous classes and add success or error class
    element.classList.remove('success', 'error');
    if (isSuccess !== null) {
        element.classList.add(isSuccess ? 'success' : 'error');
    }
}
