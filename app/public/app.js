/**
 * OWASP Top 10 Interactive Demo - Frontend JavaScript
 * Handles API calls and UI interactions
 */

// Tab switching
function showTab(tabName) {
    // Hide all tab contents
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });

    // Remove active from all tabs
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.remove('active');
    });

    // Show selected tab content
    document.getElementById(tabName).classList.add('active');

    // Add active to clicked tab
    event.target.classList.add('active');
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    loadUsers();
    loadProducts();
});

// ====================================================================================
// API Helper Functions
// ====================================================================================

async function apiCall(endpoint, method = 'GET', body = null) {
    const options = {
        method,
        headers: {
            'Content-Type': 'application/json'
        }
    };

    if (body) {
        options.body = JSON.stringify(body);
    }

    try {
        console.log(`[API Call] ${method} ${endpoint}`, body ? body : '');
        const response = await fetch(endpoint, options);
        console.log(`[API Response] Status: ${response.status}`);

        const data = await response.json();
        console.log(`[API Data]`, data);
        return data;
    } catch (error) {
        console.error(`[API Error] ${method} ${endpoint}:`, error);
        return {
            error: error.message,
            apiError: true,
            endpoint: endpoint
        };
    }
}

function displayResult(elementId, data, isVulnerable = true) {
    console.log(`[Display] Showing result in ${elementId}`, data);

    const element = document.getElementById(elementId);

    if (!element) {
        console.error(`[Display Error] Element not found: ${elementId}`);
        alert(`Error: Could not find result display element (${elementId})`);
        return;
    }

    element.style.display = 'block';
    element.innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';

    // Scroll into view
    element.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    console.log(`[Display] Result displayed successfully`);
}

// ====================================================================================
// Load Initial Data
// ====================================================================================

async function loadUsers() {
    const data = await apiCall('/api/users');

    if (data.users) {
        const usersList = document.getElementById('users-list');
        if (usersList) {
            let html = '<table class="data-table"><tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>';
            data.users.forEach(user => {
                html += `<tr>
                    <td>${user.id}</td>
                    <td>${user.username}</td>
                    <td>${user.email}</td>
                    <td><span class="badge badge-${user.role}">${user.role}</span></td>
                </tr>`;
            });
            html += '</table>';
            usersList.innerHTML = html;
        }
    }
}

async function loadProducts() {
    const data = await apiCall('/api/products');

    if (data.products) {
        const productsList = document.getElementById('products-list');
        if (productsList) {
            let html = '<table class="data-table"><tr><th>ID</th><th>Name</th><th>Price</th><th>Description</th></tr>';
            data.products.forEach(product => {
                html += `<tr>
                    <td>${product.id}</td>
                    <td>${product.name}</td>
                    <td>$${product.price}</td>
                    <td>${product.description}</td>
                </tr>`;
            });
            html += '</table>';
            productsList.innerHTML = html;
        }
    }
}

async function resetDemo() {
    const data = await apiCall('/api/reset', 'POST');
    alert(data.message || 'Demo reset!');
    loadUsers();
    loadProducts();
}

// ====================================================================================
// A01: Broken Access Control Tests
// ====================================================================================

async function testAccessControl(type) {
    // Use abbreviated 'vuln' for vulnerable element IDs
    const idPrefix = type === 'vulnerable' ? 'vuln' : 'secure';
    const userId = document.getElementById(`${idPrefix}-user-id`).value;

    const endpoint = `/api/${type}/user/${userId}`;
    const resultId = `${idPrefix}-access-result`;

    const data = await apiCall(endpoint);
    displayResult(resultId, data, type === 'vulnerable');
}

// ====================================================================================
// A02: Cryptographic Failures Tests
// ====================================================================================

async function testCrypto(type) {
    console.log(`[testCrypto] Starting test for type: ${type}`);

    // Input fields use full word 'vulnerable-username', result divs use 'vuln-crypto-result'
    const username = document.getElementById(`${type}-username`).value;
    const password = document.getElementById(`${type}-password`).value;
    const email = document.getElementById(`${type}-email`).value;

    console.log(`[testCrypto] Input values:`, { username, password: '***', email });

    const endpoint = `/api/${type}/register`;
    const idPrefix = type === 'vulnerable' ? 'vuln' : 'secure';
    const resultId = `${idPrefix}-crypto-result`;

    console.log(`[testCrypto] Calling API: ${endpoint}, result div: ${resultId}`);

    const data = await apiCall(endpoint, 'POST', { username, password, email });
    displayResult(resultId, data, type === 'vulnerable');
}

// ====================================================================================
// A03: Injection Tests
// ====================================================================================

async function testInjection(type) {
    // Use abbreviated 'vuln' for vulnerable element IDs
    const idPrefix = type === 'vulnerable' ? 'vuln' : 'secure';
    const username = document.getElementById(`${idPrefix}-login-user`).value;
    const password = document.getElementById(`${idPrefix}-login-pass`).value;

    const endpoint = `/api/${type}/login`;
    const resultId = `${idPrefix}-injection-result`;

    const data = await apiCall(endpoint, 'POST', { username, password });
    displayResult(resultId, data, type === 'vulnerable');
}

async function testCommandInjection(type) {
    // Use abbreviated 'vuln' for vulnerable element IDs
    const idPrefix = type === 'vulnerable' ? 'vuln' : 'secure';
    const host = document.getElementById(`${idPrefix}-ping-host`).value;

    const endpoint = `/api/${type}/ping`;
    const resultId = `${idPrefix}-cmd-result`;

    const data = await apiCall(endpoint, 'POST', { host });
    displayResult(resultId, data, type === 'vulnerable');
}

// ====================================================================================
// A04: Insecure Design Tests
// ====================================================================================

async function testPurchase(type) {
    // Use abbreviated 'vuln' for vulnerable element IDs
    const idPrefix = type === 'vulnerable' ? 'vuln' : 'secure';
    const productId = document.getElementById(`${idPrefix}-product`).value;
    const quantity = parseInt(document.getElementById(`${idPrefix}-quantity`).value);

    const endpoint = `/api/${type}/purchase`;
    const resultId = `${idPrefix}-purchase-result`;

    const data = await apiCall(endpoint, 'POST', { productId, quantity });
    displayResult(resultId, data, type === 'vulnerable');
}

// ====================================================================================
// A08: Cloud Storage Misconfiguration Tests
// ====================================================================================

async function testStorage(type) {
    // Use abbreviated 'vuln' for vulnerable element IDs
    const idPrefix = type === 'vulnerable' ? 'vuln' : 'secure';
    const resultId = `${idPrefix}-storage-result`;

    const endpoint = `/api/${type}/storage/customer-data`;

    if (type === 'secure') {
        const token = document.getElementById('secure-storage-token').value;
        const role = document.getElementById('secure-storage-role').value;

        if (!token) {
            displayResult(resultId, {
                error: 'Missing token',
                message: 'Please provide an authorization token'
            }, false);
            return;
        }

        if (!role) {
            displayResult(resultId, {
                error: 'Missing role',
                message: 'Please select an IAM role'
            }, false);
            return;
        }

        // Make custom fetch call with headers
        try {
            console.log(`[Storage Test] Calling ${endpoint} with token and role ${role}`);
            const response = await fetch(endpoint, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'X-User-Role': role,
                    'Content-Type': 'application/json'
                }
            });

            const data = await response.json();
            console.log(`[Storage Test] Response:`, data);
            displayResult(resultId, data, type === 'vulnerable');
        } catch (error) {
            console.error(`[Storage Test] Error:`, error);
            displayResult(resultId, {
                error: error.message,
                apiError: true
            }, false);
        }
    } else {
        // Vulnerable endpoint - no auth required
        const data = await apiCall(endpoint, 'GET');
        displayResult(resultId, data, type === 'vulnerable');
    }
}

// ====================================================================================
// OWASP AI: ML Model Poisoning Tests
// ====================================================================================

async function testMLPoisoning(type) {
    const idPrefix = type === 'vulnerable' ? 'vuln' : 'secure';
    const text = document.getElementById(`${idPrefix}-ml-text`).value;

    if (!text) {
        alert('Please enter some text for sentiment analysis');
        return;
    }

    const endpoint = `/api/${type}/ml/predict-sentiment`;
    const resultId = `${idPrefix}-ml-result`;

    console.log(`[ML Poisoning Test] Calling ${endpoint} with text: ${text}`);

    const data = await apiCall(endpoint, 'POST', { text });
    displayResult(resultId, data, type === 'vulnerable');
}

async function showTrainingStats(dataset) {
    const resultId = dataset === 'poisoned' ? 'poisoned-stats-result' : 'clean-stats-result';
    const endpoint = `/api/ml/training-stats?dataset=${dataset}`;

    console.log(`[Training Stats] Fetching stats for ${dataset} dataset`);

    const data = await apiCall(endpoint, 'GET');
    displayResult(resultId, data, false);
}

// ====================================================================================
// A10: SSRF Tests
// ====================================================================================

async function testSSRF(type) {
    // Use abbreviated 'vuln' for vulnerable element IDs
    const idPrefix = type === 'vulnerable' ? 'vuln' : 'secure';
    const url = document.getElementById(`${idPrefix}-url`).value;

    const endpoint = `/api/${type}/fetch-url`;
    const resultId = `${idPrefix}-ssrf-result`;

    const data = await apiCall(endpoint, 'POST', { url });
    displayResult(resultId, data, type === 'vulnerable');
}
