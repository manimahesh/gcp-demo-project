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
    const userId = type === 'vulnerable'
        ? document.getElementById('vuln-user-id').value
        : document.getElementById('secure-user-id').value;

    const endpoint = `/api/${type}/user/${userId}`;
    const resultId = type === 'vulnerable' ? 'vuln-access-result' : 'secure-access-result';

    const data = await apiCall(endpoint);
    displayResult(resultId, data, type === 'vulnerable');
}

// ====================================================================================
// A02: Cryptographic Failures Tests
// ====================================================================================

async function testCrypto(type) {
    console.log(`[testCrypto] Starting test for type: ${type}`);

    const username = document.getElementById(`${type}-username`).value;
    const password = document.getElementById(`${type}-password`).value;
    const email = document.getElementById(`${type}-email`).value;

    console.log(`[testCrypto] Input values:`, { username, password: '***', email });

    const endpoint = `/api/${type}/register`;
    const resultId = `${type}-crypto-result`;

    console.log(`[testCrypto] Calling API: ${endpoint}, result div: ${resultId}`);

    const data = await apiCall(endpoint, 'POST', { username, password, email });
    displayResult(resultId, data, type === 'vulnerable');
}

// ====================================================================================
// A03: Injection Tests
// ====================================================================================

async function testInjection(type) {
    const username = document.getElementById(`${type}-login-user`).value;
    const password = document.getElementById(`${type}-login-pass`).value;

    const endpoint = `/api/${type}/login`;
    const resultId = `${type}-injection-result`;

    const data = await apiCall(endpoint, 'POST', { username, password });
    displayResult(resultId, data, type === 'vulnerable');
}

async function testCommandInjection(type) {
    const host = document.getElementById(`${type}-ping-host`).value;

    const endpoint = `/api/${type}/ping`;
    const resultId = `${type}-cmd-result`;

    const data = await apiCall(endpoint, 'POST', { host });
    displayResult(resultId, data, type === 'vulnerable');
}

// ====================================================================================
// A04: Insecure Design Tests
// ====================================================================================

async function testPurchase(type) {
    const productId = document.getElementById(`${type}-product`).value;
    const quantity = parseInt(document.getElementById(`${type}-quantity`).value);

    const endpoint = `/api/${type}/purchase`;
    const resultId = `${type}-purchase-result`;

    const data = await apiCall(endpoint, 'POST', { productId, quantity });
    displayResult(resultId, data, type === 'vulnerable');
}

// ====================================================================================
// A10: SSRF Tests
// ====================================================================================

async function testSSRF(type) {
    const url = document.getElementById(`${type}-url`).value;

    const endpoint = `/api/${type}/fetch-url`;
    const resultId = `${type}-ssrf-result`;

    const data = await apiCall(endpoint, 'POST', { url });
    displayResult(resultId, data, type === 'vulnerable');
}
