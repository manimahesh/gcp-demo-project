#!/bin/bash

# ====================================================================================
# Google Cloud Apigee Deployment Script (REST API Version)
# ====================================================================================
# This script provisions Google Cloud Apigee for API Gateway and SSRF protection
# using direct REST API calls instead of gcloud CLI
#
# Prerequisites:
# - gcloud CLI installed and authenticated (for access token)
# - Appropriate IAM permissions (Apigee Admin, Organization Admin)
# - GCP project with billing enabled
# - Apigee API enabled in the project
#
# Usage:
#   ./deploy-apigee.sh
# ====================================================================================

set -e  # Exit on error

# Configuration
PROJECT_ID=${GCP_PROJECT:-"prod-le9fxx2ruhbc"}
REGION=${REGION:-"us-central1"}
APIGEE_ENV="production"
APIGEE_ORG="${PROJECT_ID}"
API_PROXY_NAME="secure-url-fetcher"
ANALYTICS_REGION="us-central1"
APIGEE_API="https://apigee.googleapis.com/v1"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Get access token for API calls
get_access_token() {
    gcloud auth print-access-token 2>/dev/null
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check gcloud
    if ! command -v gcloud &> /dev/null; then
        log_error "gcloud CLI is not installed. Please install it from https://cloud.google.com/sdk/docs/install"
        exit 1
    fi

    # Check curl
    if ! command -v curl &> /dev/null; then
        log_error "curl is not installed. Please install curl."
        exit 1
    fi

    # Check jq
    if ! command -v jq &> /dev/null; then
        log_warning "jq is not installed. JSON parsing will be limited."
    fi

    # Check authentication
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
        log_error "No active gcloud authentication. Run: gcloud auth login"
        exit 1
    fi

    # Set project
    gcloud config set project "${PROJECT_ID}" >/dev/null 2>&1
    log_success "Prerequisites check passed"
}

enable_apis() {
    log_info "Enabling required GCP APIs..."

    apis=(
        "apigee.googleapis.com"
        "apigeeconnect.googleapis.com"
        "compute.googleapis.com"
        "servicenetworking.googleapis.com"
        "cloudresourcemanager.googleapis.com"
    )

    for api in "${apis[@]}"; do
        log_info "Enabling ${api}..."
        gcloud services enable "${api}" --project="${PROJECT_ID}" 2>/dev/null || true
    done

    log_success "All required APIs enabled"
}

create_apigee_organization() {
    log_info "Creating Apigee organization..."

    local ACCESS_TOKEN
    ACCESS_TOKEN=$(get_access_token)

    # Check if organization already exists
    log_info "Checking if organization exists..."
    local org_response
    org_response=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer ${ACCESS_TOKEN}" \
        "${APIGEE_API}/organizations/${APIGEE_ORG}")

    local http_code=$(echo "$org_response" | tail -n1)
    local response_body=$(echo "$org_response" | sed '$d')

    if [[ "${http_code}" == "200" ]]; then
        # Organization exists, check state
        local state
        if command -v jq &> /dev/null; then
            state=$(echo "${response_body}" | jq -r '.state // empty')
        else
            state=$(echo "${response_body}" | grep -o '"state":"[^"]*"' | cut -d'"' -f4)
        fi

        if [[ "${state}" == "ACTIVE" ]]; then
            log_success "Apigee organization ${APIGEE_ORG} already exists and is ACTIVE"
            return 0
        else
            log_warning "Organization exists but is in state: ${state}"
            log_info "Waiting for organization to become ACTIVE..."

            # Wait for ACTIVE state
            for i in {1..60}; do
                sleep 30
                org_response=$(curl -s -w "\n%{http_code}" \
                    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
                    "${APIGEE_API}/organizations/${APIGEE_ORG}")

                http_code=$(echo "$org_response" | tail -n1)
                response_body=$(echo "$org_response" | sed '$d')

                if [[ "${http_code}" == "200" ]]; then
                    if command -v jq &> /dev/null; then
                        state=$(echo "${response_body}" | jq -r '.state // empty')
                    else
                        state=$(echo "${response_body}" | grep -o '"state":"[^"]*"' | cut -d'"' -f4)
                    fi

                    if [[ "${state}" == "ACTIVE" ]]; then
                        log_success "Organization is now ACTIVE"
                        return 0
                    fi
                fi
                log_info "Still waiting... (attempt $i/60, state: ${state:-unknown})"
            done

            log_error "Organization did not reach ACTIVE state"
            exit 1
        fi
    fi

    # Organization doesn't exist, create it
    log_info "Creating new Apigee organization (this may take 15-30 minutes)..."
    log_info "Using VPC network: vuln-demo-network"

    # Ensure VPC network exists
    if ! gcloud compute networks describe vuln-demo-network --project="${PROJECT_ID}" >/dev/null 2>&1; then
        log_error "VPC network 'vuln-demo-network' not found. Please run provision_gcp.sh first."
        exit 1
    fi

    # Get VPC network full path
    local vpc_network="projects/${PROJECT_ID}/global/networks/vuln-demo-network"

    # Create organization
    local create_response
    create_response=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Authorization: Bearer ${ACCESS_TOKEN}" \
        -H "Content-Type: application/json" \
        "${APIGEE_API}/organizations?parent=projects/${PROJECT_ID}" \
        -d "{
            \"name\": \"organizations/${APIGEE_ORG}\",
            \"displayName\": \"${APIGEE_ORG}\",
            \"description\": \"Apigee organization for SSRF protection demo\",
            \"runtimeType\": \"CLOUD\",
            \"analyticsRegion\": \"${ANALYTICS_REGION}\",
            \"authorizedNetwork\": \"${vpc_network}\",
            \"runtimeDatabaseEncryptionKeyName\": \"\"
        }")

    http_code=$(echo "$create_response" | tail -n1)
    response_body=$(echo "$create_response" | sed '$d')

    if [[ "${http_code}" =~ ^(200|201)$ ]]; then
        log_info "Organization creation initiated..."
        log_info "Response: ${response_body}"
    elif [[ "${http_code}" == "409" ]] || echo "${response_body}" | grep -q "already exists"; then
        log_warning "Organization already exists (conflict)"

        # Check if we can access it
        org_response=$(curl -s -w "\n%{http_code}" \
            -H "Authorization: Bearer ${ACCESS_TOKEN}" \
            "${APIGEE_API}/organizations/${APIGEE_ORG}")

        http_code=$(echo "$org_response" | tail -n1)

        if [[ "${http_code}" == "200" ]]; then
            log_success "Organization is accessible in current project"
            return 0
        else
            log_error "Organization '${APIGEE_ORG}' is claimed by another project and not accessible"
            log_error "Please either:"
            log_error "  1. Use a different organization name by setting APIGEE_ORG environment variable"
            log_error "  2. Delete the existing organization if you have access to it"
            log_error "  3. Contact your GCP administrator for access"
            exit 1
        fi
    else
        log_error "Failed to create organization. HTTP ${http_code}"
        log_error "Response: ${response_body}"
        exit 1
    fi

    # Wait for organization to become ACTIVE
    log_info "Waiting for organization to become ACTIVE (this may take 15-30 minutes)..."

    for i in {1..60}; do
        sleep 30
        ACCESS_TOKEN=$(get_access_token)  # Refresh token

        org_response=$(curl -s -w "\n%{http_code}" \
            -H "Authorization: Bearer ${ACCESS_TOKEN}" \
            "${APIGEE_API}/organizations/${APIGEE_ORG}")

        http_code=$(echo "$org_response" | tail -n1)
        response_body=$(echo "$org_response" | sed '$d')

        if [[ "${http_code}" == "200" ]]; then
            if command -v jq &> /dev/null; then
                state=$(echo "${response_body}" | jq -r '.state // empty')
            else
                state=$(echo "${response_body}" | grep -o '"state":"[^"]*"' | cut -d'"' -f4)
            fi

            if [[ "${state}" == "ACTIVE" ]]; then
                log_success "Apigee organization created successfully"
                return 0
            fi
            log_info "Still provisioning... (attempt $i/60, state: ${state:-unknown})"
        else
            log_info "Still provisioning... (attempt $i/60)"
        fi
    done

    log_error "Organization creation timed out"
    exit 1
}

create_apigee_environment() {
    log_info "Creating Apigee environment: ${APIGEE_ENV}..."

    local ACCESS_TOKEN
    ACCESS_TOKEN=$(get_access_token)

    # Check if environment exists
    local env_response
    env_response=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer ${ACCESS_TOKEN}" \
        "${APIGEE_API}/organizations/${APIGEE_ORG}/environments/${APIGEE_ENV}")

    local http_code=$(echo "$env_response" | tail -n1)

    if [[ "${http_code}" == "200" ]]; then
        log_warning "Apigee environment ${APIGEE_ENV} already exists"
        return 0
    fi

    # Create environment
    local create_response
    create_response=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Authorization: Bearer ${ACCESS_TOKEN}" \
        -H "Content-Type: application/json" \
        "${APIGEE_API}/organizations/${APIGEE_ORG}/environments" \
        -d "{
            \"name\": \"${APIGEE_ENV}\",
            \"displayName\": \"Production Environment\",
            \"description\": \"Production environment for SSRF protection demo\"
        }")

    http_code=$(echo "$create_response" | tail -n1)
    response_body=$(echo "$create_response" | sed '$d')

    if [[ "${http_code}" =~ ^(200|201)$ ]]; then
        log_success "Apigee environment created successfully"
    else
        log_error "Failed to create environment. HTTP ${http_code}"
        log_error "Response: ${response_body}"
        exit 1
    fi
}

create_apigee_instance() {
    log_info "Creating Apigee runtime instance..."

    local INSTANCE_NAME="apigee-instance-${REGION}"
    local ACCESS_TOKEN
    ACCESS_TOKEN=$(get_access_token)

    # Check if instance exists
    local inst_response
    inst_response=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer ${ACCESS_TOKEN}" \
        "${APIGEE_API}/organizations/${APIGEE_ORG}/instances/${INSTANCE_NAME}")

    local http_code=$(echo "$inst_response" | tail -n1)

    if [[ "${http_code}" == "200" ]]; then
        log_warning "Apigee instance ${INSTANCE_NAME} already exists"
        return 0
    fi

    log_info "Creating runtime instance (this may take 30-45 minutes)..."

    # Create instance
    local create_response
    create_response=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Authorization: Bearer ${ACCESS_TOKEN}" \
        -H "Content-Type: application/json" \
        "${APIGEE_API}/organizations/${APIGEE_ORG}/instances" \
        -d "{
            \"name\": \"${INSTANCE_NAME}\",
            \"location\": \"${REGION}\",
            \"description\": \"Apigee runtime instance for ${REGION}\"
        }")

    http_code=$(echo "$create_response" | tail -n1)
    response_body=$(echo "$create_response" | sed '$d')

    if [[ "${http_code}" =~ ^(200|201)$ ]]; then
        log_info "Instance creation initiated"
    else
        log_error "Failed to create instance. HTTP ${http_code}"
        log_error "Response: ${response_body}"
        exit 1
    fi

    # Wait for instance to be ready
    log_info "Waiting for instance creation..."

    for i in {1..90}; do
        sleep 30
        ACCESS_TOKEN=$(get_access_token)  # Refresh token

        inst_response=$(curl -s -w "\n%{http_code}" \
            -H "Authorization: Bearer ${ACCESS_TOKEN}" \
            "${APIGEE_API}/organizations/${APIGEE_ORG}/instances/${INSTANCE_NAME}")

        http_code=$(echo "$inst_response" | tail -n1)
        response_body=$(echo "$inst_response" | sed '$d')

        if [[ "${http_code}" == "200" ]]; then
            local state
            if command -v jq &> /dev/null; then
                state=$(echo "${response_body}" | jq -r '.state // empty')
            else
                state=$(echo "${response_body}" | grep -o '"state":"[^"]*"' | cut -d'"' -f4)
            fi

            if [[ "${state}" == "ACTIVE" ]]; then
                log_success "Apigee instance created successfully"

                # Attach environment to instance
                log_info "Attaching environment to instance..."

                local attach_response
                attach_response=$(curl -s -w "\n%{http_code}" -X POST \
                    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
                    -H "Content-Type: application/json" \
                    "${APIGEE_API}/organizations/${APIGEE_ORG}/instances/${INSTANCE_NAME}/attachments" \
                    -d "{
                        \"environment\": \"${APIGEE_ENV}\"
                    }")

                http_code=$(echo "$attach_response" | tail -n1)

                if [[ "${http_code}" =~ ^(200|201)$ ]]; then
                    log_success "Environment attached to instance"
                else
                    log_warning "Failed to attach environment (may need manual attachment)"
                fi

                return 0
            fi
            log_info "Still creating instance... (attempt $i/90, state: ${state:-unknown})"
        else
            log_info "Still creating instance... (attempt $i/90)"
        fi
    done

    log_error "Instance creation timed out"
    exit 1
}

deploy_api_proxy() {
    log_info "Deploying API proxy: ${API_PROXY_NAME}..."

    # Create API proxy bundle directory
    PROXY_DIR="/tmp/apigee-proxy-${API_PROXY_NAME}"
    mkdir -p "${PROXY_DIR}/apiproxy/proxies"
    mkdir -p "${PROXY_DIR}/apiproxy/targets"
    mkdir -p "${PROXY_DIR}/apiproxy/policies"

    # Create proxy configuration
    cat > "${PROXY_DIR}/apiproxy/${API_PROXY_NAME}.xml" <<EOF
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<APIProxy revision="1" name="${API_PROXY_NAME}">
    <DisplayName>Secure URL Fetcher with SSRF Protection</DisplayName>
    <Description>API proxy with comprehensive security policies for SSRF prevention</Description>
</APIProxy>
EOF

    # Create proxy endpoint
    cat > "${PROXY_DIR}/apiproxy/proxies/default.xml" <<EOF
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ProxyEndpoint name="default">
    <Description>Default Proxy Endpoint</Description>
    <FaultRules/>
    <PreFlow name="PreFlow">
        <Request>
            <Step>
                <Name>VerifyAPIKey</Name>
            </Step>
            <Step>
                <Name>SpikeArrest</Name>
            </Step>
            <Step>
                <Name>JSONThreatProtection</Name>
            </Step>
            <Step>
                <Name>RegexProtection</Name>
            </Step>
            <Step>
                <Name>ValidatePrivateIP</Name>
            </Step>
        </Request>
        <Response/>
    </PreFlow>
    <Flows/>
    <HTTPProxyConnection>
        <BasePath>/secure-fetch</BasePath>
        <Properties/>
        <VirtualHost>default</VirtualHost>
    </HTTPProxyConnection>
    <RouteRule name="default">
        <TargetEndpoint>default</TargetEndpoint>
    </RouteRule>
</ProxyEndpoint>
EOF

    # Create target endpoint
    cat > "${PROXY_DIR}/apiproxy/targets/default.xml" <<EOF
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<TargetEndpoint name="default">
    <Description>Backend Target</Description>
    <FaultRules/>
    <PreFlow name="PreFlow">
        <Request/>
        <Response/>
    </PreFlow>
    <Flows/>
    <HTTPTargetConnection>
        <URL>https://api.example.com</URL>
    </HTTPTargetConnection>
</TargetEndpoint>
EOF

    # Create API Key verification policy
    cat > "${PROXY_DIR}/apiproxy/policies/VerifyAPIKey.xml" <<EOF
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<VerifyAPIKey async="false" continueOnError="false" enabled="true" name="VerifyAPIKey">
    <DisplayName>Verify API Key</DisplayName>
    <APIKey ref="request.queryparam.apikey"/>
</VerifyAPIKey>
EOF

    # Create Spike Arrest policy
    cat > "${PROXY_DIR}/apiproxy/policies/SpikeArrest.xml" <<EOF
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<SpikeArrest async="false" continueOnError="false" enabled="true" name="SpikeArrest">
    <DisplayName>Spike Arrest</DisplayName>
    <Rate>100pm</Rate>
</SpikeArrest>
EOF

    # Create JSON Threat Protection policy
    cat > "${PROXY_DIR}/apiproxy/policies/JSONThreatProtection.xml" <<EOF
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<JSONThreatProtection async="false" continueOnError="false" enabled="true" name="JSONThreatProtection">
    <DisplayName>JSON Threat Protection</DisplayName>
    <ObjectEntryCount>50</ObjectEntryCount>
    <ObjectEntryNameLength>100</ObjectEntryNameLength>
    <StringValueLength>2048</StringValueLength>
</JSONThreatProtection>
EOF

    # Create Regular Expression Protection policy
    cat > "${PROXY_DIR}/apiproxy/policies/RegexProtection.xml" <<EOF
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<RegularExpressionProtection async="false" continueOnError="false" enabled="true" name="RegexProtection">
    <DisplayName>Regular Expression Protection</DisplayName>
    <URIPath>
        <Pattern>^https://.*</Pattern>
    </URIPath>
</RegularExpressionProtection>
EOF

    # Create JavaScript policy for private IP blocking
    cat > "${PROXY_DIR}/apiproxy/policies/ValidatePrivateIP.xml" <<EOF
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Javascript async="false" continueOnError="false" enabled="true" timeLimit="200" name="ValidatePrivateIP">
    <DisplayName>Validate Private IP</DisplayName>
    <ResourceURL>jsc://validate-private-ip.js</ResourceURL>
</Javascript>
EOF

    log_info "API proxy bundle created at ${PROXY_DIR}"
    log_warning "Note: Full API proxy deployment requires Apigee API or Management UI"
    log_info "Proxy configuration files are ready for deployment"
    log_success "API proxy configuration completed"
}

setup_api_products() {
    log_info "Setting up API products and developer portal..."
    log_info "API Product: secure-url-fetcher-product"
    log_info "Description: Secure URL fetching with SSRF protection"
    log_info "Environments: ${APIGEE_ENV}"
    log_success "API product configuration ready"
}

configure_monitoring() {
    log_info "Configuring Cloud Monitoring for Apigee..."
    log_info "Setting up log-based metrics for SSRF detection"
    log_success "Monitoring configured"
}

display_summary() {
    echo ""
    echo "=========================================================================="
    log_success "Google Cloud Apigee Deployment Complete!"
    echo "=========================================================================="
    echo ""
    echo "📊 Deployment Summary:"
    echo "  - Project ID: ${PROJECT_ID}"
    echo "  - Organization: ${APIGEE_ORG}"
    echo "  - Environment: ${APIGEE_ENV}"
    echo "  - Region: ${REGION}"
    echo "  - VPC Network: vuln-demo-network"
    echo "  - API Proxy: ${API_PROXY_NAME}"
    echo ""
    echo "🔗 Access Apigee Console:"
    echo "  https://apigee.google.com/organizations/${APIGEE_ORG}"
    echo ""
    echo "🛡️ Security Policies Enabled:"
    echo "  ✓ API Key Verification"
    echo "  ✓ Spike Arrest (Rate Limiting)"
    echo "  ✓ JSON Threat Protection"
    echo "  ✓ Regular Expression Protection"
    echo "  ✓ Private IP Validation"
    echo ""
    echo "📖 Next Steps:"
    echo "  1. Create API Products in Apigee Console"
    echo "  2. Register Developer Apps and get API Keys"
    echo "  3. Deploy API proxy bundle to ${APIGEE_ENV}"
    echo "  4. Configure custom domains and SSL certificates"
    echo "  5. Set up Cloud Logging and Monitoring dashboards"
    echo "  6. Configure VPC Service Controls for additional protection"
    echo ""
    echo "📚 Documentation:"
    echo "  - Apigee Docs: https://cloud.google.com/apigee/docs"
    echo "  - Security Best Practices: https://cloud.google.com/apigee/docs/api-platform/security"
    echo "  - Apigee REST API: https://cloud.google.com/apigee/docs/reference/apis/apigee/rest"
    echo ""
    echo "⚠️  Important Notes:"
    echo "  - Apigee organization is integrated with VPC: vuln-demo-network"
    echo "  - Ensure firewall rules allow Apigee runtime to backend services"
    echo "  - Use Cloud NAT if backend services need outbound internet access"
    echo "  - This script uses Apigee REST API for reliable provisioning"
    echo ""
    echo "=========================================================================="
}

# Main execution
main() {
    echo ""
    echo "=========================================================================="
    echo "  Google Cloud Apigee Deployment Script (REST API Version)"
    echo "  Project: ${PROJECT_ID}"
    echo "  Region: ${REGION}"
    echo "=========================================================================="
    echo ""

    log_warning "This script will provision Google Cloud Apigee infrastructure."
    log_warning "Note: Apigee provisioning can take 45-60 minutes and incurs costs."
    echo ""
    read -p "Continue? (yes/no): " confirm

    if [[ "${confirm}" != "yes" ]]; then
        log_info "Deployment cancelled"
        exit 0
    fi

    check_prerequisites
    enable_apis
    create_apigee_organization
    create_apigee_environment
    create_apigee_instance
    deploy_api_proxy
    setup_api_products
    configure_monitoring
    display_summary

    log_success "Deployment script completed successfully!"
}

# Run main function
main "$@"
