# Deployment Troubleshooting Guide

## Issue: Button Click Shows No Output in Deployed Application

### Symptoms
- Application loads successfully at external IP (e.g., http://136.113.109.181/)
- Buttons are visible and clickable
- Clicking "Register (Vulnerable)" or other buttons shows no result
- No error messages visible

### Debugging Steps

#### 1. Open Browser Developer Console

**Chrome/Edge:**
- Press `F12` or right-click → "Inspect"
- Click "Console" tab

**Firefox:**
- Press `F12` or right-click → "Inspect Element"
- Click "Console" tab

#### 2. Check Console Logs

After clicking "Register (Vulnerable)", you should see logs like:
```
[testCrypto] Starting test for type: vulnerable
[testCrypto] Input values: {username: "testuser1", password: "***", email: "test1@example.com"}
[testCrypto] Calling API: /api/vulnerable/register, result div: vuln-crypto-result
[API Call] POST /api/vulnerable/register {username: "testuser1", password: "MyPassword123", email: "test1@example.com"}
[API Response] Status: 200
[API Data] {vulnerability: "Cryptographic Failure", issue: "Password stored in PLAIN TEXT!", ...}
[Display] Showing result in vuln-crypto-result
[Display] Result displayed successfully
```

#### 3. Common Issues & Solutions

##### Issue: Network Error in Console

**Error:**
```
[API Error] POST /api/vulnerable/register: TypeError: Failed to fetch
```

**Possible Causes:**
1. **Backend pod not running**
   ```bash
   kubectl get pods
   # Should show vuln-backend pod in Running state
   ```

2. **Service not routing correctly**
   ```bash
   kubectl get svc vuln-backend-svc
   # Should show EXTERNAL-IP
   ```

3. **Health checks failing**
   ```bash
   kubectl describe pod <pod-name>
   # Check liveness/readiness probe status
   ```

**Solution:**
```bash
# Check pod logs
kubectl logs -f deployment/vuln-backend

# Restart deployment
kubectl rollout restart deployment/vuln-backend
```

##### Issue: 404 Not Found

**Error:**
```
[API Response] Status: 404
```

**Cause:** API endpoint not found

**Solution:** Verify the endpoint exists in server.js and pod is running latest image
```bash
# Force pull latest image
kubectl rollout restart deployment/vuln-backend
kubectl rollout status deployment/vuln-backend
```

##### Issue: Element Not Found

**Error:**
```
[Display Error] Element not found: vuln-crypto-result
```

**Cause:** Result div missing from HTML

**Solution:** Verify HTML has the result div:
```html
<div id="vuln-crypto-result" class="result-box vulnerable-result" style="display:none;"></div>
```

##### Issue: CORS Error

**Error:**
```
Access to fetch at 'http://...' from origin 'http://...' has been blocked by CORS policy
```

**Cause:** Trying to access API from different domain

**Solution:** This shouldn't happen with relative URLs. If it does, check if you're accessing via different domains (e.g., IP vs hostname)

#### 4. Verify Backend is Working

Test API directly:
```bash
# Get the external IP
kubectl get svc vuln-backend-svc

# Test health endpoint
curl http://YOUR_EXTERNAL_IP/healthz

# Test vulnerable register endpoint
curl -X POST http://YOUR_EXTERNAL_IP/api/vulnerable/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"pass123","email":"test@test.com"}'

# Should return JSON like:
# {"vulnerability":"Cryptographic Failure","issue":"Password stored in PLAIN TEXT!",...}
```

#### 5. Check Pod Logs

```bash
# Get pod name
kubectl get pods

# View logs
kubectl logs -f <pod-name>

# Should see requests like:
# POST /api/vulnerable/register
```

#### 6. Verify Image is Latest

```bash
# Check current image
kubectl describe deployment vuln-backend | grep Image:

# Should match your latest pushed image
# us-central1-docker.pkg.dev/YOUR_PROJECT/vuln-demo-repo/backend:latest

# Force update
kubectl rollout restart deployment/vuln-backend
```

### Quick Fixes

#### Fix 1: Rebuild and Redeploy

```bash
# Rebuild Docker image
cd app
docker build -t YOUR_REGISTRY/backend:latest .
docker push YOUR_REGISTRY/backend:latest

# Restart deployment to pull new image
kubectl rollout restart deployment/vuln-backend
kubectl rollout status deployment/vuln-backend
```

#### Fix 2: Check Service Endpoints

```bash
# Verify service is routing to pods
kubectl get endpoints vuln-backend-svc

# Should show pod IP:3000
# If empty, pods aren't ready
```

#### Fix 3: Manual Pod Inspection

```bash
# Get shell in pod
kubectl exec -it deployment/vuln-backend -- sh

# Test from inside pod
wget -O- http://localhost:3000/healthz
wget -O- http://localhost:3000/

# Should return HTML
```

### Testing Checklist

- [ ] Browser console shows no errors
- [ ] Pod is in Running state
- [ ] Health checks are passing
- [ ] Service has EXTERNAL-IP
- [ ] Curl to external IP returns expected response
- [ ] Pod logs show incoming requests
- [ ] Latest Docker image is deployed

### Still Not Working?

1. **Check browser console** - Look for JavaScript errors
2. **Clear browser cache** - Hard refresh (Ctrl+Shift+R)
3. **Try different browser** - Rule out browser-specific issues
4. **Check pod resources** - Ensure pod isn't OOM killed
   ```bash
   kubectl top pods
   kubectl describe pod <pod-name>
   ```

### Expected Behavior

When everything works correctly:

1. Click "Register (Vulnerable)" button
2. Console logs show API call
3. Result box appears below button
4. JSON response is displayed with:
   ```json
   {
     "vulnerability": "Cryptographic Failure",
     "issue": "Password stored in PLAIN TEXT!",
     "userId": 4,
     "warning": "Never do this in production!",
     "storedPassword": "MyPassword123"
   }
   ```

### Monitoring Commands

```bash
# Watch pods
kubectl get pods -w

# Watch service
kubectl get svc -w

# Continuous logs
kubectl logs -f deployment/vuln-backend

# Events
kubectl get events --sort-by='.lastTimestamp'
```

---

**Need more help?** Check the main [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for local development issues.
