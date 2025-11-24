# Troubleshooting Guide

## Issue: "Nothing happens when I click buttons"

### Problem
When you click "Register (Vulnerable)" or other buttons, nothing happens.

### Root Cause
You're likely opening the HTML file directly from the filesystem (`file:///...`) instead of through the Node.js server.

### Solution

**❌ WRONG Way (Won't Work):**
- Double-clicking `index.html`
- Opening `file:///C:/Users/.../app/public/index.html`
- Using a static HTTP server

**✅ CORRECT Way:**

1. **Start the Node.js server:**
   ```bash
   cd app
   npm install  # First time only
   npm start
   ```

2. **Open in browser:**
   ```
   http://localhost:3000
   ```
   **NOT** `file:///...` or `public/index.html`

### Why This Matters

The application needs the Node.js backend server running because:
- It provides the vulnerable and secure API endpoints
- It runs the SQLite database
- It handles all the security demonstrations
- Static files alone won't work - you need the full stack

### Verification Steps

1. **Check server is running:**
   ```bash
   # You should see this output:
   ============================================================
   🔒 OWASP Top 10 Interactive Demo Server
   ============================================================
   ✓ Server running on http://localhost:3000
   ```

2. **Test API endpoint:**
   ```bash
   curl http://localhost:3000/api/users
   ```
   You should see JSON with user data.

3. **Open correct URL:**
   ```
   http://localhost:3000
   ```

4. **Try the Cryptography demo:**
   - Click "Cryptography" tab
   - Click "Register (Vulnerable)"
   - You should see a JSON response with the plain text password

### Common Issues

#### Issue: Port 3000 already in use

**Solution:**
```bash
# Stop existing process
taskkill /F /IM node.exe  # Windows
pkill -f node             # Linux/Mac

# Or use different port
PORT=8080 npm start
```

#### Issue: npm install fails

**Solution:**
```bash
# Clear cache
rm -rf node_modules package-lock.json
npm install
```

#### Issue: Browser shows "Cannot GET /"

**Cause:** Server isn't running

**Solution:** Start the server with `npm start`

#### Issue: Button clicks do nothing, no errors

**Cause:** You're on `file:///` URL

**Solution:** Navigate to `http://localhost:3000`

### Debug Checklist

- [ ] Server is running (`npm start`)
- [ ] No errors in server console
- [ ] Accessing `http://localhost:3000` (not `file:///`)
- [ ] Browser console shows no JavaScript errors (F12)
- [ ] API test works: `curl http://localhost:3000/api/users`

### Still Having Issues?

1. **Check browser console** (F12 → Console tab)
   - Look for network errors
   - Check for JavaScript errors

2. **Check server logs**
   - Look at the terminal where you ran `npm start`
   - Any error messages there?

3. **Restart everything**
   ```bash
   # Stop server (Ctrl+C)
   # Restart
   npm start
   # Refresh browser
   ```

4. **Test with cURL**
   ```bash
   # Test vulnerable endpoint
   curl -X POST http://localhost:3000/api/vulnerable/register \
     -H "Content-Type: application/json" \
     -d '{"username":"test","password":"pass123","email":"test@test.com"}'

   # You should see JSON response
   ```

## Other Common Issues

### Database errors

**Symptom:** "Database error" messages

**Solution:** Restart the server (database is in-memory and recreated on start)

### CORS errors

**Symptom:** "CORS policy" errors in browser console

**Cause:** Trying to access from wrong origin

**Solution:** Always use `http://localhost:3000`

### Nothing in result boxes

**Symptom:** Buttons work but no results show

**Solution:**
- Check browser console for errors
- Verify API endpoint in Network tab (F12)
- Make sure server is running without errors

---

**Quick Test:**

1. Run: `npm start`
2. Open: `http://localhost:3000`
3. Click: "Cryptography" tab
4. Click: "Register (Vulnerable)"
5. **Expected:** JSON response appears showing plain text password

If this works, you're all set! 🎉
