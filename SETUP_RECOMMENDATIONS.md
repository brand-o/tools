# Setting Up GitHub Recommendations Feature

The recommendation form on `index.html` is now configured to submit issues to the `brand-o/tools` repo, but you need to add a GitHub Personal Access Token.

## Option 1: Client-Side (Simple but Less Secure)

This is the current implementation. The token is visible in the page source, but with fine-grained permissions it's relatively safe.

### Steps:

1. Go to https://github.com/settings/tokens?type=beta
2. Click "Generate new token"
3. Configure:
   - **Token name**: `brando.tools-recommendations`
   - **Expiration**: 90 days (or longer)
   - **Repository access**: "Only select repositories" → Select `brand-o/tools`
   - **Repository permissions**: 
     - Issues: **Read and write**
4. Click "Generate token"
5. Copy the token (starts with `github_pat_`)
6. In `index.html` line 315, replace `YOUR_GITHUB_TOKEN_HERE` with your token:
   ```javascript
   'Authorization':'Bearer github_pat_YOUR_ACTUAL_TOKEN_HERE'
   ```
7. Commit and push to the `brando.tools` repo

### Security Note:
The token will be visible in page source, but it can ONLY create issues in your `tools` repo. It cannot push code, delete repos, or access other repositories.

---

## Option 2: Cloudflare Worker (More Secure)

Store the token server-side using a Cloudflare Worker.

### Steps:

1. Create a Cloudflare Worker:
   ```javascript
   export default {
     async fetch(request) {
       if (request.method !== 'POST') {
         return new Response('Method not allowed', { status: 405 });
       }
       
       const { tool } = await request.json();
       if (!tool || tool.length > 32) {
         return new Response('Invalid tool name', { status: 400 });
       }
       
       const response = await fetch('https://api.github.com/repos/brand-o/tools/issues', {
         method: 'POST',
         headers: {
           'Content-Type': 'application/json',
           'Accept': 'application/vnd.github.v3+json',
           'Authorization': `Bearer ${GITHUB_TOKEN}`, // Cloudflare secret
           'User-Agent': 'brando.tools'
         },
         body: JSON.stringify({
           title: `Tool Recommendation: ${tool}`,
           body: `A user recommended adding: **${tool}**\n\nSubmitted from: https://brando.tools\nTimestamp: ${new Date().toISOString()}`,
           labels: ['recommendation', 'user-submitted']
         })
       });
       
       return new Response(JSON.stringify({ success: response.ok }), {
         status: response.status,
         headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
       });
     }
   };
   ```

2. In Cloudflare dashboard:
   - Go to Workers & Pages → Create Worker
   - Paste the code above
   - Add environment variable: `GITHUB_TOKEN` = your token
   - Deploy to `recommendations.brando.tools` or similar

3. Update `index.html` to call the worker instead:
   ```javascript
   const response = await fetch('https://recommendations.brando.tools', {
     method: 'POST',
     headers: { 'Content-Type': 'application/json' },
     body: JSON.stringify({ tool })
   });
   ```

---

## Testing

After setup, test by:
1. Go to https://brando.tools
2. Scroll to "recommend something"
3. Type a tool name (e.g., "WizTree")
4. Click "send"
5. Check https://github.com/brand-o/tools/issues for the new issue

The button should show "sending..." then "sent!" if successful, or "failed" if there was an error.
