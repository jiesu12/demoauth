### Test Steps
* Start this app.
* Open in browser - `http://localhost:8081/oauth/authorize?grant_type=authorization_code&response_type=code&client_id=client&state=1234`
* Login with user/pass. The browser will redirect to `http://localhost:8080/?code=<code>&state=1234`
* Use the code from last step, run:`curl client:secret@localhost:8081/oauth/token -dgrant_type=authorization_code -dclient_id=client -dredirect_uri=http://localhost:8080 -dcode=<code>`. It will return `access_token`.
* Use `access_token` from last step to test resource server: `curl -H "Authorization: Bearer <access_token> http://localhost:8080/api/test`.
