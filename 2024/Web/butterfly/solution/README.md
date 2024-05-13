# Butterfly &mdash; Solution

## Page source

In the page source, we will find obfuscated JS code.
The more complicated way to solve this task is to deobfuscate JS code and find what is happening there.

## Inspect page

If we inspect storage, we will find IndexDB with a `strangeStorage` database, and the database contains
There is an Object Store named `FLAG.` The flag contains key-value pairs where the index is the value, and the letter is the value.

In Local Storage you will find this value: `{"code":"CryptoJS.AES.decrypt(CIPHERTEXT, KEY).toString(CryptoJS.enc.Utf8)"}`

In the Session Storage, we find `KEY` with the value `secret key is very secure`.

## Solution

The solution is to read the encrypted flag from the IndexDB and decrypt it with `KEY`. We also have a line for decryption, so the solution is to run the following script:

```javascript
request = indexedDB.open('strangeStorage', 1);

var flag = "";

request.onerror = function(event) {
  console.log("Database error: " + event.target.errorCode);
};

request.onsuccess = function(event) {
  const db = event.target.result;
  const transaction = db.transaction(['FLAG'], 'readonly');
  const objectStore = transaction.objectStore('FLAG');

  objectStore.openCursor().onsuccess = function(event) {
    const cursor = event.target.result;
    if (cursor) {
      flag = flag + cursor.value.letter;
      cursor.continue();
    } else {
      var sol = CryptoJS.AES.decrypt(flag, "secret key is very secure").toString(CryptoJS.enc.Utf8);
      alert(sol);
    }
  };
};

```

And we got the flag: `TBTL{th15_1S_n0t_53CUR3_5T0r4G3}`
