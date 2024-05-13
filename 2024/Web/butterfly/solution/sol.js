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
