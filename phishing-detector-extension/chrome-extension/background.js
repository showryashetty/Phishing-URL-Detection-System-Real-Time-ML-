chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
    if (changeInfo.url) {
        fetch("http://localhost:5050/check", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: changeInfo.url })
        }).then(res => res.json())
          .then(data => console.log("🧠 Checked:", data.result))
          .catch(err => console.error("❌ Failed to check URL", err));
    }
});
