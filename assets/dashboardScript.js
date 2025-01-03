function deviceTable() {
    return {
        devices: [
            { deviceId: 'testId', status: '1', deviceType: 'test', rssi: '-93', heapPercent: '86%', uptime: '300' }
        ],
    };
};

document.addEventListener("DOMContentLoaded", () => {
    const logContainer = document.getElementById("log");
    const clearButton = document.getElementById("clearLog");

    function logMessage(message) {
        const messageDiv = document.createElement("div");
        messageDiv.textContent = message;
        logContainer.appendChild(messageDiv);

        logContainer.scrollTop = logContainer.scrollHeight;
    }

    clearButton.addEventListener("click", () => {
        logContainer.innerHTML = "";
    });

    const protocol = window.location.protocol === "https:" ? "wss://" : "ws://";
    const ws = new WebSocket(protocol + window.location.host + "/websocket");

    ws.onopen = () => {
        logMessage("Connected to WebSocket.");
    };

    ws.onmessage = (event) => {
        logMessage(event.data);
    };

    ws.onerror = (error) => {
        logMessage("WebSocket error: " + error);
    };

    ws.onclose = () => {
        logMessage("Disconnected from WebSocket.");
    };
});
