let ws = null;
let reconnectTimeout = null;

function formatTime(seconds) {
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;

    return [hrs, mins, secs]
        .map(value => String(value).padStart(2, '0'))
        .join(':');
}

function deviceTable() {
    return {
        devices: [],
        initWebSocket() {
            if (ws && (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN)) {
                return;
            }

            const protocol = window.location.protocol === "https:" ? "wss://" : "ws://";
            ws = new WebSocket(protocol + window.location.host + "/websocket");
            
            ws.addEventListener('open', () => {
                this.logMessage("Connected to WebSocket.");
                if (reconnectTimeout) {
                    clearTimeout(reconnectTimeout);
                    reconnectTimeout = null;
                }
                ws.send('{"call":"listDevices"}');
            });
            
            ws.addEventListener("message", (event) => {
                this.logMessage(event.data);
                try {
                    const receivedJSON = JSON.parse(event.data);

                    if ("listDevices" in receivedJSON) {
                        const updatedDeviceList = receivedJSON.listDevices;

                        this.devices = updatedDeviceList.map(newDevice => {
                            const existingDevice = this.devices.find(d => d.deviceId === newDevice.deviceId);
                            return {
                                ...newDevice,
                                ...existingDevice,
                            };
                        });
                    }

                    if ("deviceStatus" in receivedJSON) {
                        const statusUpdate = receivedJSON.deviceStatus;
                        const targetIndex = this.devices.findIndex(device => device.deviceId === statusUpdate.deviceId);

                        if (targetIndex !== -1) {
                            this.devices[targetIndex] = {
                                ...this.devices[targetIndex],
                                rssi: statusUpdate.rssi,
                                uptime: formatTime(statusUpdate.uptime),
                                heapPercent: ((statusUpdate.heapUsed / statusUpdate.heapTotal) * 100).toFixed(2) + "%",
                            };
                        } else {
                            this.logMessage(`Device with ID ${statusUpdate.deviceId} not found in listDevices.`);
                        }
                    }
                } catch (e) {
                    this.logMessage(`Failed to parse JSON: ${e}`);
                }
            });
            
            ws.addEventListener('error', (error) => {
                this.logMessage("WebSocket error: " + error);
            });
            
            ws.addEventListener('close', () => {
                this.logMessage("Disconnected from WebSocket. Reconnecting in 1 second...");
                ws = null;
                reconnectTimeout = setTimeout(() => this.initWebSocket(), 1000);
            });
        },
        logMessage(message) {
            const logContainer = document.getElementById("log");
            if (logContainer) {
                const messageDiv = document.createElement("div");
                messageDiv.textContent = message;
                logContainer.appendChild(messageDiv);
                logContainer.scrollTop = logContainer.scrollHeight;
            }
        }
    };
}

document.addEventListener("DOMContentLoaded", () => {
    const clearButton = document.getElementById("clearLog");
    if (clearButton) {
        clearButton.addEventListener("click", () => {
            const logContainer = document.getElementById("log");
            if (logContainer) {
                logContainer.innerHTML = "";
            }
        });
    }
});