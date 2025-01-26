let ws = null
let reconnectTimeout = null

function formatTime(seconds) {
  const hrs = Math.floor(seconds / 3600)
  const mins = Math.floor((seconds % 3600) / 60)
  const secs = seconds % 60
  return [hrs, mins, secs].map(value => String(value).padStart(2, '0')).join(':')
}

function deviceTable() {
  return {
    devices: [],
    cameras: [],
    selectedCamera: null,
    hlsInstance: null,
    initWebSocket() {
      if (ws && (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN)) {
        return
      }
      const protocol = window.location.protocol === "https:" ? "wss://" : "ws://"
      ws = new WebSocket(protocol + window.location.host + "/websocket")
      ws.addEventListener('open', () => {
        this.logMessage("Connected to WebSocket.")
        if (reconnectTimeout) {
          clearTimeout(reconnectTimeout)
          reconnectTimeout = null
        }
        ws.send('{"call":"listDevices"}')
        ws.send('{"call":"listCameras"}')
      })
      ws.addEventListener('message', (event) => {
        this.logMessage("RECEIVED: " + event.data)
        try {
          const receivedJSON = JSON.parse(event.data)
          if ("listDevices" in receivedJSON) {
            const updatedDeviceList = receivedJSON.listDevices
            this.devices = updatedDeviceList.map(newDevice => {
              const existing = this.devices.find(d => d.deviceId === newDevice.deviceId) || {}
              return { ...existing, ...newDevice }
            })
          }
          if ("listCameras" in receivedJSON) {
            this.cameras = receivedJSON.listCameras
            if (this.cameras.length > 0 && !this.selectedCamera) {
              this.selectCamera(this.cameras[0])
            }
          }
          if ("deviceStatus" in receivedJSON) {
            const statusUpdate = receivedJSON.deviceStatus
            const targetIndex = this.devices.findIndex(device => device.deviceId === statusUpdate.deviceId)
            if (targetIndex !== -1) {
              this.devices[targetIndex] = {
                ...this.devices[targetIndex],
                rssi: statusUpdate.rssi,
                uptime: formatTime(statusUpdate.uptime),
                heapPercent: ((statusUpdate.heapUsed / statusUpdate.heapTotal) * 100).toFixed(2) + "%"
              }
              if (statusUpdate.data) {
                this.devices[targetIndex].data = statusUpdate.data
              }
            } else {
              this.logMessage("Device with ID " + statusUpdate.deviceId + " not found in listDevices.")
            }
          }
        } catch (e) {
          this.logMessage("Failed to parse JSON: " + e)
        }
      })
      ws.addEventListener('error', (error) => {
        this.logMessage("WebSocket error: " + error)
      })
      ws.addEventListener('close', () => {
        this.logMessage("Disconnected from WebSocket. Reconnecting in 1 second...")
        ws = null
        reconnectTimeout = setTimeout(() => this.initWebSocket(), 1000)
      })
    },
    relaySwitchState(deviceId, state) {
      if (!ws || ws.readyState !== WebSocket.OPEN) {
        this.logMessage("WebSocket is not open, cannot send relay message.")
        return
      }
      const messageObject = {
        call: "relayMessage",
        deviceId: deviceId,
        message: {
          call: "changeSwitchState",
          state: state
        }
      }
      ws.send(JSON.stringify(messageObject))
      this.logMessage("SENT: " + JSON.stringify(messageObject))
    },
    selectCamera(cam) {
      this.selectedCamera = cam
      const videoElement = this.$refs.video
      if (!videoElement) {
        return
      }
      if (this.hlsInstance) {
        this.hlsInstance.destroy()
        this.hlsInstance = null
      }
      const hlsSource = "/camera/" + cam + "/playlist.m3u8"
      if (Hls.isSupported()) {
        this.hlsInstance = new Hls({
          liveSyncDurationCount: 1,
          liveMaxLatencyDurationCount: 2,
          liveDurationInfinity: true,
          lowLatencyMode: true,
          debug: true,
        })
        this.hlsInstance.loadSource(hlsSource)
        this.hlsInstance.attachMedia(videoElement)
        this.hlsInstance.on(Hls.Events.MANIFEST_PARSED, () => {
          videoElement.play()
        })
      } else {
        alert("Your browser does not support HLS playback.")
      }
    },
    startMove(direction) {
      if (!this.selectedCamera || !ws || ws.readyState !== WebSocket.OPEN) {
        this.logMessage("Cannot move camera, no camera selected or WebSocket not open.")
        return
      }
      const messageObject = {
        call: "cameraMessage",
        camera: this.selectedCamera,
        message: {
          call: "move" + direction
        }
      }
      ws.send(JSON.stringify(messageObject))
      this.logMessage("SENT: " + JSON.stringify(messageObject))
    },
    stopMove() {
      if (!this.selectedCamera || !ws || ws.readyState !== WebSocket.OPEN) {
        this.logMessage("Cannot stop move, no camera selected or WebSocket not open.")
        return
      }
      const messageObject = {
        call: "cameraMessage",
        camera: this.selectedCamera,
        message: {
          call: "moveStop"
        }
      }
      ws.send(JSON.stringify(messageObject))
      this.logMessage("SENT: " + JSON.stringify(messageObject))
    },
    resetPosition() {
      if (!this.selectedCamera || !ws || ws.readyState !== WebSocket.OPEN) {
        this.logMessage("Cannot reset camera, no camera selected or WebSocket not open.")
        return
      }
      const messageObject = {
        call: "cameraMessage",
        camera: this.selectedCamera,
        message: {
          call: "moveHome"
        }
      }
      ws.send(JSON.stringify(messageObject))
      this.logMessage("SENT: " + JSON.stringify(messageObject))
    },
    toggleIR(camera) {
      if (!ws || ws.readyState !== WebSocket.OPEN) {
        this.logMessage("WebSocket is not open, cannot send IR toggle message.")
        return
      }
      const messageObject = {
        call: "cameraMessage",
        camera: camera,
        message: {
          call: "toggleIR"
        }
      }
      ws.send(JSON.stringify(messageObject))
      this.logMessage("SENT: " + JSON.stringify(messageObject))
    },
    logMessage(message) {
      const logContainer = document.getElementById("log")
      if (logContainer) {
        const messageDiv = document.createElement("div")
        messageDiv.textContent = message
        logContainer.appendChild(messageDiv)
        logContainer.scrollTop = logContainer.scrollHeight
      }
    }
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const clearButton = document.getElementById("clearLog")
  if (clearButton) {
    clearButton.addEventListener("click", () => {
      const logContainer = document.getElementById("log")
      if (logContainer) {
        logContainer.innerHTML = ""
      }
    })
  }
})