function chartData(data) {
  return {
    rawData: data,
    chartInstance: null,
    drawChart() {
      const canvas = document.getElementById('chart')
      const ctx = canvas.getContext('2d')
      const timestamps = []
      const temperatures = []
      const humidities = []
      this.rawData.forEach(item => {
        const timestamp = Object.keys(item)[0]
        const { t, h } = item[timestamp]
        const dateObj = new Date(timestamp * 1000)
        const datePart = dateObj.toLocaleString('en-US', { month: 'numeric', day: 'numeric' })
        const timePart = dateObj.toLocaleString('en-US', { hour: '2-digit', minute: '2-digit' })
        const formattedLabel = datePart + '\n' + timePart
        timestamps.push(formattedLabel)
        temperatures.push(t)
        humidities.push(h)
      })
      this.chartInstance = new Chart(ctx, {
        type: 'line',
        data: {
          labels: timestamps,
          datasets: [
            {
              label: 'Temperature (°C)',
              data: temperatures,
              borderColor: 'orange',
              borderWidth: 2,
              fill: false,
              pointBackgroundColor: 'orange'
            },
            {
              label: 'Humidity (%)',
              data: humidities,
              borderColor: 'lime',
              borderWidth: 2,
              fill: false,
              pointBackgroundColor: 'lime'
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              labels: {
                color: 'white',
                font: {
                  size: 14,
                  family: 'Ubuntu'
                }
              }
            }
          },
          scales: {
            x: {
              ticks: {
                color: 'white',
                font: {
                  size: 14,
                  family: 'Ubuntu'
                },
              },
              title: {
                display: true,
                text: 'Date / Time',
                color: 'white',
                font: {
                  size: 16,
                  family: 'Ubuntu'
                }
              },
              grid: {
                color: 'rgba(255, 255, 255, 0.2)'
              }
            },
            y: {
              ticks: {
                color: 'white',
                font: {
                  size: 14,
                  family: 'Ubuntu'
                }
              },
              title: {
                display: true,
                text: 'Values',
                color: 'white',
                font: {
                  size: 16,
                  family: 'Ubuntu'
                }
              },
              grid: {
                color: 'rgba(255, 255, 255, 0.2)'
              }
            }
          }
        }
      })
    },
    updateChart(newData) {
      this.rawData = [...this.rawData, ...newData]
      const newTimestamps = []
      const newTemperatures = []
      const newHumidities = []
      this.rawData.forEach(item => {
        const timestamp = Object.keys(item)[0]
        const { t, h } = item[timestamp]
        const dateObj = new Date(timestamp * 1000)
        const datePart = dateObj.toLocaleString('en-US', { month: 'numeric', day: 'numeric' })
        const timePart = dateObj.toLocaleString('en-US', { hour: '2-digit', minute: '2-digit' })
        const formattedLabel = datePart + '\n' + timePart
        newTimestamps.push(formattedLabel)
        newTemperatures.push(t)
        newHumidities.push(h)
      })
      this.chartInstance.data.labels = newTimestamps
      this.chartInstance.data.datasets[0].data = newTemperatures
      this.chartInstance.data.datasets[1].data = newHumidities
      this.chartInstance.update()
    }
  }
}