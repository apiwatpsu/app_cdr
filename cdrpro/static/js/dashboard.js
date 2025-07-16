document.addEventListener("DOMContentLoaded", function () {
  // === เวลา
  function updateCurrentTime() {
    const now = new Date();
    const options = {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false
    };
    const formatted = now.toLocaleString('th-TH', options);
    document.getElementById('current-time').textContent = formatted;
  }

  setInterval(updateCurrentTime, 1000);
  updateCurrentTime();

  // === Screenshot
  document.getElementById('capture-btn')?.addEventListener('click', function () {
    html2canvas(document.getElementById('dashboard-content')).then(function (canvas) {
      let link = document.createElement('a');
      link.download = 'dashboard-screenshot.png';
      link.href = canvas.toDataURL('image/png');
      link.click();
    });
  });

  // === Fullscreen
  document.getElementById('fullscreen-btn')?.addEventListener('click', function () {
    const dashboard = document.getElementById('dashboard-content');

    if (!document.fullscreenElement) {
      dashboard.requestFullscreen?.();
      dashboard.mozRequestFullScreen?.();
      dashboard.webkitRequestFullscreen?.();
      dashboard.msRequestFullscreen?.();
    } else {
      document.exitFullscreen?.();
    }
  });

  // === Chart ===
  const queueDataScript = document.getElementById("queue-data");
  if (!queueDataScript) return;
  const queueData = JSON.parse(queueDataScript.textContent);

  Chart.register(ChartDataLabels);
  const labels = queueData.map(row => row["Queue Name"]);
  const serviceData = queueData.map(row => row["Service Calls"]);
  const abandonedData = queueData.map(row => row["Abandoned Calls"]);
  const totalData = queueData.map(row => row["Total Calls"]);
  const othersData = totalData.map((total, i) => total - serviceData[i] - abandonedData[i]);

  const ctx = document.getElementById('queueChart').getContext('2d');
  new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [
        {
          label: 'Service',
          data: serviceData,
          backgroundColor: 'rgba(25, 135, 84, 0.4)',
          borderColor: 'rgba(25, 135, 84, 1)',
          fill: true,
          tension: 0.4,
          stack: 'stack1'
        },
        {
          label: 'Abandoned',
          data: abandonedData,
          backgroundColor: 'rgba(220, 53, 69, 0.4)',
          borderColor: 'rgba(220, 53, 69, 1)',
          fill: true,
          tension: 0.4,
          stack: 'stack1'
        },
        {
          label: 'Other',
          data: othersData,
          backgroundColor: 'rgba(108, 117, 125, 0.4)',
          borderColor: 'rgba(108, 117, 125, 1)',
          fill: true,
          tension: 0.4,
          stack: 'stack1'
        }
      ]
    },
    options: {
      responsive: true,
      plugins: {
        tooltip: { mode: 'index', intersect: false },
        legend: {
          position: 'bottom',
          labels: {
            color: document.documentElement.classList.contains('dark-mode') ? '#f1f1f1' : '#333333',
            usePointStyle: true,
            pointStyle: 'circle'
          }
        }
      },
      interaction: {
        mode: 'index',
        intersect: false
      },
      scales: {
        x: { stacked: true },
        y: {
          stacked: true,
          beginAtZero: true,
          title: { display: true, text: 'Calls' }
        }
      }
    },
    plugins: [ChartDataLabels]
  });
});
