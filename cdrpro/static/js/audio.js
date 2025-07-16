document.addEventListener("DOMContentLoaded", function () {
  const modalAudio = document.getElementById('modal-audio-player');
  const modalSource = document.getElementById('modal-audio-source');
  const audioModalElement = document.getElementById('audioModal');

  // Bootstrap 5 modal instance
  const audioModal = new bootstrap.Modal(audioModalElement);

  // Get URL template from data attribute on body
  const urlTemplate = document.body.getAttribute('data-audio-url-template');

  document.querySelectorAll('.play-audio-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      const filename = this.getAttribute('data-filename');
      if (!urlTemplate) {
        console.error('Audio URL template not found');
        return;
      }
      const audioUrl = urlTemplate.replace('__FILENAME__', filename);
      modalSource.src = audioUrl;
      modalAudio.load();
      modalAudio.play();

      // Show the Bootstrap modal
      audioModal.show();
    });
  });
});
