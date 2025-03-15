
  const audio = document.getElementById('audioElement');
  const playBtn = document.getElementById('playPauseBtn');
  const progressBar = document.getElementById('progressBar');
  const currentTime = document.getElementById('currentTime');
  const duration = document.getElementById('duration');
  const volumeSlider = document.getElementById('volumeSlider');

  // Format time
  function formatTime(seconds) {
    const minutes = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60).toString().padStart(2, '0');
    return `${minutes}:${secs}`;
  }

  // Play/Pause Toggle
  playBtn.addEventListener('click', () => {
    if (audio.paused) {
      audio.play();
      playBtn.textContent = '⏸️';
    } else {
      audio.pause();
      playBtn.textContent = '▶️';
    }
  });

  // Update progress bar
  audio.addEventListener('timeupdate', () => {
    progressBar.value = (audio.currentTime / audio.duration) * 100;
    currentTime.textContent = formatTime(audio.currentTime);
  });

  // Set duration when loaded
  audio.addEventListener('loadedmetadata', () => {
    duration.textContent = formatTime(audio.duration);
  });

  // Seek audio
  progressBar.addEventListener('input', () => {
    audio.currentTime = (progressBar.value / 100) * audio.duration;
  });

  // Volume control
  volumeSlider.addEventListener('input', () => {
    audio.volume = volumeSlider.value;
  });
