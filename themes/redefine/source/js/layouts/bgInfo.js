export default function initBgInfo() {
  const bgInfoConfig = theme.home_banner.bg_info;
  
  // Exit if bg_info is disabled or not in api mode
  if (!bgInfoConfig || !bgInfoConfig.enable || bgInfoConfig.mode !== 'api') {
    return;
  }

  const titleElement = document.getElementById('bg-info-title');
  const descElement = document.getElementById('bg-info-desc');
  const containerElement = document.getElementById('bg-info-container');

  // If elements don't exist (e.g. not on home page), return
  if (!titleElement || !descElement) {
    return;
  }

  const apiUrl = bgInfoConfig.api.url;
  const titleField = bgInfoConfig.api.response_fields.title;
  const descField = bgInfoConfig.api.response_fields.desc;

  // Check session storage first
  const cachedData = sessionStorage.getItem('bg_info_data');
  if (cachedData) {
    try {
      const data = JSON.parse(cachedData);
      if (data[titleField]) titleElement.textContent = data[titleField];
      if (data[descField]) descElement.textContent = data[descField];
      return;
    } catch (e) {
      console.error('Error parsing cached bg_info data', e);
      sessionStorage.removeItem('bg_info_data');
    }
  }

  // Fetch from API
  fetch(apiUrl)
    .then(response => response.json())
    .then(data => {
      if (data[titleField]) {
        titleElement.textContent = data[titleField];
      }
      
      if (data[descField]) {
        descElement.textContent = data[descField];
      }

      // Cache the data
      sessionStorage.setItem('bg_info_data', JSON.stringify(data));
    })
    .catch(error => {
      console.error('Error fetching background info:', error);
      if (titleElement) titleElement.textContent = 'Error';
      if (descElement) descElement.textContent = 'Failed to load info';
    });
}
