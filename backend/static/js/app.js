// Minimal tab-switching controller used by every level page
document.addEventListener('click', (e) => {
  const tab = e.target.closest('.tab');
  if (!tab) return;
  const container = tab.closest('.tabs-container');
  if (!container) return;
  const target = tab.dataset.target;
  container.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  container.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  tab.classList.add('active');
  const panel = container.querySelector('#' + target);
  if (panel) panel.classList.add('active');
});
