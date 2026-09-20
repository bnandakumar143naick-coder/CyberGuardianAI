/**
 * CyberGuardian AI - App Shell
 * Common functionality for all pages
 */

// Initialize app on page load
document.addEventListener('DOMContentLoaded', () => {
  initializeAppShell();
});

function initializeAppShell() {
  // Set up navigation
  setupNavigation();
  
  // Set up responsive behavior
  setupResponsive();
  
  // Initialize any dynamic components
  initializeComponents();
}

/**
 * Navigation Setup
 */
function setupNavigation() {
  const navLinks = document.querySelectorAll('.sidebar-nav-link');
  
  navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
      // Remove active class from all links
      navLinks.forEach(l => l.classList.remove('active'));
      // Add active class to clicked link
      link.classList.add('active');
    });
  });
}

/**
 * Responsive Behavior
 */
function setupResponsive() {
  // Mobile menu toggle
  const sidebar = document.querySelector('.sidebar');
  if (!sidebar) return;
  
  // On mobile, hide sidebar by default
  if (window.innerWidth <= 640) {
    sidebar.style.display = 'none';
  }
  
  // Add mobile menu button to topbar if not present
  const topbar = document.querySelector('.topbar');
  if (topbar && !document.querySelector('.mobile-menu-toggle')) {
    const toggle = document.createElement('button');
    toggle.className = 'mobile-menu-toggle btn btn-outline btn-small';
    toggle.textContent = '☰';
    toggle.style.display = window.innerWidth <= 640 ? 'block' : 'none';
    toggle.onclick = () => {
      sidebar.classList.toggle('mobile-visible');
      sidebar.style.display = sidebar.style.display === 'none' ? 'block' : 'none';
    };
    topbar.appendChild(toggle);
  }
  
  // Update on resize
  window.addEventListener('resize', () => {
    const toggle = document.querySelector('.mobile-menu-toggle');
    if (toggle) {
      toggle.style.display = window.innerWidth <= 640 ? 'block' : 'none';
    }
  });
}

/**
 * Component Initialization
 */
function initializeComponents() {
  // Initialize tooltips, popovers, etc
  initializeTooltips();
}

function initializeTooltips() {
  // Simple tooltip implementation
  const elements = document.querySelectorAll('[data-tooltip]');
  elements.forEach(el => {
    el.addEventListener('mouseenter', (e) => {
      const tooltip = document.createElement('div');
      tooltip.className = 'tooltip';
      tooltip.textContent = el.getAttribute('data-tooltip');
      document.body.appendChild(tooltip);
      
      const rect = el.getBoundingClientRect();
      tooltip.style.left = (rect.left + rect.width / 2 - tooltip.offsetWidth / 2) + 'px';
      tooltip.style.top = (rect.top - tooltip.offsetHeight - 8) + 'px';
    });
  });
}

/**
 * Utility Functions
 */

/**
 * Format date to human readable string
 */
function formatDate(dateStr) {
  const date = new Date(dateStr);
  return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

/**
 * Format risk score as severity badge
 */
function getRiskBadge(score) {
  if (score >= 75) return '<span class="risk-level-badge CRITICAL">🔴 CRITICAL</span>';
  if (score >= 60) return '<span class="risk-level-badge HIGH">🟠 HIGH</span>';
  if (score >= 40) return '<span class="risk-level-badge MEDIUM">🟡 MEDIUM</span>';
  return '<span class="risk-level-badge LOW">🟢 LOW</span>';
}

/**
 * Show notification toast
 */
function showNotification(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  toast.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    padding: 16px 20px;
    border-radius: var(--radius-md);
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text);
    z-index: 1000;
    animation: slideIn 0.3s ease;
  `;
  
  if (type === 'error') {
    toast.style.borderColor = 'var(--risk-critical)';
    toast.style.color = '#ffb4af';
  } else if (type === 'success') {
    toast.style.borderColor = 'var(--risk-low)';
    toast.style.color = 'var(--risk-low)';
  }
  
  document.body.appendChild(toast);
  
  setTimeout(() => {
    toast.style.animation = 'slideOut 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

/**
 * Debounce function for performance
 */
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

/**
 * Check if element is in viewport
 */
function isInViewport(el) {
  const rect = el.getBoundingClientRect();
  return (
    rect.top >= 0 &&
    rect.left >= 0 &&
    rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
    rect.right <= (window.innerWidth || document.documentElement.clientWidth)
  );
}

/**
 * Smooth scroll to element
 */
function smoothScrollTo(element) {
  element.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Export for use in other scripts
window.CG = {
  formatDate,
  getRiskBadge,
  showNotification,
  debounce,
  isInViewport,
  smoothScrollTo
};
