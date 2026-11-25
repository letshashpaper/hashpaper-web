/**
 * HashPaper PWA Installer & Service Worker Registration
 * Powers the "Install App" button across Desktop, Android, and iOS Safari.
 */
(function () {
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('/sw.js').catch(() => {});
    });
  }

  let deferredPrompt = null;

  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredPrompt = e;
    document.querySelectorAll('[data-install-btn]').forEach((btn) => {
      btn.classList.remove('hidden');
    });
  });

  window.addEventListener('appinstalled', () => {
    deferredPrompt = null;
    document.querySelectorAll('[data-install-btn]').forEach((btn) => {
      btn.textContent = 'Installed';
      btn.disabled = true;
    });
  });

  window.triggerHashPaperInstall = async function () {
    if (deferredPrompt) {
      deferredPrompt.prompt();
      const { outcome } = await deferredPrompt.userChoice;
      if (outcome === 'accepted') {
        deferredPrompt = null;
      }
      return;
    }

    const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
    if (isIOS) {
      alert('To install HashPaper on iPhone/iPad: tap the Share icon at the bottom of Safari, then select "Add to Home Screen".');
    } else {
      alert('To install HashPaper as an app: open your browser menu (⋮) and select "Install HashPaper" or "Add to Home Screen".');
    }
  };
})();
