(function() {
        var installButton = document.getElementById('pwa-install-btn');
        var installStatus = document.getElementById('pwa-install-status');
        var deferredPrompt = null;
        var isIOS = /iphone|ipad|ipod/i.test(window.navigator.userAgent);
        var isStandalone = window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;

        if ('serviceWorker' in navigator) {
            window.addEventListener('load', function() {
                navigator.serviceWorker.register('./sw.js', { updateViaCache: 'none' })
                    .then(function(registration) {
                        registration.update();
                    })
                    .catch(function(error) {
                        console.error('Service worker registration failed:', error);
                    });
            });
        }

        if (installStatus) {
            if (isStandalone) {
                installStatus.textContent = 'Installed on this device.';
            } else if (isIOS) {
                installStatus.textContent = 'Safari: Share -> Add to Home Screen.';
            } else {
                installStatus.textContent = 'Tap Install if supported.';
            }
        }

        window.addEventListener('beforeinstallprompt', function(event) {
            event.preventDefault();
            deferredPrompt = event;
            if (!isStandalone && installButton) {
                installButton.classList.add('visible');
            }
            if (installStatus && !isStandalone) {
                installStatus.textContent = 'Ready to install.';
            }
        });

        if (installButton) {
            installButton.addEventListener('click', async function() {
                if (!deferredPrompt) return;
                deferredPrompt.prompt();
                try {
                    await deferredPrompt.userChoice;
                } finally {
                    deferredPrompt = null;
                    installButton.classList.remove('visible');
                }
            });
        }

        window.addEventListener('appinstalled', function() {
            if (installButton) installButton.classList.remove('visible');
            if (installStatus) installStatus.textContent = 'Installed successfully.';
        });
    })();
