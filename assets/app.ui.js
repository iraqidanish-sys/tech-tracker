// Navigation & profile menu (non-module, runs after DOM ready)
        function showSectionFallback(sectionId) {
            document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
            const t = document.getElementById(sectionId);
            if (t) t.classList.add('active');
            document.querySelectorAll('.bottom-nav-item').forEach(i => {
                i.classList.remove('active');
                if (i.dataset.section === sectionId) i.classList.add('active');
            });
            document.querySelectorAll('.desktop-nav-item').forEach(i => {
                i.classList.remove('active');
                if (i.dataset.section === sectionId) i.classList.add('active');
            });
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }

        function getShowSectionHandler() {
            return typeof window.showSection === 'function'
                ? window.showSection
                : showSectionFallback;
        }

        document.querySelectorAll('.bottom-nav-item').forEach(item => {
            if (!item.getAttribute('onclick')) {
                item.addEventListener('click', function() {
                    getShowSectionHandler()(this.dataset.section);
                });
            }
        });

        function toggleProfileMenu() {
            const m = document.getElementById('profileMenu');
            if (!m) return;
            const isOpening = m.style.display === 'none';
            m.style.display = isOpening ? 'block' : 'none';
            // Sync encryption label whenever menu opens
            if (isOpening && window.updateEncryptionStatus) window.updateEncryptionStatus();
        }

        document.addEventListener('click', function(e) {
            const m = document.getElementById('profileMenu');
            const a = document.getElementById('userAvatar');
            if (m && a && !a.contains(e.target) && !m.contains(e.target)) m.style.display = 'none';
        });

        function updateProfileMenu(user) {
            const n = document.getElementById('profileMenuName');
            const e = document.getElementById('profileMenuEmail');
            if (n) n.textContent = user.displayName || user.email.split('@')[0];
            if (e) e.textContent = user.email;
        }

        // ==========================================
        // Expandable Card Functions
        // ==========================================

        function toggleCard(cardId) {
            const card = document.getElementById(cardId);
            if (!card) return;

            // Toggle expanded class
            card.classList.toggle('expanded');
        }

        function getCategoryIcon(category) {
            // Map actual category names to icons
            const icons = {
                // Primary mappings (match actual category names)
                'Phone': `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>`,
                'Laptop': `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="2" y1="20" x2="22" y2="20"/></svg>`,
                'Smartwatch': `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="7" width="6" height="10" rx="1"/><path d="M9 7V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v3M9 17v3a1 1 0 0 0 1 1h4a1 1 0 0 0 1-1v-3"/></svg>`,
                'Audio': `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 18v-6a9 9 0 0 1 18 0v6"/><path d="M21 19a2 2 0 0 1-2 2h-1a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h3zM3 19a2 2 0 0 0 2 2h1a2 2 0 0 0 2-2v-3a2 2 0 0 0-2-2H3z"/></svg>`,
                'Camera': `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>`,
                'Gaming': `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 11h4M8 9v4m5-2h.01M18 11h.01M8 2h8l4 10-4 10H8L4 12z"/></svg>`,
                'Accessories': `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v20M2 12h20"/><circle cx="12" cy="12" r="3"/></svg>`,
                'Storage': `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>`,
                'Monitor': `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>`,
                'Keyboard/Mouse': `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M6 8h.01M10 8h.01M14 8h.01M18 8h.01M8 12h.01M12 12h.01M16 12h.01M7 16h10"/></svg>`,
                'Chargers': `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>`,
                'Other': `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="8" width="18" height="12" rx="2"/><path d="M10 8V5a2 2 0 0 1 2-2h0a2 2 0 0 1 2 2v3"/></svg>`,
                // Aliases for backwards compatibility
                'Mobile': `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>`,
                'Watch': `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="7" width="6" height="10" rx="1"/><path d="M9 7V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v3M9 17v3a1 1 0 0 0 1 1h4a1 1 0 0 0 1-1v-3"/></svg>`,
                'Headphones': `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 18v-6a9 9 0 0 1 18 0v6"/><path d="M21 19a2 2 0 0 1-2 2h-1a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h3zM3 19a2 2 0 0 0 2 2h1a2 2 0 0 0 2-2v-3a2 2 0 0 0-2-2H3z"/></svg>`,
                'Tablet': `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="2" width="16" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>`,
                'TV': `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="15" rx="2" ry="2"/><polyline points="17 2 12 7 7 2"/></svg>`,
                'Smart Home': `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>`
            };
            // Return icon or default box icon
            return icons[category] || `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="8" width="18" height="12" rx="2"/><path d="M10 8V5a2 2 0 0 1 2-2h0a2 2 0 0 1 2 2v3"/></svg>`;
        }

        function getCategoryEmoji(category) {
            return normalizeLabel(category || 'Other');
        }

        // Make functions global
        window.toggleCard = toggleCard;
        window.getCategoryEmoji = getCategoryEmoji;
        window.getCategoryIcon = getCategoryIcon;

        // ==========================================
        // IMAGE UPLOAD FUNCTIONS
        // ==========================================

        // Switch between image tabs
        function switchImageTab(event, tabId) {
            event.preventDefault();

            // Get the parent container (either image-upload-container or modal-content)
            const container = event.target.closest('.image-upload-container') || event.target.closest('.modal-content');

            if (!container) return;

            // Remove active class from all tabs and contents in this container
            container.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            container.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

            // Add active class to clicked tab
            event.target.classList.add('active');

            // Show the corresponding tab content
            const targetTab = document.getElementById(tabId);
            if (targetTab) {
                targetTab.classList.add('active');
            }
        }

        // Handle file upload

        // Search Unsplash images

        // Make functions global
        window.switchImageTab = switchImageTab;


        // ==========================================
        // IMAGE PICKER MODAL FUNCTIONS
        // ==========================================

        let currentPickerTarget = null; // Stores which form is using the picker
        let currentPickerImageUrl = null; // Stores the selected image URL

        window.openImagePicker = function(target) {
            currentPickerTarget = target;
            currentPickerImageUrl = null;

            // Reset all tabs
            document.getElementById('picker-image-url').value = '';
            document.getElementById('picker-url-preview').style.display = 'none';
            document.getElementById('picker-upload-preview').style.display = 'none';
            document.getElementById('picker-file-input').value = '';

            // Reset upload placeholder visibility
            const uploadPlaceholder = document.querySelector('#picker-upload .upload-placeholder');
            if (uploadPlaceholder) {
                uploadPlaceholder.style.display = '';
                uploadPlaceholder.style.pointerEvents = '';
            }

            // Reset to URL tab
            document.querySelectorAll('#imagePickerModal .tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('#imagePickerModal .tab-content').forEach(c => c.classList.remove('active'));
            const urlTabBtn = document.querySelector('#imagePickerModal .tab-btn:first-child');
            const urlTabContent = document.getElementById('picker-url');
            if (urlTabBtn) urlTabBtn.classList.add('active');
            if (urlTabContent) urlTabContent.classList.add('active');

            // Show modal
            const modal = document.getElementById('imagePickerModal');
            modal.style.display = 'flex';
            setTimeout(() => modal.classList.add('active'), 10);
        };

        window.closeImagePicker = function() {
            const modal = document.getElementById('imagePickerModal');
            modal.classList.remove('active');
            setTimeout(() => {
                modal.style.display = 'none';
                currentPickerTarget = null;
                currentPickerImageUrl = null;
            }, 200);
        };

        // Handle URL input with validation
        document.addEventListener('DOMContentLoaded', () => {
            const urlInput = document.getElementById('picker-image-url');
            if (urlInput) {
                // Preview on Enter key
                urlInput.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter') { e.preventDefault(); window.previewPickerUrl(); }
                });
            }
        });

        function setPickerUrlError(urlInput) {
            if (!urlInput) return;
            urlInput.style.borderColor = 'rgba(239,68,68,0.5)';
            setTimeout(() => {
                urlInput.style.borderColor = 'rgba(148,163,184,0.2)';
            }, 1500);
        }

        window.previewPickerUrl = function() {
            const urlInput = document.getElementById('picker-image-url');
            const preview = document.getElementById('picker-url-preview');
            const img = document.getElementById('picker-url-img');
            if (!urlInput || !preview || !img) return;

            const rawUrl = urlInput.value.trim();
            if (!rawUrl) return;

            const sanitizeFn = typeof window.sanitizeURL === 'function' ? window.sanitizeURL : null;
            const proxyFn = typeof window.getCORSProxyURL === 'function' ? window.getCORSProxyURL : null;
            const sanitizedUrl = sanitizeFn ? sanitizeFn(rawUrl) : '';
            if (!sanitizedUrl) {
                preview.style.display = 'none';
                currentPickerImageUrl = null;
                setPickerUrlError(urlInput);
                return;
            }

            const preferredUrl = proxyFn ? proxyFn(sanitizedUrl) : sanitizedUrl;
            const candidates = preferredUrl === sanitizedUrl ? [sanitizedUrl] : [preferredUrl, sanitizedUrl];

            const tryLoad = function(index) {
                if (index >= candidates.length) {
                    preview.style.display = 'none';
                    currentPickerImageUrl = null;
                    setPickerUrlError(urlInput);
                    return;
                }

                const candidate = candidates[index];
                const testImg = new Image();
                testImg.referrerPolicy = 'no-referrer';
                testImg.onload = function() {
                    img.src = candidate;
                    preview.style.display = 'block';
                    currentPickerImageUrl = sanitizedUrl;
                    urlInput.value = sanitizedUrl;
                };
                testImg.onerror = function() {
                    tryLoad(index + 1);
                };
                testImg.src = candidate;
            };

            tryLoad(0);
        };

        // Handle file upload with mobile support and error handling
        // Compress image for better mobile performance
        async function compressImage(file) {
            return new Promise((resolve, reject) => {
                const reader = new FileReader();
                
                reader.onload = function(e) {
                    const img = new Image();
                    
                    img.onload = function() {
                        // Create canvas for compression
                        const canvas = document.createElement('canvas');
                        const ctx = canvas.getContext('2d');
                        
                        // Calculate new dimensions (max 800px on longest side)
                        let width = img.width;
                        let height = img.height;
                        const maxSize = 800;
                        
                        if (width > height && width > maxSize) {
                            height = (height * maxSize) / width;
                            width = maxSize;
                        } else if (height > maxSize) {
                            width = (width * maxSize) / height;
                            height = maxSize;
                        }
                        
                        canvas.width = width;
                        canvas.height = height;
                        
                        // Draw and compress
                        ctx.drawImage(img, 0, 0, width, height);
                        
                        // Convert to base64 with compression (0.8 quality for JPEG)
                        const compressedDataUrl = canvas.toDataURL('image/jpeg', 0.8);
                        resolve(compressedDataUrl);
                    };
                    
                    img.onerror = function() {
                        reject(new Error('Failed to load image'));
                    };
                    
                    img.src = e.target.result;
                };
                
                reader.onerror = function() {
                    reject(new Error('Failed to read file'));
                };
                
                reader.readAsDataURL(file);
            });
        }

        window.pickerHandleUpload = async function(event) {
            const file = event.target.files[0];
            if (!file) return;

            // Validate file type
            if (!file.type.startsWith('image/')) {
                alert('Please select a valid image file');
                return;
            }

            // Validate file size (max 10MB before compression)
            if (file.size > 10 * 1024 * 1024) {
                alert('Image size should be less than 10MB');
                return;
            }

            // Show loading state on the upload placeholder
            const uploadPlaceholder = document.querySelector('#picker-upload .upload-placeholder');
            const originalPlaceholderHTML = uploadPlaceholder ? uploadPlaceholder.innerHTML : '';
            if (uploadPlaceholder) {
                uploadPlaceholder.innerHTML = '<div style="padding:12px;text-align:center;color:#10b981;">Processing...</div>';
                uploadPlaceholder.style.pointerEvents = 'none';
            }

            try {
                // Compress image
                const compressedImage = await compressImage(file);

                // Display compressed image preview
                const previewImg = document.getElementById('picker-upload-img');
                const previewContainer = document.getElementById('picker-upload-preview');
                if (previewImg) previewImg.src = compressedImage;
                if (previewContainer) previewContainer.style.display = 'block';
                currentPickerImageUrl = compressedImage;

                // Hide placeholder once preview is shown
                if (uploadPlaceholder) {
                    uploadPlaceholder.style.display = 'none';
                }
            } catch (error) {
                alert('Error processing image. Please try again.');
                if (uploadPlaceholder) {
                    uploadPlaceholder.innerHTML = originalPlaceholderHTML;
                    uploadPlaceholder.style.pointerEvents = 'auto';
                }
            }
        };

        // Save the picked image
        window.savePickedImage = function() {

            if (!currentPickerImageUrl) {
                alert('Please select or enter an image first');
                return;
            }

            const sanitizeFn = typeof window.sanitizeURL === 'function' ? window.sanitizeURL : null;
            const sanitizedPickerUrl = sanitizeFn ? sanitizeFn(currentPickerImageUrl) : '';
            if (!sanitizedPickerUrl) {
                alert('The selected image URL is invalid. Please try another URL.');
                return;
            }
            currentPickerImageUrl = sanitizedPickerUrl;

            if (!currentPickerTarget) {
                closeImagePicker();
                return;
            }

            // Determine which form to update
            const prefix = currentPickerTarget === 'gadget' ? 'g' :
                          currentPickerTarget === 'edit-gadget' ? 'edit-g' :
                          currentPickerTarget === 'game' ? 'gm' :
                          currentPickerTarget === 'edit-game' ? 'edit-gm' :
                          currentPickerTarget === 'digital' ? 'd' :
                          currentPickerTarget === 'edit-digital' ? 'edit-d' : '';


            if (prefix) {
                // Update hidden input
                const hiddenInput = document.getElementById(`${prefix}-final-image-url`);
                if (hiddenInput) {
                    hiddenInput.value = currentPickerImageUrl;
                } else {
                }

                // Update preview container with horizontal layout
                const container = document.getElementById(`${prefix}-image-preview-container`);
                if (container) {
                    container.innerHTML = `
                        <img src="${currentPickerImageUrl}" style="width: 40px; height: 40px; border-radius: 6px; object-fit: cover;">
                        <div style="font-size: 13px; color: var(--text-primary); flex: 1;">Image added</div>
                    `;
                } else {
                }
            }

            closeImagePicker();
        };

        if (typeof window.showSection !== 'function') {
            window.showSection = showSectionFallback;
        }
        window.toggleProfileMenu = toggleProfileMenu;
        window.updateProfileMenu = updateProfileMenu;

        // Toggle collapsible add form
        window.toggleAddForm = function(wrapperId) {
            const wrapper = document.getElementById(wrapperId);
            const btn = document.querySelector(`[data-toggle="${wrapperId}"]`);
            if (!wrapper) return;
            const isOpen = wrapper.classList.contains('open');
            wrapper.classList.toggle('open', !isOpen);
            if (btn) btn.classList.toggle('open', !isOpen);
            if (isOpen && wrapperId === 'games-add-wrapper' && !window.editingGameId) {
                if (typeof window.resetGameAddFormDraftOnSectionLeave === 'function') {
                    window.resetGameAddFormDraftOnSectionLeave();
                }
            }
        };
    
