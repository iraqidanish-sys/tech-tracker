// Extracted icon catalog + default lists from app.module.js for modular loading.

const iconLibrary = {
    // Gadget Categories - Each with unique colors and designs
    'Phone': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="phone-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#06b6d4;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#0ea5e9;stop-opacity:1" />
                </linearGradient>
            </defs>
            <rect x="5" y="2" width="14" height="20" rx="2" ry="2" fill="url(#phone-grad)" stroke="#06b6d4" stroke-width="1.5"/>
            <circle cx="12" cy="18" r="1.5" fill="white"/>
            <line x1="9" y1="5" x2="15" y2="5" stroke="white" stroke-width="1.5" stroke-linecap="round"/>
        </svg>`,
    'Laptop': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="laptop-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#8b5cf6;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#a78bfa;stop-opacity:1" />
                </linearGradient>
            </defs>
            <rect x="2" y="4" width="20" height="13" rx="1.5" fill="url(#laptop-grad)" stroke="#8b5cf6" stroke-width="1.5"/>
            <rect x="4" y="6" width="16" height="9" rx="0.5" fill="#1e293b"/>
            <path d="M1 17h22v2a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1v-2z" fill="url(#laptop-grad)" stroke="#8b5cf6" stroke-width="1.5"/>
        </svg>`,
    'Smartwatch': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="watch-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#ec4899;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#f472b6;stop-opacity:1" />
                </linearGradient>
            </defs>
            <rect x="7" y="6" width="10" height="12" rx="2" fill="url(#watch-grad)" stroke="#ec4899" stroke-width="1.5"/>
            <circle cx="12" cy="12" r="3" fill="none" stroke="white" stroke-width="1.5"/>
            <path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2M9 18v2a1 1 0 0 0 1 1h4a1 1 0 0 0 1-1v-2" stroke="#ec4899" stroke-width="1.5" fill="url(#watch-grad)"/>
        </svg>`,
    'Audio': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="audio-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#f59e0b;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#fbbf24;stop-opacity:1" />
                </linearGradient>
            </defs>
            <path d="M3 12v6a9 9 0 0 0 9 9 9 9 0 0 0 9-9v-6" stroke="#f59e0b" stroke-width="2" fill="none"/>
            <path d="M21 16a2 2 0 0 1-2 2h-1a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h3v5z" fill="url(#audio-grad)" stroke="#f59e0b" stroke-width="1.5"/>
            <path d="M3 16a2 2 0 0 0 2 2h1a2 2 0 0 0 2-2v-3a2 2 0 0 0-2-2H3v5z" fill="url(#audio-grad)" stroke="#f59e0b" stroke-width="1.5"/>
        </svg>`,
    'Camera': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="camera-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#10b981;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#34d399;stop-opacity:1" />
                </linearGradient>
            </defs>
            <path d="M23 17a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2v9z" fill="url(#camera-grad)" stroke="#10b981" stroke-width="1.5"/>
            <circle cx="12" cy="13" r="4" fill="none" stroke="white" stroke-width="2"/>
            <circle cx="12" cy="13" r="2" fill="white"/>
        </svg>`,
    'Gaming': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="gaming-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#ef4444;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#f87171;stop-opacity:1" />
                </linearGradient>
            </defs>
            <path d="M17.32 5H6.68a4 4 0 0 0-3.978 3.59c-.006.052-.01.101-.017.152C2.604 9.416 2 14.456 2 16a3 3 0 0 0 3 3c1 0 1.5-.5 2-1l1.414-1.414A2 2 0 0 1 9.828 16h4.344a2 2 0 0 1 1.414.586L17 18c.5.5 1 1 2 1a3 3 0 0 0 3-3c0-1.545-.604-6.584-.685-7.258-.007-.05-.011-.1-.017-.151A4 4 0 0 0 17.32 5z" fill="url(#gaming-grad)" stroke="#ef4444" stroke-width="1.5"/>
            <line x1="6" y1="11" x2="10" y2="11" stroke="white" stroke-width="2" stroke-linecap="round"/>
            <line x1="8" y1="9" x2="8" y2="13" stroke="white" stroke-width="2" stroke-linecap="round"/>
            <circle cx="15" cy="12" r="1" fill="white"/>
            <circle cx="18" cy="10" r="1" fill="white"/>
        </svg>`,
    'Accessories': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="acc-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#fbbf24;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#fcd34d;stop-opacity:1" />
                </linearGradient>
            </defs>
            <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" fill="url(#acc-grad)" stroke="#fbbf24" stroke-width="1.5" stroke-linejoin="round"/>
        </svg>`,
    'Storage': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="storage-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#6366f1;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#818cf8;stop-opacity:1" />
                </linearGradient>
            </defs>
            <ellipse cx="12" cy="5" rx="9" ry="3" fill="url(#storage-grad)" stroke="#6366f1" stroke-width="1.5"/>
            <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" fill="none" stroke="#6366f1" stroke-width="1.5"/>
            <path d="M3 12c0 1.66 4 3 9 3s9-1.34 9-3" stroke="white" stroke-width="1.5" opacity="0.6"/>
        </svg>`,
    'Monitor': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="monitor-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#14b8a6;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#2dd4bf;stop-opacity:1" />
                </linearGradient>
            </defs>
            <rect x="2" y="3" width="20" height="14" rx="2" fill="url(#monitor-grad)" stroke="#14b8a6" stroke-width="1.5"/>
            <rect x="4" y="5" width="16" height="10" rx="1" fill="#1e293b"/>
            <line x1="8" y1="21" x2="16" y2="21" stroke="#14b8a6" stroke-width="2" stroke-linecap="round"/>
            <line x1="12" y1="17" x2="12" y2="21" stroke="#14b8a6" stroke-width="2"/>
        </svg>`,
    'Keyboard/Mouse': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="keyboard-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#3b82f6;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#60a5fa;stop-opacity:1" />
                </linearGradient>
            </defs>
            <rect x="2" y="6" width="20" height="14" rx="2" fill="url(#keyboard-grad)" stroke="#3b82f6" stroke-width="1.5"/>
            <rect x="5" y="9" width="2" height="2" rx="0.5" fill="white"/>
            <rect x="9" y="9" width="2" height="2" rx="0.5" fill="white"/>
            <rect x="13" y="9" width="2" height="2" rx="0.5" fill="white"/>
            <rect x="17" y="9" width="2" height="2" rx="0.5" fill="white"/>
            <rect x="7" y="13" width="10" height="2" rx="0.5" fill="white"/>
        </svg>`,
    'Chargers': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="charger-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#22c55e;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#4ade80;stop-opacity:1" />
                </linearGradient>
            </defs>
            <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" fill="url(#charger-grad)" stroke="#22c55e" stroke-width="1.5" stroke-linejoin="round"/>
        </svg>`,
    'Other': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="other-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#94a3b8;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#cbd5e1;stop-opacity:1" />
                </linearGradient>
            </defs>
            <circle cx="12" cy="12" r="2" fill="url(#other-grad)" stroke="#94a3b8" stroke-width="1.5"/>
            <circle cx="12" cy="5" r="2" fill="url(#other-grad)" stroke="#94a3b8" stroke-width="1.5"/>
            <circle cx="12" cy="19" r="2" fill="url(#other-grad)" stroke="#94a3b8" stroke-width="1.5"/>
            <circle cx="5" cy="12" r="2" fill="url(#other-grad)" stroke="#94a3b8" stroke-width="1.5"/>
            <circle cx="19" cy="12" r="2" fill="url(#other-grad)" stroke="#94a3b8" stroke-width="1.5"/>
        </svg>`,

    // Game Platforms - Unique colored icons
    'PlayStation 5': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="ps5-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#0ea5e9;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#38bdf8;stop-opacity:1" />
                </linearGradient>
            </defs>
            <rect x="6" y="3" width="12" height="18" rx="2" fill="url(#ps5-grad)" stroke="#0ea5e9" stroke-width="1.5"/>
            <text x="12" y="14" fill="white" font-size="10" font-weight="bold" text-anchor="middle">PS</text>
            <circle cx="12" cy="18" r="1.5" fill="white"/>
        </svg>`,
    'PlayStation 4': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="ps4-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#3b82f6;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#60a5fa;stop-opacity:1" />
                </linearGradient>
            </defs>
            <rect x="6" y="3" width="12" height="18" rx="2" fill="url(#ps4-grad)" stroke="#3b82f6" stroke-width="1.5"/>
            <text x="12" y="14" fill="white" font-size="9" font-weight="bold" text-anchor="middle">PS4</text>
            <circle cx="12" cy="18" r="1.5" fill="white"/>
        </svg>`,
    'PlayStation 3': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="ps3-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#6366f1;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#818cf8;stop-opacity:1" />
                </linearGradient>
            </defs>
            <rect x="6" y="3" width="12" height="18" rx="2" fill="url(#ps3-grad)" stroke="#6366f1" stroke-width="1.5"/>
            <text x="12" y="14" fill="white" font-size="9" font-weight="bold" text-anchor="middle">PS3</text>
            <circle cx="12" cy="18" r="1.5" fill="white"/>
        </svg>`,
    'Xbox Series X/S': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="xboxsx-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#22c55e;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#4ade80;stop-opacity:1" />
                </linearGradient>
            </defs>
            <circle cx="12" cy="12" r="9" fill="url(#xboxsx-grad)" stroke="#22c55e" stroke-width="1.5"/>
            <text x="12" y="15" fill="white" font-size="10" font-weight="bold" text-anchor="middle">X</text>
        </svg>`,
    'Xbox One': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="xbone-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#16a34a;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#22c55e;stop-opacity:1" />
                </linearGradient>
            </defs>
            <circle cx="12" cy="12" r="9" fill="url(#xbone-grad)" stroke="#16a34a" stroke-width="1.5"/>
            <text x="12" y="15" fill="white" font-size="8" font-weight="bold" text-anchor="middle">XB1</text>
        </svg>`,
    'Xbox 360': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="x360-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#15803d;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#16a34a;stop-opacity:1" />
                </linearGradient>
            </defs>
            <circle cx="12" cy="12" r="9" fill="url(#x360-grad)" stroke="#15803d" stroke-width="1.5"/>
            <text x="12" y="15" fill="white" font-size="7" font-weight="bold" text-anchor="middle">360</text>
        </svg>`,
    'Nintendo Switch': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="switch-grad1" x1="0%" y1="0%" x2="100%" y2="0%">
                    <stop offset="0%" style="stop-color:#ef4444;stop-opacity:1" />
                    <stop offset="50%" style="stop-color:#dc2626;stop-opacity:1" />
                </linearGradient>
                <linearGradient id="switch-grad2" x1="0%" y1="0%" x2="100%" y2="0%">
                    <stop offset="50%" style="stop-color:#1e3a8a;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#3b82f6;stop-opacity:1" />
                </linearGradient>
            </defs>
            <rect x="4" y="2" width="7" height="20" rx="2" fill="url(#switch-grad1)" stroke="#dc2626" stroke-width="1.5"/>
            <rect x="13" y="2" width="7" height="20" rx="2" fill="url(#switch-grad2)" stroke="#3b82f6" stroke-width="1.5"/>
            <circle cx="7.5" cy="7" r="2" fill="none" stroke="white" stroke-width="1.5"/>
            <circle cx="16.5" cy="17" r="1.5" fill="white"/>
        </svg>`,
    'Nintendo Wii U': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="wiiu-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#0ea5e9;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#38bdf8;stop-opacity:1" />
                </linearGradient>
            </defs>
            <rect x="7" y="2" width="10" height="20" rx="2" fill="url(#wiiu-grad)" stroke="#0ea5e9" stroke-width="1.5"/>
            <text x="12" y="14" fill="white" font-size="7" font-weight="bold" text-anchor="middle">WiiU</text>
            <circle cx="12" cy="18" r="1.5" fill="white"/>
        </svg>`,
    'Nintendo Wii': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="wii-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#f8f9fa;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#e9ecef;stop-opacity:1" />
                </linearGradient>
            </defs>
            <rect x="7" y="2" width="10" height="20" rx="2" fill="url(#wii-grad)" stroke="#cbd5e1" stroke-width="1.5"/>
            <text x="12" y="14" fill="#475569" font-size="8" font-weight="bold" text-anchor="middle">Wii</text>
            <circle cx="12" cy="18" r="1.5" fill="#475569"/>
        </svg>`,
    'PC': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="pc-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#6366f1;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#818cf8;stop-opacity:1" />
                </linearGradient>
            </defs>
            <rect x="2" y="3" width="20" height="14" rx="2" fill="url(#pc-grad)" stroke="#6366f1" stroke-width="1.5"/>
            <rect x="4" y="5" width="16" height="10" rx="1" fill="#1e293b"/>
            <text x="12" y="12" fill="#6366f1" font-size="6" font-weight="bold" text-anchor="middle">PC</text>
            <line x1="8" y1="21" x2="16" y2="21" stroke="#6366f1" stroke-width="2" stroke-linecap="round"/>
            <line x1="12" y1="17" x2="12" y2="21" stroke="#6366f1" stroke-width="2"/>
        </svg>`,
    'Mobile': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="mobile-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#8b5cf6;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#a78bfa;stop-opacity:1" />
                </linearGradient>
            </defs>
            <rect x="5" y="2" width="14" height="20" rx="2" ry="2" fill="url(#mobile-grad)" stroke="#8b5cf6" stroke-width="1.5"/>
            <circle cx="12" cy="18" r="1.5" fill="white"/>
            <line x1="9" y1="5" x2="15" y2="5" stroke="white" stroke-width="1.5" stroke-linecap="round"/>
        </svg>`,
    'Retro': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="retro-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#f59e0b;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#fbbf24;stop-opacity:1" />
                </linearGradient>
            </defs>
            <rect x="2" y="7" width="20" height="13" rx="2" fill="url(#retro-grad)" stroke="#f59e0b" stroke-width="1.5"/>
            <rect x="5" y="10" width="14" height="8" rx="1" fill="#1e293b"/>
            <circle cx="19" cy="5" r="2" fill="#ef4444"/>
        </svg>`,

    // Game Genres - Colorful and distinct
    'Action': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="action-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#fbbf24;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#f59e0b;stop-opacity:1" />
                </linearGradient>
            </defs>
            <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" fill="url(#action-grad)" stroke="#f59e0b" stroke-width="1.5" stroke-linejoin="round"/>
        </svg>`,
    'Adventure': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="adventure-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#10b981;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#34d399;stop-opacity:1" />
                </linearGradient>
            </defs>
            <path d="M3 10l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" fill="url(#adventure-grad)" stroke="#10b981" stroke-width="1.5"/>
            <path d="M9 22V12h6v10" fill="#1e293b" stroke="#10b981" stroke-width="1.5"/>
        </svg>`,
    'RPG': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="rpg-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#8b5cf6;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#a78bfa;stop-opacity:1" />
                </linearGradient>
            </defs>
            <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" fill="url(#rpg-grad)" stroke="#8b5cf6" stroke-width="1.5"/>
        </svg>`,
    'Sports': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="sports-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#ef4444;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#f87171;stop-opacity:1" />
                </linearGradient>
            </defs>
            <circle cx="12" cy="12" r="10" fill="url(#sports-grad)" stroke="#ef4444" stroke-width="1.5"/>
            <path d="M12 2a10 10 0 0 0 0 20" stroke="white" stroke-width="1.5" fill="none"/>
            <path d="M2 12h20" stroke="white" stroke-width="1.5"/>
        </svg>`,
    'Racing': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="racing-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#ec4899;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#f472b6;stop-opacity:1" />
                </linearGradient>
            </defs>
            <rect x="3" y="10" width="18" height="8" rx="2" fill="url(#racing-grad)" stroke="#ec4899" stroke-width="1.5"/>
            <circle cx="7" cy="18" r="3" fill="#1e293b" stroke="#ec4899" stroke-width="1.5"/>
            <circle cx="17" cy="18" r="3" fill="#1e293b" stroke="#ec4899" stroke-width="1.5"/>
            <path d="M3 10l2-6h14l2 6" stroke="#ec4899" stroke-width="1.5" fill="none"/>
        </svg>`,
    'Puzzle': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="puzzle-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#06b6d4;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#22d3ee;stop-opacity:1" />
                </linearGradient>
            </defs>
            <path d="M4 4h6v6H4z" fill="url(#puzzle-grad)" stroke="#06b6d4" stroke-width="1.5"/>
            <path d="M14 4h6v6h-6z" fill="url(#puzzle-grad)" stroke="#06b6d4" stroke-width="1.5"/>
            <path d="M4 14h6v6H4z" fill="url(#puzzle-grad)" stroke="#06b6d4" stroke-width="1.5"/>
            <path d="M14 14h6v6h-6z" fill="url(#puzzle-grad)" stroke="#06b6d4" stroke-width="1.5"/>
            <circle cx="17" cy="11" r="2" fill="white"/>
        </svg>`,
    'Strategy': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="strategy-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#6366f1;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#818cf8;stop-opacity:1" />
                </linearGradient>
            </defs>
            <rect x="3" y="3" width="7" height="7" rx="1" fill="url(#strategy-grad)" stroke="#6366f1" stroke-width="1.5"/>
            <rect x="14" y="3" width="7" height="7" rx="1" fill="url(#strategy-grad)" stroke="#6366f1" stroke-width="1.5"/>
            <rect x="14" y="14" width="7" height="7" rx="1" fill="url(#strategy-grad)" stroke="#6366f1" stroke-width="1.5"/>
            <rect x="3" y="14" width="7" height="7" rx="1" fill="url(#strategy-grad)" stroke="#6366f1" stroke-width="1.5"/>
        </svg>`,
    'Horror': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="horror-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#7c3aed;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#a78bfa;stop-opacity:1" />
                </linearGradient>
            </defs>
            <circle cx="12" cy="12" r="10" fill="url(#horror-grad)" stroke="#7c3aed" stroke-width="1.5"/>
            <circle cx="9" cy="10" r="1.5" fill="white"/>
            <circle cx="15" cy="10" r="1.5" fill="white"/>
            <path d="M8 15c1 2 3 3 4 3s3-1 4-3" stroke="white" stroke-width="1.5" fill="none" stroke-linecap="round"/>
        </svg>`,
    'Simulation': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="simulation-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#14b8a6;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#2dd4bf;stop-opacity:1" />
                </linearGradient>
            </defs>
            <circle cx="12" cy="12" r="10" fill="url(#simulation-grad)" stroke="#14b8a6" stroke-width="1.5"/>
            <path d="M12 2a10 10 0 0 1 4 8 10 10 0 0 1-4 10 10 10 0 0 1-4-10 10 10 0 0 1 4-8z" stroke="white" stroke-width="1.5" fill="none"/>
            <line x1="2" y1="12" x2="22" y2="12" stroke="white" stroke-width="1.5"/>
        </svg>`,
    'Shooter': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="shooter-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#dc2626;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#ef4444;stop-opacity:1" />
                </linearGradient>
            </defs>
            <circle cx="12" cy="12" r="10" fill="url(#shooter-grad)" stroke="#dc2626" stroke-width="1.5"/>
            <circle cx="12" cy="12" r="6" fill="none" stroke="white" stroke-width="1.5"/>
            <circle cx="12" cy="12" r="2" fill="white"/>
        </svg>`,
    'Fighting': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="fighting-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#f59e0b;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#fbbf24;stop-opacity:1" />
                </linearGradient>
            </defs>
            <path d="M18 8h1a4 4 0 0 1 0 8h-1M2 8h16v9a4 4 0 0 1-4 4H6a4 4 0 0 1-4-4V8z" fill="url(#fighting-grad)" stroke="#f59e0b" stroke-width="1.5"/>
            <line x1="6" y1="1" x2="6" y2="4" stroke="#f59e0b" stroke-width="1.5" stroke-linecap="round"/>
            <line x1="10" y1="1" x2="10" y2="4" stroke="#f59e0b" stroke-width="1.5" stroke-linecap="round"/>
            <line x1="14" y1="1" x2="14" y2="4" stroke="#f59e0b" stroke-width="1.5" stroke-linecap="round"/>
        </svg>`,
    'Music': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="music-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#ec4899;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#f472b6;stop-opacity:1" />
                </linearGradient>
            </defs>
            <path d="M9 18V5l12-2v13" stroke="#ec4899" stroke-width="2" fill="none"/>
            <circle cx="6" cy="18" r="3" fill="url(#music-grad)" stroke="#ec4899" stroke-width="1.5"/>
            <circle cx="18" cy="16" r="3" fill="url(#music-grad)" stroke="#ec4899" stroke-width="1.5"/>
        </svg>`,
    'Platform': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="platform-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#22c55e;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#4ade80;stop-opacity:1" />
                </linearGradient>
            </defs>
            <rect x="3" y="14" width="18" height="8" rx="2" fill="url(#platform-grad)" stroke="#22c55e" stroke-width="1.5"/>
            <rect x="6" y="8" width="5" height="6" rx="1" fill="url(#platform-grad)" stroke="#22c55e" stroke-width="1.5"/>
            <rect x="13" y="3" width="5" height="11" rx="1" fill="url(#platform-grad)" stroke="#22c55e" stroke-width="1.5"/>
        </svg>`,

    // Digital Purchase Types
    'Game Subscription': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="gamesub-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#8b5cf6;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#a78bfa;stop-opacity:1" />
                </linearGradient>
            </defs>
            <path d="M17.32 5H6.68a4 4 0 0 0-3.978 3.59c-.006.052-.01.101-.017.152C2.604 9.416 2 14.456 2 16a3 3 0 0 0 3 3c1 0 1.5-.5 2-1l1.414-1.414A2 2 0 0 1 9.828 16h4.344a2 2 0 0 1 1.414.586L17 18c.5.5 1 1 2 1a3 3 0 0 0 3-3c0-1.545-.604-6.584-.685-7.258-.007-.05-.011-.1-.017-.151A4 4 0 0 0 17.32 5z" fill="url(#gamesub-grad)" stroke="#8b5cf6" stroke-width="1.5"/>
            <line x1="6" y1="11" x2="10" y2="11" stroke="white" stroke-width="2" stroke-linecap="round"/>
            <line x1="8" y1="9" x2="8" y2="13" stroke="white" stroke-width="2" stroke-linecap="round"/>
        </svg>`,
    'Streaming Service': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="streaming-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#ef4444;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#f87171;stop-opacity:1" />
                </linearGradient>
            </defs>
            <circle cx="12" cy="12" r="10" fill="url(#streaming-grad)" stroke="#ef4444" stroke-width="1.5"/>
            <polygon points="10 8 10 16 16 12 10 8" fill="white"/>
        </svg>`,
    'Cloud Storage': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="cloud-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#06b6d4;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#22d3ee;stop-opacity:1" />
                </linearGradient>
            </defs>
            <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z" fill="url(#cloud-grad)" stroke="#06b6d4" stroke-width="1.5"/>
        </svg>`,
    'Music Subscription': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="musicsub-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#ec4899;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#f472b6;stop-opacity:1" />
                </linearGradient>
            </defs>
            <path d="M9 18V5l12-2v13" stroke="#ec4899" stroke-width="2" fill="none"/>
            <circle cx="6" cy="18" r="3" fill="url(#musicsub-grad)" stroke="#ec4899" stroke-width="1.5"/>
            <circle cx="18" cy="16" r="3" fill="url(#musicsub-grad)" stroke="#ec4899" stroke-width="1.5"/>
        </svg>`,
    'E-Book/Audiobook': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="ebook-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#10b981;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#34d399;stop-opacity:1" />
                </linearGradient>
            </defs>
            <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" stroke="#10b981" stroke-width="2" fill="none"/>
            <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z" fill="url(#ebook-grad)" stroke="#10b981" stroke-width="1.5"/>
        </svg>`,
    'Productivity Tool': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="productivity-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#3b82f6;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#60a5fa;stop-opacity:1" />
                </linearGradient>
            </defs>
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" fill="url(#productivity-grad)" stroke="#3b82f6" stroke-width="1.5"/>
            <polyline points="14 2 14 8 20 8" fill="#1e293b"/>
            <line x1="16" y1="13" x2="8" y2="13" stroke="white" stroke-width="1.5"/>
            <line x1="16" y1="17" x2="8" y2="17" stroke="white" stroke-width="1.5"/>
        </svg>`,
    'Online Course': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="course-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#f59e0b;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#fbbf24;stop-opacity:1" />
                </linearGradient>
            </defs>
            <path d="M22 10v6M2 10l10-5 10 5-10 5z" fill="url(#course-grad)" stroke="#f59e0b" stroke-width="1.5"/>
            <path d="M6 12v5c3 3 9 3 12 0v-5" stroke="#f59e0b" stroke-width="1.5" fill="none"/>
        </svg>`,
    'Steam': `
        <svg viewBox="0 0 24 24" fill="none">
            <defs>
                <linearGradient id="steam-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#475569;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#64748b;stop-opacity:1" />
                </linearGradient>
            </defs>
            <circle cx="12" cy="12" r="10" fill="url(#steam-grad)" stroke="#475569" stroke-width="1.5"/>
            <text x="12" y="15" fill="white" font-size="8" font-weight="bold" text-anchor="middle">S</text>
        </svg>`,
};

// Helper function to create animated SVG icon with proper matching
export function createSVGIcon(categoryName, animationDelay = 0) {
    // Remove emojis and clean up the text for matching
    const cleanName = categoryName.replace(/[\u{1F300}-\u{1F9FF}]|[\u{2600}-\u{26FF}]|[\u{2700}-\u{27BF}]/gu, '').trim();

    const svgMarkup = iconLibrary[cleanName] || iconLibrary['Other'];

    return `
        <div style="position: relative; width: 24px; height: 24px; flex-shrink: 0;">
            <div class="floating-category-icon" style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); animation: floatCategoryIcon 3s ease-in-out infinite; animation-delay: ${animationDelay}s;">
                ${svgMarkup}
            </div>
        </div>
    `;
}

export function getDefaultGadgetCategories() {
    return ['Phone', 'Laptop', 'Smartwatch', 'Audio', 'Camera', 'Gaming', 'Accessories', 'Storage', 'Monitor', 'Keyboard/Mouse', 'Chargers', 'Other'];
}

export function getDefaultGamePlatforms() {
    return ['PlayStation 5', 'PlayStation 4', 'PlayStation 3', 'Xbox Series X/S', 'Xbox One', 'Xbox 360', 'Nintendo Switch', 'Nintendo Wii U', 'Nintendo Wii', 'PC', 'Mobile', 'Retro', 'Other'];
}

export function getDefaultGameGenres() {
    return ['Action', 'Adventure', 'RPG', 'Sports', 'Racing', 'Puzzle', 'Strategy', 'Horror', 'Simulation', 'Shooter', 'Fighting', 'Music', 'Platform'];
}

export function getDefaultDigitalTypes() {
    return ['Game Subscription', 'Streaming Service', 'Cloud Storage', 'Music Subscription', 'E-Book/Audiobook', 'Productivity Tool', 'Online Course', 'Other'];
}


export { iconLibrary as ICON_LIBRARY };
