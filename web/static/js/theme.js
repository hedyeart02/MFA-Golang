(function (global) {
    'use strict';

    var STORAGE_KEY = 'samlguard.theme';
    var LEGACY_KEY = 'samlguard_theme';
    var VALID_MODES = { system: true, light: true, dark: true };
    var mediaQuery = global.matchMedia ? global.matchMedia('(prefers-color-scheme: dark)') : null;

    var ICONS = {
        system: '<svg viewBox="0 0 24 24" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>',
        light: '<svg viewBox="0 0 24 24" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>',
        dark: '<svg viewBox="0 0 24 24" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>'
    };

    var LABELS = {
        system: 'Device',
        light: 'Light',
        dark: 'Dark'
    };

    function getStoredTheme() {
        try {
            var val = global.localStorage.getItem(STORAGE_KEY);
            if (VALID_MODES[val]) return val;
            var legacy = global.localStorage.getItem(LEGACY_KEY);
            if (legacy === 'device') return 'system';
            if (VALID_MODES[legacy]) return legacy;
        } catch (e) { }
        return 'system';
    }

    function resolveEffectiveTheme(mode) {
        if (mode === 'system') {
            return (mediaQuery && mediaQuery.matches) ? 'dark' : 'light';
        }
        return mode === 'light' ? 'light' : 'dark';
    }

    function applyTheme(mode) {
        var setting = VALID_MODES[mode] ? mode : 'system';
        var effective = resolveEffectiveTheme(setting);
        document.documentElement.setAttribute('data-theme', effective);
        document.documentElement.setAttribute('data-theme-setting', setting);

        var options = document.querySelectorAll('.theme-option');
        for (var i = 0; i < options.length; i++) {
            if (options[i].getAttribute('data-val') === setting) {
                options[i].classList.add('selected');
            } else {
                options[i].classList.remove('selected');
            }
        }

        var btnLabel = document.getElementById('themeBtnLabel');
        var btnIcon = document.getElementById('themeBtnIcon');
        if (btnLabel) btnLabel.textContent = LABELS[setting];
        if (btnIcon) btnIcon.innerHTML = ICONS[setting];
    }

    function selectTheme(mode) {
        var setting = VALID_MODES[mode] ? mode : 'system';
        try {
            global.localStorage.setItem(STORAGE_KEY, setting);
        } catch (e) { }
        applyTheme(setting);
        var menu = document.getElementById('themeMenu');
        if (menu) menu.classList.remove('active');
    }

    function toggleThemeMenu() {
        var menu = document.getElementById('themeMenu');
        if (menu) menu.classList.toggle('active');
    }

    // Apply immediately in <head> before body paint to avoid theme flicker
    applyTheme(getStoredTheme());

    document.addEventListener('DOMContentLoaded', function () {
        applyTheme(getStoredTheme());
    });

    document.addEventListener('click', function (e) {
        var menu = document.getElementById('themeMenu');
        if (!menu) return;
        var wrap = document.querySelector('.theme-dropdown-wrapper, .theme-dropdown-wrap');
        if (wrap && !wrap.contains(e.target)) {
            menu.classList.remove('active');
        }
    });

    if (mediaQuery) {
        var onSystemChange = function () {
            if (getStoredTheme() === 'system') {
                applyTheme('system');
            }
        };
        if (mediaQuery.addEventListener) {
            mediaQuery.addEventListener('change', onSystemChange);
        } else if (mediaQuery.addListener) {
            mediaQuery.addListener(onSystemChange);
        }
    }

    global.selectTheme = selectTheme;
    global.toggleThemeMenu = toggleThemeMenu;
    global.applyTheme = applyTheme;
    global.getStoredTheme = getStoredTheme;
})(window);

