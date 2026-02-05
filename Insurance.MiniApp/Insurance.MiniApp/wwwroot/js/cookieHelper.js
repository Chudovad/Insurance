// Функции для работы с cookies через JavaScript
window.cookieHelper = {
    setCookie: function (name, value, expires, secure, sameSite) {
        let cookieString = `${name}=${encodeURIComponent(value)}`;
        
        if (expires) {
            // Преобразуем в Date объект, если это строка или уже Date
            const expiresDate = expires instanceof Date ? expires : new Date(expires);
            cookieString += `; expires=${expiresDate.toUTCString()}`;
        }
        
        cookieString += `; path=/`;
        
        if (secure) {
            cookieString += `; secure`;
        }
        
        if (sameSite) {
            cookieString += `; samesite=${sameSite}`;
        }
        
        document.cookie = cookieString;
    },
    
    getCookie: function (name) {
        const nameEQ = name + "=";
        const ca = document.cookie.split(';');
        for (let i = 0; i < ca.length; i++) {
            let c = ca[i];
            while (c.charAt(0) === ' ') c = c.substring(1, c.length);
            if (c.indexOf(nameEQ) === 0) {
                return decodeURIComponent(c.substring(nameEQ.length, c.length));
            }
        }
        return null;
    },
    
    deleteCookie: function (name, secure, sameSite) {
        let cookieString = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/`;
        
        if (secure) {
            cookieString += `; secure`;
        }
        
        if (sameSite) {
            cookieString += `; samesite=${sameSite}`;
        }
        
        document.cookie = cookieString;
    }
};
