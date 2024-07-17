import { Request } from "express"
import { isProd } from "./env-loader.js";

export function getCookie(search: string, req: Request) {
    var cookie = req.headers.cookie;
    if (!cookie) {
        return {};
    }

    const dict = cookie.split('; ').reduce((obj, pair) => {
        const [key, value] = pair.split('=')
        obj[key] = value
        return obj;
    }, {} as any);

    return dict[search]
}

export function setCookie(newKey: string, val: string, req: Request) {
    const dict = req.headers.cookie?.split(';').reduce((dict, pair) => {
        const [key, value] = pair.replace(' ', '').split('=')
        dict[key] = value;
        return dict
    }, {} as any)
    dict[newKey] = val;

    req.headers.cookie = Object.keys(dict).map(key => `${key}=${dict[key]}`).join('; ')
}

export type CookieKeys = 'callback-url' | 'csrf-token';

export function getCookieName(key: CookieKeys) {
    const prefixBase = 'authjs.'
    const cookies = {
        'callback-url': {
            dev: prefixBase,
            prod: '__Secure-' + prefixBase
        },
        'csrf-token': {
            dev: prefixBase,
            prod: '__Host-' + prefixBase
        }
    }

    const prefix = isProd() ? cookies[key].prod : cookies[key].dev;
    return prefix + key;
}