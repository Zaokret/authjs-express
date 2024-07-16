import { Request } from "express"

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

/*
__Host-authjs.csrf-token
__Secure-authjs.callback-url
*/