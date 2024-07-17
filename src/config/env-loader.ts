export function loadEnvArrVal(key: string) {
    return process.env[key]?.replace(' ', '').split(',') || [];
}

export function isProd() {
    return process.env.NODE_ENV === 'production'
}