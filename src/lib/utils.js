export const PATTERNS = {
    ip: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
    domain: /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/,
    hash: /^[a-fA-F0-9]{32,64}$/,
}

export const res = (
    body,
    { status, statusText, headers }
) => new Response(body, { status, statusText, headers })