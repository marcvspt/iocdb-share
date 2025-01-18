export async function GET({ request }) {
    const { url } = request
    const urlObject = new URL(url)
    const ioc = urlObject.searchParams.get("ioc")

    if (!ioc) {
        return new Response(JSON.stringify({ error: "Invalid input" }), {
            status: 400,
        })
    }
    /* if (!result.success) {
        return new Response(JSON.stringify({ error: "Invalid input" }), {
            status: 400,
        })
    } */

    // Simple regex patterns for each type
    const patterns = {
        ip: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
        domain: /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/,
        hash: /^[a-fA-F0-9]{32,64}$/,
    }

    for (const [type, pattern] of Object.entries(patterns)) {
        if (pattern.test(ioc)) {
            return new Response(JSON.stringify({ type }))
        }
    }

    return new Response(JSON.stringify({ error: "Unknown IoC type" }), {
        status: 400,
    })
}
