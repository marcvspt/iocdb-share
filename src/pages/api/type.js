import { PATTERNS, res } from "@/lib/utils";

export async function GET({ request }) {
    const { url } = request
    const urlObject = new URL(url)
    const ioc = urlObject.searchParams.get("ioc")

    if (!ioc) {
        return res(JSON.stringify({ error: "Invalid input" }), {
            status: 400,
        })
    }

    for (const [type, pattern] of Object.entries(PATTERNS)) {
        if (pattern.test(ioc)) {
            return res(JSON.stringify({ type }), {
                status: 200,
            })
        }
    }

    return res(JSON.stringify({ error: "Unknown IoC type" }), {
        status: 400,
    })
}
