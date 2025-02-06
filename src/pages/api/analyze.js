import { PATTERNS } from "@/scripts/utils"

import { analyzeIP } from "@/scripts/analyzer/ip"
import { analyzeDomain } from "@/scripts/analyzer/domain"
import { analyzeHash } from "@/scripts/analyzer/hash"

export async function GET({ request }) {
    const { url } = request
    const urlObject = new URL(url)
    const ioc = urlObject.searchParams.get("ioc")

    if (!ioc) {
        return new Response(
            JSON.stringify({ error: "Missing IoC parameter" }), {
            status: 400,
            headers: { "Content-Type": "application/json" }
        }
        )
    }

    // Determine IoC type
    let iocType = null
    for (const [type, pattern] of Object.entries(PATTERNS)) {
        if (pattern.test(ioc)) {
            iocType = type
            break
        }
    }

    if (!iocType) {
        return new Response(
            JSON.stringify({ error: "Unknown IoC type" }), {
            status: 400,
            headers: { "Content-Type": "application/json" }
        }
        )
    }

    try {
        let result
        switch (iocType) {
            case "ip":
                result = await analyzeIP(ioc)
                break
            case "domain":
                result = await analyzeDomain(ioc)
                break
            case "hash":
                result = await analyzeHash(ioc)
                break
            default:
                throw new Error("Invalid analysis type")
        }

        return new Response(JSON.stringify(result), {
            status: 200,
            headers: { "Content-Type": "application/json" }
        })
    } catch (error) {
        return new Response(
            JSON.stringify({ error: error.message || "Analysis failed" }), {
            status: 500,
            headers: { "Content-Type": "application/json" }
        }
        )
    }
}