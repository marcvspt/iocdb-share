import { analyzeIP } from "@/lib/ip";
import { analyzeDomain } from "@/lib/domain";
import { analyzeHash } from "@/lib/hash";

import { res } from "@/lib/utils";

export async function GET({ params, request }) {
    const { analyze } = params;
    const { url } = request
    const urlObject = new URL(url)
    const ioc = urlObject.searchParams.get("ioc");

    if (!ioc) {
        return res(JSON.stringify({ error: "Missing IoC parameter" }), {
            status: 400,
        });
    }

    let result;

    switch (analyze) {
        case "ip":
            result = await analyzeIP(ioc);
            break;
        case "domain":
            result = await analyzeDomain(ioc);
            break;
        case "hash":
            result = await analyzeHash(ioc);
            break;
        default:
            return res(
                JSON.stringify({ error: "Invalid analysis type" }), {
                status: 400,
            },

            );
    }

    return res(JSON.stringify(result), {
        status: 200,
    });
}
