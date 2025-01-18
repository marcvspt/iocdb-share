const API_VT_DOMAIN = "https://www.virustotal.com/api/v3/domains"
const API_OTX_DOMAIN = "https://otx.alienvault.com/api/v1/indicators/domain"

export async function analyzeDomain(domain) {
    const virustotalKey = import.meta.env.VIRUSTOTAL_API_KEY
    const otxKey = import.meta.env.OTX_API_KEY


    const urlVTDomainInfo = `${API_VT_DOMAIN}/${domain}`
    const virustotalResponse = await fetch(urlVTDomainInfo, {
        headers: {
            "x-apikey": virustotalKey,
        },
    })

    const urlOTXDomainInfo = `${API_OTX_DOMAIN}/${domain}/general`
    const otxResponse = await fetch(urlOTXDomainInfo, {
        headers: {
            "X-OTX-API-KEY": otxKey,
        },
    })

    const virustotalData = await virustotalResponse.json()
    const otxData = await otxResponse.json()

    return {
        virustotal: {
            source: "VirusTotal",
            apiResponse: virustotalData
        },
        otx: {
            source: "AlienVault OTX",
            apiResponse: otxData
        }
    }
}

