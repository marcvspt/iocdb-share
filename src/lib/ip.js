const API_VT_IP = "https://www.virustotal.com/api/v3/ip_addresses"
const API_ABUSEIPDB = "https://api.abuseipdb.com/api/v2/check?ipAddress"

export async function analyzeIP(ip) {
    const virustotalKey = import.meta.env.VIRUSTOTAL_API_KEY
    const abuseipdbKey = import.meta.env.ABUSEIPDB_API_KEY

    const urlVTIPInfo = `${API_VT_IP}/${ip}`
    const virustotalResponse = await fetch(urlVTIPInfo, {
        headers: {
            'x-apikey': virustotalKey,
        },
    })

    const urlAbuseIPDBInfo = `${API_ABUSEIPDB}=${ip}&verbose`
    const abuseipdbResponse = await fetch(urlAbuseIPDBInfo, {
        headers: {
            'Key': abuseipdbKey,
            'Accept': 'application/json',
        },
    })


    const virustotalData = await virustotalResponse.json()
    const abuseipdbData = await abuseipdbResponse.json()


    return {
        virustotal: {
            source: "VirusTotal",
            apiResponse: virustotalData
        },
        abuseipdb: {
            source: "AbuseIPDB",
            apiResponse: abuseipdbData
        }
    }
}

