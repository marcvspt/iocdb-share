const API_VT_FILEHASH = "https://www.virustotal.com/api/v3/files"
const API_POLYSWARM = "https://api.polyswarm.network/v3/search/hash"

const VALID_HASH_TYPES = {
    MD5: "md5",
    SHA1: "sha1",
    SHA256: "sha256"
}

function checkHashType(hash) {
    if (/^[a-f0-9]{32}$/i.test(hash)) {
        return VALID_HASH_TYPES.MD5
    }

    if (/^[a-f0-9]{40}$/i.test(hash)) {
        return VALID_HASH_TYPES.SHA1
    }

    if (/^[a-f0-9]{64}$/i.test(hash)) {
        return VALID_HASH_TYPES.SHA256
    }

    return "N/A"
}

export async function analyzeHash(hash) {
    const virustotalKey = import.meta.env.VIRUSTOTAL_API_KEY;
    const polyswarmKey = import.meta.env.POLYSWARM_API_KEY;

    const urlVTFilehashInfo = `${API_VT_FILEHASH}/${hash}`
    const virustotalResponse = await fetch(urlVTFilehashInfo, {
        headers: {
            'x-apikey': virustotalKey,
        },
    });

    const hashType = checkHashType(hash)
    const urlPolyswarmInfo = `${API_POLYSWARM}/${hashType}?hash=${hash}`
    const polyswarmResponse = await fetch(urlPolyswarmInfo, {
        headers: {
            'Authorization': polyswarmKey,
        },
    });

    const virustotalData = await virustotalResponse.json();
    const polyswarmData = await polyswarmResponse.json()

    return {
        virustotal: {
            source: "VirusTotal",
            apiResponse: virustotalData
        },
        polyswarm: {
            source: "PolySwarm",
            apiResponse: polyswarmData
        }
    };
}

