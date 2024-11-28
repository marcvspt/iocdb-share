const API_EMAILREP = "https://emailrep.io"
const API_HIBP = "https://haveibeenpwned.com/api/v3/breachedaccount"

export async function analyzeEmail(email: string) {
    const emailrepKey = import.meta.env.EMAILREP_API_KEY;
    const hibpKey = import.meta.env.HIBP_API_KEY;

    const urlEmailrepInfo = `${API_EMAILREP}/${email}`
    const emailrepResponse = await fetch(urlEmailrepInfo, {
        headers: {
            'Key': emailrepKey,
        },
    });

    const urlHIBPInfo = `${API_HIBP}/${email}`
    const hibpResponse = await fetch(urlHIBPInfo, {
        headers: {
            'hibp-api-key': hibpKey,
        },
    });

    const emailrepData = await emailrepResponse.json();
    const hibpData = await hibpResponse.json();

    return {
        emailrep: {
            reputation: emailrepData.reputation,
            suspicious: emailrepData.suspicious,
        },
        haveibeenpwned: hibpData.map(breach => ({
            name: breach.Name,
            date: breach.BreachDate,
        })),
    };
}

