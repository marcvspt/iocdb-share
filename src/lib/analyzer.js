const $ = (el) => document.querySelector(el)
const $$ = (el) => document.querySelectorAll(el)

const $formAnalyzer = $("#iocForm")
const $input = $("#ioc")
const $submitIoC = $("#iocSubmit")
const $errorMsg = $("#error")
const $loader = $("#loader")
const $results = $("#iocResults")


const $vtIP = $("#vtip")
const $vtIPTitle = $("#vtip-title")
const $vtIPReputation = $("#vtip-reputation")
const $vtIPOwner = $("#vtip-owner")
const $vtIPCountry = $("#vtip-country")
const $vtIPAnalysisHarmless = $("#vtip-analysis-harmless")
const $vtIPAnalysisMalicious = $("#vtip-analysis-malicious")
const $vtIPAnalysisSuspicious = $("#vtip-analysis-suspicious")
const $vtIPAnalysisUndetected = $("#vtip-analysis-undetected")
const $vtIPAnalysisTimeout = $("#vtip-analysis-timeout")
const $vtIPVotesHarmless = $("#vtip-votes-harmless")
const $vtIPVotesMalicious = $("#vtip-votes-malicious")

const $vtDomain = $("#vtdomain")
const $vtDomainTitle = $("#vtdomain-title")
const $vtDomainReputation = $("#vtdomain-reputation")
const $vtDomainAnalysisHarmless = $("#vtdomain-analysis-harmless")
const $vtDomainAnalysisMalicious = $("#vtdomain-analysis-malicious")
const $vtDomainAnalysisSuspicious = $("#vtdomain-analysis-suspicious")
const $vtDomainAnalysisUndetected = $("#vtdomain-analysis-undetected")
const $vtDomainAnalysisTimeout = $("#vtdomain-analysis-timeout")
const $vtDomainVotesHarmless = $("#vtdomain-votes-harmless")
const $vtDomainVotesMalicious = $("#vtdomain-votes-malicious")

const $vtHash = $("#vthash")
const $vtHashTitle = $("#vthash-title")
const $vtHashReputation = $("#vthash-reputation")
const $vtHashTypefile = $("#vthash-typefile")
const $vtHashMagicNumber = $("#vthash-magicnumber")
const $vtHashAnalysisHarmless = $("#vthash-analysis-harmless")
const $vtHashAnalysisMalicious = $("#vthash-analysis-malicious")
const $vtHashAnalysisSuspicious = $("#vthash-analysis-suspicious")
const $vtHashAnalysisUndetected = $("#vthash-analysis-undetected")
const $vtHashAnalysisTimeout = $("#vthash-analysis-timeout")
const $vtHashVotesHarmless = $("#vthash-votes-harmless")
const $vtHashVotesMalicious = $("#vthash-votes-malicious")

const $abuseIPDB = $("#abuseipdb")
const $abuseIPDBTitle = $("#abuseipdb-title")
const $abuseIPDBISP = $("#abuseipdb-isp")
const $abuseIPDBCountryName = $("#abuseipdb-countryname")
const $abuseIPDBTotalReports = $("#abuseipdb-totalreports")
const $abuseIPDBConfidenceScore = $("#abuseipdb-confidencescore")
const $abuseIPDBVotesWhitelist = $("#abuseipdb-whitelist")

const $otx = $("#otx")
const $otxTitle = $("#otx-title")
const $otxPulseCount = $("#otx-pulsecount")

const $polyswarm = $("#polyswarm")
const $polyswarmTitle = $("#polyswarm-title")
const $polyswarmExtfiletype = $("#polyswarm-extfiletype")
const $polyswarmMalwarefamliy = $("#polyswarm-malwarefamliy")

function resetUI() {
    $errorMsg.classList.add("hidden")
    $results.classList.add("hidden")
    $loader.classList.remove("hidden")
}

function resetResults() {
    $vtIP.classList.add("hidden")
    $vtDomain.classList.add("hidden")
    $vtHash.classList.add("hidden")
    $abuseIPDB.classList.add("hidden")
    $otx.classList.add("hidden")
    $polyswarm.classList.add("hidden")
}

function resultsAPI1(api1Json, iocType) {
    const { source, apiResponse } = api1Json
    const { data } = apiResponse

    if (iocType === "ip") {
        $vtIP.classList.remove("hidden")

        $vtIPTitle.textContent = source
        $vtIPReputation.textContent = data.attributes.reputation
        $vtIPOwner.textContent = data.attributes.as_owner
        $vtIPCountry.textContent = data.attributes.country
        $vtIPAnalysisHarmless.textContent = data.attributes.last_analysis_stats.harmless
        $vtIPAnalysisMalicious.textContent = data.attributes.last_analysis_stats.malicious
        $vtIPAnalysisSuspicious.textContent = data.attributes.last_analysis_stats.suspicious
        $vtIPAnalysisUndetected.textContent = data.attributes.last_analysis_stats.undetected
        $vtIPAnalysisTimeout.textContent = data.attributes.last_analysis_stats.timeout
        $vtIPVotesHarmless.textContent = data.attributes.total_votes.harmless
        $vtIPVotesMalicious.textContent = data.attributes.total_votes.malicious
    } else if (iocType === "domain") {
        $vtDomain.classList.remove("hidden")

        $vtDomainTitle.textContent = source
        $vtDomainReputation.textContent = data.attributes.reputation
        $vtDomainAnalysisHarmless.textContent = data.attributes.last_analysis_stats.harmless
        $vtDomainAnalysisMalicious.textContent = data.attributes.last_analysis_stats.malicious
        $vtDomainAnalysisSuspicious.textContent = data.attributes.last_analysis_stats.suspicious
        $vtDomainAnalysisUndetected.textContent = data.attributes.last_analysis_stats.undetected
        $vtDomainAnalysisTimeout.textContent = data.attributes.last_analysis_stats.timeout
        console.log(data.attributes.total_votes)
        $vtDomainVotesHarmless.textContent = data.attributes.total_votes.harmless
        $vtDomainVotesMalicious.textContent = data.attributes.total_votes.malicious
    } else if (iocType === "hash") {
        $vtHash.classList.remove("hidden");

        $vtHashTitle.textContent = source
        $vtHashReputation.textContent = data.attributes.reputation
        $vtHashTypefile.textContent = data.attributes.trid[0].file_type
        $vtHashMagicNumber.textContent = data.attributes.magic
        $vtHashAnalysisHarmless.textContent = data.attributes.last_analysis_stats.harmless
        $vtHashAnalysisMalicious.textContent = data.attributes.last_analysis_stats.malicious
        $vtHashAnalysisSuspicious.textContent = data.attributes.last_analysis_stats.suspicious
        $vtHashAnalysisUndetected.textContent = data.attributes.last_analysis_stats.undetected
        $vtHashAnalysisTimeout.textContent = data.attributes.last_analysis_stats.timeout
        $vtHashVotesHarmless.textContent = data.attributes.total_votes.harmless
        $vtHashVotesMalicious.textContent = data.attributes.total_votes.malicious
    }
}

function resultsAPI2(api2Json, iocType) {
    const { source, apiResponse } = api2Json

    if (iocType === "ip") {
        $abuseIPDB.classList.remove("hidden")

        const { data } = apiResponse

        $abuseIPDBTitle.textContent = source
        $abuseIPDBISP.textContent = data.isp
        $abuseIPDBCountryName.textContent = data.countryName
        $abuseIPDBTotalReports.textContent = data.totalReports
        $abuseIPDBConfidenceScore.textContent = `${data.abuseConfidenceScore}%`
        $abuseIPDBVotesWhitelist.textContent = data.isWhitelisted
    } else if (iocType === "domain") {
        $otx.classList.remove("hidden")

        $otxTitle.textContent = source
        $otxPulseCount.append(apiResponse.pulse_info.count)

    } else if (iocType === "hash") {
        $polyswarm.classList.remove("hidden")

        const { result } = apiResponse

        $polyswarmTitle.textContent = source
        $polyswarmExtfiletype.append(result[0].extended_type)
        $polyswarmMalwarefamliy.append(result[0].metadata[0].tool_metadata.malware_family)
    }
}

async function handleFormSubmit(e) {
    const ioc = $input.value
    e.preventDefault()

    // Reset UI
    resetUI()
    $submitIoC.disabled = true
    $submitIoC.textContent = "Analizando..."

    try {
        const typeResponse = await fetch(
            `/api/type?ioc=${encodeURIComponent(ioc)}`,
        )
        const typeData = await typeResponse.json()

        if (typeData.error) {
            throw new Error(typeData.error)
        }

        const analyzeResponse = await fetch(
            `/api/analyze/${typeData.type}?ioc=${encodeURIComponent(ioc)}`,
        )
        const analyzeData = await analyzeResponse.json()

        // Process results
        let api1ResultData = null
        let api2ResultData = null

        if (typeData.type === "ip" || typeData.type === "domain") {
            api1ResultData = analyzeData.virustotal
            api2ResultData =
                typeData.type === "ip"
                    ? analyzeData.abuseipdb
                    : analyzeData.otx
        } else if (typeData.type === "hash") {
            api1ResultData = analyzeData.virustotal
            api2ResultData = analyzeData.polyswarm
            console.log(analyzeData.polyswarm)
        }

        resetResults()
        resultsAPI1(api1ResultData, typeData.type)
        resultsAPI2(api2ResultData, typeData.type)

        $results.classList.remove("hidden")
    } catch (err) {
        const errMsg = err.message || "An error occurred while analyzing the IoC."
        $errorMsg.textContent = errMsg
        $errorMsg.classList.remove("hidden")
    } finally {
        $loader.classList.add("hidden")
        $submitIoC.disabled = false
        $submitIoC.textContent = "Analizar"
    }
}

$formAnalyzer.addEventListener("submit", handleFormSubmit)