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
const $abuseIPDBUsetype = $("#abuseipdb-usetype")
const $abuseIPDBCountryName = $("#abuseipdb-countryname")
const $abuseIPDBWhitelist = $("#abuseipdb-whitelist")
const $abuseIPDBIstor = $("#abuseipdb-istor")
const $abuseIPDBTotalReports = $("#abuseipdb-totalreports")
const $abuseIPDBConfidenceScore = $("#abuseipdb-confidencescore")
const $abuseIPDBReports = $("#abuseipdb-reports")

const $otx = $("#otx")
const $otxTitle = $("#otx-title")
const $otxPulseCount = $("#otx-pulsecount")
const $otxPulseReports = $("#otx-pulsereports")

const $polyswarm = $("#polyswarm")
const $polyswarmTitle = $("#polyswarm-title")
const $polyswarmExtfiletype = $("#polyswarm-extfiletype")
const $polyswarmMalwarefamliy = $("#polyswarm-malwarefamliy")
const $polyswarmReports = $("#polyswarm-reports")

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

    if (apiResponse.error) {
        $vtHash.classList.remove("hidden")
        $vtHash.textContent = "No hay información"
        return
    }

    const { attributes } = apiResponse.data

    $vtIPTitle.textContent = source

    if (iocType === "ip") {
        $vtIP.classList.remove("hidden")

        $vtIPReputation.textContent = attributes.reputation
        $vtIPOwner.textContent = attributes.as_owner
        $vtIPCountry.textContent = attributes.country
        $vtIPAnalysisHarmless.textContent = attributes.last_analysis_stats.harmless
        $vtIPAnalysisMalicious.textContent = attributes.last_analysis_stats.malicious
        $vtIPAnalysisSuspicious.textContent = attributes.last_analysis_stats.suspicious
        $vtIPAnalysisUndetected.textContent = attributes.last_analysis_stats.undetected
        $vtIPAnalysisTimeout.textContent = attributes.last_analysis_stats.timeout
        $vtIPVotesHarmless.textContent = attributes.total_votes.harmless
        $vtIPVotesMalicious.textContent = attributes.total_votes.malicious
    } else if (iocType === "domain") {
        $vtDomain.classList.remove("hidden")

        $vtDomainTitle.textContent = source
        $vtDomainReputation.textContent = attributes.reputation
        $vtDomainAnalysisHarmless.textContent = attributes.last_analysis_stats.harmless
        $vtDomainAnalysisMalicious.textContent = attributes.last_analysis_stats.malicious
        $vtDomainAnalysisSuspicious.textContent = attributes.last_analysis_stats.suspicious
        $vtDomainAnalysisUndetected.textContent = attributes.last_analysis_stats.undetected
        $vtDomainAnalysisTimeout.textContent = attributes.last_analysis_stats.timeout
        $vtDomainVotesHarmless.textContent = attributes.total_votes.harmless
        $vtDomainVotesMalicious.textContent = attributes.total_votes.malicious
    } else if (iocType === "hash") {
        $vtHash.classList.remove("hidden")

        $vtHashTitle.textContent = source
        $vtHashReputation.textContent = attributes.reputation
        $vtHashTypefile.textContent = attributes.trid[0].file_type
        $vtHashMagicNumber.textContent = attributes.magic
        $vtHashAnalysisHarmless.textContent = attributes.last_analysis_stats.harmless
        $vtHashAnalysisMalicious.textContent = attributes.last_analysis_stats.malicious
        $vtHashAnalysisSuspicious.textContent = attributes.last_analysis_stats.suspicious
        $vtHashAnalysisUndetected.textContent = attributes.last_analysis_stats.undetected
        $vtHashAnalysisTimeout.textContent = attributes.last_analysis_stats.timeout
        $vtHashVotesHarmless.textContent = attributes.total_votes.harmless
        $vtHashVotesMalicious.textContent = attributes.total_votes.malicious
    }
}

function resultsAPI2(api2Json, iocType) {
    const { source, apiResponse } = api2Json

    if (iocType === "ip") {
        $abuseIPDB.classList.remove("hidden")

        if (apiResponse === null) {
            $abuseIPDB.textContent = "No hay información"
            return
        }

        const { data } = apiResponse
        const { reports } = data

        $abuseIPDBTitle.textContent = source
        $abuseIPDBISP.textContent = data.isp
        $abuseIPDBUsetype.textContent = data.usageType
        $abuseIPDBCountryName.textContent = data.countryName
        $abuseIPDBWhitelist.textContent = data.isWhitelisted === true ? "Si" : "No"
        $abuseIPDBIstor.textContent = data.isTor === true ? "Si" : "No"
        $abuseIPDBTotalReports.textContent = data.totalReports
        $abuseIPDBConfidenceScore.textContent = `${data.abuseConfidenceScore}%`

        $abuseIPDBReports.textContent = ""
        reports.forEach(report => {
            const $reportItem = document.createElement("li")
            const $commentItem = $reportItem.appendChild(document.createElement("span"))

            const commentItem = report.comment || "Sin reportes"

            $commentItem.classList.add("text-base", "font-normal")
            $commentItem.textContent = commentItem
            // Agregar el <li> al contenedor UL
            $abuseIPDBReports.appendChild($reportItem)
        })

    } else if (iocType === "domain") {
        $otx.classList.remove("hidden")

        if (apiResponse.error) {
            $otx.textContent = "No hay información"
            return
        }

        const { pulses } = apiResponse.pulse_info

        $otxTitle.textContent = source
        $otxPulseCount.textContent = apiResponse.pulse_info.count

        $otxPulseReports.textContent = ""
        pulses.forEach(pulse => {
            const $pulseItem = document.createElement("li")
            const $titleItem = $pulseItem.appendChild(document.createElement("strong"))

            const pulseName = pulse.name || "Sin nombre"
            const pulseDescription = pulse.description || "Sin descripción"

            $titleItem.textContent = `${pulseName}: `
            const $contentItem = $titleItem.appendChild(document.createElement("span"))
            $contentItem.classList.add("text-base", "font-normal")
            $contentItem.textContent = pulseDescription
            $otxPulseReports.appendChild($pulseItem)

        })

    } else if (iocType === "hash") {
        $polyswarm.classList.remove("hidden")

        if (apiResponse === null) {
            $polyswarm.textContent = "No hay información"
            return
        }

        const { result } = apiResponse
        const { assertions } = result[0]

        $polyswarmTitle.textContent = source
        $polyswarmExtfiletype.textContent = result[0].extended_type
        $polyswarmMalwarefamliy.textContent = result[0].metadata[0].tool_metadata.malware_family

        $polyswarmReports.textContent = ""
        assertions.forEach(assertion => {
            const $assertionItem = document.createElement("li")
            const $titleItem = $assertionItem.appendChild(document.createElement("strong"))

            const assertionAuthorName = assertion.author_name || "Sin nombre"
            const assertionVerdict = assertion.verdict ? "Malicioso" : "Inofensivo"

            $titleItem.textContent = `${assertionAuthorName}: `
            const $contentItem = $titleItem.appendChild(document.createElement("span"))
            $contentItem.classList.add("text-base", "font-normal")
            $contentItem.textContent = assertionVerdict
            $polyswarmReports.appendChild($assertionItem)
        })
    }
}

async function handleFormSubmit(e) {
    const ioc = $input.value
    e.preventDefault()

    resetUI()
    $submitIoC.disabled = true
    $submitIoC.textContent = "Analizando..."

    try {
        const analyzeResponse = await fetch(`/api/analyze?ioc=${encodeURIComponent(ioc)}`)
        const analyzeData = await analyzeResponse.json()

        if (analyzeData.error) {
            throw new Error(analyzeData.error)
        }

        resetResults()
        resultsAPI1(analyzeData.virustotal, analyzeData.type)

        const secondaryAPI = analyzeData.type === 'ip' ? analyzeData.abuseipdb :
            analyzeData.type === 'domain' ? analyzeData.otx :
                analyzeData.polyswarm

        resultsAPI2(secondaryAPI, analyzeData.type)

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