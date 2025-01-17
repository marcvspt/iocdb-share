const $formAnalyzer = document.querySelector("#iocForm");
const $input = document.querySelector("#ioc");
const $submitIoC = document.querySelector("#iocSubmit");
const $errorMsg = document.querySelector("#error");
const $loader = document.querySelector("#loader");
const $result = document.querySelector("#iocResults");
const $api1Title = document.querySelector("#api1-title");
const $api2Title = document.querySelector("#api2-title");
const $api1Result = document.querySelector("#api1-result");
const $api2Result = document.querySelector("#api2-result");
const $virustotalIP = document.querySelector("#virustotalip");
const $abuseipdb = document.querySelector("#abuseipdb");
const $virustotalDomain = document.querySelector("#virustotaldomain");
const $alienvaultotx = document.querySelector("#alienvaultotx");
const $virustotalHash = document.querySelector("#virustotalhash");
const $polyswarm = document.querySelector("#polyswarm");

function resetUI() {
    $errorMsg.classList.add("hidden");
    $result.classList.add("hidden");
    $loader.classList.remove("hidden");
}

function resultsAPI1(api1Json, iocType) {

    const { source, apiResponse } = api1Json;

    if (iocType === "ip") {
        $virustotalIP.classList.remove("hidden");
        $virustotalDomain.classList.add("hidden");
        $virustotalHash.classList.add("hidden");

        const $api1ResultReputation = document.querySelector("#api1-result-virustotalip-reputation");
        const $api1ResultOwner = document.querySelector("#api1-result-virustotalip-owner");
        const $api1ResultCountry = document.querySelector("#api1-result-virustotalip-country");

        const $api1ResultAnalysisHarmless = document.querySelector("#api1-result-virustotalip-analysis-harmless");
        const $api1ResultAnalysisMalicious = document.querySelector("#api1-result-virustotalip-analysis-malicious");
        const $api1ResultAnalysisSuspicious = document.querySelector("#api1-result-virustotalip-analysis-suspicious");
        const $api1ResultAnalysisUndetected = document.querySelector("#api1-result-virustotalip-analysis-undetected");
        const $api1ResultAnalysisTimeout = document.querySelector("#api1-result-virustotalip-analysis-timeout");

        const $api1ResultVotesHarmless = document.querySelector("#api1-result-virustotalip-votes-harmless");
        const $api1ResultVotesMalicious = document.querySelector("#api1-result-virustotalip-votes-malicious");
        const { data } = apiResponse;


        $api1Title.textContent = source;
        $api1ResultReputation.append(data.attributes.reputation);
        $api1ResultOwner.append(data.attributes.as_owner);
        $api1ResultCountry.append(data.attributes.country);
        $api1ResultAnalysisHarmless.append(data.attributes.last_analysis_stats.harmless);
        $api1ResultAnalysisMalicious.append(data.attributes.last_analysis_stats.malicious);
        $api1ResultAnalysisSuspicious.append(data.attributes.last_analysis_stats.suspicious);
        $api1ResultAnalysisUndetected.append(data.attributes.last_analysis_stats.undetected);
        $api1ResultAnalysisTimeout.append(data.attributes.last_analysis_stats.timeout);
        $api1ResultVotesHarmless.append(data.attributes.total_votes.harmless);
        $api1ResultVotesMalicious.append(data.attributes.total_votes.malicious);
    } else if (iocType === "domain") {
        $virustotalIP.classList.add("hidden");
        $virustotalDomain.classList.remove("hidden");
        $virustotalHash.classList.add("hidden");


        const $api1ResultReputation = document.querySelector("#api1-result-virustotaldomain-reputation");
        const $api1ResultAnalysisHarmless = document.querySelector("#api1-result-virustotaldomain-analysis-harmless");
        const $api1ResultAnalysisMalicious = document.querySelector("#api1-result-virustotaldomain-analysis-malicious");
        const $api1ResultAnalysisSuspicious = document.querySelector("#api1-result-virustotaldomain-analysis-suspicious");
        const $api1ResultAnalysisUndetected = document.querySelector("#api1-result-virustotaldomain-analysis-undetected");
        const $api1ResultAnalysisTimeout = document.querySelector("#api1-result-virustotaldomain-analysis-timeout");

        const $api1ResultVotesHarmless = document.querySelector("#api1-result-virustotaldomain-votes-harmless");
        const $api1ResultVotesMalicious = document.querySelector("#api1-result-virustotaldomain-votes-malicious");
        const { data } = apiResponse;


        $api1Title.textContent = source;
        $api1ResultReputation.append(data.attributes.reputation);
        $api1ResultAnalysisHarmless.append(data.attributes.last_analysis_stats.harmless);
        $api1ResultAnalysisMalicious.append(data.attributes.last_analysis_stats.malicious);
        $api1ResultAnalysisSuspicious.append(data.attributes.last_analysis_stats.suspicious);
        $api1ResultAnalysisUndetected.append(data.attributes.last_analysis_stats.undetected);
        $api1ResultAnalysisTimeout.append(data.attributes.last_analysis_stats.timeout);
        $api1ResultVotesHarmless.append(data.attributes.total_votes.harmless);
        $api1ResultVotesMalicious.append(data.attributes.total_votes.malicious);
    } else if (iocType === "hash") {
        $virustotalIP.classList.add("hidden");
        $virustotalDomain.classList.add("hidden");
        $virustotalHash.classList.remove("hidden");

        const $api1ResultReputation = document.querySelector("#api1-result-virustotalhash-reputation");
        const $api1ResultTypefile = document.querySelector("#api1-result-virustotalhash-typefile");
        const $api1ResultMagicNumber = document.querySelector("#api1-result-virustotalhash-magicnumber");

        const $api1ResultAnalysisHarmless = document.querySelector("#api1-result-virustotalhash-analysis-harmless");
        const $api1ResultAnalysisMalicious = document.querySelector("#api1-result-virustotalhash-analysis-malicious");
        const $api1ResultAnalysisSuspicious = document.querySelector("#api1-result-virustotalhash-analysis-suspicious");
        const $api1ResultAnalysisUndetected = document.querySelector("#api1-result-virustotalhash-analysis-undetected");
        const $api1ResultAnalysisTimeout = document.querySelector("#api1-result-virustotalhash-analysis-timeout");

        const $api1ResultVotesHarmless = document.querySelector("#api1-result-virustotalhash-votes-harmless");
        const $api1ResultVotesMalicious = document.querySelector("#api1-result-virustotalhash-votes-malicious");

        const { data } = apiResponse;


        $api1Title.textContent = source;
        $api1ResultReputation.append(data.attributes.reputation);
        $api1ResultTypefile.append(data.attributes.trid[0].file_type);
        $api1ResultMagicNumber.append(data.attributes.magic);
        $api1ResultAnalysisHarmless.append(data.attributes.last_analysis_stats.harmless);
        $api1ResultAnalysisMalicious.append(data.attributes.last_analysis_stats.malicious);
        $api1ResultAnalysisSuspicious.append(data.attributes.last_analysis_stats.suspicious);
        $api1ResultAnalysisUndetected.append(data.attributes.last_analysis_stats.undetected);
        $api1ResultAnalysisTimeout.append(data.attributes.last_analysis_stats.timeout);
        $api1ResultVotesHarmless.append(data.attributes.total_votes.harmless);
        $api1ResultVotesMalicious.append(data.attributes.total_votes.malicious);
    }
}

function resultsAPI2(api2Json, iocType) {
    const { source, apiResponse } = api2Json;

    if (iocType === "ip") {
        $abuseipdb.classList.remove("hidden");
        $alienvaultotx.classList.add("hidden");
        $polyswarm.classList.add("hidden");


        const $api2ResultISP = document.querySelector("#api2-result-abuseipdb-isp");
        const $api2ResultCountryName = document.querySelector("#api2-result-abuseipdb-countryname");
        const $api2ResultTotalReports = document.querySelector("#api2-result-abuseipdb-totalreports");
        const $api2ResultConfidenceScore = document.querySelector("#api2-result-abuseipdb-confidencescore");
        const $api2ResultVotesWhitelist = document.querySelector("#api2-result-abuseipdb-whitelist");

        const { data } = apiResponse;

        $api2Title.textContent = source;
        $api2ResultISP.append(data.isp);
        $api2ResultCountryName.append(data.countryName);
        $api2ResultTotalReports.append(data.totalReports);
        $api2ResultConfidenceScore.append(`${data.abuseConfidenceScore}%`);
        $api2ResultVotesWhitelist.append(data.isWhitelisted);
    } else if (iocType === "domain") {
        $abuseipdb.classList.add("hidden");
        $alienvaultotx.classList.remove("hidden");
        $polyswarm.classList.add("hidden");

        const $api2ResultPulseCount = document.querySelector("#api2-result-alienvaultotx-pulsecount");

        $api2Title.textContent = source;
        $api2ResultPulseCount.append(apiResponse.pulse_info.count);

    } else if (iocType === "hash") {
        $abuseipdb.classList.add("hidden");
        $alienvaultotx.classList.add("hidden");
        $polyswarm.classList.remove("hidden");

        const $api2ResultExtfiletype = document.querySelector("#api2-result-polyswarm-extfiletype");
        const $api2ResultMalwarefamliy = document.querySelector("#api2-result-polyswarm-malwarefamliy");

        const { result } = apiResponse;

        $api2Title.textContent = source;
        $api2ResultExtfiletype.append(result[0].extended_type);
        $api2ResultMalwarefamliy.append(result[0].metadata[0].tool_metadata.malware_family);
    }
}

async function handleFormSubmit(e) {
    const ioc = $input.value;
    e.preventDefault();

    // Reset UI
    resetUI()
    $submitIoC.disabled = true;
    $submitIoC.textContent = "Analizando...";

    try {
        const typeResponse = await fetch(
            `/api/type?ioc=${encodeURIComponent(ioc)}`,
        );
        const typeData = await typeResponse.json();

        if (typeData.error) {
            throw new Error(typeData.error);
        }

        const analyzeResponse = await fetch(
            `/api/analyze/${typeData.type}?ioc=${encodeURIComponent(ioc)}`,
        );
        const analyzeData = await analyzeResponse.json();

        // Process results
        let api1ResultData = null;
        let api2ResultData = null;

        if (typeData.type === "ip" || typeData.type === "domain") {
            api1ResultData = analyzeData.virustotal;
            api2ResultData =
                typeData.type === "ip"
                    ? analyzeData.abuseipdb
                    : analyzeData.otx;
        } else if (typeData.type === "hash") {
            api1ResultData = analyzeData.virustotal;
            api2ResultData = analyzeData.polyswarm;
            console.log(analyzeData.polyswarm)
        }

        // Update results
        resultsAPI1(api1ResultData, typeData.type)
        resultsAPI2(api2ResultData, typeData.type)



        $result.classList.remove("hidden");
    } catch (err) {
        $errorMsg.textContent =
            err.message || "An error occurred while analyzing the IoC.";
        $errorMsg.classList.remove("hidden");
    } finally {
        $loader.classList.add("hidden");
        $submitIoC.disabled = false;
        $submitIoC.textContent = "Analizar";
    }
}

$formAnalyzer.addEventListener("submit", handleFormSubmit);