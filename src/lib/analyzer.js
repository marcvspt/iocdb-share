async function handleFormSubmit(e) {
    e.preventDefault();
    const input = document.getElementById("ioc");
    const ioc = input.value;
    const submitButton = document.getElementById("iocSubmit");
    const errorElement = document.getElementById("error");
    const loaderElement = document.getElementById("loader");
    const resultElement = document.getElementById("iocResults");

    // Reset UI
    errorElement.classList.add("hidden");
    resultElement.classList.add("hidden");
    loaderElement.classList.remove("hidden");
    submitButton.disabled = true;
    submitButton.textContent = "Analizando...";

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
        let result = {
            api1: null,
            api2: null,
        };

        if (typeData.type === "ip" || typeData.type === "domain") {
            result.api1 = analyzeData.virustotal;
            result.api2 =
                typeData.type === "ip"
                    ? analyzeData.abuseipdb
                    : analyzeData.otx;
        } else if (typeData.type === "hash") {
            result.api1 = analyzeData.virustotal;
            result.api2 = analyzeData.polyswarm;
        }

        // Update results
        document.getElementById("api1-title").textContent =
            result.api1.source;
        document.getElementById("api1-result").textContent = JSON.stringify(
            result.api1.apiResponse,
            null,
            2,
        );
        document.getElementById("api2-title").textContent =
            result.api2.source;
        document.getElementById("api2-result").textContent = JSON.stringify(
            result.api2.apiResponse,
            null,
            2,
        );
        resultElement.classList.remove("hidden");
    } catch (err) {
        errorElement.textContent =
            err.message || "An error occurred while analyzing the IoC.";
        errorElement.classList.remove("hidden");
    } finally {
        loaderElement.classList.add("hidden");
        submitButton.disabled = false;
        submitButton.textContent = "Analizar";
    }
}

const form = document.getElementById("iocForm");
form.addEventListener("submit", handleFormSubmit);