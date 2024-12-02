import { useState } from "react";

export const useIoCAnalyzer = () => {
    const [ioc, setIoc] = useState("");
    const [result, setResult] = useState(null);
    const [error, setError] = useState("");

    const updateIoC = (newIoC) => {
        setIoc(newIoC);
    };

    const analyzeIoC = async () => {
        setError("");
        setResult(null);

        try {
            // Fetch IoC type
            const typeResponse = await fetch(`/api/type?ioc=${ioc}`);
            const typeData = await typeResponse.json();

            if (typeData.error) {
                throw new Error(typeData.error);
            }

            // Fetch analysis data based on type
            const analyzeResponse = await fetch(
                `/api/analyze/${typeData.type}?ioc=${encodeURIComponent(ioc)}`
            );
            const analyzeData = await analyzeResponse.json();

            // Set results based on IoC type
            if (typeData.type === "ip" || typeData.type === "domain") {
                setResult({
                    api1: analyzeData.virustotal,
                    api2: typeData.type === "ip" ? analyzeData.abuseipdb : analyzeData.otx,
                });
            } else if (typeData.type === "email") {
                setResult({
                    api1: analyzeData.emailrep,
                    api2: analyzeData.haveibeenpwned,
                });
            } else if (typeData.type === "hash") {
                setResult({
                    api1: analyzeData.virustotal,
                    api2: analyzeData.filescan,
                });
            }
        } catch (err) {
            setError(`Error: ${err.message}`);
        }
    };

    return {
        updateIoC,
        analyzeIoC,
        result,
        error,
    };
};
