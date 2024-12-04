import React, { useState } from "react";
import { IoCResult } from "@/components/IoCResult";
import { Loader } from "@/components/Loader";

export const IoCAnalyzer = () => {
  const [ioc, setIoc] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [typeData, setTypeData] = useState(null)

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError("");
    setResult(null);
    setTypeData(null);

    try {
      const typeIoCResponse = await fetch(`/api/type?ioc=${encodeURIComponent(ioc)}`);
      const iocType = await typeIoCResponse.json();

      if (iocType.error) {
        throw new Error(iocType.error);
      }

      setTypeData(iocType);

      // Fetch analysis data based on type
      const analyzeResponse = await fetch(
        `/api/analyze/${iocType.type}?ioc=${encodeURIComponent(ioc)}`
      );
      const analyzeData = await analyzeResponse.json();

      // Set results based on IoC type
      if (iocType.type === "ip") {
        setResult({
          api1: { source: "VirusTotal", data: analyzeData.virustotal },
          api2: { source: "AbuseIPDB", data: analyzeData.abuseipdb },
        });
      } else if (iocType.type === "domain") {
        setResult({
          api1: { source: "VirusTotal", data: analyzeData.virustotal },
          api2: { source: "AlienVault OTX", data: analyzeData.otx },
        });
      }else if (iocType.type === "hash") {
        setResult({
          api1: { source: "VirusTotal", data: analyzeData.virustotal },
          api2: { source: "PolySwarm", data: analyzeData.polyswarm },
        });
      }
    } catch (err) {
      setError(err.message || "An error occurred while analyzing the IoC.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <section className="mx-auto pt-8 w-full max-w-screen-lg text-white text-lg leading-relaxed">
      <form
        onSubmit={handleSubmit}
        className="flex flex-col gap-4 mb-8"
        aria-label="IoC Analysis Form"
      >
        <div className="flex flex-col gap-2">
          <label htmlFor="ioc" className="text-sm text-accent-light">
            Introduce un IoC (IP, Hash o Dominio)
          </label>
          <input
            id="ioc"
            type="text"
            value={ioc}
            onChange={(e) => setIoc(e.target.value)}
            placeholder="8.8.8.8, 44d88612fea8a8f36de82e1278abb02f o example.com"
            required
            className="p-2 text-base border border-accent-light/20 rounded bg-accent-dark/10 text-white"
            aria-required="true"
          />
        </div>
        <button
          type="submit"
          className="p-2 text-base font-semibold text-gray-800 bg-gradient-to-r from-blue-400 to-purple-500 bg-size-200 bg-pos-0 border-none rounded cursor-pointer transition-all duration-300 ease-in-out hover:bg-pos-100"
          disabled={isLoading}
        >
          {isLoading ? "Analizando..." : "Analizar"}
        </button>
      </form>
      {error && <p className="text-red-600 font-bold">{error}</p>}
      {isLoading && <Loader />}
      {result && <IoCResult result={result} typeData={typeData.type} />}
    </section>
  );
};
