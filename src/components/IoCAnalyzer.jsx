import React, { useState } from "react";
import { IoCResult } from "@/components/IoCResult";
import { Loader } from "@/components/Loader";

export const IoCAnalyzer = () => {
  const [ioc, setIoc] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError("");
    setResult(null);

    try {
      const typeResponse = await fetch(`/api/type?ioc=${encodeURIComponent(ioc)}`);
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
          api2: analyzeData.polyswarm,
        });
      }
    } catch (err) {
      setError(err.message || "An error occurred while analyzing the IoC.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <section className="mx-auto p-8 w-full max-w-3xl text-white text-lg leading-relaxed">
      <form
        onSubmit={handleSubmit}
        className="flex flex-col gap-4 mb-8"
        aria-label="IoC Analysis Form"
      >
        <div className="flex flex-col gap-2">
          <label htmlFor="ioc" className="text-sm text-accent-light">
            Introduce un IoC (IP, Hash, Email o Dominio)
          </label>
          <input
            id="ioc"
            type="text"
            value={ioc}
            onChange={(e) => setIoc(e.target.value)}
            placeholder="8.8.8.8, test@example.com, 44d88612fea8a8f36de82e1278abb02f, etc"
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
      {result && <IoCResult result={result} />}
    </section>
  );
};
