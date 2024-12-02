import React, { useState } from "react";
import { IoCResult } from "@/components/IoCResult";
import styles from "@/styles/IoCAnalyzer.module.css";
import { useIoCAnalyzer } from "@/hooks/useIoCAnalyzer";

export const IoCAnalyzer = () => {
  const { updateIoC, analyzeIoC, result, error } = useIoCAnalyzer();
  const [input, setInput] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    updateIoC(input); // Actualiza el IoC en el hook
    await analyzeIoC(); // Analiza el IoC
  };

  return (
    <section className={styles.iocAnalyzer}>
      <form onSubmit={handleSubmit} className={styles.form} aria-label="IoC Analysis Form">
        <div className={styles.inputGroup}>
          <label htmlFor="ioc" className={styles.label}>
            Introduce un IoC (IP, Hash, Email o Dominio)
          </label>
          <input
            id="ioc"
            type="text"
            placeholder="8.8.8.8, test@example.com, 44d88612fea8a8f36de82e1278abb02f, etc"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            required
            className={styles.input}
            aria-required="true"
          />
        </div>
        <button type="submit" className={styles.button}>
          Analizar
        </button>
      </form>
      {error && <p className={styles.error}>{error}</p>}
      {result && <IoCResult result={result} />}
    </section>
  );
};
