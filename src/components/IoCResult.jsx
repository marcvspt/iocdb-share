import React from "react";
import styles from "@/styles/IoCResult.module.css"

export const IoCResult = ({ result }) => (
    <section className={styles.result} aria-labelledby="analysis-title">
        <header>
            <h2 id="analysis-title" className={styles.resultTitle}>
                Analysis Result
            </h2>
        </header>
        <div className={styles.resultGrid}>
            <article className={styles.resultCard} aria-labelledby="api1-title">
                <header>
                    <h3 id="api1-title" className={styles.resultCardTitle}>
                        API 1
                    </h3>
                </header>
                <pre className={styles.resultContent}>
                    {JSON.stringify(result.api1, null, 2)}
                </pre>
            </article>
            <article className={styles.resultCard} aria-labelledby="api2-title">
                <header>
                    <h3 id="api2-title" className={styles.resultCardTitle}>
                        API 2
                    </h3>
                </header>
                <pre className={styles.resultContent}>
                    {JSON.stringify(result.api2, null, 2)}
                </pre>
            </article>
        </div>
    </section>
);
