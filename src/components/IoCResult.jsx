import React from "react";

export const IoCResult = ({ result }) => (
    <section className="mt-8" aria-labelledby="analysis-title">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-auto-fit gap-4">
            <article
                className="bg-accent-dark/20 rounded-lg p-4"
                aria-labelledby="api1-title"
            >
                <header>
                    <h3
                        id="api1-title"
                        className="text-base font-semibold mb-2 text-accent-light"
                    >
                        API 1
                    </h3>
                </header>
                <pre className="font-mono text-sm whitespace-pre-wrap break-words">
                    {JSON.stringify(result.api1, null, 2)}
                </pre>
            </article>
            <article
                className="bg-accent-dark/20 rounded-lg p-4"
                aria-labelledby="api2-title"
            >
                <header>
                    <h3
                        id="api2-title"
                        className="text-base font-semibold mb-2 text-accent-light"
                    >
                        API 2
                    </h3>
                </header>
                <pre className="font-mono text-sm whitespace-pre-wrap break-words">
                    {JSON.stringify(result.api2, null, 2)}
                </pre>
            </article>
        </div>
    </section>
);
