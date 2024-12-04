import React from "react";
import { IPVirusTotal } from "@/components/APIs/IPVirusTotal";
import { IPAbuseIPDB } from "@/components/APIs/IPAbuseIPDB";
import { DomainVirusTotal } from "@/components/APIs/DomainVirusTotal";
import { DomainOTX } from "@/components/APIs/DomainOTX";
import { HashVirusTotal } from "@/components/APIs/HashVirusTotal";
import { HashPolySwarm } from "@/components/APIs/HashPolySwarm";


export const IoCResult = ({ result, typeData }) => {
    const api1Source = result.api1.source
    const api1Data = result.api1.data

    const api2Source = result.api2.source
    const api2Data = result.api2.data

    return (
        <section className="mt-8" aria-labelledby="analysis-title">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-auto-fit gap-4">
                <article
                    className="bg-accent-dark/20 rounded-lg"
                    aria-labelledby="api1-title"
                >
                    <header>
                        <h3
                            id="api1-title"
                            className="font-bold text-accent-light text-center"
                        >
                            {api1Source}
                        </h3>
                    </header>
                    <aside className="mt-3 p-6 border border-accent-dark rounded-lg shadow-lg">
                        {typeData === "ip" && <IPVirusTotal jsonData={api1Data} />}
                        {typeData === "domain" && <DomainVirusTotal jsonData={api1Data} />}
                        {typeData === "hash" && <HashVirusTotal jsonData={api1Data} />}
                    </aside>
                </article>
                <article
                    className="bg-accent-dark/20 rounded-lg"
                    aria-labelledby="api2-title"
                >
                    <header>
                        <h3
                            id="api2-title"
                            className="font-bold text-accent-light text-center"
                        >
                            {api2Source}
                        </h3>
                    </header>
                    <aside className="mt-3 p-6 border border-accent-dark rounded-lg shadow-lg">
                        {typeData === "ip" && <IPAbuseIPDB jsonData={api2Data} />}
                        {typeData === "domain" && <DomainOTX jsonData={api2Data} />}
                        {typeData === "hash" && <HashPolySwarm jsonData={api2Data} />}
                    </aside>
                </article>
            </div>
        </section>
    )
};
