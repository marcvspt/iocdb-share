export const IPAbuseIPDB = ({ jsonData }) => {
    const reportData = jsonData.data

    return (
        <aside className="mt-3 p-6 border border-accent-dark rounded-lg shadow-lg bg-accent-dark">
            <h3 className="font-bold">Fiabilidad de reputación:</h3>
            <p>
                <span>{reportData.abuseConfidenceScore}</span>
            </p>
        </aside>
    );
}