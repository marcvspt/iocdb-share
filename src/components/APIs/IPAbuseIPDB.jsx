export const IPAbuseIPDB = ({ jsonData }) => {
    const reportData = jsonData.data

    return (
        <>
            <h3 className="font-bold">Fiabilidad de reputación:</h3>
            <p>
                <span>{reportData.abuseConfidenceScore}</span>
            </p>
        </>
    );
}